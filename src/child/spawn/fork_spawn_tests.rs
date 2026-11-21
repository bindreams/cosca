//! The ordinary Linux spawn's status channel, through the public `Command`: a child fd on the channel's
//! number, two of fds 0-2 closed, and what a spawn says of each way the child ends.
//!
//! Each row runs in a process of its own: it fills the descriptor table and closes std fds.

use std::cell::RefCell;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use super::{conclude, start, start_via, OnFailure, Started};
use crate::child::spawn::child_env::child_env_over;
use crate::child::spawn::in_child::InChild;
use crate::child::spawn::launch::Launch;
use crate::child::spawn::policy::SpawnPolicy;
use crate::child::spawn::SpawnFailure;
use crate::containment::cgroup::{CgroupLeaf, NotEntered, NotPlaced};
use crate::error::Error;
use crate::os_process::linux::fork::{fails_with, CloneKind, Fork, ForkFn, NewChild, Path};
use crate::resolve::Candidate;
use crate::test_own_process::{child_completion, own_process, run, test_filter, test_path};
use crate::test_stdio::RestoreStdio;
use crate::Stdio;

/// The launch of the one file `path`, with `argv` and an empty environment, for a spawn through a stand-in
/// clone or a program that is run.
pub(super) fn launch_of(path: &str, argv: &[&str]) -> Launch {
    let candidate = Candidate {
        path: path.into(),
        entry: None,
    };
    let argv: Vec<&OsStr> = argv.iter().map(OsStr::new).collect();
    Launch::new(vec![candidate], &argv, std::iter::empty()).expect("no NUL")
}

/// A program that does not exist: the spawn's `execve` fails with `ENOENT`.
const MISSING: &str = "/nonexistent/cosca-fork-spawn-tests";

fn assert_not_found(spawned: Result<crate::Child, Error>, what: &str) {
    match spawned {
        Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{what}: {e:?}"),
        Err(other) => panic!("{what}: expected the exec's ENOENT, got {other:?}"),
        Ok(child) => panic!(
            "{what}: the spawn of a program that does not exist succeeded (child {:?})",
            child.pid()
        ),
    }
}

/// Fills every free descriptor number below the soft `RLIMIT_NOFILE` with a duplicate of fd 0, and
/// returns them: the table is then full.
fn fill_to_the_limit() -> Vec<OwnedFd> {
    let stdin = rustix::stdio::stdin();
    let mut filled = Vec::new();
    loop {
        match rustix::io::fcntl_dupfd_cloexec(stdin, 3) {
            Ok(fd) => filled.push(fd),
            Err(rustix::io::Errno::MFILE) => return filled,
            Err(e) => panic!("dup fd 0 above stdio: {e}"),
        }
    }
}

/// A `child_fd` on the number the status channel took must not hide a failed exec.
///
/// The descriptor limit is lowered to 256 and every free number below it is filled, then a block of
/// `BLOCK_LEN` is released: the spawn's descriptors can only take the block's numbers. The command maps a
/// child fd onto each of a run of numbers that covers every one the spawn's channel can take after its stdio
/// ends and its mapping sources. A channel that took one of them would be replaced by the mapping in the
/// child, and the failed exec's record would go to the mapped file: the spawn would answer `Ok`.
///
/// The block is the first run of free numbers the process has, so the test needs no number to be free that
/// the host's own descriptors might hold. A status channel made with the same descriptors open before it
/// takes a number in the mapped run (the premise the mutant depends on).
///
/// Mutant: the channel's write end is not kept off the fd map's numbers.
#[skuld::test]
fn a_child_fd_on_the_status_channels_number_does_not_hide_a_failed_exec() {
    const BLOCK_LEN: RawFd = 80;
    const SOURCES: RawFd = 24;
    const LIMIT: libc::rlim_t = 256;
    let Some(done) = own_process(
        test_path!(a_child_fd_on_the_status_channels_number_does_not_hide_a_failed_exec),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let _limit = crate::test_child::lower_fd_limit(&done, LIMIT);
    let filled = fill_to_the_limit();
    let free: std::collections::BTreeSet<RawFd> = filled.iter().map(AsRawFd::as_raw_fd).collect();
    let start = free
        .iter()
        .copied()
        .find(|&n| (n..n + BLOCK_LEN).all(|m| free.contains(&m)))
        .expect("a run of free numbers below the limit for the block");
    let block = start..start + BLOCK_LEN;
    // The three std ends of the spawn and the mappings' sources take the first of the block; whatever the spawn
    // opens next starts after them.
    let first_free = block.start + 3 + SOURCES;
    let targets = first_free..first_free + SOURCES;
    let (_kept, holes): (Vec<_>, Vec<_>) = filled.into_iter().partition(|fd| !block.contains(&fd.as_raw_fd()));
    assert_eq!(holes.len(), block.len(), "the block is made of free numbers");
    drop(holes);

    // The premise: with that many descriptors open, the channel's write end takes a number the command maps.
    {
        let stand_ins: Vec<OwnedFd> = (0..first_free - block.start)
            .map(|_| rustix::io::fcntl_dupfd_cloexec(rustix::stdio::stdin(), 3).expect("a stand-in for a source"))
            .collect();
        assert_eq!(stand_ins.last().map(AsRawFd::as_raw_fd), Some(first_free - 1));
        let (_status, write) = super::fork_exec::channel(CloneKind::Vfork, &[]).expect("a status channel");
        assert!(
            targets.contains(&write.as_raw_fd()),
            "the channel's write end {} is not among the mapped numbers {targets:?}",
            write.as_raw_fd()
        );
    }

    let mut cmd = crate::test_child::command(crate::test_child::Console::Hidden);
    cmd.args([MISSING]);
    for target in targets {
        cmd.fd(target, Stdio::null()).expect("map a child fd");
    }
    assert_not_found(cmd.spawn(), "a child fd on every number the channels can take");
}

/// What a case of [`a_failed_exec_is_an_error_with_two_of_fds_0_to_2_closed`] closes: the slots, then how
/// the command's stdio is given.
const SLOTS_ENV: &str = "COSCA_TESTCFG_CLOSED_SLOTS";
const STDIO_ENV: &str = "COSCA_TESTCFG_STDIO";

/// With two of fds 0-2 closed the spawn is still an error for a failed exec, nothing
/// reaches the child's redirected stdout or stderr, and a spawn that works still runs its program with the
/// right stdio. `files`: the command's ends are files opened before the close (numbered above 2);
/// `null`: they are `/dev/null` opened by the spawn itself, which takes the closed numbers.
///
/// Mutant: the channel's ends are not moved above stdio.
#[skuld::test]
fn a_failed_exec_is_an_error_with_two_of_fds_0_to_2_closed() {
    let path = test_path!(a_failed_exec_is_an_error_with_two_of_fds_0_to_2_closed);
    if let Some(done) = child_completion(path) {
        let slots = std::env::var(SLOTS_ENV).expect(SLOTS_ENV);
        let null = std::env::var(STDIO_ENV).expect(STDIO_ENV) == "null";
        let slots: Vec<RawFd> = slots.split(',').map(|s| s.parse().expect("a slot")).collect();
        let dir = tempfile::tempdir().expect("tempdir");
        for (program, what) in [(MISSING, "a failed exec"), ("/bin/sh", "a program that runs")] {
            let (out, err) = (dir.path().join("out"), dir.path().join("err"));
            let mut cmd = crate::test_child::command(crate::test_child::Console::Hidden);
            if program == MISSING {
                cmd.args([program]);
            } else {
                cmd.args([program, "-c", "echo out; echo err >&2"]);
            }
            if null {
                cmd.stdin(Stdio::null()).expect("stdin");
                cmd.stdout(Stdio::null()).expect("stdout");
                cmd.stderr(Stdio::null()).expect("stderr");
            } else {
                let file = |path: &std::path::Path| File::create(path).expect("create");
                cmd.stdin(Stdio::from_file(File::open("/dev/null").expect("open")))
                    .expect("stdin");
                cmd.stdout(Stdio::from_file(file(&out))).expect("stdout");
                cmd.stderr(Stdio::from_file(file(&err))).expect("stderr");
            }
            let restore = RestoreStdio::close(&done, &slots);
            let spawned = cmd.spawn();
            let label = format!(
                "{what}, slots {slots:?} closed, stdio {}",
                if null { "null" } else { "files" }
            );
            // Nothing the spawn keeps (the child's pidfd, a status channel) is in a slot the application
            // left closed: it could `dup2` its stdio over it.
            for &slot in &slots {
                // SAFETY: `fcntl` of a number that is open or not; the descriptor is never used.
                let slot_fd = unsafe { rustix::fd::BorrowedFd::borrow_raw(slot) };
                assert!(
                    rustix::io::fcntl_getfd(slot_fd).is_err(),
                    "{label}: the spawn left a descriptor in the closed slot {slot}"
                );
            }
            drop(restore);
            if program == MISSING {
                assert_not_found(spawned, &label);
                if !null {
                    assert_eq!(std::fs::read(&out).expect("read"), b"", "{label}: stdout");
                    assert_eq!(std::fs::read(&err).expect("read"), b"", "{label}: stderr");
                }
            } else {
                let status = spawned
                    .unwrap_or_else(|e| panic!("{label}: {e:?}"))
                    .wait()
                    .expect("wait");
                assert!(status.success(), "{label}: {status:?}");
                if !null {
                    assert_eq!(std::fs::read(&out).expect("read"), b"out\n", "{label}: stdout");
                    assert_eq!(std::fs::read(&err).expect("read"), b"err\n", "{label}: stderr");
                }
            }
        }
        return;
    }
    let failures: Vec<String> = ["files", "null"]
        .into_iter()
        .flat_map(|stdio| ["1,2", "0,1", "0,2", "0,1,2"].map(|slots| (slots, stdio)))
        .filter_map(|(slots, stdio)| {
            run(
                test_filter(path),
                &[(SLOTS_ENV, slots), (STDIO_ENV, stdio)],
                crate::test_spawn::spawn,
            )
            .err()
            .map(|failure| format!("slots [{slots}], stdio {stdio}: {failure}"))
        })
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// What a spawn says of each way the child ends ---------------------------------------------------

thread_local! {
    /// The child the stand-in clone of this thread hands over.
    pub(super) static HANDED_OVER: RefCell<Option<NewChild>> = const { RefCell::new(None) };
}

/// A clone that makes no child and answers the child [`HANDED_OVER`] holds, whose status channel the
/// spawn made and closed: it ended with no record.
///
/// # Safety
///
/// As `fork_with_pidfd`; it makes no child, and never returns in one.
pub(super) unsafe fn hand_over(_kind: CloneKind) -> Result<Fork, i32> {
    HANDED_OVER
        .with(|child| child.borrow_mut().take())
        .map(Fork::Parent)
        .ok_or(libc::EAGAIN)
}

/// [`start_via`] over `fork`, for a program that is never run. `placement`: the spawn's leaf and
/// whether its slot refuses a failed write.
fn start_over(fork: ForkFn, placement: Option<(&mut CgroupLeaf, bool)>) -> Result<Started, SpawnFailure> {
    let (placement, refusing_placement) = match placement {
        Some((channel, refusing)) => (Some(channel), refusing),
        None => (None, false),
    };
    let launch = launch_of("/bin/true", &["true"]);
    let lock = crate::child::spawn::spawn_lock();
    start_via(
        fork,
        &launch,
        &mut InChild::default(),
        crate::identity::spawn_kernel(crate::identity::HostKernel),
        OnFailure {
            policy: SpawnPolicy::SYNC,
            tracked: crate::elevation::front::TrackedKind::Own,
            placement,
            refusing_placement,
        },
        &lock,
    )
}

/// Makes the stand-in clone hand over a child that has already ended, as one that ended before its
/// `execve` does: its status channel holds no record.
fn hand_over_an_ended_child() -> std::process::Child {
    hand_over_a_child_that_exited_with(0)
}

/// [`hand_over_an_ended_child`], for a child that exited with `code`.
fn hand_over_a_child_that_exited_with(code: i32) -> std::process::Child {
    let mut child = std::process::Command::new("/bin/sh");
    child.args(["-c", &format!("exit {code}")]);
    let child = crate::test_spawn::spawn(&mut child).expect("spawn a child that exits at once");
    let pid = child.id();
    HANDED_OVER.with(|handed| {
        *handed.borrow_mut() = Some(NewChild {
            pid: pid as i32,
            pidfd: crate::containment::cgroup::test_support::pidfd_of(pid),
            path: Path::Clone3,
        });
    });
    child
}

/// A spawn torn down whole: the failure says the child died before its `execve`, and the teardown
/// reaped `pid` through the pidfd it held. Returns what the failure says.
fn assert_torn_down(started: Result<Started, SpawnFailure>, pid: u32) -> String {
    let failure = match started {
        Ok(started) => panic!("a child with no ready record started: pid {}", started.pid),
        Err(failure) => failure,
    };
    let (cause, _fate) = failure.expect_not_started_with_child();
    let said = crate::error::Report(&cause).to_string();
    assert!(said.contains("died before exec"), "{cause:?}");
    // SAFETY: a `waitid` with no output buffer, `WNOWAIT`: it consumes nothing.
    let waited = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            std::ptr::null_mut(),
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    assert_eq!(
        (waited, std::io::Error::last_os_error().raw_os_error()),
        (-1, Some(libc::ECHILD)),
        "the teardown reaped the child it held"
    );
    said
}

/// A child with no record on its status channel, which ended before its ready record, did not start:
/// the spawn tears it down through its pidfd and says so.
///
/// Mutant: a channel that ended with no ready record is read as a started program.
#[skuld::test]
fn a_child_that_ended_before_exec_is_torn_down_and_the_spawn_did_not_start() {
    let child = hand_over_an_ended_child();
    let pid = child.id();
    assert_torn_down(start_over(hand_over, None), pid);
    drop(child);
}

/// A test leaf in `dir`, whose `cgroup.procs` the verdict can read.
fn test_leaf(dir: &std::path::Path) -> CgroupLeaf {
    let leaf_path = dir.join("cosca-fork-spawn-leaf");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    std::fs::write(leaf_path.join("cgroup.procs"), "").expect("write cgroup.procs");
    CgroupLeaf::for_test_at(leaf_path)
}

/// What `leaf`'s verdict says of the spawn's child, for any child: `Ok` is a placed one, the error says
/// what it reported.
fn verdict_of(leaf: &mut CgroupLeaf) -> Result<(), NotEntered> {
    let pidfd = crate::containment::cgroup::test_support::pidfd_of(std::process::id());
    leaf.take_placement(crate::containment::cgroup::test_support::handle_of(
        std::process::id(),
        &pidfd,
    ))
    .map_err(|not_placed| match not_placed {
        NotPlaced::Absent { report, .. } | NotPlaced::Unreadable { report, .. } => report,
    })
}

/// A spawn of `/bin/true` through the real clone, whose child runs the placement step on `procs_fd`
/// (`refusing`: a failed write ends it), then `more`'s steps, with `leaf` to record its report on.
fn start_placed(
    leaf: &mut CgroupLeaf,
    procs_fd: RawFd,
    refusing: bool,
    more: impl FnOnce(&mut InChild),
) -> Result<Started, SpawnFailure> {
    start_placed_expecting(leaf, procs_fd, refusing, refusing, more)
}

/// [`start_placed`] for a spawn whose parent expects a refusing child (`expects_refusal`) of a child that
/// does not, or the other way round.
fn start_placed_expecting(
    leaf: &mut CgroupLeaf,
    procs_fd: RawFd,
    refusing: bool,
    expects_refusal: bool,
    more: impl FnOnce(&mut InChild),
) -> Result<Started, SpawnFailure> {
    let launch = launch_of("/bin/true", &["true"]);
    let mut steps = InChild::default();
    // SAFETY: `procs_fd` stays open until the spawn has returned.
    unsafe { steps.place(procs_fd, refusing) };
    more(&mut steps);
    let lock = crate::child::spawn::spawn_lock();
    start(
        &launch,
        &mut steps,
        crate::identity::spawn_kernel(crate::identity::HostKernel),
        OnFailure {
            policy: SpawnPolicy::SYNC,
            tracked: crate::elevation::front::TrackedKind::Own,
            placement: Some(leaf),
            refusing_placement: expects_refusal,
        },
        &lock,
    )
}

/// An fd-map step that fails in the child: a mapping onto a descriptor number no process can have.
fn failing_fd_map(steps: &mut InChild) {
    crate::child::spawn::fd_map::install(
        steps,
        vec![crate::child::spawn::fd_map::FdMapping {
            parent_fd: File::open("/dev/null").expect("open /dev/null").into(),
            child_fd: i32::MAX,
        }],
    )
    .expect("install the mapping");
}

/// A child that placed itself in its cgroup leaf and then ended before its `execve` (a later step failed)
/// did not start, whatever its placement report says: only a refused placement hands a child to the
/// attach. The spawn's error is the step's, and the leaf learned that the child entered it.
///
/// Mutants: a child that reported `Placed` is handed to the attach; the report is not recorded on the leaf.
#[skuld::test]
fn a_child_that_placed_itself_and_ended_before_exec_is_torn_down() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut leaf = test_leaf(dir.path());
    let sink = File::options().write(true).open("/dev/null").expect("open /dev/null");
    let failure = match start_placed(&mut leaf, sink.as_raw_fd(), true, failing_fd_map) {
        Ok(started) => panic!("a child whose fd map failed started: pid {}", started.pid),
        Err(failure) => failure,
    };
    let (cause, _fate) = failure.expect_not_started_with_child();
    assert!(
        matches!(&cause, Error::Io(e) if e.raw_os_error() == Some(libc::EBADF)),
        "{cause:?}"
    );
    assert_eq!(
        verdict_of(&mut leaf),
        Ok(()),
        "the child placed itself before its fd map failed"
    );
}

/// A child whose placement write failed in a slot that does not refuse a failed write goes on, and when a
/// later step then ends it, the failure is that step's, not blamed on the placement; the leaf still learns
/// what the child reported.
///
/// Mutant: a reported failed write is read as the cause of any end before the ready record.
#[skuld::test]
fn a_child_that_reported_a_failed_placement_and_went_on_is_not_blamed_on_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut leaf = test_leaf(dir.path());
    crate::containment::cgroup::fault::set_force_placement_write_result(
        crate::containment::cgroup::fault::ForcedWrite::FailsWith(libc::EBUSY),
    );
    let failure = match start_placed(&mut leaf, -1, false, failing_fd_map) {
        Ok(started) => panic!("a child whose fd map failed started: pid {}", started.pid),
        Err(failure) => failure,
    };
    let (cause, _fate) = failure.expect_not_started_with_child();
    assert!(
        matches!(&cause, Error::Io(e) if e.raw_os_error() == Some(libc::EBADF)),
        "the fd map's EBADF, not the placement's EBUSY: {cause:?}"
    );
    assert_eq!(verdict_of(&mut leaf), Err(NotEntered::WriteFailed(libc::EBUSY)));
}

/// A child whose refusing placement failed ended in its placement step: it is handed to the attach as it
/// is, to read the report and say why, and the leaf holds the report.
///
/// Mutants: a refused child is torn down in the spawn (with the step's error, not the attach's); the
/// refused report is not recorded.
#[skuld::test]
fn a_child_whose_placement_was_refused_is_handed_to_the_attach() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut leaf = test_leaf(dir.path());
    crate::containment::cgroup::fault::set_force_placement_write_result(
        crate::containment::cgroup::fault::ForcedWrite::FailsWith(libc::EBUSY),
    );
    let started = start_placed(&mut leaf, -1, true, |_| {})
        .unwrap_or_else(|failure| panic!("a refused placement is the attach's to read: {failure:?}"));
    assert_eq!(
        crate::child::spawn::in_child::exit_code(&started),
        Some(super::STEP_EXIT),
        "the refused child ended in its placement step"
    );
    drop(started);
    assert_eq!(verdict_of(&mut leaf), Err(NotEntered::WriteFailed(libc::EBUSY)));
}

/// A child that ended in its placement step, with a record that says so, did not start, and the failure
/// names the placement step, as a placement failure is named elsewhere ([`Error::Containment`]), with the
/// step's errno as its source: not the bare `Error::Io` of any other step.
///
/// A step that fails on its report write cannot be made to leave its record here (the record goes through
/// the same write), so a refusing child whose write fails, under a parent that does not expect a refusal
/// (and so does not hand it to the attach), stands in: the child ends in the placement step with the step's
/// own record. Mutants: every step failure is a placement one (a child that ended in a later step, as in
/// `a_child_that_placed_itself_and_ended_before_exec_is_torn_down`, says the step's own `Error::Io`); a
/// placement step's failure is the bare `Error::Io`.
#[skuld::test]
fn a_child_that_ended_in_its_placement_step_says_so() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut leaf = test_leaf(dir.path());
    crate::containment::cgroup::fault::set_force_placement_write_result(
        crate::containment::cgroup::fault::ForcedWrite::FailsWith(libc::EBUSY),
    );
    let failure = match start_placed_expecting(&mut leaf, -1, true, false, |_| {}) {
        Ok(started) => panic!("a child that ended in its placement step started: pid {}", started.pid),
        Err(failure) => failure,
    };
    let (cause, _fate) = failure.expect_not_started_with_child();
    let Error::Containment { detail, source } = &cause else {
        panic!("a placement step's failure is a containment failure: {cause:?}");
    };
    assert!(
        detail.contains("died before exec in its cgroup placement step: the program never ran"),
        "{detail}"
    );
    assert!(
        matches!(source.as_deref(), Some(Error::Io(e)) if e.raw_os_error() == Some(libc::EBUSY)),
        "the step's errno is the source: {source:?}"
    );
}

/// A child that ended before it reported anything, in a spawn with a leaf, is torn down with the generic
/// error, and the leaf is left with no report.
///
/// Mutant: a child with no ready record is handed to the attach whenever it has a leaf; a child with no
/// report is blamed on its placement.
#[skuld::test]
fn a_child_that_ended_before_it_reported_its_placement_is_torn_down() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut leaf = test_leaf(dir.path());
    let child = hand_over_a_child_that_exited_with(1);
    let pid = child.id();
    let said = assert_torn_down(start_over(hand_over, Some((&mut leaf, true))), pid);
    assert!(!said.contains("placement"), "{said}");
    assert_eq!(verdict_of(&mut leaf), Err(NotEntered::NotReported));
    drop(child);
}

/// A child with a cgroup leaf whose status channel says it reached its `execve` has reported its placement:
/// its placement step writes the report before the ready record. A child that did not (here, one whose steps
/// carry no placement) breaks that, which debug builds assert; release builds go on, and the leaf has no report.
///
/// Mutants: the invariant is not asserted, so a spawn that lost the placement step records no report and goes
/// on (debug); the leaf is given a report of its own (release).
#[skuld::test]
#[cfg_attr(
    debug_assertions,
    should_panic(expected = "reached its execve with no placement report")
)]
fn a_child_with_a_leaf_that_reached_its_exec_without_a_report_asserts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut leaf = test_leaf(dir.path());
    let started = start_via_the_real_clone(&mut leaf);
    #[cfg(not(debug_assertions))]
    assert_eq!(verdict_of(&mut leaf), Err(NotEntered::NotReported));
    drop(started);
}

/// A spawn of `/bin/true` through the real clone with no placement step, for `leaf`.
fn start_via_the_real_clone(leaf: &mut CgroupLeaf) -> Result<Started, SpawnFailure> {
    let launch = launch_of("/bin/true", &["true"]);
    let lock = crate::child::spawn::spawn_lock();
    start_via(
        crate::os_process::linux::fork::fork_with_pidfd,
        &launch,
        &mut InChild::default(),
        crate::identity::spawn_kernel(crate::identity::HostKernel),
        OnFailure {
            policy: SpawnPolicy::SYNC,
            tracked: crate::elevation::front::TrackedKind::Own,
            placement: Some(leaf),
            refusing_placement: false,
        },
        &lock,
    )
}

/// A status channel the spawn cannot read proves nothing: the spawn goes on as one of a program that may have
/// started (`Ok`), and warns, naming the child. The channel is made here, its read end replaced with a
/// directory (a read of it is `EISDIR`), and handed to the spawn's conclusion with the child. Where the child
/// has a cgroup leaf, its placement is unknown: the leaf records that and the read's errno, and does not
/// take the child as placed (the attach must not build on a proof the spawn does not have), nor as absent (a
/// kill through the leaf is owed, whether or not the child entered).
///
/// Mutants: an unreadable channel fails the spawn, or is taken as "did not start" and the child torn down;
/// the leaf is taken to hold the child as placed, or to hold no child.
#[skuld::test]
fn an_unreadable_status_channel_is_a_started_spawn_with_a_warning() {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let dir = tempfile::tempdir().expect("tempdir");
    let mut leaf = test_leaf(dir.path());
    let child = hand_over_an_ended_child();
    let pid = child.id();
    let handed = HANDED_OVER
        .with(|handed| handed.borrow_mut().take())
        .expect("a handed-over child");
    let (status, _write) = super::fork_exec::channel(CloneKind::Vfork, &[]).expect("a status channel");
    let read_end = status.as_fd().as_raw_fd();
    let directory = File::open("/").expect("open a directory");
    // SAFETY: `dup2` of an open descriptor onto the channel's read end, which only `status` owns; it stays
    // open for `status`'s drop.
    assert_eq!(unsafe { libc::dup2(directory.as_raw_fd(), read_end) }, read_end);
    let started = conclude(
        handed,
        status,
        crate::identity::spawn_kernel(crate::identity::HostKernel),
        OnFailure {
            policy: SpawnPolicy::SYNC,
            tracked: crate::elevation::front::TrackedKind::Own,
            placement: Some(&mut leaf),
            refusing_placement: false,
        },
        &launch_of("/bin/true", &["true"]),
    )
    .unwrap_or_else(|failure| panic!("an unreadable status channel failed the spawn: {failure:?}"));
    assert_eq!(started.pid, pid);
    assert_eq!(
        verdict_of(&mut leaf),
        Err(NotEntered::Unknown(libc::EISDIR)),
        "the leaf records that the placement is unknown, with the read's errno"
    );
    let warns = crate::log_capture::warns_since(mark, "its status channel is unreadable");
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(warns[0].contains(&pid.to_string()), "{warns:?}");
    drop(started);
    drop(child);
}

/// A spawn that cannot make its status channel (no descriptor to spare) makes no clone and no child, and
/// says the errno of the pipe: `NotStarted`.
///
/// Mutants: the pipe's failure is mapped to a failure that may have started; the clone runs before the
/// channel is made.
#[skuld::test]
fn a_status_channel_that_cannot_be_opened_is_not_started_with_emfile_and_no_child() {
    unsafe fn no_clone(_: CloneKind) -> Result<Fork, i32> {
        panic!("a clone ran although the status channel was not made")
    }

    let Some(done) = own_process(
        test_path!(a_status_channel_that_cannot_be_opened_is_not_started_with_emfile_and_no_child),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let restore = crate::test_child::exhaust_fds(&done);
    let failure = start_over(no_clone, None);
    drop(restore);
    match failure.err().expect("no descriptor, no spawn").expect_not_started() {
        Error::Io(e) => assert_eq!(e.raw_os_error(), Some(libc::EMFILE), "{e:?}"),
        other => panic!("expected Io(EMFILE), got {other:?}"),
    }
}

thread_local! {
    /// The pid of the child [`clone_then_refuse_new_descriptors`] made.
    static CLONED: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
}

/// The real clone, after which this process takes no descriptor at 3 or above: the descriptor limit is
/// 3 from here on, so the move of the pidfd out of a stdio slot fails.
///
/// # Safety
///
/// As `fork_with_pidfd`.
unsafe fn clone_then_refuse_new_descriptors(kind: CloneKind) -> Result<Fork, i32> {
    // SAFETY: the caller's contract.
    let forked = unsafe { crate::os_process::linux::fork::fork_with_pidfd(kind) }?;
    if let Fork::Parent(child) = &forked {
        CLONED.set(Some(child.pid.unsigned_abs()));
        // The hard limit stays, so the test can put the soft one back.
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: reads and lowers this process's own limit.
        unsafe {
            libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit);
            limit.rlim_cur = 3;
            libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
        }
    }
    Ok(forked)
}

/// A pidfd the spawn cannot move out of a stdio slot (the descriptor limit leaves no number at 3 or
/// above) is a failed spawn of a child that may be running: the spawn says so, tears the child down
/// through the pidfd it still holds, and leaves nothing of it.
///
/// Mutants: a failed move is ignored and the pidfd is kept in the slot; the child is left running.
#[skuld::test]
fn a_pidfd_that_cannot_be_moved_above_stdio_fails_the_spawn_and_ends_the_child() {
    let Some(done) = own_process(
        test_path!(a_pidfd_that_cannot_be_moved_above_stdio_fails_the_spawn_and_ends_the_child),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let launch = launch_of("/bin/sleep", &["sleep", "1000"]);
    assert_unmovable_pidfd_ends_the_child(start_with_an_unmovable_pidfd(&done, &launch, None));
}

/// A child whose pidfd cannot be moved still tells its leaf where it placed itself: the spawn fails, the
/// child is torn down, and the leaf, which the failed spawn's `Drop` kills through when the child entered
/// it, holds the report.
///
/// Mutant: the placement report is read only when the pidfd moved.
#[skuld::test]
fn a_child_whose_pidfd_cannot_be_moved_still_tells_its_leaf_where_it_placed_itself() {
    let Some(done) = own_process(
        test_path!(a_child_whose_pidfd_cannot_be_moved_still_tells_its_leaf_where_it_placed_itself),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let mut leaf = test_leaf(dir.path());
    let sink = File::options().write(true).open("/dev/null").expect("open /dev/null");
    let launch = launch_of("/bin/sleep", &["sleep", "1000"]);
    assert_unmovable_pidfd_ends_the_child(start_with_an_unmovable_pidfd(
        &done,
        &launch,
        Some((&mut leaf, sink.as_raw_fd())),
    ));
    assert_eq!(verdict_of(&mut leaf), Ok(()), "the child reported its placement");
}

/// [`start_via`] over [`clone_then_refuse_new_descriptors`] with stdio slot 0 closed, so the clone's pidfd
/// takes it and cannot be moved. `placement`: a leaf, and the descriptor its child's placement step writes.
fn start_with_an_unmovable_pidfd(
    done: &crate::test_own_process::Completion,
    launch: &Launch,
    placement: Option<(&mut CgroupLeaf, RawFd)>,
) -> Result<Started, SpawnFailure> {
    let mut steps = InChild::default();
    let leaf = placement.map(|(leaf, procs_fd)| {
        // SAFETY: the caller keeps `procs_fd` open until the spawn has returned.
        unsafe { steps.place(procs_fd, false) };
        leaf
    });
    let mut before = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: reads this process's own limit.
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut before) }, 0);
    // The clone's pidfd takes the closed slot.
    let restore = RestoreStdio::close(done, &[0]);
    let lock = crate::child::spawn::spawn_lock();
    let failure = start_via(
        clone_then_refuse_new_descriptors,
        launch,
        &mut steps,
        crate::identity::spawn_kernel(crate::identity::HostKernel),
        OnFailure {
            policy: SpawnPolicy::SYNC,
            tracked: crate::elevation::front::TrackedKind::Own,
            placement: leaf,
            refusing_placement: false,
        },
        &lock,
    );
    drop(lock);
    // SAFETY: puts this process's own soft limit back.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &before) }, 0);
    drop(restore);
    failure
}

/// A pidfd the spawn could not move is moved (or fails the spawn) before the status channel is read: even a
/// child whose channel says its program does not exist is a failed spawn of a child that may be running,
/// with the failed move as its cause, and is torn down.
///
/// Mutant: the pidfd is moved only after the channel has been read.
#[skuld::test]
fn the_pidfd_is_moved_above_stdio_before_the_status_channel_is_read() {
    let Some(done) = own_process(
        test_path!(the_pidfd_is_moved_above_stdio_before_the_status_channel_is_read),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let launch = launch_of(MISSING, &["missing"]);
    assert_unmovable_pidfd_ends_the_child(start_with_an_unmovable_pidfd(&done, &launch, None));
}

/// The spawn failed as a child that may be running, for the failed move of its pidfd, and the child it made
/// is ended and reaped.
fn assert_unmovable_pidfd_ends_the_child(failure: Result<Started, SpawnFailure>) {
    let (cause, _fate) = match failure {
        Ok(started) => {
            // Ends the child, so the drop of its box that the panic runs does not wait for the sleeper.
            // SAFETY: `kill` of the child this spawn made, which nothing has reaped.
            unsafe { libc::kill(started.pid as libc::pid_t, libc::SIGKILL) };
            panic!("the spawn kept a pidfd in a stdio slot (child {})", started.pid)
        }
        Err(failure) => failure.expect_may_have_started_with(),
    };
    assert!(
        crate::error::Report(&cause)
            .to_string()
            .contains("moving the child's pidfd above stdio"),
        "{cause:?}"
    );
    let pid = CLONED.get().expect("the clone ran");
    // SAFETY: a `waitid` with no output buffer, `WNOWAIT`: it consumes nothing.
    let waited = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            std::ptr::null_mut(),
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    assert_eq!(
        (waited, std::io::Error::last_os_error().raw_os_error()),
        (-1, Some(libc::ECHILD)),
        "the teardown through the unmoved pidfd ended and reaped the child"
    );
}

/// What the spawn says of a clone the kernel refused: `Unsupported` for the two errnos that are a
/// refusal on both paths, and the clone's own `Io` for any other. No child, and the program never ran.
///
/// Mutants: `Unsupported` mapped to `Io`; an errno other than `ENOSYS` and `EPERM` mapped to `Unsupported`.
#[skuld::test]
fn a_refused_clone_is_unsupported_and_any_other_is_the_clones_own_io() {
    let refusals: [(ForkFn, &str); 2] = [
        (|_| fails_with(libc::ENOSYS), "ENOSYS"),
        (|_| fails_with(libc::EPERM), "EPERM"),
    ];
    for (fork, name) in refusals {
        let failure = match start_over(fork, None) {
            Ok(_) => panic!("a refused clone made a child"),
            Err(failure) => failure,
        };
        match failure.expect_not_started() {
            Error::Unsupported { op, detail, .. } => {
                assert_eq!(op, "spawn", "{name}");
                let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").expect("the kernel release");
                assert!(
                    detail.ends_with(&format!("clone answered {name} (kernel {})", release.trim_end())),
                    "{name}: {detail}"
                );
            }
            other => panic!("{name}: expected Unsupported, got {other:?}"),
        }
    }
    let failure = match start_over(|_| fails_with(libc::EAGAIN), None) {
        Ok(_) => panic!("a failed clone made a child"),
        Err(failure) => failure,
    };
    match failure.expect_not_started() {
        Error::Io(e) => assert_eq!(e.raw_os_error(), Some(libc::EAGAIN), "{e:?}"),
        other => panic!("expected Io, got {other:?}"),
    }
}

/// A step that fails is the spawn's error, with its errno, and the program never runs: the directory
/// the child must enter is not there.
///
/// Mutant: a failed step does not stop the child before its `execve`.
#[skuld::test]
fn a_failing_step_is_the_spawns_error_and_the_program_never_runs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ran = dir.path().join("ran");
    let mut cmd = crate::test_child::command(crate::test_child::Console::Hidden);
    cmd.args(["/bin/sh".into(), "-c".into(), format!("touch {}", ran.display())])
        .current_dir(dir.path().join("missing"));
    assert_not_found(cmd.spawn(), "a child that cannot enter its directory");
    assert!(!ran.exists(), "the program ran although its step failed");
}

/// A program the spawn cannot start is a spawn error with the `execve` errno, whichever it is.
#[skuld::test]
fn an_exec_that_fails_is_the_spawns_error_with_its_errno() {
    let dir = tempfile::tempdir().expect("tempdir");
    let denied = dir.path().join("denied");
    std::fs::write(&denied, "#!/bin/sh\n").expect("write");
    let mut cmd = crate::test_child::command(crate::test_child::Console::Hidden);
    cmd.args([denied.as_os_str()]);
    match cmd.spawn() {
        Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{e:?}"),
        other => panic!(
            "a file that is not executable: expected EACCES, got {:?}",
            other.map(|c| c.pid())
        ),
    }
}

/// An interior NUL in an argument or in the environment is `InvalidInput`, as `std` says, and no
/// child is made.
#[skuld::test]
fn a_nul_in_an_argument_or_the_environment_is_invalid_input() {
    let mut in_argument = crate::test_child::command(crate::test_child::Console::Hidden);
    in_argument.args(["/bin/true", "a\0b"]);
    let mut in_environment = crate::test_child::command(crate::test_child::Console::Hidden);
    in_environment.args(["/bin/true"]).env("COSCA_NUL", "a\0b");
    for (mut cmd, what) in [(in_argument, "argument"), (in_environment, "environment")] {
        match cmd.spawn() {
            Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{what}: {e:?}"),
            other => panic!("{what}: expected InvalidInput, got {:?}", other.map(|c| c.pid())),
        }
    }
}

// The environment is `std`'s ---------------------------------------------------------------------

/// This process's environment, as [`child_env_over`] builds it.
fn child_env(ops: &[crate::command::EnvOp], marker: bool) -> Vec<(OsString, OsString)> {
    child_env_over(std::env::vars_os(), ops, marker)
}

/// The environment is this process's, changed by the ops in order, with the nesting marker last: an
/// `env_clear` leaves the marker, and the keys are in order, as `std` gives them.
///
/// Mutants: the marker is set before the ops; `Clear` is ignored.
#[skuld::test]
fn the_childs_environment_is_the_ops_applied_in_order_and_then_the_marker() {
    use crate::command::EnvOp;

    let marker = OsString::from(crate::containment::NESTED_ENV);
    let ops = [
        EnvOp::Set("B".into(), "1".into()),
        EnvOp::Clear,
        EnvOp::Set("Z".into(), "2".into()),
        EnvOp::Set("A".into(), "3".into()),
        EnvOp::Remove("Z".into()),
    ];
    assert_eq!(
        child_env(&ops, true),
        [
            (OsString::from("A"), OsString::from("3")),
            (marker.clone(), OsString::from("1"))
        ]
    );
    assert_eq!(child_env(&ops, false), [(OsString::from("A"), OsString::from("3"))]);
    // No `Clear`: this process's own variables are in it, the marker after them.
    let inherited = child_env(&[EnvOp::Set("COSCA_FORK_SPAWN_TESTS".into(), "x".into())], false);
    assert!(inherited.contains(&(OsString::from("COSCA_FORK_SPAWN_TESTS"), OsString::from("x"))));
    assert!(inherited.len() > 1, "this process's own environment is inherited");
}

/// With no op and no marker the child gets every `name=value` entry of this process's environment as it
/// is, in `environ`'s order and with its duplicates, as `std` passes `environ` through (an entry with no
/// `=` is not a variable and is dropped, as `std` drops it under any env op); with an op or the marker it
/// is `std`'s sorted map.
///
/// Mutant: the environment is always rebuilt as a sorted map.
#[skuld::test]
fn an_environment_no_op_changes_is_passed_through_as_it_is() {
    use crate::command::EnvOp;

    let pair = |key: &str, value: &str| (OsString::from(key), OsString::from(value));
    let inherited = || [pair("Z", "1"), pair("A", "2"), pair("Z", "3"), pair("M", "4")].into_iter();
    assert_eq!(
        child_env_over(inherited(), &[], false),
        [pair("Z", "1"), pair("A", "2"), pair("Z", "3"), pair("M", "4")]
    );
    assert_eq!(
        child_env_over(inherited(), &[EnvOp::Remove("M".into())], false),
        [pair("A", "2"), pair("Z", "3")]
    );
    let sorted = std::collections::BTreeMap::from([
        pair("A", "2"),
        pair("M", "4"),
        pair(crate::containment::NESTED_ENV, "1"),
        pair("Z", "3"),
    ]);
    assert_eq!(
        child_env_over(inherited(), &[], true),
        sorted.into_iter().collect::<Vec<_>>()
    );
}

/// The environment a program started through cosca's `Command` and through `std::process::Command` sees is
/// the same for the same ops: none (this process's, as it is), a removal, and a clear with two variables
/// set. The program prints `/proc/self/environ`; cosca's nesting marker, which std has no counterpart for,
/// is the only entry set aside.
///
/// Mutants: the spawn rebuilds an unchanged environment as a sorted map; a removal or a clear is ignored.
#[skuld::test]
fn a_childs_environment_is_the_one_std_gives_for_the_same_ops() {
    let marker = format!("{}=", crate::containment::NESTED_ENV);
    let environ_of_cosca = |ops: &dyn Fn(&mut crate::Command)| {
        let mut cmd = crate::test_child::command(crate::test_child::Console::Hidden);
        cmd.args(["/bin/cat", "/proc/self/environ"]);
        ops(&mut cmd);
        cmd.stdout(Stdio::pipe()).expect("stdout");
        let out = cmd.spawn().expect("spawn").communicate(None).expect("communicate");
        let entries: Vec<Vec<u8>> = out
            .stdout
            .split(|&b| b == 0)
            .filter(|entry| !entry.is_empty() && !entry.starts_with(marker.as_bytes()))
            .map(<[u8]>::to_vec)
            .collect();
        entries
    };
    let environ_of_std = |ops: &dyn Fn(&mut std::process::Command)| {
        let mut cmd = std::process::Command::new("/bin/cat");
        cmd.arg("/proc/self/environ");
        ops(&mut cmd);
        let out = crate::test_spawn::output_captured(&mut cmd).expect("run cat");
        let entries: Vec<Vec<u8>> = out
            .stdout
            .split(|&b| b == 0)
            .filter(|entry| !entry.is_empty())
            .map(<[u8]>::to_vec)
            .collect();
        entries
    };
    let ours = environ_of_cosca(&|_| {});
    assert!(ours.len() > 1, "this process's own environment is inherited: {ours:?}");
    assert_eq!(ours, environ_of_std(&|_| {}), "no op");
    assert!(
        ours.iter().any(|entry| entry.starts_with(b"PATH=")),
        "the test removes a variable that is set"
    );
    assert_eq!(
        environ_of_cosca(&|cmd| {
            cmd.env_remove("PATH");
        }),
        environ_of_std(&|cmd| {
            cmd.env_remove("PATH");
        }),
        "a removal"
    );
    assert_eq!(
        environ_of_cosca(&|cmd| {
            cmd.env_clear().env("B", "2").env("A", "1");
        }),
        environ_of_std(&|cmd| {
            cmd.env_clear().env("B", "2").env("A", "1");
        }),
        "a clear and two variables"
    );
}

/// The child's signal mask is the spawning thread's, as `std` leaves it (its `do_exec` resets `SIGPIPE`'s
/// disposition and never calls `pthread_sigmask`): a program spawned from a thread that blocks `SIGINT` and
/// `SIGTERM` starts with both blocked.
///
/// Mutant: the child clears its signal mask before its `execve`.
#[skuld::test]
fn the_childs_signal_mask_is_the_spawning_threads() {
    let blocked = |signal: i32| 1u64 << (signal - 1);
    // SAFETY: blocks two signals on this thread only, and puts the mask back.
    let previous = unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        let mut previous: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::sigaddset(&mut set, libc::SIGTERM);
        assert_eq!(libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut previous), 0);
        previous
    };
    let mut cmd = crate::test_child::command(crate::test_child::Console::Hidden);
    // Not through `sh`, which clears the mask itself.
    cmd.args(["/bin/grep", "^SigBlk", "/proc/self/status"]);
    cmd.stdout(Stdio::pipe()).expect("stdout");
    let spawned = cmd.spawn();
    // SAFETY: puts this thread's mask back.
    assert_eq!(
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut()) },
        0
    );
    let out = spawned.expect("spawn").communicate(None).expect("communicate");
    let text = String::from_utf8_lossy(&out.stdout);
    let mask = u64::from_str_radix(text.trim().rsplit(char::is_whitespace).next().expect("a mask"), 16)
        .expect("a hexadecimal mask");
    let wanted = blocked(libc::SIGINT) | blocked(libc::SIGTERM);
    assert_eq!(mask & wanted, wanted, "the child's SigBlk {mask:#x} lacks {wanted:#x}");
}

/// The child's `SIGPIPE` is the default, as `std` leaves it, whatever this process (whose Rust runtime
/// ignores it) does.
///
/// Mutant: the `SIGPIPE` step is not run.
#[skuld::test]
fn the_childs_sigpipe_is_the_default() {
    // SAFETY: querying this process's disposition for `SIGPIPE`, which a Rust runtime sets to ignored.
    let mut ours = unsafe { std::mem::zeroed::<libc::sigaction>() };
    // SAFETY: a null new action only reads.
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGPIPE, std::ptr::null(), &mut ours) },
        0
    );
    assert_eq!(
        ours.sa_sigaction,
        libc::SIG_IGN,
        "this process ignores SIGPIPE, as a Rust program's runtime does"
    );
    let mut cmd = crate::test_child::command(crate::test_child::Console::Hidden);
    cmd.args(["/bin/sh", "-c", r#"grep '^SigIgn' /proc/$$/status"#]);
    cmd.stdout(Stdio::pipe()).expect("stdout");
    let out = cmd.spawn().expect("spawn").communicate(None).expect("communicate");
    let ignored = String::from_utf8_lossy(&out.stdout);
    let mask = u64::from_str_radix(ignored.trim().rsplit(char::is_whitespace).next().expect("a mask"), 16)
        .expect("a hexadecimal mask");
    assert_eq!(
        mask & (1 << (libc::SIGPIPE - 1)),
        0,
        "the child ignores SIGPIPE: SigIgn {mask:#x}"
    );
}
