//! Sweep tests. Every one runs against the real host process table with real descriptors —
//! nothing here is faked, because a sweep fired at a synthetic table proves nothing.
//!
//! Three rules these tests obey, because the unit suite runs in parallel in ONE process:
//! never clear `FD_CLOEXEC` on a descriptor of the test process (a concurrent fork+exec on
//! another thread would leak it into an unrelated child); never key a log assertion on the
//! shared pid alone (every test shares it) — key on the marker handle; and every test that
//! calls `install()` (opening a write-end fd this process holds, CLOEXEC or not) holds
//! `test_spawn_lock()` for its WHOLE body, WHETHER OR NOT that test itself goes on to spawn.
//! The exposure is not "this test's own fork races its own write end" — it is "ANY sibling
//! test's fork, anywhere in this shared process, can land while THIS test's write end happens
//! to be open" — so the guard is owed by every test that opens one, not only the ones that also
//! fork. Without it, a sibling test's `.spawn()` could fork WHILE this test's marker write end
//! is open, transiently inheriting it; if that sibling is mid-`hard_kill()`/`holders()` at that
//! exact moment, its sweep would find and SIGKILL the bystander child.
//!
//! `test_spawn_lock()` is `crate::child::spawn::spawn_lock()` ITSELF, not a private mutex — a
//! separate lock would only serialize these tests against each other, not against every OTHER
//! fork in the same test binary. `cosca::Command::spawn()` (used by tests throughout this
//! crate) already takes `spawn_lock()` internally, so reusing it here gets those tests'
//! serialization for free.
//!
//! This reuse is what makes the guard effective crate-wide, not just within this module:
//! `crate::test_child::spawn_a_process_that_exits` (used by unrelated tests, e.g.
//! `identity/persist_tests.rs`) and every other `--lib`-binary fork site that could race a
//! marker-holding test here — `src/process/graceful_tests.rs`,
//! `src/tokio/process/graceful_tests.rs`, `src/containment/unix_tests.rs`,
//! `src/wait/macos_tests.rs`, `src/containment/dispatch_tests.rs`, `src/tokio/wait_tests.rs` —
//! also take `spawn_lock()` around their own `std::process::Command::spawn()`/`.output()`
//! calls, for exactly the reason the paragraph above states: any of those forking while THIS
//! module's tests hold a marker write end open could otherwise transiently inherit it, and a
//! concurrently-running `hard_kill()`/`holders()` scan in THIS module could then find and
//! SIGKILL that bystander.

use std::io::BufRead;
use std::os::fd::{AsFd, AsRawFd};

use super::{holders, holds_marker, holds_marker_query, pipe_handle_of, MarkerQuery, PipeFdInfo, PROC_PIDFDPIPEINFO};

fn all_pids() -> Vec<crate::identity::RawPid> {
    crate::containment::enumerate::snapshot().0
}

/// See the module docs above: held for the WHOLE body of every test that both installs a
/// marker and spawns a real child, so no such test's fork can land inside another's marker
/// window in this shared, parallel-test process. Delegates to the SAME lock production code
/// uses, not a private one, so it also excludes every other cosca-originated spawn elsewhere
/// in this test binary.
fn test_spawn_lock() -> std::sync::MutexGuard<'static, ()> {
    crate::child::spawn::spawn_lock()
}

// No standalone layout test: the layout is guarded at compile time by the
// `const _: () = assert!(…)` trio in the implementation (the crate does not build if it's
// wrong), and at runtime by `a_live_pipe_has_a_nonzero_handle_distinct_per_end` plus the sweep
// tests below (the wrong struct returns `<= 0` and finds nobody — measured fact B's note). A
// test comparing hand-transcribed copies of the same measured-fact table against each other
// would not catch a transcription error either copy shared, so it adds no independent coverage.

/// A real pipe has a readable handle; the two ends are distinct kernel objects with distinct
/// handles, so matching on the write end's handle cannot match a process holding only a read end.
#[test]
fn a_live_pipe_has_a_nonzero_handle_distinct_per_end() {
    let (r, w) = std::io::pipe().expect("pipe");
    let hw = pipe_handle_of(w.as_fd()).expect("the write end is a pipe");
    let hr = pipe_handle_of(r.as_fd()).expect("the read end is a pipe");
    assert_ne!(hw, 0, "a live pipe's handle must be non-zero");
    assert_ne!(hw, hr, "the two ends of a pipe are distinct kernel objects");
}

/// The mechanism's identity claim needs more than "a released handle isn't reissued while
/// held" — it needs simultaneously-LIVE pipes to never share a handle, or `holders()` could
/// match an unrelated live process by coincidence and get it SIGKILL'd. Measured directly
/// rather than inferred from the `VM_KERNEL_ADDRHASH` name (which suggests a lossy hash): a
/// one-off measurement backing this claim used 20,000 simultaneously-live pipes (40,000
/// handles) on an unconstrained shell (see the final report). THIS test deliberately uses far
/// fewer: macOS's launchd-inherited soft `RLIMIT_NOFILE` defaults to 256 (measured on this host
/// via `launchctl limit maxfiles`), which is what a CI runner gets unless a step raises it, and
/// this suite runs every unit test in parallel in ONE process — parking thousands of
/// descriptors here would both risk this test's own `pipe()` calls panicking with `EMFILE` and
/// starve concurrently-running sibling tests' `pipe()`/`File::open` calls into spurious `EMFILE`
/// failures. `N = 50` (100 descriptors) leaves comfortable headroom under even the unraised
/// default while still meaningfully exercising "many simultaneously-live handles, checked
/// pairwise" — weaker statistical power than the one-off 20,000-pipe measurement, but a
/// regression-pinning unit test's job here is to catch a REVERSION of the property (e.g. a
/// kernel/SDK change that reintroduces collisions), not to reproduce the full-scale measurement
/// inside a shared, resource-constrained test process.
#[test]
fn many_simultaneously_live_pipes_never_share_a_handle() {
    const N: usize = 50;
    let mut pipes = Vec::with_capacity(N);
    for _ in 0..N {
        pipes.push(std::io::pipe().expect("pipe"));
    }
    let mut handles: Vec<u64> = Vec::with_capacity(N * 2);
    for (r, w) in &pipes {
        handles.push(pipe_handle_of(r.as_fd()).expect("read end handle"));
        handles.push(pipe_handle_of(w.as_fd()).expect("write end handle"));
    }
    let unique: std::collections::HashSet<u64> = handles.iter().copied().collect();
    assert_eq!(
        unique.len(),
        handles.len(),
        "{} simultaneously-live pipe handles must all be distinct; found {} unique among {}",
        N,
        unique.len(),
        handles.len()
    );
}

/// A non-pipe descriptor is reported as "not a pipe", never as handle 0.
#[test]
fn a_non_pipe_descriptor_has_no_pipe_handle() {
    let f = std::fs::File::open("/dev/null").expect("open /dev/null");
    assert!(
        pipe_handle_of(f.as_fd()).is_none(),
        "a character device is not a pipe and must not yield a pipe handle"
    );
}

/// THE MECHANISM'S CENTRAL SAFETY INVARIANT, measured rather than assumed. Once every write
/// end is closed, the kernel frees the pipe pair only if the read end is gone too — so while
/// the supervisor holds the read end, no newly created pipe on this host can ever carry the
/// marker's handle. (With BOTH ends closed the handle is re-issued to the very next pipe,
/// every time, which is why `Marker` owns the read end for its whole life.)
#[test]
fn holding_the_read_end_keeps_the_handle_from_being_reissued() {
    let (read, write) = std::io::pipe().expect("pipe");
    let handle = pipe_handle_of(write.as_fd()).expect("write end handle");
    drop(write); // the "tree drained" moment: the last write end goes away

    // Churn: allocate and free pipes, looking for the handle to come back.
    for _ in 0..2000 {
        let (r2, w2) = std::io::pipe().expect("churn pipe");
        let h2 = pipe_handle_of(w2.as_fd()).expect("churn handle");
        assert_ne!(
            h2, handle,
            "a new pipe took the marker's handle while the read end was still held — \
             the sweep could match an unrelated process"
        );
        drop((r2, w2));
    }
    drop(read);
}

/// The sweep must find this process, which really does hold the write end.
#[test]
fn the_sweep_finds_this_process_holding_the_marker() {
    let (_r, w) = std::io::pipe().expect("pipe");
    let handle = pipe_handle_of(w.as_fd()).expect("write end handle");
    let me = std::process::id();
    let found = holders(handle, &all_pids());
    assert!(
        found.iter().any(|h| h.pid == me),
        "the sweep must find pid {me}, which holds the marker; found {found:?}"
    );
    assert!(
        holds_marker(me, handle),
        "the single-pid membership check must agree with the sweep"
    );
}

/// `PROC_PIDLISTFDS` denial is measured to return `0` with `errno == EPERM`, not a negative
/// value — pinned here (independent of `pipe_fds_of`/`clear_errno_and_call`, which this fact
/// drives) so the `<= 0` failure gate cannot silently regress to the wrong assumption. pid 1
/// (launchd, root-owned) queried directly is the oracle; this crate's CI and dev hosts run
/// unprivileged, matching every other test here that assumes pid 1 is launchd and unreachable
/// as a signal target.
#[test]
fn proc_pidlistfds_denial_returns_zero_with_eperm_not_negative() {
    // SAFETY: the sizing form takes a null buffer; `__error()` returns this thread's own errno
    // cell, which writing 0 into is always defined.
    let n = unsafe {
        *libc::__error() = 0;
        libc::proc_pidinfo(1, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0)
    };
    let e = std::io::Error::last_os_error();
    assert_eq!(
        n, 0,
        "an EPERM denial from PROC_PIDLISTFDS is measured to return 0 on this platform, not a \
         negative value — a `< 0` failure gate would silently miss it"
    );
    assert_eq!(
        e.raw_os_error(),
        Some(libc::EPERM),
        "pid 1 (launchd, root-owned) must be denied to an unprivileged caller with EPERM; got {e}"
    );
}

/// `PROC_PIDFDPIPEINFO` on an fd that is not currently a pipe on the calling process — never
/// opened, already closed, or open but a different fd type — is measured to return `0` with
/// `errno == EBADF` in every case (not `ENOENT`/`EINVAL`/a type-specific code), pinned here so
/// `fd_pipe_info`'s `Absent` classification cannot silently drift from what the kernel actually
/// reports. Measured directly on this host: a never-opened fd, a closed-then-reused-numerically
/// pipe fd, and an open regular-file fd all produced identical `(0, EBADF)`.
#[test]
fn proc_pidfdinfo_on_a_non_pipe_fd_returns_zero_with_ebadf_not_a_type_specific_code() {
    let me = std::process::id() as libc::c_int;
    let mut info: PipeFdInfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<PipeFdInfo>() as libc::c_int;

    // A regular file is open, valid, and NOT a pipe — this is the case the plan's own
    // `Absent` classification must cover, distinct from a genuinely unopened descriptor.
    let file = std::fs::File::open("/dev/null").expect("open /dev/null");
    // SAFETY: `info`'s pointer and `size` match; `file`'s fd stays valid for this call.
    let n = unsafe {
        *libc::__error() = 0;
        libc::proc_pidfdinfo(
            me,
            file.as_raw_fd(),
            PROC_PIDFDPIPEINFO,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        )
    };
    let e = std::io::Error::last_os_error();
    assert_eq!(
        n, 0,
        "a non-pipe fd is measured to return 0, not a negative value; got {n}"
    );
    assert_eq!(
        e.raw_os_error(),
        Some(libc::EBADF),
        "a non-pipe fd is measured to fail with EBADF specifically (not ENOENT/EINVAL); got {e}"
    );
}

/// `holds_marker_query` must report `Denied`, not `NotHeld`, when the WHOLE-pid fd list read
/// is refused — collapsing the two would silently reclassify "still a member, now unreachable"
/// as "no longer a member" (the exact failure `MarkerQuery` exists to prevent; see its doc
/// comment). pid 1 (launchd, root-owned) is the same real, deterministic, unprivileged-EPERM
/// oracle `proc_pidlistfds_denial_returns_zero_with_eperm_not_negative` already establishes —
/// no fault injection needed for this one, since a real, always-available denial exists. The
/// handle value passed is irrelevant: the denial happens before any per-fd handle comparison.
#[test]
fn holds_marker_query_reports_denied_not_not_held_for_an_unqueryable_pid() {
    assert_eq!(
        holds_marker_query(1, 0),
        MarkerQuery::Denied,
        "pid 1 must be unqueryable (EPERM) to an unprivileged caller; a Denied fd-list read \
         must not be reported as NotHeld"
    );
}

/// A handle naming no live pipe finds nobody, and must not panic or mis-match. `0` is never a
/// valid `pipe_handle` (established above by `a_live_pipe_has_a_nonzero_handle_distinct_per_end`)
/// and cannot become one through any amount of churn (this suite churns pipes across many tests
/// running in parallel in ONE process), so this is race-free by construction rather than by
/// timing luck.
#[test]
fn a_dead_handle_finds_no_holders() {
    assert!(
        !holds_marker(std::process::id(), 0),
        "handle 0 is never a valid pipe_handle and must not be reported as held"
    );
}

// Installing the marker on a spawn =====

/// `preserved_fds` only clears FD_CLOEXEC — it does not renumber, so the marker keeps the
/// parent's descriptor NUMBER inside the child. `command-fds`' user mappings `dup2` onto
/// their `child_fd` numbers in the same forked child, closing whatever occupies them, so a
/// marker on one of those numbers would be silently clobbered and the tree would silently
/// lose membership. `F_DUPFD_CLOEXEC` never overwrites an open descriptor, so only `child_fd`
/// values are hazards; std `dup2`s the stdio slots before any pre_exec hook runs, so 0-2 are too.
#[test]
fn the_marker_fd_is_chosen_clear_of_reserved_child_fds_stdio_and_the_conventional_shell_range() {
    use super::{safe_marker_fd, HIGH_FLOOR};
    assert_eq!(
        safe_marker_fd(7, &[]),
        HIGH_FLOOR,
        "even a low, uncontested candidate is raised clear of the conventional shell-\
         redirection range (3-9), not merely clear of stdio"
    );
    assert_eq!(
        safe_marker_fd(HIGH_FLOOR + 3, &[]),
        HIGH_FLOOR + 3,
        "a candidate already above the floor is kept"
    );
    assert!(
        safe_marker_fd(7, &[HIGH_FLOOR]) > HIGH_FLOOR,
        "a candidate colliding with a reserved fd must move up, even above the floor"
    );
    assert!(
        safe_marker_fd(4, &[3, 4, HIGH_FLOOR + 5]) > HIGH_FLOOR + 5,
        "the marker must clear the HIGHEST reserved fd, whether below or above the floor"
    );
    assert!(safe_marker_fd(1, &[]) >= 3, "the marker must never sit on a stdio slot");
    assert!(
        safe_marker_fd(0, &[3]) >= HIGH_FLOOR,
        "the high floor applies regardless of how low the reserved set is"
    );
}

/// The placement contract, asserted on the placed number itself: `install` must move the
/// marker above every reserved child fd it is told about.
///
/// `cmd` is never spawned here, but `install()` still opens a real, CLOEXEC'd write end in
/// THIS process that stays open for the rest of the test's body (module docs above) — the
/// fork-bystander exposure the lock guards against does not depend on this specific test ever
/// spawning, only on the write end being open while ANY sibling test forks.
#[test]
fn install_places_the_marker_above_every_reserved_child_fd() {
    let _serialize = test_spawn_lock();
    let reserved = [3, 4, 5, 6, 7, 8, 9, 10];
    let mut cmd = std::process::Command::new("/usr/bin/true");
    let prepared = super::install(&mut cmd, &reserved).expect("install");
    assert!(
        prepared.fd > 10,
        "the marker landed on fd {}, which a user mapping would dup2 over",
        prepared.fd
    );
}

/// The same contract end to end, against a REAL colliding mapping: the child gets an fd
/// mapping on the number the marker would naturally have taken, and must still be a holder.
#[test]
fn a_child_with_a_colliding_fd_mapping_still_holds_the_marker() {
    let _serialize = test_spawn_lock();
    use command_fds::{CommandFdExt, FdMapping};

    let (_probe_r, probe_w) = std::io::pipe().expect("probe pipe");
    // The number `install` would pick with nothing reserved.
    let natural = super::safe_marker_fd(probe_w.as_fd().as_raw_fd(), &[]);
    drop(probe_w);

    let filler = std::fs::File::open("/dev/null").expect("open /dev/null");
    let mut cmd = std::process::Command::new("/bin/sh");
    cmd.arg("-c")
        .arg("echo $$; read _ignored")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let prepared = super::install(&mut cmd, &[natural]).expect("install");
    let handle = prepared.handle;
    cmd.fd_mappings(vec![FdMapping {
        parent_fd: filler.into(),
        child_fd: natural,
    }])
    .expect("unique child fd");

    let mut child = cmd.spawn().expect("spawn sh");
    drop(cmd);
    let mut out = std::io::BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut line = String::new();
    out.read_line(&mut line).expect("read pid line");
    let kid: crate::identity::RawPid = line.trim().parse().expect("child pid");

    assert!(
        holds_marker(kid, handle),
        "a user fd mapping on fd {natural} must not clobber the marker in the child"
    );
    let _keep_alive = prepared.read;

    drop(child.stdin.take()); // EOF releases the child (cleanup, not an assertion)
    let _ = child.wait();
}

/// A real spawn through the real installer: the child must be a holder, and the SUPERVISOR
/// must not be — it hands the write end away, so it is never a member of its own tree.
#[test]
fn install_hands_the_marker_to_the_child_and_keeps_the_supervisor_out() {
    let _serialize = test_spawn_lock();
    let mut cmd = std::process::Command::new("/bin/sh");
    cmd.arg("-c")
        .arg("echo $$; read _ignored")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let prepared = super::install(&mut cmd, &[]).expect("install");
    let handle = prepared.handle;
    let mut child = cmd.spawn().expect("spawn sh");
    drop(cmd); // the Command owns the write end; dropping it closes the supervisor's copy

    let mut out = std::io::BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut line = String::new();
    out.read_line(&mut line).expect("read pid line");
    let kid: crate::identity::RawPid = line.trim().parse().expect("child pid");

    let found = holders(handle, &all_pids());
    assert!(
        found.iter().any(|h| h.pid == kid),
        "the child must inherit the marker across exec; found {found:?}"
    );
    assert!(
        !found.iter().any(|h| h.pid == std::process::id()),
        "the supervisor must not hold the marker, or a sweep could signal it; found {found:?}"
    );
    let _keep_alive = prepared.read;

    drop(child.stdin.take());
    let _ = child.wait();
}

/// A holder whose descriptor survives exec is NOT an imminent membership loss, so no warning
/// is due. The check runs against a spawned child (whose copy `preserved_fds` has already
/// un-CLOEXEC'd) rather than by mutating this process's own fd table, which a concurrent
/// fork+exec on another thread would leak. The assertion keys on the per-pid message
/// (`fd marker {handle:#x}: holder pid {kid} will lose the marker…`), not on the handle alone:
/// unit tests run in parallel in ONE process, and the marker write end is open in that shared
/// process from `install()` until `drop(cmd)` — a SIBLING test's `Command::spawn()` forking in
/// that window transiently inherits this fd into a not-yet-`exec`'d bystander (documented in
/// "Holding the read end is a precondition of soundness"), whose CLOEXEC-armed copy of THIS
/// handle would satisfy a handle-only negative check by accident. Keying on the child's own pid
/// too makes that bystander unable to satisfy or spoil the assertion.
#[test]
fn a_child_holding_a_non_cloexec_marker_produces_no_exec_warning() {
    let _serialize = test_spawn_lock();
    crate::log_capture::install();
    let mut cmd = std::process::Command::new("/bin/sh");
    cmd.arg("-c")
        .arg("echo $$; read _ignored")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let prepared = super::install(&mut cmd, &[]).expect("install");
    let handle = prepared.handle;
    let mut child = cmd.spawn().expect("spawn sh");
    drop(cmd);
    let mut out = std::io::BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut line = String::new();
    out.read_line(&mut line).expect("read pid line");
    let kid: crate::identity::RawPid = line.trim().parse().expect("child pid");

    let mark = crate::log_capture::mark();
    let found = holders(handle, &all_pids());
    let theirs = found.iter().find(|h| h.pid == kid).expect("the child holds the marker");
    assert!(
        !theirs.clexec,
        "preserved_fds clears FD_CLOEXEC in the child, so the marker survives its next exec"
    );
    assert!(
        !crate::log_capture::contains_since(
            mark,
            &format!("fd marker {handle:#x}: holder pid {kid} will lose the marker")
        ),
        "no exec warning is due for pid {kid}, whose own descriptor survives exec"
    );
    let _keep_alive = prepared.read;

    drop(child.stdin.take());
    let _ = child.wait();
}

/// The complement: a holder whose descriptor is CLOEXEC WILL lose membership at its next exec,
/// and that must be visible one exec in advance via both `Holder.clexec` and a log line.
///
/// Constructed self-referentially against THIS test process, not a spawned child. A live
/// holder whose ONLY copy is CLOEXEC needs to be observed AFTER the exec that starts it, but
/// arming `FD_CLOEXEC` in a `pre_exec` hook closes the descriptor AT the exec that immediately
/// follows — it never survives to be observed as a live holder at all. Setting the flag from
/// WITHIN a live, already-running process is what the real property requires, and nothing
/// available to a unit test (`/bin/sh` has no `fcntl` builtin; a compiled testbin mode is
/// unavailable here — Global Constraints) can do that post-exec. `std::io::pipe()` sets
/// `FD_CLOEXEC` on both ends by default (the reason `install()` needs `F_DUPFD_CLOEXEC` +
/// `preserved_fds` to make the write end survive an exec at all), so a bare pipe's write end,
/// right here in this process, IS already the exact state under test — no fd-table mutation
/// needed, so this does not touch the "never clear FD_CLOEXEC on this process's own
/// descriptors" rule (that rule is about CLEARING an existing flag; this relies on the
/// default, never-cleared SET state).
#[test]
fn a_cloexec_holder_is_reported_and_warned_about() {
    crate::log_capture::install();
    let (_r, w) = std::io::pipe().expect("pipe");
    let handle = pipe_handle_of(w.as_fd()).expect("write end handle");
    let me = std::process::id();

    let mark = crate::log_capture::mark();
    let found = holders(handle, &all_pids());
    let theirs = found
        .iter()
        .find(|h| h.pid == me)
        .expect("this process holds the marker");
    assert!(theirs.clexec, "std::io::pipe() sets FD_CLOEXEC on both ends by default");
    assert!(
        crate::log_capture::contains_since(
            mark,
            &format!("fd marker {handle:#x}: holder pid {me} will lose the marker at its next exec")
        ),
        "an imminent membership loss must leave a log line naming the marker and the pid"
    );
}

/// THE DOCUMENTED ESCAPE, pinned by a test rather than by prose: a child that closes the
/// inherited descriptor leaves the containment set.
///
/// Ordered by a real handshake on BOTH sides of the close, not merely on the print after it:
/// printing `$$` alone orders nothing against the very next statement in the same script, since
/// nothing blocks the child between them — a shell runs its own script far faster than the
/// parent can complete a multi-syscall `holders()` scan, so the first check would otherwise race
/// the close and could observe it already gone (measured: it reliably does, on this host). The
/// child instead blocks on its own `read` immediately after printing `$$`, and only the
/// PARENT'S write releases it into the close — so the first `holds_marker` check is guaranteed
/// to run while the descriptor is still open, not merely likely to.
#[test]
fn a_child_that_closes_the_marker_leaves_the_holder_set() {
    let _serialize = test_spawn_lock();
    let mut cmd = std::process::Command::new("/bin/sh");
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let prepared = super::install(&mut cmd, &[]).expect("install");
    let (handle, marker_fd) = (prepared.handle, prepared.fd);
    cmd.arg("-c").arg(format!(
        "echo $$; read _go; exec {marker_fd}>&-; echo closed; read _ignored"
    ));
    let mut child = cmd.spawn().expect("spawn sh");
    drop(cmd);

    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut out = std::io::BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut line = String::new();
    out.read_line(&mut line).expect("read pid line");
    let kid: crate::identity::RawPid = line.trim().parse().expect("child pid");
    assert!(
        holds_marker(kid, handle),
        "the child inherited the marker, and must still hold it while blocked before its own close"
    );

    use std::io::Write;
    stdin.write_all(b"go\n").expect("release the child into its close");

    line.clear();
    out.read_line(&mut line).expect("read closed line");
    assert_eq!(
        line.trim(),
        "closed",
        "the child must confirm the close before the second check"
    );
    assert!(
        !holds_marker(kid, handle),
        "close(fd) leaves the containment set — the documented limit"
    );
    let _keep_alive = prepared.read;

    drop(stdin);
    let _ = child.wait();
}

/// Each real failure arm of `install` degrades to "no marker" and says so, with the message
/// naming which step failed. The seams replace the SYSCALL result, so the genuine branch —
/// its own log line and its own early return — is what executes.
///
/// **Deliberate, documented exception to this crate's no-mocks rule**, not an oversight: these
/// three syscalls (`pipe()`, `F_DUPFD_CLOEXEC`, and "the marker pipe has no readable handle")
/// are genuinely hard to fail for real inside this suite without collateral damage.
/// `RLIMIT_NOFILE` (the textbook way to force `pipe()`/`fcntl` to fail) is PROCESS-WIDE, and
/// this suite runs every unit test in parallel in ONE process — lowering it would spuriously
/// fail any concurrently-running sibling test that happens to open a file or pipe at that
/// moment. The third arm (`pipe_handle_of` returning `None`) has no realistic real-world
/// trigger at all on a healthy pipe. The seam exercises exactly the code adjacent to each
/// injection point (each wrapper's own `if fault::take_if(X) { … }` arm), which is what needs
/// covering here; the SYSCALLS themselves (`pipe()`, `F_DUPFD_CLOEXEC`, `proc_pidfdinfo`) are
/// exercised for real, unmocked, by every OTHER test in this file's success paths. **State this
/// plainly rather than implying more:** this test proves `install`'s three early-return arms
/// compile, log the right message, and degrade to `None` — it does NOT prove `install` degrades
/// correctly under a genuine OS-level `pipe()`/`fcntl`/`proc_pidfdinfo` failure (`EMFILE`,
/// `ENFILE`, …), whose exact errno/shape this seam does not attempt to reproduce.
#[test]
fn each_install_failure_arm_falls_back_and_says_which_step_failed() {
    use super::fault::{set_fault, Fault};
    // Held for the whole test: these log lines carry no per-call discriminator, so this test
    // and `dispatch_tests.rs`'s `a_failed_marker_install_leaves_prepare_without_one` (which
    // asserts on the identical text) could otherwise satisfy each other's `contains_since`
    // check across threads in the shared `log_capture` buffer.
    let _serialize = super::fault::lock_for_log_assertion();
    crate::log_capture::install();
    for (fault, marker) in [
        (Fault::Pipe, "fd marker: pipe() failed"),
        (Fault::Place, "fd marker: could not place the marker descriptor"),
        (Fault::Handle, "fd marker: the marker pipe has no readable handle"),
    ] {
        let mut cmd = std::process::Command::new("/usr/bin/true");
        set_fault(Some(fault));
        let mark = crate::log_capture::mark();
        assert!(
            super::install(&mut cmd, &[]).is_none(),
            "a failed {fault:?} step must yield no marker"
        );
        assert!(
            crate::log_capture::contains_since(mark, marker),
            "the {fault:?} failure must log {marker:?}"
        );
        assert!(
            super::fault::take_fault().is_none(),
            "the seam must be consumed by install"
        );
    }
}

// Teardown: one snapshot, three channels =====

/// The sweep must never signal the supervisor or pid 1. Asserted on the filter directly, not
/// inferred from "the test process is still alive" — which would pass by luck if the filter
/// were wrong and the signal merely failed.
#[test]
fn the_kill_filter_excludes_this_process_and_pid_one() {
    assert!(
        !super::is_signalable(std::process::id()),
        "the supervisor is never a sweep target"
    );
    assert!(!super::is_signalable(1), "pid 1 is never a sweep target");
    assert!(!super::is_signalable(0), "pid 0 is never a sweep target");
    assert!(
        super::is_signalable(std::process::id() + 1),
        "an ordinary pid is signalable"
    );
}

/// The shape the ppid walk structurally cannot reach: a descendant that calls `setsid`,
/// double-forks so its parent exits, is reparented to launchd, and execs — its ppid is 1, but
/// the marker sweep still finds it, and `hard_kill` kills it.
///
/// Deterministic with no timer: `sh` prints the orphan's pid, then exits; `wait()` returning
/// proves `sh` is gone, which is exactly the event that reparents the orphan. Death is proven
/// by EOF on the orphan's OWN inherited stdout, not by re-resolving its identity right after
/// `kill()` returns: `kill(2)` only posts the signal and returns immediately, so checking
/// `ProcessId::of` in the very next line races the kernel's own delivery-and-reap timing — a
/// zombie orphan (signalled, not yet reaped by launchd) still resolves via `proc_pidinfo` with
/// the SAME start token, so that check alone can pass before the kill has actually landed. `sh`
/// backgrounds `sleep` without redirecting it, so `sleep` inherits `sh`'s piped stdout; once
/// `sh` exits (`child.wait()`, above), the orphaned `sleep` is the pipe's ONLY remaining write
/// end, so a blocking read on it returns EOF exactly when `sleep` dies — a real event, not a
/// timer.
#[test]
fn hard_kill_reaches_a_setsid_double_forked_orphan_the_ppid_walk_cannot() {
    let _serialize = test_spawn_lock();
    let mut cmd = std::process::Command::new("/bin/sh");
    // `sleep` inherits the marker across sh's fork and its own exec; `echo $!` publishes it.
    cmd.arg("-c")
        .arg("sleep 600 & echo $!")
        .stdout(std::process::Stdio::piped());
    // setsid: the orphan leaves this process's session AND process group, so killpg misses it.
    // SAFETY: pre_exec runs post-fork, pre-exec; `libc::setsid` is async-signal-safe.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let prepared = super::install(&mut cmd, &[]).expect("install");
    let mut child = cmd.spawn().expect("spawn sh");
    drop(cmd);

    let mut out = std::io::BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut line = String::new();
    out.read_line(&mut line).expect("read orphan pid");
    let orphan: crate::identity::RawPid = line.trim().parse().expect("orphan pid");
    child.wait().expect("reap sh"); // sh's exit is what reparents the orphan

    let (_, parents, _) = crate::containment::enumerate::snapshot();
    let ppid = parents.iter().find(|(p, _)| *p == orphan).map(|(_, pp)| *pp);
    assert_eq!(ppid, Some(1), "precondition: the orphan must be reparented to launchd");

    // No root identity: sh is reaped, so ONLY the marker channel can reach the orphan.
    let marker = super::Marker::new(prepared, None, None, false);
    marker.hard_kill().expect("hard_kill");

    // The proof: `sleep` is the pipe's sole remaining writer, so EOF fires exactly on its
    // death — a real event, not a timer. This DOES block until then, unlike `Member::assert_dead`
    // in Task 7: there is no alive/dead round trip available on a plain, un-echoing `sleep`, so
    // there is no way to fail non-blockingly on the "still alive" branch here. Accepted
    // deliberately for this one unit test (the integration tests in Task 7 use control sockets
    // precisely to avoid this tradeoff at the suite's more expensive layer).
    let mut rest = Vec::new();
    std::io::Read::read_to_end(&mut out, &mut rest).expect("read to EOF on the orphan's stdout");
    assert!(rest.is_empty(), "unexpected trailing output from the orphan: {rest:?}");

    // No liveness assertion follows the EOF, deliberately: `proc_exit` invalidates the fd table
    // (what the EOF above observes) long before it marks the process a zombie, the state
    // `is_alive` reads — so `Alive` is reachable here for an orphan that has already died. Nor is
    // there a sound edge to wait for instead: this orphan belongs to launchd, so `waitid` returns
    // `ECHILD`. The EOF is the proof, and it is the only one available.
}

/// A pid that stopped holding the marker before the sweep must survive a REAL `hard_kill()`,
/// not merely fail the underlying `holds_marker` primitive in isolation (`a_dead_handle_finds_
/// no_holders`, Task 2, already covers that narrower claim) — proving `kill_holder`'s live
/// re-check inside a genuine sweep. The escapee is Task 3's documented `close(fd)` limit: it
/// closes the marker, confirms the close over the SAME pipe (ordering the sweep strictly
/// after, not racing it), then proves it is still alive by echoing back what the
/// test writes to it AFTER `hard_kill()` returns.
#[test]
fn hard_kill_never_reaches_a_pid_that_closed_the_marker_before_the_sweep() {
    let _serialize = test_spawn_lock();
    let mut cmd = std::process::Command::new("/bin/sh");
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let prepared = super::install(&mut cmd, &[]).expect("install");
    let (handle, marker_fd) = (prepared.handle, prepared.fd);
    cmd.arg("-c").arg(format!(
        r#"echo $$; exec {marker_fd}>&-; echo closed; while read x; do echo "$x"; done"#
    ));
    let mut child = cmd.spawn().expect("spawn sh");
    drop(cmd);
    let mut out = std::io::BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut line = String::new();
    out.read_line(&mut line).expect("read child pid");
    let kid: crate::identity::RawPid = line.trim().parse().expect("child pid");
    line.clear();
    out.read_line(&mut line).expect("read closed confirmation");
    assert_eq!(
        line.trim(),
        "closed",
        "the child must confirm the close before the sweep runs"
    );
    assert!(
        !holds_marker(kid, handle),
        "precondition: the escapee no longer holds the marker"
    );

    let marker = super::Marker::new(prepared, None, None, false);
    marker.hard_kill().expect("hard_kill");

    // Alive, proven positively: a line in, the same line back — the sweep must not have
    // touched a pid that was never in its holder set to begin with.
    let mut stdin = child.stdin.take().expect("piped stdin");
    std::io::Write::write_all(&mut stdin, b"still-here\n").expect("write probe line");
    line.clear();
    out.read_line(&mut line).expect("read probe echo");
    assert_eq!(
        line.trim(),
        "still-here",
        "the escapee closed the marker before hard_kill ran and must survive it"
    );

    drop(stdin);
    let _ = child.wait();
}

/// A root whose identity could not be read because the OS refused (`root_denied` — set only
/// for `Resolved::Unknown`, never for a root that had simply already exited; see
/// `dispatch.rs`) is a standing gap for the marker's whole life: `hard_kill` must report
/// `incomplete` even on a pass that converges immediately with nothing else to signal — proving
/// the flag actually reaches `finish_sweep`, not merely that `Marker::new` accepts it.
#[test]
fn hard_kill_reports_incomplete_for_a_denied_root_even_with_nothing_else_to_signal() {
    let (read, write) = std::io::pipe().expect("pipe");
    let handle = super::pipe_handle_of(write.as_fd()).expect("handle");
    let read_handle = super::pipe_handle_of(read.as_fd()).expect("read handle");
    let prepared = super::PreparedMarker {
        read: std::os::fd::OwnedFd::from(read),
        handle,
        read_handle,
        fd: write.as_fd().as_raw_fd(),
    };
    drop(write); // nobody holds the write end: nothing for the sweep to find or signal

    let marker = super::Marker::new(prepared, None, None, true);
    let err = marker.hard_kill().expect_err("a denied root must report incomplete");
    assert!(
        matches!(err, crate::error::Error::Unassessable { source: None, .. }),
        "unexpected error shape: {err:?}"
    );
}

/// `pid_is_live_group_member` — the group-signal re-fire gate's anchor — confirms a real,
/// currently-live member of its own group, and rejects both a mismatched pgid and a pid that
/// has already exited (the `getpgid` call itself fails `ESRCH` for a gone pid, which is the
/// whole reason no separate liveness check is needed — see the function's doc).
#[test]
fn pid_is_live_group_member_confirms_membership_and_rejects_mismatch_or_death() {
    use std::os::unix::process::CommandExt;
    let _serialize = test_spawn_lock();
    let mut cmd = std::process::Command::new("/bin/sleep");
    cmd.arg("600").process_group(0); // pgid == the child's own pid — `process_group` is safe.
    let mut child = cmd.spawn().expect("spawn sleep");
    let pid = child.id() as crate::identity::RawPid;
    let pgid = child.id() as i32;

    assert!(
        super::pid_is_live_group_member(pid, pgid),
        "a live child must be confirmed a member of its own pgid"
    );
    assert!(
        !super::pid_is_live_group_member(pid, pgid.wrapping_add(1)),
        "a mismatched pgid must not be confirmed, even for a live pid"
    );

    child.kill().expect("kill");
    child.wait().expect("reap");
    assert!(
        !super::pid_is_live_group_member(pid, pgid),
        "a reaped pid must not be confirmed a member of anything — getpgid must fail ESRCH"
    );
}

/// A process-group member for the sweep tests: a `/bin/sh` that announces its own pid on a
/// piped stdout and then blocks on a piped stdin. `pgid` is the group to join (`0` mints a new
/// one of the member's own). The caller installs any marker on the returned command, spawns it,
/// and must then take the readiness edge with [`await_member_ready`] before scanning for it.
fn member_command(pgid: i32) -> std::process::Command {
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new("/bin/sh");
    cmd.arg("-c")
        .arg("echo $$; read _ignored")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .process_group(pgid);
    cmd
}

/// Block until a [`member_command`] child has announced itself, and check that the announcement
/// came from that child.
///
/// The edge a spawned member must be scanned behind. `spawn()` returning reports the fork and
/// the exec hand-off; it does not establish that the member's image is running, that its
/// descriptor table answers a `proc_pidfdinfo` query, or that its `setpgid` is visible to
/// `getpgid` — the three states a holder scan and the group-signal gate assert against. A
/// `/bin/sleep` member can announce none of that, so the only way to wait for it would be a
/// clock.
fn await_member_ready(child: &mut std::process::Child) {
    let mut out = std::io::BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut line = String::new();
    out.read_line(&mut line).expect("read the member's announcement");
    let announced: crate::identity::RawPid = line.trim().parse().expect("the announcement carries a pid");
    assert_eq!(
        announced,
        child.id(),
        "the announcement must come from the member itself"
    );
    // Hand the pipe back rather than dropping it: the member outlives this call, and closing
    // the read end under a live child would make any later write to it a `SIGPIPE`.
    child.stdout = Some(out.into_inner());
}

/// Item 1's central regression test: `sweep_pass`'s group-signal gate must re-fire on a LATER
/// pass when THAT pass's own holder scan just confirmed a fresh, live, `getpgid`-verified member
/// of `self.pgid` — closing the "a process joins the group strictly between passes" gap
/// `sweep_pass`'s own doc names — and the "skipping this pass's group signal" log line, the
/// probe an earlier review round used to catch this gap missing entirely, must NOT appear on
/// that pass.
///
/// `sweep_pass` is called directly, twice, bypassing `hard_kill`'s automatic loop — the only way
/// to get a deterministic injection point *between* two passes with no sleep and no race:
/// `hard_kill`'s own loop offers no such hook.
///
/// Four roles, three real target processes:
/// - **P** mints a real, currently-valid pgid (`process_group(0)`: P's pgid == P's own pid), AND
///   carries a THROWAWAY marker (`scratch`, installed on P's own command) that exists only to
///   give pass 1 a valid `Marker` to call `sweep_pass` on — pass 1's own holder scan finding P
///   holding it is incidental (P dies from the group signal either way) and is not asserted on.
///   Reusing P's command this way, rather than leaving a SEPARATE unspawned command's write end
///   sitting open in this test process across pass 1, is what keeps this test itself clear of
///   the self-exclusion guard `sweep_pass` enforces on its caller (see below).
/// - **T** ("witness") carries the REAL marker (`marker`, installed on T's own command) `hard_
///   kill`/`terminate` would actually track. Not spawned until strictly between the two passes,
///   for two independent reasons that happen to coincide: (a) `pid_is_live_group_member` must
///   confirm T as a FRESH `pgid` member on pass 2, so T cannot have been a member during pass
///   1's unconditional `killpg`; (b) `install()`'s write end sits open in the CALLER (this test)
///   until the command is actually spawned, and `sweep_pass`'s own self-exclusion guard
///   `debug_assert!`-panics if a holder scan ever finds ITS OWN caller holding the marker it is
///   sweeping — so `marker`'s `install()` must not be called until immediately before spawning
///   T, with no `sweep_pass` call in between.
/// - **Q** ("protected target") holds no marker and is never named as `root`, so `killpg` on
///   `self.pgid` is the ONLY channel that can reach it. Q's death is therefore unambiguous proof
///   that pass 2's group signal actually fired, not a side effect of the marker or ppid-walk
///   channels. Also not spawned until between the two passes, for reason (a) above.
///
/// T and Q join `pgid` directly at their own spawn (`.process_group(pgid)`, a `setpgid(0, pgid)`
/// on THEMSELVES before their own `exec`, always POSIX-legal) rather than via a `setpgid` issued
/// BY this test after the fact: POSIX reserves that second form for a still-pre-`exec` child of
/// the caller, so a parent-issued `setpgid` on an already-`exec`'d child fails `EPERM`/`EACCES`
/// on every POSIX platform — measured here as `EPERM`, a real, unconditional OS restriction an
/// earlier draft of this test hit and had to route around, not a flake. `pgid` stays valid for T
/// and Q to join because P is left an unreaped zombie throughout (never `.wait()`ed) — the same
/// "the kernel still lists a zombie in its process group" fact `group_tests.rs`'s `await_zombie`
/// already relies on, applied here to keep `pgid` allocated across the gap instead of to query
/// it.
///
/// All three are [`member_command`] members, and none of them is passed to a sweep until
/// [`await_member_ready`] has read its announcement — see there for what `spawn()` alone does
/// and does not establish.
#[test]
fn sweep_pass_refires_the_group_signal_on_a_later_pass_that_confirms_a_new_live_member() {
    let _serialize = test_spawn_lock();
    crate::log_capture::install();

    let mut p_cmd = member_command(0); // pgid == P's own pid.
    let scratch = super::install(&mut p_cmd, &[]).expect("install scratch marker on P");
    // P is deliberately left unreaped for the rest of the test — see the doc above ("P is left
    // an unreaped zombie throughout"). That's what keeps `pgid` allocated across the gap, so
    // clippy's zombie-processes lint is a false positive here, not a real leak.
    #[allow(clippy::zombie_processes)]
    let mut p_child = p_cmd.spawn().expect("spawn P");
    drop(p_cmd);
    await_member_ready(&mut p_child); // P's own group exists before T and Q ask to join it.
    let pgid = p_child.id() as i32;

    let pass1_marker = super::Marker::new(scratch, None, Some(pgid), false);
    let mut seen: std::collections::HashSet<crate::identity::ProcessId> = std::collections::HashSet::new();
    let mut group_result: Result<(), crate::error::Error> = Ok(());
    let mut incomplete = false;

    // Pass 1: fires unconditionally (first_pass=true), killing P via killpg(pgid). Neither T
    // nor Q exists yet, so pass 1 cannot reach either regardless.
    pass1_marker.sweep_pass(
        nix::sys::signal::Signal::SIGKILL,
        &mut seen,
        &mut group_result,
        &mut incomplete,
        true,
    );
    drop(pass1_marker); // its scratch handle has no further use.

    // Between passes: T's real marker is installed and T is spawned in the same breath (no
    // sweep_pass call in between — see the self-exclusion note above), born directly into
    // `pgid`. Q is born into `pgid` too, holding no marker.
    let mut t_cmd = member_command(pgid);
    let prepared = super::install(&mut t_cmd, &[]).expect("install marker on T");
    let mut t_child = t_cmd.spawn().expect("spawn T");
    drop(t_cmd);
    // T is the member pass 2's own holder scan must find, so the scan runs behind T's
    // announcement — the state `spawn()` returning leaves unestablished.
    await_member_ready(&mut t_child);

    let mut q_cmd = member_command(pgid);
    let mut q_child = q_cmd.spawn().expect("spawn Q");
    // Q's announcement proves it is a live member of `pgid` and blocked on its stdin before the
    // signal fires, so its non-success exit below can only be that signal.
    await_member_ready(&mut q_child);

    let marker = super::Marker::new(prepared, None, Some(pgid), false);
    let mark = crate::log_capture::mark();

    // Pass 2: T's own holder scan on THIS pass confirms a live member of `pgid` (T itself), so
    // the gate must open and the group signal must re-fire, reaching Q via killpg.
    marker.sweep_pass(
        nix::sys::signal::Signal::SIGKILL,
        &mut seen,
        &mut group_result,
        &mut incomplete,
        false,
    );

    assert!(
        !crate::log_capture::contains_since(mark, "skipping this pass's group signal"),
        "pass 2 must not skip the group signal: a live, getpgid-confirmed member (T) was just \
         found in this pass's own holder scan"
    );

    // The proof: Q holds no marker and was never named `root`, so only a `killpg` on `pgid`
    // could have killed it.
    let status = q_child.wait().expect("reap Q");
    assert!(
        !status.success(),
        "Q must have been killed by the pass-2 group signal (killpg), not left running; got {status:?}"
    );

    // T is reachable by the marker channel too (this same pass 2 call's own holder-kill loop),
    // so it should already be gone or going; reap it rather than leave it running either way.
    let _ = t_child.kill();
    let _ = t_child.wait();
}

/// `kill_holder`'s `MarkerQuery::Denied` arm, end to end: a KNOWN holder that becomes
/// unqueryable at re-check time must be left unsignalled AND reported as incomplete (`true`),
/// never silently treated as resolved. `id` names pid 1 (launchd) — the same real,
/// unprivileged-EPERM oracle used throughout this file — fed directly to the private method
/// rather than through a real sweep, since pid 1 can never naturally appear in a real sweep's
/// holder set (it does not hold this marker) or its ppid-walk (the pid 1 launchd walk read
/// would itself be catastrophic — see the `Marker::sweep`-level test below for why root=pid 1
/// is never used there either).
///
/// `ProcessId::of(1)` is asserted to resolve (not skipped if it doesn't): `identity/macos.rs`
/// falls back to the `sysctl(KERN_PROC_PID)` reader specifically because `proc_pidinfo` denies
/// pid 1 to an unprivileged caller, and that fallback is documented to succeed for exactly this
/// case — a `Resolved::Unknown` here would mean that documented fallback regressed, which this
/// test must fail loudly on, not quietly skip past.
#[test]
fn kill_holder_leaves_a_denied_pid_unsignalled_and_reports_incomplete() {
    let _serialize = test_spawn_lock();
    let mut cmd = std::process::Command::new("/usr/bin/true");
    let prepared = super::install(&mut cmd, &[]).expect("install");
    let marker = super::Marker::new(prepared, None, None, false);

    let id = match crate::identity::ProcessId::of(1) {
        crate::identity::Resolved::Found(id) => id,
        other => panic!(
            "pid 1 must resolve via the documented sysctl fallback for this test's oracle to \
             hold; got {other:?}"
        ),
    };

    assert!(
        marker.kill_holder(id, nix::sys::signal::Signal::SIGKILL),
        "a Denied re-check on a supposedly-known holder must report incomplete (true), not \
         silently succeed"
    );
}

/// `Marker::sweep`'s top-level `incomplete`/`Err` return, end to end through the REAL public
/// `hard_kill()` — not a synthetic check of the `incomplete` bool in isolation. Forces a
/// genuinely blind pass via the enumerate backend's test-only fault seam (module docs at the
/// top of `enumerate/macos.rs`), NOT by naming an unkillable real pid as `root`: an unprivileged
/// but real identity like pid 1 cannot be used as `root` here, because `treewalk::descendants`
/// would then walk pid 1's ENTIRE real ppid subtree — every process on the host, launchd being
/// everyone's eventual ancestor — and this sweep would attempt to SIGKILL every one of them.
/// `root: None, pgid: None` keeps every channel this test does not need inert, so the blind
/// pass is the ONLY source of `incomplete` — no real process is signalled by this test at all.
#[test]
fn hard_kill_reports_err_on_a_genuinely_blind_pass() {
    let _serialize = test_spawn_lock();
    let mut cmd = std::process::Command::new("/usr/bin/true");
    let prepared = super::install(&mut cmd, &[]).expect("install");
    let marker = super::Marker::new(prepared, None, None, false);

    crate::containment::enumerate::force_blind_snapshot_for_next_call(true);
    let result = marker.hard_kill();

    assert!(
        result.is_err(),
        "a sweep whose only pass was blind must report Err, not silently converge as Ok(())"
    );
}
