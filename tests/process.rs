//! Foreign `Process` integration tests. A child we spawn (and own) is treated as a foreign
//! process via its `ProcessId`; nothing here is proven by sleep/poll. A real exit event
//! (control-socket EOF, or the kernel exit edge a death-watch returns on) proves the EXIT.
//! Only a reap or `common::block_until_zombie` proves NOT-ALIVE: on macOS both of those events
//! fire while the kernel is still tearing the process down, before it is marked a zombie —
//! the state `is_alive` reads.

// Shadows the built-in #[test] in every module of this binary so a stray one registers with skuld (harness = false).
#[allow(
    unused_imports,
    reason = "a stray #[test] must register with skuld, not silently never run"
)]
#[macro_use]
extern crate skuld;

use std::io::{Read, Write};
use std::time::Duration;

#[path = "common/mod.rs"]
mod common;
use common::spawn_blocker;

#[skuld::test]
fn foreign_wait_returns_when_the_process_exits() {
    let (child, mut sock) = spawn_blocker();
    let p = cosca::Process::from_pid(child.id().pid())
        .found()
        .expect("foreign process resolves");
    sock.write_all(b"x").expect("trigger child exit");
    p.wait().expect("foreign wait");
    // Prove the exit via a real event (the dead child's socket EOFs), not is_alive().
    let mut buf = [0u8; 1];
    match sock.read(&mut buf) {
        Ok(0) => {}
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("expected EOF/ConnectionReset after wait observed the exit, got {other:?}"),
    }
    let _ = child.wait();
}

#[skuld::test]
fn foreign_wait_timeout_times_out_on_a_live_process() {
    // The blocker is structurally wedged on its never-written socket, so it cannot
    // exit; wait_timeout returns Ok(false) regardless of the (short) duration.
    let (child, _sock) = spawn_blocker();
    let p = cosca::Process::from_pid(child.id().pid()).found().expect("resolves");
    let exited = p.wait_timeout(Duration::from_millis(200)).expect("wait_timeout");
    assert!(
        !exited,
        "a wedged process must time out to Ok(false), got exited={exited}"
    );
    child.kill().expect("kill cleanup");
    let _ = child.wait();
}

#[skuld::test]
fn foreign_wait_timeout_observes_an_exit() {
    let (child, mut sock) = spawn_blocker();
    let p = cosca::Process::from_pid(child.id().pid()).found().expect("resolves");
    sock.write_all(b"x").expect("trigger child exit");
    assert!(p.wait_timeout(Duration::from_secs(30)).expect("wait_timeout"));
    let _ = child.wait();
}

#[skuld::test]
fn foreign_wait_timeout_zero_returns_immediately_on_a_live_process() {
    // ZERO is the poll-once edge in each backend; a wedged child must yield Ok(false).
    let (child, _sock) = spawn_blocker();
    let p = cosca::Process::from_pid(child.id().pid()).found().expect("resolves");
    assert!(!p.wait_timeout(Duration::ZERO).expect("wait_timeout"));
    child.kill().expect("kill cleanup");
    let _ = child.wait();
}

#[skuld::test]
fn foreign_wait_timeout_huge_duration_does_not_panic() {
    // Duration::MAX overflows Instant + Duration; the saturating deadline must make
    // it unbounded, not panic. Trigger the exit first so the wait completes.
    let (child, mut sock) = spawn_blocker();
    let p = cosca::Process::from_pid(child.id().pid()).found().expect("resolves");
    sock.write_all(b"x").expect("trigger child exit");
    assert!(p.wait_timeout(Duration::MAX).expect("wait_timeout"));
    let _ = child.wait();
}

#[skuld::test]
fn current_and_from_id_round_trip() {
    let me = cosca::Process::current();
    assert_eq!(me.is_alive(), cosca::identity::Liveness::Alive);
    assert_eq!(cosca::Process::from_id(me.id()).id(), me.id());
    assert_eq!(
        cosca::Process::from_id(me.id()).exists(),
        cosca::identity::Existence::Present
    );
}

#[skuld::test]
fn from_pid_resolves_a_live_foreign_child_then_reports_it_dead() {
    // from_pid resolves a live foreign child to its true identity; after the child is
    // killed+reaped, that resolved Process reports !is_alive (the zombie-EXCLUSIVE liveness
    // check, distinct from the zombie-inclusive exists()). The reap is what makes the liveness
    // assertion sound — an exit event alone would not (see the module doc).
    let (child, _sock) = spawn_blocker();
    let p = cosca::Process::from_pid(child.id().pid())
        .found()
        .expect("live foreign child resolves");
    assert_eq!(p.id(), child.id());
    assert_eq!(
        p.is_alive(),
        cosca::identity::Liveness::Alive,
        "a freshly spawned foreign child is alive"
    );
    child.kill().expect("kill");
    child.wait().expect("reap"); // synchronously confirm exit before the liveness assertion
    assert_eq!(
        p.is_alive(),
        cosca::identity::Liveness::Dead,
        "a killed+reaped foreign process must report not-alive"
    );
}

#[skuld::test]
fn parent_and_children_resolve_the_spawned_tree() {
    let (child, mut sock) = spawn_blocker();
    let me = cosca::Process::current();
    let kid = cosca::Process::from_pid(child.id().pid())
        .found()
        .expect("child resolves");

    assert_eq!(
        kid.parent()
            .expect("the parent is queryable")
            .expect("child has a parent")
            .id(),
        me.id()
    );
    assert!(me
        .children(cosca::Recursive::No)
        .expect("children are enumerable")
        .iter()
        .any(|p| p.id() == kid.id()));
    assert!(me
        .children(cosca::Recursive::Yes)
        .expect("children are enumerable")
        .iter()
        .any(|p| p.id() == kid.id()));

    sock.write_all(b"x").expect("release child");
    let _ = child.wait();
}

#[skuld::test]
fn children_recursive_distinguishes_direct_from_descendant() {
    // spawn-grandchild: the child connects (tag "R") and spawns a control-block grandchild
    // (tag "G"). `spawn_grandchild` accepts BOTH, death-watched, which proves the 2-level tree
    // is alive; we learn the grandchild's identity via kid.children(No), then assert it is in
    // me.children(Yes) but NOT No — the one-level-vs-recursive distinction a No<->Yes arm swap
    // would otherwise pass silently.
    let (child, socks) = common::spawn_grandchild(false);
    let me = cosca::Process::current();
    let kid = cosca::Process::from_pid(child.id().pid())
        .found()
        .expect("child resolves");
    // The grandchild is kid's only direct child — use it to learn the grandchild's identity.
    let grandkids = kid.children(cosca::Recursive::No).expect("children are enumerable");
    assert_eq!(
        grandkids.len(),
        1,
        "the spawn-grandchild child has exactly one direct child"
    );
    let grandkid = grandkids[0];

    let direct = me.children(cosca::Recursive::No).expect("children are enumerable");
    assert!(
        direct.iter().any(|p| p.id() == kid.id()),
        "Recursive::No must include the direct child"
    );
    assert!(
        !direct.iter().any(|p| p.id() == grandkid.id()),
        "Recursive::No must EXCLUDE the grandchild"
    );
    let all = me.children(cosca::Recursive::Yes).expect("children are enumerable");
    assert!(
        all.iter().any(|p| p.id() == kid.id()),
        "Recursive::Yes must include the child"
    );
    assert!(
        all.iter().any(|p| p.id() == grandkid.id()),
        "Recursive::Yes must include the grandchild"
    );

    // Teardown: kill the direct child; the reparented grandchild exits when its socket closes.
    child.kill().expect("kill child");
    let _ = child.wait();
    drop(socks);
    grandkid.wait().expect("wait for the orphaned grandchild");
}

#[skuld::test]
fn foreign_kill_terminates_the_process() {
    let (child, mut sock) = spawn_blocker();
    let p = cosca::Process::from_pid(child.id().pid()).found().expect("resolves");
    p.kill().expect("kill");
    let mut buf = [0u8; 1];
    match sock.read(&mut buf) {
        Ok(0) => {}                                                     // EOF — process died
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {} // reset — also death
        Ok(n) => panic!("expected EOF/ConnectionReset after kill, got {n} bytes"),
        Err(e) => panic!("unexpected error: {e}"),
    }
    let _ = child.wait();
    p.kill().expect("second kill on a dead process must be Ok");
}

// pid 1 is root-owned, resolvable on Linux (procfs) and macOS (sysctl), and a non-root `SIGKILL`
// to it is refused with `EPERM`, which `Process::kill` must surface as `Err`, not swallow into
// `Ok`. The precondition keeps this off root, where the signal could land.
#[cfg(unix)]
#[skuld::test(requires = [common::unprivileged_with_root_init])]
fn foreign_kill_of_a_root_process_surfaces_permission_denied() {
    let init = cosca::Process::from_pid(1).found().expect("pid 1 resolves");
    assert_eq!(init.is_alive(), cosca::identity::Liveness::Alive, "init must be alive");
    let r = init.kill();
    assert!(
        matches!(&r, Err(cosca::error::Error::Io(e)) if e.raw_os_error() == Some(libc::EPERM)),
        "a non-root kill of init must surface EPERM as Err, got {r:?}"
    );
    assert_eq!(init.is_alive(), cosca::identity::Liveness::Alive, "init must survive");
}

#[cfg(unix)]
#[skuld::test]
fn is_alive_is_false_for_a_real_zombie() {
    // Spawn a RAW std child (std does NOT reap on drop), take it foreign, drive it to a
    // zombie, then — before reaping — assert is_alive()==Dead while the identity still
    // resolves (exists). Finally reap to avoid a leak.
    use std::io::Read;
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    // RAW std::process::Command: argv[0] is the exe path, so the testbin mode is args[1] —
    // do NOT prepend "cosca_testbin" the way the crate's Command requires.
    let mut raw = common::spawn_locked(
        std::process::Command::new(common::testbin())
            .args(["control-block", &addr, "Z"])
            .env(common::ACK_ENV, "1"),
    )
    .expect("spawn raw child");
    let p = cosca::Process::from_pid(raw.id()).found().expect("raw child resolves");
    let mut sock = common::accept_or_die(&listener, &mut raw);
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("read tag");

    sock.write_all(b"x").expect("trigger exit");
    p.wait().expect("death-watch"); // the OS exit edge — non-reaping, but not yet the zombie edge
    common::block_until_zombie(raw.id()); // the zombie edge, still unreaped

    assert_eq!(
        p.is_alive(),
        cosca::identity::Liveness::Dead,
        "an exited-but-unreaped child is a zombie => not alive"
    );
    // exists() is zombie-inclusive on ALL Unixes: Linux `/proc` persists, and macOS
    // resolves zombies via `sysctl KERN_PROC` (identity.rs).
    assert_eq!(
        cosca::Process::from_id(p.id()).exists(),
        cosca::identity::Existence::Present,
        "a zombie identity still resolves"
    );
    raw.wait().expect("reap the zombie");
}

// Death-watched accept =====

/// A pid no OS issues: above Linux's `pid_max` cap (2^22), macOS's 99999 and Windows' handle-table
/// range, and a multiple of 4 for Windows. Nothing can ever be running under it, so a test can
/// name "a process that does not exist" without racing pid reuse.
const NO_SUCH_PID: u32 = 0x7FFF_FFFC;

/// Runs `f`, which must panic, and returns the panic message.
fn panic_message_of<R>(f: impl FnOnce() -> R) -> String {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    common::panic_message(result.err().expect("the call must panic, not return or hang"))
}

fn assert_died_before_connecting(message: &str, pid: u32) {
    assert!(
        message.contains(&format!("the control target (pid {pid}) died before it connected")),
        "expected pid {pid} to be reported as died before it connected, got: {message:?}"
    );
}

/// A target that has always exited, whose pid must never be opened.
struct AlreadyDead {
    asked: u32,
}

impl common::Target for AlreadyDead {
    fn pid(&self) -> u32 {
        NO_SUCH_PID
    }

    fn has_exited(&mut self) -> bool {
        self.asked += 1;
        true
    }
}

/// A target that dies before connecting makes `accept_or_die` panic naming it, not hang.
#[skuld::test]
fn death_watch_accept_or_die_panics_loudly_when_the_target_dies_first() {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let mut child = common::spawn_locked(
        std::process::Command::new(common::testbin()).args(["--not-a-real-mode"]), // testbin exits immediately on an unknown mode
    )
    .expect("spawn a child that exits immediately");
    let pid = child.id();
    let message = panic_message_of(|| common::accept_or_die(&listener, &mut child));
    assert_died_before_connecting(&message, pid);
    child.wait().expect("reap the already-exited child");
}

/// An exit AFTER the watch is armed. The target is alive when `accept_or_die` starts; the armed
/// hook, which runs once the watches are in place, closes its stdin so it exits. This reaches the
/// OS exit notification itself (pidfd, kqueue `NOTE_EXIT`, process handle).
#[skuld::test]
fn death_watch_accept_or_die_reports_a_target_that_exits_after_the_watch_is_armed() {
    use std::net::TcpListener;
    use std::process::Stdio;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let mut child = common::spawn_locked(
        std::process::Command::new(common::testbin())
            .arg("hold-until-stdin-eof")
            .stdin(Stdio::piped()),
    )
    .expect("spawn a target that waits for its stdin to close");
    let pid = child.id();
    let mut stdin = child.stdin.take();
    let armed = std::rc::Rc::new(std::cell::Cell::new(false));
    let armed_in_hook = armed.clone();
    let message = common::with_armed_hook(
        move || {
            armed_in_hook.set(true);
            drop(stdin.take()); // EOF: the target exits now, after the watch was armed
        },
        || panic_message_of(|| common::accept_or_die(&listener, &mut child)),
    );
    assert!(armed.get(), "the wait must arm its watches before blocking");
    assert_died_before_connecting(&message, pid);
    child.wait().expect("reap");
}

/// A signal handled while the wait is parked must retry it, not panic (see `kevent_eintr`), and the
/// wait must still report the target's exit.
#[cfg(target_os = "macos")]
#[skuld::test]
fn death_watch_accept_or_die_retries_a_kevent_wait_interrupted_by_a_signal() {
    use std::net::TcpListener;
    use std::process::Stdio;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let mut child = common::spawn_locked(
        std::process::Command::new(common::testbin())
            .arg("hold-until-stdin-eof")
            .stdin(Stdio::piped()),
    )
    .expect("spawn a target that waits for its stdin to close");
    let pid = child.id();
    let stdin = child.stdin.take();
    let interrupter = common::kevent_eintr::interrupt_once_blocked(move || drop(stdin));
    let message = panic_message_of(|| common::accept_or_die(&listener, &mut child));
    interrupter.finish();
    assert_died_before_connecting(&message, pid);
    child.wait().expect("reap");
}

/// A target that `has_exited` is dead, and its pid (here one that cannot exist) is never opened:
/// a reaped pid could name a stranger.
#[skuld::test]
fn death_watch_accept_or_die_reports_an_already_exited_target_without_opening_its_pid() {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let mut target = AlreadyDead { asked: 0 };
    let message = panic_message_of(|| common::accept_or_die(&listener, &mut target));
    assert_died_before_connecting(&message, NO_SUCH_PID);
    assert_eq!(target.asked, 1, "has_exited must be asked exactly once, before arming");
}

/// A std child reaped by its own `wait` is reported exited by `Target::has_exited`, so it takes the
/// same path as above with a real pid.
#[skuld::test]
fn a_reaped_std_child_is_reported_exited() {
    use common::Target as _;
    let mut child =
        common::spawn_locked(std::process::Command::new(common::testbin()).args(["--not-a-real-mode"])).expect("spawn");
    child.wait().expect("reap");
    assert!(child.has_exited());
}

/// A target that connects and exits without waiting for the ack is dead whether or not its
/// connection reached the accept queue: the exit alone decides.
#[skuld::test]
fn death_watch_accept_or_die_reports_a_target_that_connected_and_exited_without_the_ack_as_dead() {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let mut child = common::spawn_locked(
        std::process::Command::new(common::testbin()).args(["control-once", &addr, "R"]), // connects, sends the tag, exits; no ack env
    )
    .expect("spawn a target that connects and exits immediately");
    let pid = child.id();
    let status = child.wait().expect("wait for the target to exit");
    assert!(status.success(), "control-once should exit 0, got {status:?}");
    let message = panic_message_of(|| common::accept_or_die(&listener, &mut child));
    assert_died_before_connecting(&message, pid);
}

/// The ack is written on the accepted connection; the opted-in target sends its tag only after it.
#[skuld::test]
fn death_watch_accept_or_die_acks_the_connection_it_accepts() {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let mut child = common::spawn_locked(
        std::process::Command::new(common::testbin())
            .args(["control-block", &addr, "R"])
            .env(common::ACK_ENV, "1"),
    )
    .expect("spawn an acking target");
    let mut sock = common::accept_or_die(&listener, &mut child);
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("the acked target sends its tag");
    assert_eq!(&tag, b"R");
    sock.write_all(b"x").expect("release the target");
    child.wait().expect("reap");
}

/// A descendant that is gone (reaped, so its identity no longer resolves) is reported dead, not
/// panicked over: Linux `pidfd_open` ESRCH, macOS `EV_ADD` ESRCH, Windows `OpenProcess` failing
/// with `ERROR_INVALID_PARAMETER`. The target is alive throughout.
#[skuld::test]
fn death_watch_accept_or_die_also_reports_a_gone_descendant_as_dead() {
    use std::net::TcpListener;
    use std::process::Stdio;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let mut target = common::spawn_locked(
        std::process::Command::new(common::testbin())
            .arg("hold-until-stdin-eof")
            .stdin(Stdio::piped()),
    )
    .expect("spawn the live target");
    let mut gone = common::spawn_locked(
        std::process::Command::new(common::testbin())
            .arg("hold-until-stdin-eof")
            .stdin(Stdio::piped()),
    )
    .expect("spawn the descendant");
    let gone_id = cosca::identity::ProcessId::of(gone.id())
        .found()
        .expect("the live descendant resolves");
    drop(gone.stdin.take());
    gone.wait().expect("reap the descendant: its identity is now Gone");
    // Windows keeps the process object alive while a handle to it is open; closing it is what
    // makes `OpenProcess` fail for the pid.
    drop(gone);

    let message = panic_message_of(|| common::accept_or_die_also(&listener, &mut target, Some(gone_id)));
    assert_died_before_connecting(&message, gone_id.pid());
    drop(target.stdin.take());
    target.wait().expect("reap the target");
}

/// A pid now running a DIFFERENT process (a live one, with the identity forged to differ in its
/// start token, which is what a reissued pid looks like) is reported as the descendant being gone,
/// never watched.
#[skuld::test]
fn death_watch_accept_or_die_also_does_not_watch_a_reissued_pid() {
    use std::net::TcpListener;
    use std::process::Stdio;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let spawn_holder = || {
        common::spawn_locked(
            std::process::Command::new(common::testbin())
                .arg("hold-until-stdin-eof")
                .stdin(Stdio::piped()),
        )
        .expect("spawn a holder")
    };
    let mut target = spawn_holder();
    let mut stranger = spawn_holder();
    let real = cosca::identity::ProcessId::of(stranger.id())
        .found()
        .expect("the stranger resolves");
    let mut record = real.to_record().expect("persistable identity");
    record.token += 1;
    let forged = cosca::identity::ProcessId::try_from(&record).expect("a well-formed record");
    assert_ne!(forged, real);

    let message = panic_message_of(|| common::accept_or_die_also(&listener, &mut target, Some(forged)));
    assert_died_before_connecting(&message, stranger.id());
    for holder in [&mut target, &mut stranger] {
        drop(holder.stdin.take());
        holder.wait().expect("reap");
    }
}

/// `wait_handles` reports the OS error of a failed wait, captured before anything can overwrite it.
#[cfg(windows)]
#[skuld::test]
fn wait_handles_reports_the_os_error_of_a_failed_wait() {
    use windows::Win32::Foundation::{ERROR_INVALID_HANDLE, HANDLE};
    let err = common::wait_handles(&[HANDLE(std::ptr::null_mut())]).expect_err("a null handle cannot be waited on");
    assert_eq!(err.raw_os_error(), Some(ERROR_INVALID_HANDLE.0 as i32), "got {err:?}");
}

// Tree helpers =====

/// The helpers themselves (`spawn_control`, `spawn_tree`), end to end, fail rather than hang.
#[skuld::test]
fn death_watch_spawn_control_panics_if_its_death_watch_is_ever_reverted_to_a_plain_accept() {
    let message = panic_message_of(|| common::spawn_control("--not-a-real-mode", &[], false));
    assert!(
        message.contains("died before it connected"),
        "expected a \"died before it connected\" panic, got: {message:?}"
    );
}

#[skuld::test]
fn death_watch_spawn_tree_panics_if_its_death_watch_is_ever_reverted_to_a_plain_accept() {
    let message = panic_message_of(|| common::spawn_tree("--not-a-real-mode", false));
    assert!(
        message.contains("died before it connected"),
        "expected a \"died before it connected\" panic, got: {message:?}"
    );
}

/// Only the GRANDCHILD dies before connecting; the panic must name it (the pid the root
/// reported), not the live root.
#[skuld::test]
fn death_watch_spawn_tree_panics_when_the_grandchild_dies_before_connecting_while_the_root_lives() {
    let message = panic_message_of(|| common::spawn_tree("spawn-grandchild-dies", false));
    let grandchild = common::last_reported_grandchild().expect("the root reported its grandchild");
    assert_died_before_connecting(&message, grandchild);
}

/// The root reports a live grandchild and exits without ever connecting to the main address, so
/// the report accept passes and the main loop must fail on the ROOT (not the live grandchild).
#[skuld::test]
fn death_watch_spawn_tree_panics_when_the_root_dies_after_reporting_before_connecting() {
    root_dies_after_reporting(|| common::spawn_tree("spawn-grandchild-report-then-exit", true));
}

/// [`death_watch_spawn_tree_panics_when_the_root_dies_after_reporting_before_connecting`] with the root's exit
/// complete before the harness first looks at it.
#[skuld::test]
fn death_watch_spawn_tree_panics_when_the_root_dies_after_reporting_before_the_harness_looks() {
    let seam = common::reapable_after_release();
    let message = root_dies_after_reporting(|| common::spawn_tree("spawn-grandchild-report-then-exit", true));
    assert_died_before_connecting(&message, seam.root().expect("the seam waited on the released root"));
}

/// Runs `spawn_tree`, which must panic on a root that exits right after reporting its grandchild,
/// and returns the panic message. Contained so unwinding kills the orphaned grandchild.
fn root_dies_after_reporting<R>(spawn_tree: impl FnOnce() -> R) -> String {
    common::install_log_capture();
    let mark = common::log_mark();
    let message = panic_message_of(spawn_tree);
    assert!(message.contains("died before it connected"), "got: {message:?}");
    common::wait_for_the_dropped_trees_grandchild(mark, &message);
    let grandchild = common::last_reported_grandchild().expect("the root reported before it exited");
    assert!(
        !message.contains(&format!("(pid {grandchild})")),
        "the live grandchild must not be the one blamed: {message:?}"
    );
    message
}

/// The root connects to the report address and exits without reporting: the failure names that,
/// not a parse error on an empty line.
#[skuld::test]
fn death_watch_spawn_tree_panics_when_the_root_dies_before_reporting_the_grandchild_pid() {
    let message = panic_message_of(|| common::spawn_tree("spawn-grandchild-report-eof", false));
    assert!(
        message.contains("died before it reported the grandchild pid"),
        "got: {message:?}"
    );
}

// The testbin's ack seam (`testbin/ack.rs`) =====

/// Spawns `control-block` with the seam set to `seam` and, when `opted_in`, the accept opt-in.
fn seamed_control_block(seam: &str, opted_in: bool) -> (std::process::Child, std::net::TcpListener) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let mut cmd = std::process::Command::new(common::testbin());
    cmd.args(["control-block", &addr, "T"]).env("COSCA_TEST_ACK_SEAM", seam);
    if opted_in {
        cmd.env(common::ACK_ENV, "1");
    }
    let child = common::spawn_locked(&mut cmd).expect("spawn control-block");
    (child, listener)
}

fn reap(mut child: std::process::Child) {
    let _ = child.kill();
    child.wait().expect("reap");
}

/// `strict` turns a missing opt-in into a death before connecting, which is how the mode tests
/// see that a mode forgot to opt its child in.
#[skuld::test]
fn death_watch_accept_or_die_seam_strict_kills_a_target_that_was_not_opted_in() {
    let (mut child, listener) = seamed_control_block("strict", false);
    let message = panic_message_of(|| common::accept_or_die(&listener, &mut child));
    assert_died_before_connecting(&message, child.id());
}

#[skuld::test]
fn death_watch_accept_or_die_seam_strict_lets_an_opted_in_target_connect() {
    let (mut child, listener) = seamed_control_block("strict", true);
    let mut sock = common::accept_or_die(&listener, &mut child);
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("read the tag");
    assert_eq!(&tag, b"T");
    drop(sock);
    reap(child);
}

/// `die-now` is the state the `die` seam leaves a mode in for its children.
#[skuld::test]
fn death_watch_accept_or_die_seam_die_now_exits_the_target_before_it_connects() {
    let (mut child, listener) = seamed_control_block("die-now", true);
    let message = panic_message_of(|| common::accept_or_die(&listener, &mut child));
    assert_died_before_connecting(&message, child.id());
}

/// Pid 1 has no parent, and that is `Ok(None)`: a real absence, not an unanswerable question.
#[cfg(target_os = "linux")]
#[skuld::test]
fn pid_one_has_no_parent() {
    let init = cosca::Process::from_pid(1).found().expect("pid 1 resolves");
    assert!(init.parent().expect("pid 1's parent is answerable").is_none());
}

/// The identity of the unreaped child `pid`.
fn found_id(pid: u32) -> cosca::identity::ProcessId {
    match cosca::identity::ProcessId::of(pid) {
        cosca::identity::Resolved::Found(id) => id,
        other => panic!("the unreaped child {pid} must resolve, got {other:?}"),
    }
}

/// `accept_tree_also` arms one death watch per accept, so a two-member tree arms two.
fn healthy_tree_arms_a_watch_for_each_accept() {
    use std::cell::Cell;
    use std::rc::Rc;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let spawn = |tag: &str| {
        common::spawn_locked(
            std::process::Command::new(common::testbin())
                .args(["control-block", &addr, tag])
                .env(common::ACK_ENV, "1"),
        )
        .expect("spawn a healthy tree member")
    };
    let mut root = spawn("R");
    let mut grandchild = spawn("G");
    let grandchild_id = found_id(grandchild.id());
    let armings = Rc::new(Cell::new(0usize));
    let in_hook = armings.clone();
    let socks = common::with_armed_hook(
        move || in_hook.set(in_hook.get() + 1),
        || {
            common::accept_tree_also(&listener, &mut root, grandchild_id, |s| {
                let mut tag = [0u8; 1];
                s.read_exact(&mut tag).expect("read tag");
                tag[0] == b'G'
            })
        },
    );
    drop(socks);
    root.kill().expect("kill the root");
    root.wait().expect("reap the root");
    grandchild.kill().expect("kill the grandchild");
    grandchild.wait().expect("reap the grandchild");
    assert_eq!(
        armings.get(),
        2,
        "each accept over a healthy tree must arm a death watch"
    );
}

/// `accept_tree` must fail promptly when the first member to connect is the grandchild and the
/// root then dies before ever connecting. Every accept has to keep watching the ROOT, not a
/// connected peer's socket: the peer is healthy and silent.
///
/// The root (`hold-until-stdin-eof`, stdin held by this test) never connects, so the first accept
/// resolves through the grandchild. The armed hook then kills the root once a later accept's watch
/// is in place; the root must die of that kill, not exit on its own.
#[skuld::test]
fn death_watch_accept_tree_panics_when_the_root_dies_before_connecting_after_another_member_already_did() {
    healthy_tree_arms_a_watch_for_each_accept();
    use std::cell::Cell;
    use std::net::TcpListener;
    use std::process::Stdio;
    use std::rc::Rc;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();

    // The grandchild: connects, tags 'G', and blocks.
    let mut grandchild = common::spawn_locked(
        std::process::Command::new(common::testbin())
            .args(["control-block", &addr, "G"])
            .env(common::ACK_ENV, "1"),
    )
    .expect("spawn the grandchild");
    let grandchild_id = found_id(grandchild.id());
    // The root: alive while `root.stdin` stays open, and never connects.
    let mut root = common::spawn_locked(
        std::process::Command::new(common::testbin())
            .args(["hold-until-stdin-eof"])
            .stdin(Stdio::piped()),
    )
    .expect("spawn a root that stays alive without ever connecting");
    let root_pid = root.id();
    let root_id = found_id(root_pid);

    let member_connected = Rc::new(Cell::new(false));
    let (in_hook, in_accept) = (member_connected.clone(), member_connected.clone());
    let message = common::with_armed_hook(
        move || {
            if in_hook.get() {
                cosca::Process::from_id(root_id).kill().expect("kill the root");
            }
        },
        || {
            panic_message_of(|| {
                common::accept_tree_also(&listener, &mut root, grandchild_id, |s| {
                    let mut tag = [0u8; 1];
                    s.read_exact(&mut tag).expect("read tag");
                    assert_eq!(&tag, b"G", "the root never connects in this scenario");
                    in_accept.set(true);
                    true
                })
            })
        },
    );
    let status = root.wait().expect("reap the root");
    grandchild.kill().expect("kill the grandchild");
    grandchild.wait().expect("reap the grandchild");
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "the root must die of the hook's SIGKILL, not exit on its own: {status:?}"
        );
    }
    #[cfg(windows)]
    assert!(
        !status.success(),
        "the root must die of the hook's kill, not exit on its own: {status:?}"
    );
    assert_died_before_connecting(&message, root_pid);
}

/// `accept_tree` must fail promptly when the grandchild dies before connecting while the root is
/// alive and connects: watching the root alone would wait for a `G` that never comes.
/// `spawn-grandchild-dies` spawns a grandchild that exits at once, reports its pid, and connects
/// as the root. The panic must name the grandchild.
#[skuld::test]
fn death_watch_accept_tree_panics_when_the_grandchild_dies_before_connecting_while_the_root_lives() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let (report, report_addr) = common::bind_report();
    let mut cmd = cosca::Command::new();
    cmd.executable(common::testbin())
        .args(["cosca_testbin", "spawn-grandchild-dies", &addr])
        .env(common::ACK_ENV, "1")
        .env(common::GC_PID_ADDR_ENV, &report_addr);
    common::silence(&mut cmd);
    let mut root = cmd.spawn().expect("spawn the tree");
    let grandchild = common::report_grandchild(&report, &mut root);
    let grandchild_pid = grandchild.pid();
    // The root connects as soon as it is released. Waiting for the grandchild's exit first makes
    // accept #1 report it dead on every interleaving.
    cosca::Process::from_id(grandchild)
        .wait()
        .expect("wait for the grandchild to exit");

    // Accept #1 must watch the grandchild too. The hook fires only under a regression: a healthy
    // accept reports the dead grandchild before it arms.
    let message = common::with_armed_hook(
        move || {
            let watched = common::armed_watch();
            assert!(
                watched.contains(&grandchild_pid),
                "the tree accept armed {watched:?} without the grandchild {grandchild_pid}"
            );
        },
        || {
            panic_message_of(|| {
                common::accept_tree_also(&listener, &mut root, grandchild, |s| {
                    let mut tag = [0u8; 1];
                    s.read_exact(&mut tag).expect("read tag");
                    tag[0] == b'G'
                })
            })
        },
    );
    // The grandchild exited, so it must not be named a `G` connection; the root stays alive.
    root.kill().expect("kill the root");
    root.wait().expect("reap the root");
    assert_died_before_connecting(&message, grandchild_pid);
}

/// In the `spawn-orphan-escapee` tree the reporter of the grandchild's pid is the relay, not the
/// root, and the root only waits for the relay. A relay that dies before it reports must fail the
/// report accept, which watches the root: the root has to exit with it, not carry on to its own
/// connection and leave the accept waiting on a live root.
///
/// The failed relay must also leave nothing behind: nothing contains this tree, and an orphan
/// would hold the test's stdout and stderr.
#[cfg(unix)]
#[skuld::test]
fn death_watch_a_relay_that_dies_before_reporting_fails_the_report_accept() {
    use std::net::TcpListener;
    use std::os::fd::AsRawFd;
    let main = TcpListener::bind("127.0.0.1:0").expect("bind");
    let report = TcpListener::bind("127.0.0.1:0").expect("bind");
    // An address with no port never resolves, so the relay's report connection fails at once. A
    // port freed by dropping a listener could be taken by another test and answered.
    let refused_addr = "no-port";
    // The tree's only stdout and stderr: each member holds the write end until it exits.
    let (mut output, output_w) = std::io::pipe().expect("create the tree's output pipe");
    let mut root = common::spawn_locked(
        std::process::Command::new(common::testbin())
            .args(["spawn-orphan-escapee", &main.local_addr().unwrap().to_string()])
            .env(common::ACK_ENV, "1")
            .env(common::GC_PID_ADDR_ENV, refused_addr)
            .stdout(output_w.try_clone().expect("clone the output pipe"))
            .stderr(output_w),
    )
    .expect("spawn the orphan tree");
    let root_pid = root.id();
    let message = panic_message_of(|| common::accept_or_die(&report, &mut root));
    root.wait().expect("reap the root");
    assert_died_before_connecting(&message, root_pid);

    // The root exits only after the relay has, so the write end is now open only in a process
    // the relay left behind. A grandchild it spawned blocks on `main`, still open here, so it is
    // alive now and the read cannot see EOF: `WouldBlock` is the leak, without any wait.
    // SAFETY: F_GETFL and F_SETFL on a pipe this frame owns.
    unsafe {
        let flags = libc::fcntl(output.as_raw_fd(), libc::F_GETFL);
        assert!(flags >= 0, "F_GETFL: {}", std::io::Error::last_os_error());
        let rc = libc::fcntl(output.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
        assert_eq!(rc, 0, "F_SETFL: {}", std::io::Error::last_os_error());
    }
    let mut printed = Vec::new();
    let drained = output.read_to_end(&mut printed);
    let printed = String::from_utf8_lossy(&printed);
    match drained {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            panic!("a process the failed relay left behind still holds the tree's output; it printed: {printed}")
        }
        Err(e) => panic!("reading the tree's output: {e}; it printed: {printed}"),
    }
    drop(main);
}

/// The second tree accept must watch the grandchild too: the root connects first, the grandchild
/// stays silent, and the armed hook kills it once the second accept's watch is in place. The hook
/// asserts the grandchild is in every armed set.
#[skuld::test]
fn death_watch_accept_tree_panics_when_the_grandchild_dies_before_connecting_after_the_root_already_did() {
    use std::cell::Cell;
    use std::process::Stdio;
    use std::rc::Rc;
    healthy_tree_arms_a_watch_for_each_accept();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    // The root: connects, tags 'R', and blocks.
    let mut root = common::spawn_locked(
        std::process::Command::new(common::testbin())
            .args(["control-block", &addr, "R"])
            .env(common::ACK_ENV, "1"),
    )
    .expect("spawn the root");
    // The grandchild: alive while its stdin stays open, and never connects.
    let mut grandchild = common::spawn_locked(
        std::process::Command::new(common::testbin())
            .args(["hold-until-stdin-eof"])
            .stdin(Stdio::piped()),
    )
    .expect("spawn a grandchild that stays alive without ever connecting");
    let grandchild_pid = grandchild.id();
    let grandchild_id = found_id(grandchild_pid);
    let armings = Rc::new(Cell::new(0usize));
    let in_hook = armings.clone();
    let message = common::with_armed_hook(
        move || {
            let watched = common::armed_watch();
            assert!(
                watched.contains(&grandchild_pid),
                "the tree accept armed {watched:?} without the grandchild {grandchild_pid}"
            );
            in_hook.set(in_hook.get() + 1);
            if in_hook.get() == 2 {
                cosca::Process::from_id(grandchild_id)
                    .kill()
                    .expect("kill the grandchild");
            }
        },
        || {
            panic_message_of(|| {
                common::accept_tree_also(&listener, &mut root, grandchild_id, |s| {
                    let mut tag = [0u8; 1];
                    s.read_exact(&mut tag).expect("read tag");
                    assert_eq!(&tag, b"R", "the grandchild never connects in this scenario");
                    false
                })
            })
        },
    );
    root.kill().expect("kill the root");
    root.wait().expect("reap the root");
    grandchild.wait().expect("reap the grandchild");
    assert_eq!(
        armings.get(),
        2,
        "the second accept must have armed before the grandchild died"
    );
    assert_died_before_connecting(&message, grandchild_pid);
}

/// A watcher whose `wait_tree` FAILED must not be reported as the tree having drained: the panic
/// names the failure and its cause.
#[cfg(target_os = "linux")]
#[skuld::test]
fn death_watch_accept_or_signalled_panics_naming_a_failed_wait_tree_not_a_drain() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let drained = common::DrainSignal::new();
    drained.record(Err::<(), _>("the leaf could not be read"));
    let message = panic_message_of(|| common::accept_or_signalled(&listener, &drained));
    assert_eq!(
        message,
        "wait_tree failed while waiting for a connection: the leaf could not be read"
    );
}

/// A real drain is reported as one, with what `wait_tree` returned.
#[cfg(target_os = "linux")]
#[skuld::test]
fn death_watch_accept_or_signalled_panics_naming_the_drain_when_wait_tree_returned_ok() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let drained = common::DrainSignal::new();
    drained.record(Ok::<_, String>("AllMembersExited"));
    let message = panic_message_of(|| common::accept_or_signalled(&listener, &drained));
    assert_eq!(
        message,
        "the leaf drained (\"AllMembersExited\") before anything connected"
    );
}

/// A connection that arrives while nothing has drained is accepted and acked, and its stream is
/// returned: the success path, with no cgroup involved.
#[cfg(target_os = "linux")]
#[skuld::test]
fn death_watch_accept_or_signalled_returns_the_acked_connection_while_nothing_has_drained() {
    use std::io::Write as _;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    let drained = common::DrainSignal::new();
    let client = std::thread::spawn(move || {
        let mut sock = std::net::TcpStream::connect(addr).expect("connect");
        let mut ack = [0u8; 1];
        sock.read_exact(&mut ack).expect("read the ack");
        sock.write_all(b"T").expect("write the tag");
        ack[0]
    });
    let mut stream = common::accept_or_signalled(&listener, &drained);
    let mut tag = [0u8; 1];
    stream.read_exact(&mut tag).expect("read the tag");
    assert_eq!(&tag, b"T");
    assert_eq!(client.join().expect("the client"), common::ack::ACK_BYTE);
}

/// A drain and a queued connection both ready: the drain wins, as an exit wins in `accept_or_die`.
#[cfg(target_os = "linux")]
#[skuld::test]
fn death_watch_accept_or_signalled_reports_the_drain_when_a_connection_is_also_queued() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let _queued = std::net::TcpStream::connect(listener.local_addr().unwrap()).expect("connect");
    let drained = common::DrainSignal::new();
    drained.record(Ok::<_, String>("AllMembersExited"));
    let message = panic_message_of(|| common::accept_or_signalled(&listener, &drained));
    assert_eq!(
        message,
        "the leaf drained (\"AllMembersExited\") before anything connected"
    );
}

/// A watcher whose `wait_tree` panics must signal the drain at once, with an error outcome. The
/// signal is read with a zero-timeout poll, so a missing wake fails by assertion.
#[cfg(target_os = "linux")]
#[skuld::test]
fn death_watch_a_panicking_watcher_wakes_the_acceptor_with_an_error() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let drained = common::DrainSignal::new();
    assert!(!drained.is_signalled(), "nothing has signalled the drain yet");
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        drained.watch(|| -> Result<(), String> { panic!("wait_tree blew up") })
    }));
    assert!(unwound.is_err(), "the watcher's panic must propagate");
    assert!(
        drained.is_signalled(),
        "a panicking watcher must still signal the drain"
    );
    let message = panic_message_of(|| common::accept_or_signalled(&listener, &drained));
    assert_eq!(
        message,
        "wait_tree failed while waiting for a connection: the watcher panicked before wait_tree returned"
    );
}

/// An exit wins over a ready source in every platform's wait.
#[skuld::test]
fn death_watch_an_exit_wins_over_a_ready_source() {
    assert_eq!(common::first_ready(true, true), Some(common::Ready::Exit));
    assert_eq!(common::first_ready(false, true), Some(common::Ready::Source));
    assert_eq!(common::first_ready(true, false), Some(common::Ready::Exit));
    assert_eq!(common::first_ready(false, false), None);
}

fn main() {
    skuld::run_all();
}
