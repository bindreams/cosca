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

/// Runtime preconditions for `#[skuld::test(requires = [...])]`. Each one is `fn() -> Result<(),
/// String>`; an unmet one reports the test as `ignored` with the `Err`'s text, instead of a
/// silent skip or a hard failure on every environment that doesn't happen to run as root.
#[cfg(unix)]
mod preconditions {
    /// `geteuid() == 0`. cosca's tests that must run as an actual privileged caller (as opposed
    /// to merely a foreign, same-uid one) declare this instead of assuming CI happens to run
    /// that way — see `README.md`'s "Running tests" section for how a human opts in locally.
    pub fn root() -> Result<(), String> {
        // SAFETY: geteuid() takes no arguments and has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            Ok(())
        } else {
            Err(
                "requires root — rerun as root, e.g. `sudo cargo nextest run --test process -E \
                 'test(=foreign_kill_surfaces_permission_denied)'`"
                    .into(),
            )
        }
    }
}

/// The target's uid/gid: an ordinary unprivileged account, distinct from both root (0) and
/// `READER_UID` below. No `/etc/passwd` entry is required for either — `setuid`/`execve` only
/// need a number, and neither the target nor the reader ever looks itself up by name.
#[cfg(unix)]
const TARGET_UID: u32 = 65534;
/// The uid/gid `foreign_kill_surfaces_permission_denied` re-execs itself as, to make the actual
/// `Process::kill` call under test. Different from `TARGET_UID`: this proves a GENUINELY foreign,
/// unprivileged caller gets `EPERM`, not merely "some non-root uid or other."
#[cfg(unix)]
const READER_UID: u32 = 65533;

/// Set by [`foreign_kill_surfaces_permission_denied`] on its own re-exec of this binary, routing
/// `fn main` (bottom of this file) to [`foreign_kill_helper_main`] instead of the skuld harness —
/// checked before skuld ever parses argv, so the re-exec'd process never itself becomes a skuld
/// test run.
#[cfg(unix)]
const ENV_TARGET_PID: &str = "COSCA_FOREIGN_KILL_TARGET_PID";

/// Kills and reaps a raw `std::process::Child` on drop, including mid-unwind — so a panic
/// anywhere in [`foreign_kill_surfaces_permission_denied`] cannot orphan the target. The target
/// runs under `TARGET_UID`, never root, so THIS kill (issued by the test itself, which only runs
/// at all once `preconditions::root` has passed) can never itself come back `EPERM`.
#[cfg(unix)]
struct KillOnDrop(Option<std::process::Child>);

#[cfg(unix)]
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// A genuinely foreign, unprivileged caller's `kill` on a genuinely foreign, unprivileged target
/// must surface `EPERM` as `Err`, never swallow it into `Ok`. Runs only as root
/// (`preconditions::root`): the test needs `CAP_SETUID`/`CAP_SETGID` to drop into two DIFFERENT
/// unprivileged identities of its own choosing, rather than depending on whatever uid CI happens
/// to run tests as (see `README.md`'s "Running tests" section for the local `sudo` invocation).
///
/// Both the target and the actual caller under test run as ordinary child PROCESSES of this
/// (root) one — never as this process itself — so root can always name and clean up the target
/// regardless of what the assertions below do.
///
/// Identity crosses the uid boundary as a bare pid (`ENV_TARGET_PID`), not a pidfd: no reuse
/// window exists to protect against in the first place. This (root) process holds the target's
/// `std::process::Child` open, UNREAPED, for the target's entire lifetime — the kernel cannot
/// recycle its pid until this process reaps it, which happens only after the reader below has
/// already run and reported its verdict. `cosca::Process::from_pid` then does its own identity
/// resolution (a pidfd on Linux, the platform's equivalent elsewhere) from that pid, at the
/// instant the reader actually uses it — the same safety property a passed-down pidfd would give,
/// obtained here for free from the pid simply staying valid throughout.
#[cfg(unix)]
#[skuld::test(requires = [preconditions::root])]
fn foreign_kill_surfaces_permission_denied() {
    use std::net::TcpListener;
    use std::os::unix::process::CommandExt;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind control listener");
    let addr = listener.local_addr().unwrap().to_string();

    // The target. `cosca::Command` has no uid()/gid() (a cross-platform builder — Windows has no
    // such concept), so this one spawn uses `std::process::Command` directly, replicating
    // `tests/common/mod.rs`'s `spawn_control` handshake by hand instead of reusing it.
    let target = std::process::Command::new(common::testbin())
        .args(["control-block", &addr, "R"])
        .uid(TARGET_UID)
        .gid(TARGET_UID)
        .spawn()
        .expect("spawn the target under an unprivileged uid");
    let target_pid = target.id();
    let (mut sock, _) = listener.accept().expect("accept the target's control connection");
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("read the target's ready tag");

    // From here on, any panic below (an assertion, or `Command::status()` itself) must still
    // reach this — see the struct doc for why this kill can never itself return EPERM.
    let _target_guard = KillOnDrop(Some(target));

    // The actual caller under test: re-exec THIS SAME test binary as READER_UID. Its result
    // crosses back as an exit code ONLY (never parsed text) — see `foreign_kill_helper_main`'s
    // doc for the exact mapping.
    let exe = std::env::current_exe().expect("this test binary's own path");
    let status = std::process::Command::new(&exe)
        .uid(READER_UID)
        .gid(READER_UID)
        .env(ENV_TARGET_PID, target_pid.to_string())
        .status()
        .expect("re-exec this binary as the unprivileged reader");

    assert_eq!(
        status.code(),
        Some(0),
        "the unprivileged reader did not confirm EPERM (see its stderr, above, for which check \
         failed) — got exit code {:?}",
        status.code()
    );

    // `_target_guard`'s Drop kills and reaps the target; the OS reclaims the reader's own
    // resources on its own exit.
}

/// [`foreign_kill_surfaces_permission_denied`]'s re-exec'd helper mode — dispatched from `fn
/// main` (bottom of this file) via `ENV_TARGET_PID`, before skuld ever sees argv. Reports its
/// verdict PURELY via the process exit code, per the caller's own assertion:
/// - `0`: `Process::kill` on the target surfaced `EPERM` as `Err` — the expected outcome.
/// - `10`: `kill` unexpectedly returned `Ok(())`.
/// - `11`: `kill` returned an `Err` other than `Io(EPERM)`.
/// - `12`: the target pid did not resolve at all.
/// - `13`: this process is still euid 0 — the uid drop to `READER_UID` silently failed, so the
///   scenario below never actually ran as an unprivileged caller in the first place.
///
/// Every code above `0` also writes a one-line diagnostic to stderr — for a human reading CI
/// output, never for the test itself to parse back.
#[cfg(unix)]
fn foreign_kill_helper_main() -> i32 {
    // SAFETY: geteuid() takes no arguments and has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("foreign_kill_helper: still euid 0 — the uid drop to READER_UID silently failed");
        return 13;
    }
    let pid_str = std::env::var(ENV_TARGET_PID).expect("ENV_TARGET_PID set by the caller");
    let pid: cosca::identity::RawPid = pid_str.parse().expect("ENV_TARGET_PID is a valid pid");
    let Some(target) = cosca::Process::from_pid(pid).found() else {
        eprintln!("foreign_kill_helper: target pid {pid} did not resolve");
        return 12;
    };
    match target.kill() {
        Err(cosca::error::Error::Io(e)) if e.raw_os_error() == Some(libc::EPERM) => 0,
        Ok(()) => {
            eprintln!("foreign_kill_helper: kill() unexpectedly succeeded");
            10
        }
        other => {
            eprintln!("foreign_kill_helper: kill() returned an unexpected result: {other:?}");
            11
        }
    }
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
fn accept_or_die_panics_loudly_when_the_target_dies_first() {
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
fn accept_or_die_reports_a_target_that_exits_after_the_watch_is_armed() {
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

/// A target that `has_exited` is dead, and its pid (here one that cannot exist) is never opened:
/// a reaped pid could name a stranger.
#[skuld::test]
fn accept_or_die_reports_an_already_exited_target_without_opening_its_pid() {
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
fn accept_or_die_reports_a_target_that_connected_and_exited_without_the_ack_as_dead() {
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
fn accept_or_die_acks_the_connection_it_accepts() {
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
fn accept_or_die_also_reports_a_gone_descendant_as_dead() {
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
fn accept_or_die_also_does_not_watch_a_reissued_pid() {
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
fn spawn_control_panics_if_its_death_watch_is_ever_reverted_to_a_plain_accept() {
    let message = panic_message_of(|| common::spawn_control("--not-a-real-mode", &[], false));
    assert!(
        message.contains("died before it connected"),
        "expected a \"died before it connected\" panic, got: {message:?}"
    );
}

#[skuld::test]
fn spawn_tree_panics_if_its_death_watch_is_ever_reverted_to_a_plain_accept() {
    let message = panic_message_of(|| common::spawn_tree("--not-a-real-mode", false));
    assert!(
        message.contains("died before it connected"),
        "expected a \"died before it connected\" panic, got: {message:?}"
    );
}

/// Only the GRANDCHILD dies before connecting; the panic must name it (the pid the root
/// reported), not the live root.
#[skuld::test]
fn spawn_tree_panics_when_the_grandchild_dies_before_connecting_while_the_root_lives() {
    let message = panic_message_of(|| common::spawn_tree("spawn-grandchild-dies", false));
    let grandchild = common::last_reported_grandchild().expect("the root reported its grandchild");
    assert_died_before_connecting(&message, grandchild);
}

/// The root reports a live grandchild and exits without ever connecting to the main address, so
/// the report accept passes and the main loop must fail on the ROOT (not the live grandchild).
#[skuld::test]
fn spawn_tree_panics_when_the_root_dies_after_reporting_before_connecting() {
    // Contained so unwinding kills the orphaned grandchild (it would otherwise outlive the test
    // holding its stdio). The kill is only sent on drop, so wait for the grandchild's exit by
    // identity (never a reissued pid).
    let message = panic_message_of(|| common::spawn_tree("spawn-grandchild-report-then-exit", true));
    assert!(message.contains("died before it connected"), "got: {message:?}");
    let id = common::last_reported_grandchild_id()
        .unwrap_or_else(|| panic!("no grandchild identity; helper panicked with: {message:?}"));
    assert_eq!(
        common::last_reported_grandchild_contained(),
        Some(true),
        "the grandchild must be inside the root's containment when identified, or the drop does not kill it"
    );
    assert_eq!(
        common::last_reported_grandchild_liveness(),
        Some(cosca::identity::Liveness::Alive),
        "the grandchild must be alive when identified, so its exit is the containment kill's"
    );
    cosca::Process::from_id(id)
        .wait()
        .expect("wait for the orphaned grandchild");
    let grandchild = common::last_reported_grandchild().expect("the root reported before it exited");
    assert!(
        !message.contains(&format!("(pid {grandchild})")),
        "the live grandchild must not be the one blamed: {message:?}"
    );
}

/// The root connects to the report address and exits without reporting: the failure names that,
/// not a parse error on an empty line.
#[skuld::test]
fn spawn_tree_panics_when_the_root_dies_before_reporting_the_grandchild_pid() {
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
fn accept_or_die_seam_strict_kills_a_target_that_was_not_opted_in() {
    let (mut child, listener) = seamed_control_block("strict", false);
    let message = panic_message_of(|| common::accept_or_die(&listener, &mut child));
    assert_died_before_connecting(&message, child.id());
}

#[skuld::test]
fn accept_or_die_seam_strict_lets_an_opted_in_target_connect() {
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
fn accept_or_die_seam_die_now_exits_the_target_before_it_connects() {
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

fn main() {
    // Routes to `foreign_kill_helper_main` on the ONE re-exec `foreign_kill_surfaces_permission_
    // denied` performs of this same binary — checked first, so that re-exec never itself becomes
    // a (root-owned, wrongly-uid'd) skuld test run.
    #[cfg(unix)]
    if std::env::var_os(ENV_TARGET_PID).is_some() {
        std::process::exit(foreign_kill_helper_main());
    }
    skuld::run_all();
}
