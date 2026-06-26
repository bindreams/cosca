//! Foreign `Process` integration tests. A child we spawn (and own) is treated as
//! a foreign process via its `ProcessId`; death/liveness is proven only by a real
//! exit event (control-socket EOF or the kernel exit edge), never by sleep/poll.

use std::io::{Read, Write};
use std::time::Duration;

#[path = "common/mod.rs"]
mod common;
use common::spawn_blocker;

#[test]
fn foreign_wait_returns_when_the_process_exits() {
    let (child, mut sock) = spawn_blocker();
    let p = subprocess::Process::from_pid(child.id().pid()).expect("foreign process resolves");
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

#[test]
fn foreign_wait_timeout_times_out_on_a_live_process() {
    // The blocker is structurally wedged on its never-written socket, so it cannot
    // exit; wait_timeout returns Ok(false) regardless of the (short) duration.
    let (child, _sock) = spawn_blocker();
    let p = subprocess::Process::from_pid(child.id().pid()).expect("resolves");
    let exited = p.wait_timeout(Duration::from_millis(200)).expect("wait_timeout");
    assert!(
        !exited,
        "a wedged process must time out to Ok(false), got exited={exited}"
    );
    child.kill().expect("kill cleanup");
    let _ = child.wait();
}

#[test]
fn foreign_wait_timeout_observes_an_exit() {
    let (child, mut sock) = spawn_blocker();
    let p = subprocess::Process::from_pid(child.id().pid()).expect("resolves");
    sock.write_all(b"x").expect("trigger child exit");
    assert!(p.wait_timeout(Duration::from_secs(30)).expect("wait_timeout"));
    let _ = child.wait();
}

#[test]
fn foreign_wait_timeout_zero_returns_immediately_on_a_live_process() {
    // ZERO is the poll-once edge in each backend; a wedged child must yield Ok(false).
    let (child, _sock) = spawn_blocker();
    let p = subprocess::Process::from_pid(child.id().pid()).expect("resolves");
    assert!(!p.wait_timeout(Duration::ZERO).expect("wait_timeout"));
    child.kill().expect("kill cleanup");
    let _ = child.wait();
}

#[test]
fn foreign_wait_timeout_huge_duration_does_not_panic() {
    // Duration::MAX overflows Instant + Duration; the saturating deadline must make
    // it unbounded, not panic. Trigger the exit first so the wait completes.
    let (child, mut sock) = spawn_blocker();
    let p = subprocess::Process::from_pid(child.id().pid()).expect("resolves");
    sock.write_all(b"x").expect("trigger child exit");
    assert!(p.wait_timeout(Duration::MAX).expect("wait_timeout"));
    let _ = child.wait();
}

#[test]
fn current_and_from_id_round_trip() {
    let me = subprocess::Process::current();
    assert!(me.is_alive());
    assert_eq!(subprocess::Process::from_id(me.id()).map(|p| p.id()), Some(me.id()));
}

#[test]
fn from_pid_resolves_a_live_foreign_child_then_reports_it_dead() {
    // from_pid resolves a live foreign child to its true identity; after the child is
    // killed+reaped, that resolved Process reports !is_alive (the synchronously-correct
    // liveness check, distinct from the zombie-inclusive exists()). Death is proven by the
    // reap, never by sleep.
    let (child, _sock) = spawn_blocker();
    let p = subprocess::Process::from_pid(child.id().pid()).expect("live foreign child resolves");
    assert_eq!(p.id(), child.id());
    assert!(p.is_alive(), "a freshly spawned foreign child is alive");
    child.kill().expect("kill");
    child.wait().expect("reap"); // synchronously confirm exit before the liveness assertion
    assert!(!p.is_alive(), "a killed+reaped foreign process must report not-alive");
}

#[test]
fn parent_and_children_resolve_the_spawned_tree() {
    let (child, mut sock) = spawn_blocker();
    let me = subprocess::Process::current();
    let kid = subprocess::Process::from_pid(child.id().pid()).expect("child resolves");

    assert_eq!(kid.parent().expect("child has a parent").id(), me.id());
    assert!(me
        .children(subprocess::Recursive::No)
        .iter()
        .any(|p| p.id() == kid.id()));
    assert!(me
        .children(subprocess::Recursive::Yes)
        .iter()
        .any(|p| p.id() == kid.id()));

    sock.write_all(b"x").expect("release child");
    let _ = child.wait();
}

#[test]
fn children_recursive_distinguishes_direct_from_descendant() {
    use std::net::TcpListener;
    // spawn-grandchild: the child connects (tag "R") and spawns a control-block grandchild
    // (tag "G"). Accepting BOTH proves the 2-level tree is alive; we learn the grandchild's
    // identity via kid.children(No), then assert it is in me.children(Yes) but NOT No — the
    // one-level-vs-recursive distinction a No<->Yes arm swap would otherwise pass silently.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let mut cmd = subprocess::Command::new();
    cmd.executable(common::testbin())
        .args(["subprocess_testbin", "spawn-grandchild", &addr]);
    let child = cmd.spawn().expect("spawn tree");
    let mut socks = Vec::new();
    for _ in 0..2 {
        let (mut s, _) = listener.accept().expect("accept");
        let mut tag = [0u8; 1];
        s.read_exact(&mut tag).expect("read tag");
        socks.push(s);
    }
    let me = subprocess::Process::current();
    let kid = subprocess::Process::from_pid(child.id().pid()).expect("child resolves");
    // The grandchild is kid's only direct child — use it to learn the grandchild's identity.
    let grandkids = kid.children(subprocess::Recursive::No);
    assert_eq!(
        grandkids.len(),
        1,
        "the spawn-grandchild child has exactly one direct child"
    );
    let grandkid = grandkids[0];

    let direct = me.children(subprocess::Recursive::No);
    assert!(
        direct.iter().any(|p| p.id() == kid.id()),
        "Recursive::No must include the direct child"
    );
    assert!(
        !direct.iter().any(|p| p.id() == grandkid.id()),
        "Recursive::No must EXCLUDE the grandchild"
    );
    let all = me.children(subprocess::Recursive::Yes);
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
}

#[test]
fn foreign_kill_terminates_the_process() {
    let (child, mut sock) = spawn_blocker();
    let p = subprocess::Process::from_pid(child.id().pid()).expect("resolves");
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

// Linux-only: pid 1 (init) is world-resolvable (`/proc/1`) AND non-root-unkillable there.
// On macOS, launchd (pid 1) is NOT `proc_pidinfo`-resolvable by a non-root process, and there
// is no portable resolvable-but-unkillable target — the macOS `wait::kill` EPERM->Err mapping
// is the same reviewed code, and its success path is covered by `foreign_kill_terminates`.
#[cfg(target_os = "linux")]
#[test]
fn foreign_kill_surfaces_permission_denied() {
    // pid 1 (init) is always alive but unkillable: SIGKILL to it is kernel-ignored. As a
    // non-root user kill(1) returns EPERM, which Process::kill must SURFACE as Err (not
    // swallow into Ok); as root the kernel returns Ok (init is immune). Assert the real
    // per-privilege behavior either way — init is unharmed. This drives the Err arm of
    // wait::kill that distinguishes "denied on a live process" from "already-dead".
    let init = subprocess::Process::from_pid(1).expect("pid 1 resolves");
    assert!(init.is_alive(), "init must be alive");
    let r = init.kill();
    // SAFETY: geteuid() takes no arguments and is always safe.
    if unsafe { libc::geteuid() } == 0 {
        assert!(r.is_ok(), "as root, SIGKILL to init is kernel-ignored => Ok, got {r:?}");
    } else {
        assert!(
            matches!(r, Err(subprocess::error::Error::Io(_))),
            "non-root kill of init must surface EPERM as Err, got {r:?}"
        );
    }
    assert!(
        init.is_alive(),
        "init must survive (SIGKILL to pid 1 is kernel-ignored)"
    );
}

#[cfg(unix)]
#[test]
fn is_alive_is_false_for_a_real_zombie() {
    // The deferred Plan-2 test. Spawn a RAW std child (std does NOT reap on drop), take it
    // foreign, death-watch it to its exit, then — before reaping — assert is_alive()==false
    // (zombie) while the identity still resolves (exists). The kernel exit edge is the sync
    // point; no sleep. Finally reap to avoid a leak.
    use std::io::Read;
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    // RAW std::process::Command: argv[0] is the exe path, so the testbin mode is args[1] —
    // do NOT prepend "subprocess_testbin" the way the crate's Command requires.
    let mut raw = std::process::Command::new(common::testbin())
        .args(["control-block", &addr, "Z"])
        .spawn()
        .expect("spawn raw child");
    let (mut sock, _) = listener.accept().expect("accept");
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("read tag");

    let p = subprocess::Process::from_pid(raw.id()).expect("raw child resolves");
    sock.write_all(b"x").expect("trigger exit");
    p.wait().expect("death-watch"); // returns at the zombie instant (no reap yet)

    assert!(!p.is_alive(), "an exited-but-unreaped child is a zombie => not alive");
    // Linux keeps a zombie resolvable (`/proc` persists → exists() is zombie-inclusive). macOS
    // `proc_pidinfo` does NOT return for a zombie, so its identity stops resolving the instant
    // it exits — assert the still-resolves property only where it holds.
    #[cfg(target_os = "linux")]
    assert!(
        subprocess::Process::from_id(p.id()).is_some(),
        "a zombie identity still resolves on Linux"
    );
    raw.wait().expect("reap the zombie");
}
