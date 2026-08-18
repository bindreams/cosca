// `wait_and_reap` is the half of the teardown primitive that a caller which has ALREADY killed
// uses. Its whole point is that it issues no kill of its own, so its wait rests on the caller's
// kill instead of on a second one that can be refused.
//
// The fixture is the oracle. `test_child::fixture_registers_then_blocks` tags the rendezvous
// socket (proving it is live and executing its own code — no timer, no poll), blocks on a 1-byte
// read of that socket, and on receiving the byte exits 0 of its own accord. Exit code 0 is
// unreachable through a kill: `TerminateProcess(_, 1)` reports 1 and `SIGKILL` reports no code at
// all. So the status this test reads distinguishes "waited for the child's own exit" from "killed
// it and waited for that", which is exactly the difference between this function and `reap_now`.
//
// Runs on every target: the elevated-spawn cleanup path that needs the wait-only entry is
// `#[cfg(unix)]`, but the primitive and its Windows arm are not, and a kill re-added on either
// arm fails here.
#[tokio::test]
async fn wait_and_reap_waits_for_the_childs_own_exit_and_never_kills() {
    use std::io::{Read, Write};

    let (listener, addr) = crate::test_child::registration_rendezvous();
    let mut child = {
        // Every cosca-originated spawn takes this lock; a raw tokio spawn here must too, so a
        // macOS fork cannot transiently inherit another test's fd-marker write end.
        let _guard = crate::child::spawn::spawn_lock();
        ::tokio::process::Command::new(std::env::current_exe().expect("current_exe"))
            .args([
                "--test-threads=1",
                "--exact",
                crate::test_child::FIXTURE_REGISTERS_THEN_BLOCKS_TEST,
            ])
            .env(crate::test_child::FIXTURE_REGISTERS_THEN_BLOCKS_ADDR_ENV, &addr)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn the rendezvous fixture")
    };
    let pid = child.id().expect("tokio owns an un-reaped child");

    let (mut sock, _) = listener.accept().expect("accept the fixture's rendezvous connection");
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("read the fixture's readiness tag");

    // Release the fixture: its blocking read returns and it exits 0 on its own.
    sock.write_all(b"g").expect("release the fixture");
    sock.flush().expect("flush the release byte");

    super::wait_and_reap(&mut child, pid, true);

    // No poll loop and no retry: `try_wait` is called exactly once, immediately. It can only
    // report an exit if `wait_and_reap` already blocked until the child had one.
    let status = child
        .try_wait()
        .expect("try_wait")
        .expect("wait_and_reap must return only after the child has exited");
    assert_eq!(
        status.code(),
        Some(0),
        "the fixture must have exited on its own; a kill inside wait_and_reap would report the \
         forced code instead ({status:?})"
    );
}
