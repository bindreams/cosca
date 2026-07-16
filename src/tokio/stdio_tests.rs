//! Unit tests for the Windows overlapped merge-target pipe (the fns are pub(crate)).
#![cfg(windows)]

use tokio::io::AsyncReadExt;

// The full Out-direction production shape: pair -> (connect via connect_task's underlying
// await) -> a REAL child writes on the client end -> the server end reads to EOF. Pins the
// connect-mandatory contract: without the connect, this read never completes.
#[tokio::test]
async fn overlapped_pipe_reads_a_real_childs_output() {
    let (server, client) = super::overlapped_out_pipe().expect("pipe pair");
    // The production seam: connect_task genuinely awaits the mandatory connect (immediate
    // here — the client is already open).
    let mut server = super::connect_task(server).await.expect("join").expect("connect");
    let mut child = std::process::Command::new("cmd")
        .args(["/C", "echo overlapped-e2e"])
        .stdout(std::process::Stdio::from(client))
        .spawn()
        .expect("spawn writer child");
    let mut buf = Vec::new();
    server.read_to_end(&mut buf).await.expect("read to EOF");
    child.wait().expect("reap");
    assert_eq!(String::from_utf8_lossy(&buf).trim(), "overlapped-e2e");
}

// The In-direction production shape: the parent writes through the outbound server; the
// client end is a real child's stdin (findstr "^" echoes every line). Dropping the server
// delivers the buffered payload THEN clean EOF — the fact ChildStdin's drop contract rests
// on. The child's stdout is read via spawn_blocking so the runtime keeps ticking (the
// server teardown is processed via the runtime).
#[tokio::test]
async fn overlapped_in_pipe_feeds_a_real_childs_input() {
    use tokio::io::AsyncWriteExt;
    let (server, client) = super::overlapped_in_pipe().expect("pipe pair");
    let mut server = super::connect_task(server).await.expect("join").expect("connect");
    let mut child = std::process::Command::new("findstr")
        .arg("^")
        .stdin(std::process::Stdio::from(client))
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn reader child");
    server.write_all(b"in-e2e\r\n").await.expect("write");
    drop(server); // buffered data first, then EOF (never disconnect(): it discards)
    let mut stdout = child.stdout.take().expect("piped stdout");
    let out = tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let mut s = String::new();
        stdout.read_to_string(&mut s).expect("read child stdout");
        s
    })
    .await
    .expect("join");
    child.wait().expect("reap");
    assert_eq!(out.trim(), "in-e2e");
}

// A squatted name must ERROR (never attach to the stranger's pipe) in BOTH orientations:
// first_pipe_instance makes the second create fail PermissionDenied.
#[tokio::test]
async fn overlapped_pipe_never_attaches_to_a_squatted_name() {
    let name = format!(r"\\.\pipe\subprocess-test-squat.{}", std::process::id());
    let _squatter = tokio::net::windows::named_pipe::ServerOptions::new()
        .first_pipe_instance(true)
        .create(&name)
        .expect("squat the name");
    for parent_writes in [false, true] {
        let err = super::overlapped_pipe_named(&name, parent_writes).expect_err("must not attach");
        assert!(
            matches!(&err, crate::error::Error::Io(e) if e.kind() == std::io::ErrorKind::PermissionDenied),
            "squatted name must surface PermissionDenied (parent_writes={parent_writes}), got {err:?}"
        );
    }
}

// max_instances(1) slot exclusivity — the fact that closes the create->open client race —
// asserted through the CRATE'S OWN claim path: after a thief takes the single client slot,
// the production `open_client_slot` must fail typed (never a silent wrong-attach), exactly
// what `overlapped_pipe_named` does when it loses the race.
#[tokio::test]
async fn overlapped_pipe_client_slot_is_exclusive() {
    let name = format!(r"\\.\pipe\subprocess-test-slot.{}", std::process::id());
    // The same instance overlapped_pipe_named creates (Out orientation).
    let _server = tokio::net::windows::named_pipe::ServerOptions::new()
        .access_inbound(true)
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .max_instances(1)
        .create(&name)
        .expect("create");
    let _thief = std::fs::OpenOptions::new()
        .write(true)
        .open(&name)
        .expect("thief takes the slot");
    let err =
        super::open_client_slot(&name, false).expect_err("a stolen slot must fail our claim, never silently attach");
    // ERROR_PIPE_BUSY (231) has no stable ErrorKind mapping — assert the raw code (verified).
    assert!(
        matches!(&err, crate::error::Error::Io(e) if e.raw_os_error() == Some(231)),
        "ERROR_PIPE_BUSY through the production claim path, got {err:?}"
    );
}

// Poll-after-error, the connect-`Err` arm: a wrapper whose connect task resolved `Err` must
// yield `Err` on EVERY poll — the state machine must park in a terminal state rather than
// re-poll the completed `JoinHandle` (tokio panics on that: "polled after completion").
// Reachable through the public wrappers (a caller legally retries after `Err`; communicate's
// write path swallows a BrokenPipe from write_all and then flushes). Event-driven: the first
// read completes exactly when the doomed task's result lands — no timing.
#[tokio::test]
async fn owned_read_poll_after_connect_error_is_err_not_panic() {
    let handle: tokio::task::JoinHandle<std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer>> =
        tokio::spawn(async { Err(std::io::Error::other("doomed connect")) });
    let mut r = super::WinOwnedRead(super::ConnectingPipe::Connecting(handle));
    let mut buf = [0u8; 4];
    let first = tokio::io::AsyncReadExt::read(&mut r, &mut buf).await;
    assert!(first.is_err(), "the failed connect must surface as Err, got {first:?}");
    let second = tokio::io::AsyncReadExt::read(&mut r, &mut buf).await;
    assert!(
        second.is_err(),
        "a later poll must yield Err again (never a panic), got {second:?}"
    );
}

// Poll-after-error, the JoinError arm (a panicked connect task), through the WRITE wrapper:
// same terminal-state contract — the error repeats, the completed handle is never re-polled.
#[tokio::test]
async fn owned_write_poll_after_join_error_is_err_not_panic() {
    let handle: tokio::task::JoinHandle<std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer>> =
        tokio::spawn(async { panic!("doomed connect task") });
    let mut w = super::WinOwnedWrite(super::ConnectingPipe::Connecting(handle));
    let first = tokio::io::AsyncWriteExt::write(&mut w, b"x").await;
    assert!(
        first.is_err(),
        "the panicked connect task must surface as Err, got {first:?}"
    );
    let second = tokio::io::AsyncWriteExt::write(&mut w, b"x").await;
    assert!(
        second.is_err(),
        "a later poll must yield Err again (never a panic), got {second:?}"
    );
}

// The OTHER connect world: armed with NO client, connect is genuinely Pending (asserted,
// not assumed), and a late client open completes it via a reactor wakeup. Together with
// the two E2E tests above (client-already-open => immediate), BOTH connect worlds are
// pinned — no timing assumption.
#[tokio::test]
async fn overlapped_pipe_connect_pending_completes_on_late_client_open() {
    use std::future::Future;
    use std::io::Write;
    let name = format!(r"\\.\pipe\subprocess-test-pending.{}", std::process::id());
    let mut server = tokio::net::windows::named_pipe::ServerOptions::new()
        .access_inbound(true)
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .max_instances(1)
        .create(&name)
        .expect("create");
    {
        let mut connect = std::pin::pin!(server.connect());
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(
            connect.as_mut().poll(&mut cx).is_pending(),
            "no client exists yet — ConnectNamedPipe must be genuinely pending"
        );
        let mut client = std::fs::OpenOptions::new()
            .write(true)
            .open(&name)
            .expect("late client");
        connect
            .as_mut()
            .await
            .expect("connect completes via the reactor wakeup");
        client.write_all(b"pending-path").expect("client write");
    } // client dropped => EOF
    let mut buf = Vec::new();
    server.read_to_end(&mut buf).await.expect("read to EOF");
    assert_eq!(buf, b"pending-path");
}
