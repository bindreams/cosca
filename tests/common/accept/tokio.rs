//! The async death-watched accept: the same contract as the sync one (see the `accept` module
//! doc), built on the exit watches cosca itself implements rather than per-platform plumbing.

use std::net::TcpStream;

use cosca::identity::ProcessId;

use super::{ack_now, died_before_connecting};

/// [`accept_or_die_async_also`] watching only `child`.
pub async fn accept_or_die_async(listener: &::tokio::net::TcpListener, child: &mut cosca::tokio::Child) -> TcpStream {
    accept_or_die_async_also(listener, child, None).await
}

/// Async sibling of [`accept_or_die_also`](super::accept_or_die_also): a biased `tokio::select!`
/// between accepting and the SAME exit watches cosca itself implements
/// (`cosca::tokio::Child::wait`, `cosca::tokio::Process::wait`). An exit arm firing is a
/// failure, not a prompt to look again: an opted-in target cannot exit with its connection
/// unacked, so no queue inspection decides the verdict. The accept arm is first so that when
/// both are ready the connection wins, which is only ever reachable for a target that broke the
/// handshake. A target that had already exited before the call is dead without any wait.
pub async fn accept_or_die_async_also(
    listener: &::tokio::net::TcpListener,
    child: &mut cosca::tokio::Child,
    also: Option<ProcessId>,
) -> TcpStream {
    let target_pid = child.id().pid();
    // As in the sync path: a target that has already exited is dead, decided before any wait so
    // that no reactor-readiness ordering between the accept arm and the exit arm can matter.
    #[cfg(unix)]
    let exited = super::has_exited_unreaped(child.id());
    #[cfg(windows)]
    let exited = child
        .try_wait()
        .expect("try_wait the control target before watching it")
        .is_some();
    if exited {
        died_before_connecting(target_pid);
    }
    #[cfg(unix)]
    let target = cosca::tokio::Process::from_id(child.id());
    #[cfg(unix)]
    let target_exit = target.wait();
    #[cfg(windows)]
    let target_exit = async { child.wait().await.map(drop) };
    let also_exit = async {
        let Some(id) = also else {
            return std::future::pending().await;
        };
        // Identity-verified: a reissued pid resolves to a different identity and is Gone.
        if let Err(e) = cosca::tokio::Process::from_id(id).wait().await {
            panic!("watching pid {}'s exit while waiting for a connection: {e}", id.pid());
        }
        id.pid()
    };
    ::tokio::select! {
        biased;
        accepted = listener.accept() => {
            let (stream, _) = accepted.expect("accept a control connection");
            ack_now(blocking_std(stream.into_std().expect("convert the accepted tokio stream to std")))
        }
        status = target_exit => match status {
            Ok(()) => died_before_connecting(target_pid),
            // An error watching the exit is reported as exactly that, never folded into "died",
            // which would misattribute a wait-mechanism failure to the target.
            Err(e) => panic!("watching the control target's exit while waiting for a connection: {e}"),
        },
        pid = also_exit => died_before_connecting(pid),
    }
}

/// `into_std` does NOT reset blocking mode (it rewraps the same fd/socket, which tokio keeps
/// non-blocking), and every caller does ordinary BLOCKING std reads and writes on the result.
pub(crate) fn blocking_std(stream: TcpStream) -> TcpStream {
    stream
        .set_nonblocking(false)
        .expect("restore the accepted stream to blocking mode");
    stream
}
