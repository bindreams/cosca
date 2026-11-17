//! The waits a stop makes, over which the prepared functions' bodies are written once
//! ([`Waits`](crate::child::graceful::shutdown::Waits) extends it with the waits of the shutdown calls).

use std::time::Duration;

use crate::error::Error;

/// The waits [`StopTarget::wait_exit`](super::StopTarget::wait_exit) and the console-event proxy's
/// caller side make. A driver blocks ([`BlockingDriver`](crate::child::graceful::shutdown::BlockingDriver)) or
/// awaits (`AsyncDriver`, with the `tokio` feature); each is made from the child alone, so a prepared
/// function can build one from the [`StopTarget`](super::StopTarget) it is given.
pub(crate) trait StopWaits {
    /// Whether the root has exited within `within`, looked at through its handle. Non-reaping, so its
    /// pid stays pinned. `Duration::ZERO` is one look.
    async fn root_exited(&self, within: Duration) -> Result<bool, Error>;

    /// Windows: the proxy's handle as this driver starts it: the sync `Child`, or the async one. Dropping
    /// it kills and reaps the proxy, so a call that ends or is dropped while it holds one ends the proxy.
    #[cfg(windows)]
    type Proxy;

    /// Windows: starts `exe` as the console-event proxy for `args`; the proxy's pid and handle.
    #[cfg(windows)]
    async fn start_proxy(
        &self,
        exe: &std::path::Path,
        args: &super::proxy::protocol::ProxyArgs,
    ) -> Result<(u32, Self::Proxy), Error>;

    /// Windows: waits, with no cap, for `proxy` to end and reaps it, and calls `late` once with `after`
    /// if it has not ended by then. A failed wait is the error, whichever driver made it.
    #[cfg(windows)]
    async fn wait_proxy(
        &self,
        proxy: &mut Self::Proxy,
        after: Duration,
        late: impl FnOnce(Duration) + Send,
    ) -> Result<std::process::ExitStatus, Error>;
}
