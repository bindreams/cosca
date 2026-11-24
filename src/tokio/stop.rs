//! The async counterparts of [`cosca::stop`](crate::stop): what [`tokio::Child::terminate`], its
//! `graceful_shutdown` and the two tree calls run before they wait, as an action the caller chooses
//! ([`tokio::Command::graceful_stop`](crate::tokio::Command::graceful_stop)) and the functions it is
//! composed of.
//!
//! An action is an async function of a [`StopTarget`], the same type the sync actions take. Each prepared
//! function here is the sync one of the same name over the same target, with its waits awaited: no
//! runtime thread blocks and no wait for a process uses the blocking pool. That holds for these
//! functions, not for an action that also calls the blocking ones of [`cosca::stop`](crate::stop) over
//! the same target. A prepared function that sends and does not wait (`send_signal`,
//! `send_ctrl_break_to_group`) is the sync function made `async`, so an action composes it as it
//! composes the others. So is `send_wm_close`, whose awaits are only looks at the root.
//!
//! [`tokio::Child::terminate`]: crate::tokio::Child::terminate

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::error::Error;
use crate::stop::{ClockKind, Deadline, StopTarget, StopWaits};

/// What an async stop action returns: a boxed future of the action's answer that borrows its
/// [`StopTarget`] and is `Send`, so the call that runs it can be spawned. Box an `async` block that
/// awaits the prepared functions of this module:
///
/// ```no_run
/// # #[cfg(unix)] fn demo() {
/// use cosca::tokio::{stop, Command};
/// use cosca::Signal;
///
/// let mut command = Command::new();
/// command.arg("my-service");
/// command.graceful_stop(|target| Box::pin(async move { stop::send_signal(target, Signal::Int).await }));
/// # }
/// ```
pub type StopFuture<'a> = Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'a>>;

/// The async driver of the waits a stop makes (the proxy's spawn uses the blocking pool, as every async
/// spawn does).
pub(crate) struct AsyncDriver<'a>(pub(crate) &'a crate::Child);

impl StopWaits for AsyncDriver<'_> {
    async fn root_exited(&self, within: Duration) -> Result<bool, Error> {
        crate::tokio::drive::exited_held(self.0.proc.os_process(), Some(within)).await
    }

    async fn root_exited_by(&self, by: Deadline) -> Result<bool, Error> {
        crate::tokio::drive::exited_until(self.0.proc.os_process(), by.at_on(ClockKind::ASYNC_PROCESS_WAIT)).await
    }

    #[cfg(windows)]
    type Proxy = crate::tokio::Child;

    #[cfg(windows)]
    async fn start_proxy(
        &self,
        exe: &std::path::Path,
        args: &crate::stop::proxy::protocol::ProxyArgs,
    ) -> Result<(u32, crate::tokio::Child), Error> {
        let mut command = crate::tokio::Command::new();
        crate::stop::proxy::configure_start(command.as_sync_mut(), exe, args)?;
        let proxy = command.spawn().await?;
        Ok((proxy.pid(), proxy))
    }

    #[cfg(windows)]
    async fn wait_proxy(
        &self,
        proxy: &mut crate::tokio::Child,
        after: Duration,
        late: impl FnOnce(Duration) + Send,
        deadline: Option<std::time::Instant>,
    ) -> Result<Option<std::process::ExitStatus>, Error> {
        proxy.wait_saying(after, late, deadline).await
    }
}

/// The stop a child does when its command set none. As [`stop::default`](crate::stop::default), with the
/// proxy's wait awaited on Windows; an async action calls this one, not the sync one.
///
/// # Panics
///
/// On Windows: see [`stop::default`](crate::stop::default#panics).
pub async fn default(target: &StopTarget<'_>) -> Result<(), Error> {
    #[cfg(unix)]
    return crate::stop::default(target);
    #[cfg(windows)]
    return crate::stop::default_with(&AsyncDriver(target.child()), target).await;
}

/// Unix: sends `signal`, and does not wait. As [`stop::send_signal`](crate::stop::send_signal), with the
/// same rules, on a root target and on a tree target.
#[cfg(unix)]
pub async fn send_signal(target: &StopTarget<'_>, signal: crate::Signal) -> Result<(), Error> {
    crate::stop::send_signal(target, signal)
}

/// Windows: sends `CTRL_BREAK` to the child's console process group from this process, and does not wait.
/// As [`stop::send_ctrl_break_to_group`](crate::stop::send_ctrl_break_to_group).
#[cfg(windows)]
pub async fn send_ctrl_break_to_group(target: &StopTarget<'_>) -> Result<(), Error> {
    crate::stop::send_ctrl_break_to_group(target)
}

/// Windows: sends `event` to the console of the child, from a process of its own. As
/// [`stop::send_console_event_via_proxy`](crate::stop::send_console_event_via_proxy), with the wait for the
/// proxy awaited: no runtime thread blocks, and the wait has no cap unless the call that runs it was given a
/// timeout ([`Child::terminate_timeout`](crate::tokio::Child::terminate_timeout),
/// [`Child::graceful_shutdown_timeout`](crate::tokio::Child::graceful_shutdown_timeout) or their tree forms).
///
/// The proxy is started with [`tokio::Command`](crate::tokio::Command), on the blocking pool as every async
/// spawn is, and the wait for its exit is registered with the OS.
///
/// After a dropped call, whether the event was sent is unknown. A proxy that had started is ended: by the
/// drop, which kills and reaps it before returning, when the call already held it; by the start, when it
/// completes on the pool, if the drop came during the start (the proxy has run since it was created, so it
/// may have attached and sent before it was ended).
///
/// # Panics
///
/// On Windows: see
/// [`stop::send_console_event_via_proxy`](crate::stop::send_console_event_via_proxy#panics).
#[cfg(windows)]
pub async fn send_console_event_via_proxy(target: &StopTarget<'_>, event: crate::CtrlEvent) -> Result<(), Error> {
    crate::stop::proxy::send(&AsyncDriver(target.child()), target, event).await
}

/// Windows: asks the child's windows to close, and does not wait. As
/// [`stop::send_wm_close`](crate::stop::send_wm_close), with the look at the root awaited: the windows are
/// listed and posted to on the calling thread, which is bounded work that waits for no process.
#[cfg(windows)]
pub async fn send_wm_close(target: &StopTarget<'_>) -> Result<(), Error> {
    crate::stop::send_wm_close_with(&AsyncDriver(target.child()), target).await
}

/// Waits up to `grace` for the child's root to exit, and whether it did, through the child's handle. As
/// [`StopTarget::wait_exit`], awaited: the wait reaps nothing, and the same for a root and a tree target.
///
/// # Runtime
///
/// On Unix, a non-zero `grace` arms a timer and registers the child with the reactor: it needs a runtime
/// with the IO **and** time drivers enabled (the `#[tokio::main]` / `#[tokio::test]` defaults), and on a
/// hand-built runtime missing either, tokio panics rather than returning a typed error. On Windows the
/// wait holds no thread and needs neither driver.
pub async fn wait_exit(target: &StopTarget<'_>, grace: Duration) -> Result<bool, Error> {
    crate::stop::wait_exit_with(&AsyncDriver(target.child()), target, grace).await
}

#[cfg(test)]
#[path = "stop_tests.rs"]
mod stop_tests;

#[cfg(all(test, windows))]
#[path = "stop_real_tests.rs"]
mod stop_real_tests;
