//! macOS child reaping for [`crate::wait`]: `await_reapable` waits for a child to become reapable
//! and `tracer_watch` follows its tracers. The kqueue primitives they arm and block on are
//! [`crate::os_process::macos::kqueue`].

#[path = "macos/await_reapable.rs"]
mod await_reapable;
#[path = "macos/tracer_watch.rs"]
mod tracer_watch;
#[cfg(test)]
pub(crate) use await_reapable::await_reapable_on;
#[cfg(feature = "tokio")]
pub(crate) use await_reapable::{
    arm_backoff_timer, drain_exit_events, register_exit_events, BACKOFF_CAP, BACKOFF_START,
};
pub(crate) use await_reapable::{await_reapable, Waited};
#[cfg(test)]
pub(crate) use tracer_watch::seams as tracer_seams;
#[cfg(feature = "tokio")]
pub(crate) use tracer_watch::WalkError;
pub(crate) use tracer_watch::{OnTracer, TracerWatch};

#[cfg(test)]
#[path = "macos_tests.rs"]
mod macos_tests;
