//! macOS child reaping for [`crate::wait`]: `exit_events` registers and reads the kqueue a child's
//! exit wait blocks on, and `tracer_watch` follows its tracers. The kqueue primitives they arm and
//! block on are [`crate::os_process::macos::kqueue`].

#[path = "macos/exit_events.rs"]
mod exit_events;
#[path = "macos/tracer_watch.rs"]
mod tracer_watch;
#[cfg(test)]
pub(crate) use exit_events::reap_registration;
pub(crate) use exit_events::{drain_exit_events, register_exit_events};
#[cfg(test)]
pub(crate) use tracer_watch::seams as tracer_seams;
pub(crate) use tracer_watch::{OnTracer, TracerWatch};
