//! Deadlock-free `communicate`: stdin is fed while stdout and stderr are drained, so no full pipe
//! buffer wedges the child. Unix does it on the calling thread, Windows on one thread per stream.

#[cfg(unix)]
#[path = "pump/poll.rs"]
mod poll;
#[cfg(windows)]
#[path = "pump/threads.rs"]
mod threads;

#[cfg(unix)]
pub(crate) use poll::communicate;
#[cfg(windows)]
pub(crate) use threads::communicate;

#[cfg(all(test, unix))]
#[path = "pump_tests.rs"]
mod pump_tests;
