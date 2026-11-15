//! Tests for [`OwnedChild`](super::OwnedChild): one deterministic test per row of the state
//! table, each with the mutant it turns RED against named in its doc.
//!
//! The macOS tests that wait on a kqueue look at the wait's block from a
//! [`block_probe`](crate::wait::block_probe) hook and assert there.

#[cfg(unix)]
#[path = "owned_tests/drop_reap.rs"]
mod drop_reap;
#[path = "owned_tests/fixtures.rs"]
mod fixtures;
#[cfg(target_os = "linux")]
#[path = "owned_tests/foreign_tracer.rs"]
mod foreign_tracer;
#[cfg(target_os = "linux")]
#[path = "owned_tests/linux.rs"]
mod linux;
#[cfg(target_os = "macos")]
#[path = "owned_tests/macos.rs"]
mod macos;
#[path = "owned_tests/slot.rs"]
mod slot;
#[path = "owned_tests/states.rs"]
mod states;
#[path = "owned_tests/teardown.rs"]
pub(crate) mod teardown;
#[path = "owned_tests/teardown_lines.rs"]
pub(crate) mod teardown_lines;
#[path = "owned_tests/teardown_look.rs"]
mod teardown_look;
#[path = "owned_tests/teardown_policy.rs"]
mod teardown_policy;
#[cfg(target_os = "macos")]
#[path = "owned_tests/traced.rs"]
mod traced;
#[cfg(unix)]
#[path = "owned_tests/tracer.rs"]
mod tracer;
#[path = "owned_tests/unreaped.rs"]
mod unreaped;
#[cfg(feature = "tokio")]
#[path = "owned_tests/wait_async.rs"]
mod wait_async;
#[cfg(windows)]
#[path = "owned_tests/windows.rs"]
mod windows;
