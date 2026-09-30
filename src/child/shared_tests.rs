//! Tests for [`SharedChild`](super::SharedChild): one deterministic test per row of the state
//! table, each with the mutant it turns RED against named in its doc.
//!
//! Every test that `recv()`s or `join()`s on our own code has a nextest override
//! (`.config/nextest.toml`) as the failure bound of a hanging mutant.

#[path = "shared_tests/fixtures.rs"]
mod fixtures;
#[cfg(target_os = "linux")]
#[path = "shared_tests/linux.rs"]
mod linux;
#[cfg(target_os = "macos")]
#[path = "shared_tests/macos.rs"]
mod macos;
#[path = "shared_tests/states.rs"]
mod states;
#[cfg(target_os = "macos")]
#[path = "shared_tests/traced.rs"]
mod traced;
#[cfg(windows)]
#[path = "shared_tests/windows.rs"]
mod windows;
