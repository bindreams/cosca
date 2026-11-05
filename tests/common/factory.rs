//! The one place an integration test builds a `cosca::Command`.
//!
//! On Windows a [`Console::Hidden`] command asks for `no_window()`, so a test run from a process
//! with no console opens no window; a test that signals the child's console group or measures
//! console membership passes [`Console::Asked`]. Off Windows both are a plain `Command::new()`.
//! The library's unit tests have the same pair in `crate::test_child`.

use super::console_flags::Console;

/// A new `cosca::Command` for a test child on `console`.
pub fn command(console: Console) -> cosca::Command {
    let mut cmd = cosca::Command::new();
    if console.hides_window() {
        cmd.no_window();
    }
    cmd
}

/// [`command`] for the async `Command`.
#[cfg(feature = "tokio")]
pub fn tokio_command(console: Console) -> cosca::tokio::Command {
    let mut cmd = cosca::tokio::Command::new();
    if console.hides_window() {
        cmd.no_window();
    }
    cmd
}
