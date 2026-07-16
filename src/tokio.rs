//! Async (tokio) mirror of the owned-`Child` I/O surface.

#[path = "tokio/child.rs"]
mod child;
#[path = "tokio/command.rs"]
mod command;
#[path = "tokio/process.rs"]
mod process;
#[path = "tokio/pump.rs"]
mod pump;
#[path = "tokio/spawn.rs"]
mod spawn;
#[path = "tokio/stdio.rs"]
mod stdio;
#[path = "tokio/wait.rs"]
pub(crate) mod wait;

pub use child::Child;
pub use command::Command;
pub use process::Process;
pub use stdio::{ChildStderr, ChildStdin, ChildStdout};

/// Start building an async command from an argument vector.
pub fn run<I, S>(args: I) -> Command
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString>,
{
    let mut c = Command::new();
    c.args(args);
    c
}

/// Start building an async command from a single command-line string.
pub fn run_line(line: impl Into<std::ffi::OsString>) -> Command {
    let mut c = Command::new();
    c.commandline(line);
    c
}
