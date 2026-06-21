//! `subprocess`: unified cross-platform subprocess management.
//!
//! Under construction. The first landed layer is the pure core: the error
//! taxonomy, argv quoting, and the command input model. Modules are added by
//! the foundation plan task-by-task.

pub mod error;
pub mod identity;
pub mod quote;
pub mod stdio;
pub use stdio::{Fd, Stdio};

mod child;
pub use child::Child;

mod command;
pub use command::Command;

pub use std::process::ExitStatus;

/// Captured result of a finished process.
#[derive(Debug)]
pub struct Output {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Start building a command from an argument vector.
pub fn run<I, S>(args: I) -> Command
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString>,
{
    let mut c = Command::new();
    c.args(args);
    c
}

/// Start building a command from a single command-line string.
pub fn run_line(line: impl Into<std::ffi::OsString>) -> Command {
    let mut c = Command::new();
    c.commandline(line);
    c
}
