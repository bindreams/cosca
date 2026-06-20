//! The `Command` builder. This plan implements only the input surface
//! (executable / args / commandline); stdio, env, containment, and spawning
//! are added by later plans.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// A process to be configured and (later) spawned.
#[derive(Debug, Clone, Default)]
pub struct Command {
    // Read syntactically by input()/executable_path(), so the fields themselves
    // are not flagged; the accessors (consumed only by the next plan) carry the
    // allow below.
    input: CommandInput,
    executable: Option<PathBuf>,
}

/// The argument source of truth. `Argv` and `CommandLine` are mutually
/// exclusive — the last one set wins.
// The CommandLine field is read by tests and the resolution plan, not the lib target yet.
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub(crate) enum CommandInput {
    #[default]
    Empty,
    Argv(Vec<OsString>),
    CommandLine(OsString),
}

impl Command {
    /// A fresh command with no arguments. argv is not special: set it via
    /// [`Command::args`]/[`Command::arg`] or [`Command::commandline`].
    pub fn new() -> Command {
        Command::default()
    }

    /// Append one argument, switching to argv mode if a command line was set.
    pub fn arg<S: Into<OsString>>(&mut self, a: S) -> &mut Command {
        match &mut self.input {
            CommandInput::Argv(v) => v.push(a.into()),
            _ => self.input = CommandInput::Argv(vec![a.into()]),
        }
        self
    }

    /// Append several arguments, switching to argv mode if a command line was set.
    pub fn args<I, S>(&mut self, args: I) -> &mut Command
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let items = args.into_iter().map(Into::into);
        match &mut self.input {
            CommandInput::Argv(v) => v.extend(items),
            _ => self.input = CommandInput::Argv(items.collect()),
        }
        self
    }

    /// Set the argument source to a single command-line string (Windows-native
    /// form). Discards any previously set argv.
    pub fn commandline<S: Into<OsString>>(&mut self, line: S) -> &mut Command {
        self.input = CommandInput::CommandLine(line.into());
        self
    }

    /// Override the executable file that the OS loads, independently of argv[0]
    /// (e.g. load `/bin/busybox` while argv[0] is `sh`).
    pub fn executable<P: Into<PathBuf>>(&mut self, path: P) -> &mut Command {
        self.executable = Some(path.into());
        self
    }

    // Consumed by the resolution plan; unused by the lib target in this plan.
    #[allow(dead_code)]
    pub(crate) fn input(&self) -> &CommandInput {
        &self.input
    }

    #[allow(dead_code)]
    pub(crate) fn executable_path(&self) -> Option<&Path> {
        self.executable.as_deref()
    }
}

#[cfg(test)]
#[path = "command_tests.rs"]
mod command_tests;
