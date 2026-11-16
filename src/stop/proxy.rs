//! The console-event proxy: a role of the host program (`cosca::init()`) or of the
//! `cosca-ctrl-proxy` executable. It attaches to a child's console, sends Ctrl+C or Ctrl+Break to
//! that whole console, and answers by exit code.
//!
//! [`protocol`] is the argv a caller starts it with and the exit codes it answers with; [`run`] is
//! its own sequence.

pub(crate) mod protocol;
#[cfg(windows)]
pub(crate) mod run;
