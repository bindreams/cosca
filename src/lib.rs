//! `subprocess`: unified cross-platform subprocess management.
//!
//! Under construction. The first landed layer is the pure core: the error
//! taxonomy, argv quoting, and the command input model. Modules are added by
//! the foundation plan task-by-task.

pub mod error;
pub mod quote;

mod command;
pub use command::Command;
