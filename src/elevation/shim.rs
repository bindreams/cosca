//! The elevation shim: a small cosca-controlled executable that an elevation front runs in place of
//! the elevated program, so that cosca can reach the program through a socket.
//!
//! [`protocol`] is the wire format between the two: the shim's argv, its frames to cosca, and
//! cosca's commands to it. [`private_dir`] is the directory that holds the socket, and [`link`] is
//! cosca's end of the channel.

mod choice;
pub(crate) mod codes;
#[cfg(target_os = "linux")]
pub(crate) mod creds;
#[cfg(test)]
pub(crate) mod fixtures;
pub(crate) mod fork_guard;
pub mod hooks;
pub(crate) mod link;
#[cfg(all(test, target_os = "linux"))]
pub(crate) mod owner_helper;
pub(crate) mod owner_watch;
pub(crate) mod private_dir;
pub(crate) mod protocol;
#[cfg(target_os = "linux")]
pub(crate) mod run;
pub(crate) mod step;

#[allow(unused_imports, reason = "nothing outside the tests of this module uses it")]
pub(crate) use choice::ShimChoice;

pub use hooks::{Gate, Inject, ShimTestHooks};

use std::ffi::OsString;

use protocol::ShimArgs;

/// Plays the shim with `argv` as its data and returns its exit code. [`init_helpers`](crate::init_helpers)
/// calls it when [`HELPER_ENV`](crate::role::HELPER_ENV) names the shim; arguments the shim cannot use are
/// refused with the invocation code, in a line that begins with `started with __COSCA_HELPER=<value>`.
pub(crate) fn play(argv: &[OsString], hooks: Option<&'static dyn ShimTestHooks>) -> i32 {
    match ShimArgs::parse(argv) {
        Ok(args) => run_shim(&args, hooks),
        Err(e) => {
            crate::role::line(
                crate::role::SHIM,
                format_args!(
                    "{}: {}; the program was not started (exit {})",
                    crate::role::started_with(std::ffi::OsStr::new(crate::role::ELEVATION_SHIM)),
                    crate::error::Report(&e),
                    codes::INVOCATION
                ),
            );
            codes::INVOCATION
        }
    }
}

#[cfg(target_os = "linux")]
fn run_shim(args: &ShimArgs, hooks: Option<&'static dyn ShimTestHooks>) -> i32 {
    run::run(args, hooks)
}

/// Other platforms have no shim; it reports that and does not start the program.
#[cfg(not(target_os = "linux"))]
fn run_shim(_: &ShimArgs, _: Option<&'static dyn ShimTestHooks>) -> i32 {
    crate::role::line(
        crate::role::SHIM,
        format_args!(
            "this platform has no shim; the program was not started (exit {})",
            codes::INVOCATION
        ),
    );
    codes::INVOCATION
}
