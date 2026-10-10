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
pub(crate) mod program_path;
pub(crate) mod protocol;
#[cfg(target_os = "linux")]
pub(crate) mod run;
pub(crate) mod stderr;
pub(crate) mod step;

#[allow(unused_imports, reason = "nothing outside the tests of this module uses it")]
pub(crate) use choice::ShimChoice;

pub use hooks::{Gate, Inject, ShimTestHooks};

use std::sync::atomic::{AtomicBool, Ordering};

use protocol::ShimArgs;

static INSTALLED: AtomicBool = AtomicBool::new(false);

/// Makes this process able to be the elevation shim. Call it first in `main`, before anything else
/// reads arguments, starts threads or changes signal dispositions.
///
/// When the process was started as the shim (its arguments say so), `init` runs the shim to its end
/// and exits the process; it does not return. Otherwise it returns at once and does nothing else.
///
/// The shim runs on Linux. Other platforms have no shim; `init` reports that and does not start the
/// program (exit 120).
pub fn init() {
    install(None);
}

/// Whether [`init`] has run in this process.
pub fn installed() -> bool {
    INSTALLED.load(Ordering::Relaxed)
}

/// [`init`] with test seams. Not public API.
#[doc(hidden)]
pub fn init_with_test_hooks(hooks: &'static dyn ShimTestHooks) {
    install(Some(hooks));
}

fn install(hooks: Option<&'static dyn ShimTestHooks>) {
    INSTALLED.store(true, Ordering::Relaxed);
    let argv: Vec<_> = std::env::args_os().collect();
    match ShimArgs::parse(&argv) {
        Ok(None) => {}
        Ok(Some(args)) => std::process::exit(run_shim(&args, hooks)),
        Err(e) => {
            stderr::line(format_args!(
                "{e}; the program was not started (exit {})",
                codes::INVOCATION
            ));
            std::process::exit(codes::INVOCATION);
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
    stderr::line(format_args!(
        "this platform has no shim; the program was not started (exit {})",
        codes::INVOCATION
    ));
    codes::INVOCATION
}

#[cfg(test)]
#[path = "shim/init_tests.rs"]
mod init_tests;
