//! The hook a host program calls first in `main`: [`init`]. It makes the process able to play the
//! two roles cosca starts a copy of the host program for, and tells the host's own code
//! ([`installed`]) that it has.
//!
//! `argv[1]` says which role the process was started in: the elevation shim
//! ([`elevation::shim`](crate::elevation::shim), Unix) or the console-event proxy
//! ([`stop::proxy`](crate::stop::proxy)).

use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::role;
use crate::stop::proxy::protocol::{ProxyAnswer, ProxyArgs};

static INSTALLED: AtomicBool = AtomicBool::new(false);

/// Makes this process able to be the elevation shim and the console-event proxy. Call it first in
/// `main`, before anything else reads arguments, starts threads or changes signal dispositions.
///
/// When the process was started in one of those roles (its arguments say so), `init` plays the role
/// to its end and exits the process; it does not return. Otherwise it returns at once and does
/// nothing else.
///
/// - **The shim** runs on Linux. macOS has no shim: `init` reports that and does not start the
///   program (exit 120).
/// - **The proxy** runs on Windows: it attaches to another process's console, sends it Ctrl+C or
///   Ctrl+Break, and exits with its answer (150 to 160). Other platforms have no proxy: `init`
///   reports that and exits 159.
pub fn init() {
    #[cfg(unix)]
    install(None);
    #[cfg(not(unix))]
    install();
}

/// The whole `main` of the `cosca-ctrl-proxy` executable: [`init`], which plays the proxy when the
/// arguments say so, and otherwise one stderr line and exit with the usage answer. Not public API.
#[doc(hidden)]
pub fn ctrl_proxy_main() -> ! {
    init();
    role::line(
        role::PROXY,
        format_args!("not started by cosca; it takes the arguments cosca gives it and nothing else"),
    );
    std::process::exit(ProxyAnswer::Usage.code())
}

/// Whether [`init`] has run in this process.
pub fn installed() -> bool {
    INSTALLED.load(Ordering::Relaxed)
}

/// [`init`] with test seams. Not public API.
#[doc(hidden)]
#[cfg(unix)]
pub fn init_with_test_hooks(hooks: &'static dyn crate::elevation::shim::ShimTestHooks) {
    install(Some(hooks));
}

/// `hooks` are the seams the shim takes from a test host; a platform without a shim has none.
fn install(#[cfg(unix)] hooks: Option<&'static dyn crate::elevation::shim::ShimTestHooks>) {
    INSTALLED.store(true, Ordering::Relaxed);
    let argv: Vec<OsString> = std::env::args_os().collect();
    #[cfg(unix)]
    crate::elevation::shim::run_if_invoked(&argv, hooks);
    run_proxy_if_invoked(&argv);
}

/// Plays the proxy and exits when `argv` is a proxy invocation, valid or not; returns otherwise.
fn run_proxy_if_invoked(argv: &[OsString]) {
    let args = match ProxyArgs::parse(argv) {
        Ok(None) => return,
        Ok(Some(args)) => args,
        Err(e) => {
            let answer = e.answer();
            role::line(
                role::PROXY,
                format_args!(
                    "{}; nothing was sent (exit {})",
                    crate::error::Report(&e),
                    answer.code()
                ),
            );
            std::process::exit(answer.code());
        }
    };
    std::process::exit(serve(&args));
}

#[cfg(windows)]
fn serve(args: &ProxyArgs) -> i32 {
    let answer = crate::stop::proxy::run::run(args);
    if answer != ProxyAnswer::Sent {
        role::line(
            role::PROXY,
            format_args!("answering {answer:?} (exit {})", answer.code()),
        );
    }
    answer.code()
}

/// Other platforms have no proxy; it reports that and sends nothing.
#[cfg(not(windows))]
fn serve(_: &ProxyArgs) -> i32 {
    let answer = ProxyAnswer::NoProxyHere;
    role::line(
        role::PROXY,
        format_args!(
            "this platform has no console-event proxy; nothing was sent (exit {})",
            answer.code()
        ),
    );
    answer.code()
}

#[cfg(test)]
#[path = "init_tests.rs"]
mod init_tests;
