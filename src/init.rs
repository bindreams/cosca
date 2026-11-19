//! The hook a host program calls first in `main`: [`init_helpers`]. It makes the process able to be
//! started as the helpers cosca starts a copy of the host program for, and tells the host's own code
//! ([`helpers_initialized`]) that it has.
//!
//! The helpers are the elevation shim ([`elevation::shim`](crate::elevation::shim), Unix) and the
//! console-event proxy ([`stop::proxy`](crate::stop::proxy)). The proxy is told it is one by the
//! environment variable [`role::HELPER_ENV`]; the shim, on Unix, by its first argument.

use std::ffi::{OsStr, OsString};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::role;
use crate::stop::proxy::protocol::{ProxyAnswer, ProxyArgs};

static HELPERS_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Sets this process up to be started as a helper of cosca: the console-event proxy on Windows, the
/// elevation shim on Linux. Call it first thing in `main`: code before it also runs in a helper launch,
/// and could disturb the helper (a thread started, a signal disposition changed, a file written).
///
/// In a helper launch `init_helpers` plays the role to its end and exits the process; it does not
/// return. Otherwise it returns at once and does nothing else.
///
/// # How a helper launch is recognised
///
/// By the environment variable `__COSCA_HELPER`, which names the role (`ctrl-proxy`). Cosca sets it on
/// the helper's command; it is not for setting by hand. A process that is started with it set never
/// runs as the program: it plays the role the value names, or, for a role this build does not have or
/// arguments the role cannot use, writes one line to stderr (it begins with
/// `started with __COSCA_HELPER=<value>`, so a person who finds a program exiting learns why) and exits
/// with an error code. Its arguments are the role's data and are read only once the variable has said so.
///
/// A program's own arguments never decide it: a program whose first argument is `--cosca-ctrl-proxy`
/// runs as itself. The one exception is the Unix elevation shim, which is still recognised by its first
/// argument, because the tools that start it (`sudo`, `doas`, `pkexec`) reset the environment.
///
/// On Windows, a stop that would start this program as the console-event proxy panics when this was never
/// called, as a broken contract of the program: see [`stop::default`](crate::stop::default#panics).
///
/// - **The shim** runs on Linux. macOS has no shim: `init_helpers` reports that and does not start the
///   program (exit 120).
/// - **The proxy** runs on Windows: it attaches to another process's console, sends it Ctrl+C or
///   Ctrl+Break, and exits with its answer (150 to 160). Other platforms have no proxy:
///   `init_helpers` reports that and exits 159.
pub fn init_helpers() {
    #[cfg(unix)]
    start(None);
    #[cfg(not(unix))]
    start();
}

/// The whole `main` of the `cosca-ctrl-proxy` executable: [`init_helpers`], which plays the proxy when
/// the environment says so and exits with the unknown-role code for a role it does not know, as it
/// documents. With the variable unset, one stderr line and exit with the usage answer. Not public API.
#[doc(hidden)]
pub fn ctrl_proxy_main() -> ! {
    init_helpers();
    role::line(
        role::PROXY,
        format_args!(
            "this is a helper that cosca starts, with {}={} set; run by hand it does nothing",
            role::HELPER_ENV,
            role::CTRL_PROXY
        ),
    );
    std::process::exit(ProxyAnswer::Usage.code())
}

/// Whether [`init_helpers`] has run in this process.
pub fn helpers_initialized() -> bool {
    HELPERS_INITIALIZED.load(Ordering::Relaxed)
}

/// [`init_helpers`] with test seams. Not public API.
#[doc(hidden)]
#[cfg(unix)]
pub fn init_helpers_with_test_hooks(hooks: &'static dyn crate::elevation::shim::ShimTestHooks) {
    start(Some(hooks));
}

/// `hooks` are the seams the shim takes from a test host; a platform without a shim has none.
fn start(#[cfg(unix)] hooks: Option<&'static dyn crate::elevation::shim::ShimTestHooks>) {
    HELPERS_INITIALIZED.store(true, Ordering::Relaxed);
    let argv: Vec<OsString> = std::env::args_os().collect();
    match helper_role() {
        Some(helper) => play(&helper, &argv),
        #[cfg(unix)]
        None => crate::elevation::shim::run_if_invoked(&argv, hooks),
        #[cfg(not(unix))]
        None => {}
    }
}

/// The role [`role::HELPER_ENV`] names: `None` when the variable is unset. Only reads the variable;
/// removing it would race with other threads on Unix.
fn helper_role() -> Option<OsString> {
    std::env::var_os(role::HELPER_ENV)
}

/// Plays the helper role `helper` names, with `argv` as its data, and exits the process: this process
/// was started as a helper and is never the program.
fn play(helper: &OsStr, argv: &[OsString]) -> ! {
    if helper != role::CTRL_PROXY {
        let answer = role::UNKNOWN_HELPER_ROLE;
        role::line(
            role::HELPER,
            format_args!(
                "{}: no such helper role in this build (it has {:?}); the program was not started (exit {answer})",
                role::started_with(helper),
                role::CTRL_PROXY
            ),
        );
        std::process::exit(answer);
    }
    std::process::exit(run_proxy(argv))
}

/// Plays the proxy for `argv` and returns the exit code.
fn run_proxy(argv: &[OsString]) -> i32 {
    match ProxyArgs::parse(argv) {
        Ok(args) => serve(&args),
        Err(e) => {
            let answer = e.answer();
            role::line(
                role::PROXY,
                format_args!(
                    "{}: {}; nothing was sent (exit {})",
                    role::started_with(OsStr::new(role::CTRL_PROXY)),
                    crate::error::Report(&e),
                    answer.code()
                ),
            );
            answer.code()
        }
    }
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
            "{}: this platform has no console-event proxy; nothing was sent (exit {})",
            role::started_with(OsStr::new(role::CTRL_PROXY)),
            answer.code()
        ),
    );
    answer.code()
}

#[cfg(test)]
#[path = "init_tests.rs"]
mod init_tests;
