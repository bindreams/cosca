//! `cosca`: unified cross-platform subprocess management.
//!
//! Build a process with [`Command`] (stdio, env, tree containment, elevation),
//! spawn it into an owned [`Child`], or open an already-running process with
//! [`Process`]. Sync by default; async counterparts live in the `tokio`
//! module behind the `tokio` feature.
//!
//! # Which type do I use?
//!
//! With the `tokio` feature, `cosca::tokio::Command`, `cosca::tokio::Child` and
//! `cosca::tokio::Process` are the async twins of [`Command`], [`Child`] and [`Process`];
//! [`ProcessId`](identity::ProcessId) is shared.
//!
//! ## A process you spawn: [`Command`] and [`Child`]
//!
//! [`Command::spawn`] makes a [`Child`], and the caller is its parent: the child's exit status,
//! its stdio pipes and, with [`contain`](Command::contain), its whole process tree are the handle's.
//! `contain` takes the strongest mechanism the host offers and fails the spawn when it cannot set
//! one up; [`contain_with`](Command::contain_with)(`BestEffort`) takes a weaker one instead
//! ([`ContainMode`]). [`kill_tree`](Child::kill_tree) kills the tree and waits for it. A drop kills
//! the contained tree, then the child, unless the handle opted out with
//! [`kill_on_drop(false)`](Command::kill_on_drop).
//!
//! ```no_run
//! fn serve() -> Result<(), cosca::error::Error> {
//!     let mut cmd = cosca::run(["my-server", "--port", "8080"]);
//!     let child = cmd.contain().spawn()?;
//!     // ... later:
//!     child.kill_tree()?;
//!     let status = child.wait()?;
//!     println!("my-server exited: {status}");
//!     Ok(())
//! }
//! ```
//!
//! ## A process you did not spawn: [`Process`]
//!
//! [`Process::open_pid`] and [`Process::open`] hold a running process by identity. Once opened,
//! [`kill`](Process::kill), the tree acts such as [`kill_tree`](Process::kill_tree), and
//! [`wait`](Process::wait) reach that process or report it gone, never a later holder of its pid.
//! `Process::wait` reports no exit status; [`Child::wait`] does. A pid whose identity cannot be
//! read is an `Err`, not `Ok(None)`: usually [`Error::Unassessable`](error::Error::Unassessable),
//! and [`Process::open`]'s `# Errors` lists the rest.
//!
//! ```no_run
//! use cosca::error::Report;
//! use cosca::Process;
//!
//! fn stop(pid: u32) {
//!     match Process::open_pid(pid) {
//!         Ok(Some(process)) => {
//!             if let Err(e) = process.kill().and_then(|()| process.wait()) {
//!                 eprintln!("could not stop pid {pid}: {}", Report::new(&e));
//!             }
//!         }
//!         // No process has this pid.
//!         Ok(None) => println!("pid {pid} is not running"),
//!         Err(e) => eprintln!("could not open pid {pid}: {}", Report::new(&e)),
//!     }
//! }
//! ```
//!
//! ## Naming a process exactly: [`ProcessId`](identity::ProcessId)
//!
//! A `ProcessId` is a pid plus a per-process key from the kernel, compared exactly, so the id of a
//! process that has exited does not equal the id of a later holder of its pid (except on Linux
//! below 6.9: see [`ProcessId`](identity::ProcessId)).
//! [`ProcessId::of`](identity::ProcessId::of) reads the id of a pid and answers
//! [`Found`](identity::Resolved::Found), [`Gone`](identity::Resolved::Gone) (no such process) or
//! [`Unknown`](identity::Resolved::Unknown) (the OS refused to say). [`Child::id`] gives a spawned
//! child's, or `None` when the OS refused to report it at spawn. An id is `Copy`, `Eq` and `Hash`.
//! It holds nothing and acts on nothing: [`exists`](identity::ProcessId::exists) and
//! [`is_alive`](identity::ProcessId::is_alive) read the OS at that moment, and [`Process::open`]
//! turns an id into a handle to act through.
//!
//! To keep an id past this process, [`to_record`](identity::ProcessId::to_record) makes an
//! [`identity::ProcessIdRecord`] (serializable with the `serde` feature), and the only way back is
//! `ProcessId::try_from`. It refuses a record that cannot be compared on this host, so a record
//! cannot silently alias onto an unrelated process: [`RecordErrorKind`](error::RecordErrorKind)
//! lists each refusal. A restored id says nothing about whether its process is still there:
//! opening it does.
//!
//! ```no_run
//! use cosca::error::Error;
//! use cosca::identity::{ProcessId, ProcessIdRecord, Resolved};
//! use cosca::Process;
//!
//! // The id of a child this program spawned.
//! fn save_child(child: &cosca::Child) -> Result<Option<ProcessIdRecord>, Error> {
//!     match child.id() {
//!         Some(id) => Ok(Some(id.to_record()?)),
//!         // The OS refused to report its identity at spawn: there is no id to keep.
//!         None => Ok(None),
//!     }
//! }
//!
//! // The id of a process this program did not spawn.
//! fn save_pid(pid: u32) -> Result<Option<ProcessIdRecord>, Error> {
//!     match ProcessId::of(pid) {
//!         Resolved::Found(id) => Ok(Some(id.to_record()?)),
//!         // No process has this pid.
//!         Resolved::Gone => Ok(None),
//!         // The OS refused to say: a process may well be there.
//!         Resolved::Unknown => {
//!             eprintln!("could not read the identity of pid {pid}");
//!             Ok(None)
//!         }
//!     }
//! }
//!
//! // Later, possibly in another run of the program, from a stored record.
//! fn stop(record: &ProcessIdRecord) -> Result<(), Error> {
//!     let id = ProcessId::try_from(record)?;
//!     match Process::open(id)? {
//!         Some(process) => process.kill(),
//!         // That process is gone, and its pid may name another now.
//!         None => Ok(()),
//!     }
//! }
//! ```
//!
//! # Asking a child to stop: [`stop`]
//!
//! [`Child::terminate`], [`graceful_shutdown`](Child::graceful_shutdown) and their `_tree` forms ask the
//! child to stop: `SIGTERM` on Unix, `Ctrl+Break` on Windows, as [`stop::default`] says.
//! [`Command::graceful_stop`] replaces what is sent with an action composed from the functions of the
//! [`stop`] module, whose docs say what a stop reaches on each platform and how to choose one.
//!
//! # Platform requirements
//!
//! **Linux 5.6 or newer**, with `pidfd_open` and `openat2` not blocked by a seccomp profile or an
//! LSM.
//!
//! Each requirement comes from a different syscall:
//!
//! - `pidfd_open` needs 5.3, and cosca requires it to read the identity of any process by its pid,
//!   [`ProcessId::current`](identity::ProcessId::current) and
//!   [`to_record`](identity::ProcessId::to_record) / `restore` included. A refusal is
//!   [`Error::Unsupported`](error::Error::Unsupported); a transient failure such as `EMFILE` is
//!   [`Error::Io`](error::Error::Io) naming the syscall (an identity read that meets one is
//!   unknown, and a member of a process group whose pidfd cannot be opened is not signalled).
//!   `ProcessId::current` panics on either.
//! - `clone3` (5.3), or `clone` with `CLONE_PIDFD` (5.2) where `clone3` is refused, makes every child
//!   cosca spawns, and gives its pidfd as the child is made, so no child exists without one. A spawn
//!   whose `clone3` and `clone` are both refused with `ENOSYS` or `EPERM` is
//!   [`Error::Unsupported`](error::Error::Unsupported) naming `spawn` and the running kernel, and makes
//!   no child. The one exception is a kernel before 5.2, whose `clone` ignores `CLONE_PIDFD`: the
//!   spawn is the same `Unsupported`, but a child was made, and it is left (cosca never reaps by
//!   pid). Such kernels are below the 5.6 floor.
//! - On Linux 6.9 and newer pidfds have an inode of their own, one per process and never reused,
//!   which is a process's identity: `pidfd_open` by pid, then `fstat`, with no `/proc`. Before 6.9
//!   the identity is the `starttime` in `/proc/<pid>/stat`. cosca finds out which by asking the
//!   pidfd's filesystem, and never parses a kernel version.
//! - `waitid(P_PIDFD)` needs 5.4, and is how an owned child is waited for and reaped, by its
//!   pidfd and not its pid.
//! - `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS` needs 5.6. The
//!   checked `/proc` view uses it to read a process's start time and to list processes.
//!   Before Linux 6.9 a refusal (what counts as one is under
//!   [`Error::Unsupported`](error::Error::Unsupported)) is that error naming `openat2`,
//!   from a by-pid identity read, wait or kill, and from a spawn inside
//!   [`Error::MayHaveStarted`](error::Error::MayHaveStarted): a spawn reads the identity once the
//!   child runs. On 6.9+ a by-pid identity read, an open and a spawn need no view; listing a
//!   process group or the process table, and a start time (`created_at`), still do.
//!   [`ProcessId::current`](identity::ProcessId::current) needs only a readable `/proc/self/stat`
//!   before 6.9, and on 6.9+ no `/proc` at all.
//! - The elevation shim (`cosca::init_helpers`) runs on Linux. macOS has no shim; `init_helpers` reports that
//!   and does not start the program. Windows has none. It needs `/proc` mounted: it reaches cosca's socket through
//!   `/proc/thread-self/fd`. Without it the shim refuses, saying so, and the program is not started.
//!
//! 32-bit Linux is unsupported: cosca does not compile there. Before Linux 6.14 a 32-bit kernel gives
//! only the low 32 bits of a pidfs inode number, so a process's identity (its pidfd's inode on 6.9+)
//! would not be unique.
//!
//! Linux on an architecture other than x86_64, aarch64, riscv64, s390x, powerpc64 and loongarch64 is
//! unsupported too, and cosca does not compile there: its raw `clone`, which gives a child its pidfd
//! from the fork, is checked to return 0 in the child only on those.
//!
//! [`Containment::CgroupV2`] additionally needs `cgroup.kill` (Linux 5.14); without it `CgroupV2`
//! is not used: on an older kernel a spawn gets a process group under both
//! [`ContainMode::Strongest`] and [`ContainMode::BestEffort`], as documented on
//! [`ContainMode`]. It also assumes kernel
//! commit `b69bb476dee9` ("cgroup: fix race between fork and cgroup.kill"), in mainline from 6.14
//! or in a stable kernel that carries it. cosca does not probe for it; the cost of its absence is
//! described under [`Command::kill_on_drop`].
//!
//! Linux 5.6 on its own oopses under systemd 254 or newer: `systemd-udevd` writes a cgroup's
//! `memory.pressure`, and that write dereferences NULL in the 5.6 kernel. cosca does not touch
//! pressure-stall information; the CI guest boots 5.6 with `psi=0` for that reason.
//!
//! **macOS 14.4 or newer**, for `proc_signal_with_audittoken`. It signals a process by an audit token
//! that names its pid and `exec` version, so the kernel never signals a process that took a reused
//! pid. Earlier versions are unsupported, with no fallback.
//!
//! # A console event to a Windows child: the proxy
//!
//! A Windows process can send a console event (Ctrl+C, Ctrl+Break) only to the console it is attached
//! to. `stop::send_console_event_via_proxy` (Windows) reaches a child on another console, or from a
//! caller with none (a service), through a helper process, the proxy, that has no console of its own.
//! The proxy is a role of the host program: call [`init_helpers`] first thing in `main`, and the default
//! (`CtrlProxy::HostExecutable`) starts the file at the host's path, when the stop runs, as the proxy.
//! A host that cannot call `init_helpers`, or that replaces its own image while it runs, installs the
//! `cosca-ctrl-proxy` executable (`cargo install cosca --bin cosca-ctrl-proxy`) and names it with
//! `Command::ctrl_proxy`. A Windows stop that would start the host as the proxy panics in a host that did
//! neither; see [`stop::default`](stop::default#panics).
//!
//! # A child under a debugger
//!
//! A debugger that traces a [`Child`] owns its signal delivery: a graceful signal, such as the
//! one [`Child::terminate_tree`] sends, reaches the child only if the debugger passes it on. It
//! cannot cancel the `SIGKILL` of [`Child::kill`], but it can delay the death:
//!
//! - On Linux only if it traces exits (`PTRACE_O_TRACEEXIT`): it then holds the dying child at an
//!   exit stop until it continues it ([ptrace(2)], BUGS). Otherwise the child dies at once.
//! - On macOS a running child stops for the debugger on `SIGKILL` too, and a stopped child just
//!   holds it. Either way the child dies once the debugger resumes it, detaches or exits.
//!
//! [`Child::wait`] returns the child's exit once the debugger lets go of it: when it detaches, when
//! it collects the exit, which hands the child back, or when it exits itself. The debugger's exit
//! kills the child on macOS; on Linux it detaches it, or kills it if the debugger asked to
//! (`PTRACE_O_EXITKILL`).
//!
//! [ptrace(2)]: https://man7.org/linux/man-pages/man2/ptrace.2.html

// `SpawnLockGuard` is `#[must_use]`, but only this lint keeps `let _ = spawn_lock();` (a lock released
// at once) flagged, as rustc's `let_underscore_lock` did when the guard was a `MutexGuard`. Discard a
// result on purpose with `_ = expr;`. Crate-level, not in `[lints]`, which would extend it to the
// tests and test binaries.
#![warn(clippy::let_underscore_must_use)]

#[cfg(all(target_os = "linux", target_pointer_width = "32"))]
compile_error!("cosca does not support 32-bit Linux (see \"Platform requirements\" in the crate docs)");

// The README as the doc of an item only rustdoc's test pass sees, so the doctest step compiles its Rust
// examples.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
mod readme_examples {}

pub mod containment;
pub mod elevation;
pub mod error;
mod graceful;
pub mod identity;
pub mod quote;
pub mod stdio;
pub mod stop;
#[cfg(windows)]
pub use containment::Job;
pub use containment::{ContainMode, Containment};
#[doc(hidden)]
#[cfg(unix)]
pub use elevation::shim::{Gate, Inject, ShimTestHooks};
pub use elevation::{Auth, Backend, ElevatedStdio, ElevatedVia, ElevationReport, EnvSanitizer, Privilege, Secret};
#[cfg(unix)]
pub use signal::Signal;
pub use stdio::{Fd, Stdio};
#[cfg(windows)]
pub use stop::proxy::protocol::CtrlEvent;
#[cfg(windows)]
pub use stop::proxy::CtrlProxy;
pub use stop::StopTarget;

mod init;
mod role;
#[doc(hidden)]
pub use init::ctrl_proxy_main;
#[doc(hidden)]
#[cfg(unix)]
pub use init::init_helpers_with_test_hooks;
pub use init::{helpers_initialized, init_helpers};

mod child;
pub use child::{Child, SuspendedChild, Unreaped};

mod pipe;
pub use pipe::{PipeReader, PipeWriter};

// Lets `tests/common/locked.rs`, which names `cosca::test_spawn_lock`, compile into the lib's tests.
#[cfg(test)]
extern crate self as cosca;

/// Test-only: the same process-wide lock production spawns take internally
/// (`child::spawn::spawn_lock`), exposed so this crate's OWN integration tests
/// (`tests/*.rs`, a separate compilation unit that cannot name a `pub(crate)` item) can
/// serialize a raw `std::process::Command` spawn against it too — closing the same
/// fork-bystander-inherits-a-live-marker window `containment::fdmarker`'s module docs
/// describe, for a raw spawn that bypasses `cosca::Command` entirely. `#[doc(hidden)]`: not
/// public API, present only for this crate's own `tests/` binaries to link against.
///
/// Returns a guard: hold it for the raw spawn. Re-taking the lock on the same thread (a
/// `cosca::Command::spawn` under it, say) panics under `debug_assertions` instead of deadlocking.
#[doc(hidden)]
pub fn test_spawn_lock() -> TestSpawnLockGuard {
    TestSpawnLockGuard(child::spawn::spawn_lock())
}

/// Holds [`test_spawn_lock`]'s lock until dropped.
#[doc(hidden)]
#[must_use = "if unused the spawn lock is released immediately; bind the guard for the whole window"]
pub struct TestSpawnLockGuard(#[allow(dead_code, reason = "held only for its Drop")] child::spawn::SpawnLockGuard);

mod command;
// Not cfg-gated: keeping the policy platform-independent is what makes it testable from any host.
mod resolve;
pub use command::Command;

mod wait;

mod os_process;

#[cfg(unix)]
mod above_stdio;

#[cfg(all(test, unix))]
mod send_log;
mod signal;

#[cfg(test)]
mod log_capture;

#[cfg(test)]
mod graceful_hooks;

#[cfg(test)]
mod oneshot_hook;

#[cfg(test)]
mod relayed_probe;

#[cfg(test)]
mod test_child;

#[cfg(test)]
mod test_groups;

// Declared here, not in `test_groups.rs`: integration roots include that file by `#[path]`.
#[cfg(test)]
#[path = "test_groups_tests.rs"]
mod test_groups_tests;

#[cfg(test)]
mod test_harness;

// Also mounted into `tests/common`.
#[cfg(test)]
mod test_pattern;

#[cfg(test)]
mod test_reexec;
#[cfg(test)]
mod test_reexec_tests;

#[cfg(all(test, unix))]
mod test_privilege;

#[cfg(all(test, unix))]
mod test_own_process;
// Its Windows twin, under the same name.
#[cfg(all(test, windows))]
#[path = "test_own_process_windows.rs"]
mod test_own_process;
#[cfg(test)]
mod test_own_process_gate;
#[cfg(all(test, unix))]
mod test_own_process_tests;
#[cfg(all(test, unix))]
mod test_stdio;
#[cfg(all(test, unix))]
mod test_stdio_tests;
#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
mod test_support;

// The integration tests' seccomp filters, included rather than copied.
#[cfg(all(test, target_os = "linux"))]
#[allow(dead_code, reason = "each user, here and in tests/, takes a subset of the file")]
#[path = "../tests/common/seccomp.rs"]
mod test_seccomp;

#[cfg(test)]
mod test_spawn;

#[cfg(all(test, windows))]
mod test_frozen;

pub mod process;
pub use identity::Recursive;
pub use process::Process;

#[cfg(feature = "tokio")]
pub mod tokio;

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

#[cfg(all(test, unix))]
#[path = "../testbin/shim_hooks.rs"]
mod shim_env_hooks;

/// The stand-in for the console-event proxy, which the caller side's tests name and read.
#[cfg(all(test, windows))]
#[path = "../testbin/proxy_fixture.rs"]
mod proxy_fixture;

#[cfg(test)]
fn main() {
    // This binary is also the elevation shim in the shim's end-to-end tests: a process started with
    // the shim's arguments runs it here and exits.
    #[cfg(unix)]
    shim_env_hooks::init();
    // And the console-event proxy, which the proxy's tests start as a copy of this binary.
    #[cfg(windows)]
    init_helpers();
    // The fixture roles the tests re-run this binary as.
    test_child::fixture_role::run_if_requested();
    let mut runner = skuld::TestRunner::new();
    runner.libtest_names();
    runner.require_known_labels();
    runner.run()
}
