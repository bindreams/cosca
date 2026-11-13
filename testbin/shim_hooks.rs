//! The shim's test seams, read from the environment.
//!
//! Compiled into the test binary and the lib's unit-test binary, never into the library: a host
//! that calls `cosca::init()` has no way to reach a seam, whatever the environment says. Through a
//! front that strips the environment (sudo's `env_reset`, doas, pkexec) a test names a wrapper script
//! that sets these variables and execs the test binary. A seam the environment asks for and that
//! cannot be honoured panics, naming the path or the name and the error.
//!
//! - [`LOG_ENV`] (`COSCA_SEAM_LOG`): a path (a FIFO whose reader is already open, or a file) the shim's
//!   log lines are appended to.
//! - [`gate_env`] (`COSCA_SEAM_GATE_<NAME>`): a FIFO the shim opens and reads one byte from when it reaches the
//!   gate; the test releases the gate by opening the FIFO for writing. `NAME` is the gate's
//!   name in upper case with `_` for `-`.
//! - [`INJECT_ENV`] (`COSCA_SEAM_INJECT`): a comma-separated list of injection names.
//! - [`CHILD_GATE_ENV`] (`COSCA_SEAM_CHILD_GATE`), [`LOOP_FAILURE_ENV`] (`COSCA_SEAM_LOOP_FAILURE`): paths, as the hooks' docs say.
//! - [`CHILD_FAULT_ENV`] (`COSCA_SEAM_CHILD_FAULT`), [`EXHAUST_FDS_ENV`] (`COSCA_SEAM_EXHAUST_FDS`): `1`.
//!
//! [`init`] is what the test binaries call first in `main`. Two variables change what it does:
//!
//! - [`SHIM_SHIPPED_ENV`] (`COSCA_TESTCFG_SHIM_SHIPPED`): the process runs the shim as a host ships it, through `cosca::init()`
//!   with no hooks, whatever else the environment says.
//! - [`INIT_PROBE_ENV`] (`COSCA_TESTCFG_INIT_PROBE`): the process prints whether `cosca::installed()` held before and after
//!   `cosca::init()`, and exits.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::fd::{IntoRawFd, RawFd};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::PathBuf;
use std::sync::OnceLock;

use cosca::{Gate, Inject, ShimTestHooks};

/// Set in a process's environment to make [`init`] start the shim as a host ships it.
pub const SHIM_SHIPPED_ENV: &str = "COSCA_TESTCFG_SHIM_SHIPPED";
/// Set in a process's environment to make [`init`] print whether `cosca::installed()` held before and
/// after `cosca::init()`, and exit.
pub const INIT_PROBE_ENV: &str = "COSCA_TESTCFG_INIT_PROBE";

// The seam variables, as the module doc describes them -----

pub const LOG_ENV: &str = "COSCA_SEAM_LOG";
pub const INJECT_ENV: &str = "COSCA_SEAM_INJECT";
pub const CHILD_GATE_ENV: &str = "COSCA_SEAM_CHILD_GATE";
pub const CHILD_FAULT_ENV: &str = "COSCA_SEAM_CHILD_FAULT";
pub const LOOP_FAILURE_ENV: &str = "COSCA_SEAM_LOOP_FAILURE";
pub const EXHAUST_FDS_ENV: &str = "COSCA_SEAM_EXHAUST_FDS";

/// The variable that holds `gate`'s FIFO.
pub fn gate_env(gate: Gate) -> String {
    format!("COSCA_SEAM_GATE_{}", gate.name().to_uppercase().replace('-', "_"))
}

pub struct EnvHooks {
    log: OnceLock<Option<RawFd>>,
}

pub static HOOKS: EnvHooks = EnvHooks { log: OnceLock::new() };

fn var(name: &str) -> Option<OsString> {
    std::env::var_os(name).filter(|v| !v.is_empty())
}

/// `1` is on, unset is off, and anything else is a request nothing can honour.
fn flag(name: &str) -> bool {
    match var(name) {
        None => false,
        Some(v) if v == "1" => true,
        Some(v) => panic!("{name} is {v:?}; it is 1 or unset"),
    }
}

/// Starts the shim if this process was started as one, and otherwise returns.
pub fn init() {
    if var(INIT_PROBE_ENV).is_some() {
        let before = cosca::installed();
        cosca::init();
        // Not `quiet_io`: the lib's unit-test binary includes this file too. A closed stdout is a
        // normal end here, as in every testbin mode.
        let mut out = std::io::stdout().lock();
        match writeln!(out, "installed before={before} after={}", cosca::installed()).and_then(|()| out.flush()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(e) => panic!("{INIT_PROBE_ENV}: write stdout: {e}"),
        }
        std::process::exit(0);
    }
    if var(SHIM_SHIPPED_ENV).is_some() {
        cosca::init();
    } else {
        cosca::init_with_test_hooks(&HOOKS);
    }
}

impl ShimTestHooks for EnvHooks {
    fn gate(&self, gate: Gate) {
        let name = gate_env(gate);
        let Some(fifo) = var(&name) else { return };
        // Blocks until the test opens the FIFO for writing, then until it writes or closes.
        let mut f = std::fs::File::open(&fifo)
            .unwrap_or_else(|e| panic!("{name}: cannot open the gate {}: {e}", fifo.to_string_lossy()));
        let mut byte = [0u8; 1];
        // A byte or the end of the FIFO releases the gate; either is the test's.
        let _released = f
            .read(&mut byte)
            .unwrap_or_else(|e| panic!("{name}: cannot read the gate {}: {e}", fifo.to_string_lossy()));
    }

    fn inject(&self, what: Inject) -> bool {
        let Some(list) = var(INJECT_ENV) else {
            return false;
        };
        let list = list.to_string_lossy();
        for name in list.split(',') {
            assert!(
                Inject::ALL.iter().any(|known| known.name() == name),
                "{INJECT_ENV} names {name:?}, which is not an injection: {:?}",
                Inject::ALL.map(Inject::name)
            );
        }
        list.split(',').any(|n| n == what.name())
    }

    fn log_fd(&self) -> Option<RawFd> {
        *self.log.get_or_init(|| {
            let path = var(LOG_ENV)?;
            let file = OpenOptions::new()
                .append(true)
                .custom_flags(libc::O_CLOEXEC)
                .open(&path)
                .unwrap_or_else(|e| panic!("{LOG_ENV}: cannot open {}: {e}", path.to_string_lossy()));
            Some(file.into_raw_fd())
        })
    }

    fn child_gate(&self) -> Option<PathBuf> {
        let path = PathBuf::from(var(CHILD_GATE_ENV)?);
        // The child opens it with raw calls and cannot report a failure to.
        let meta = std::fs::metadata(&path)
            .unwrap_or_else(|e| panic!("{CHILD_GATE_ENV}: cannot stat {}: {e}", path.display()));
        assert!(
            meta.file_type().is_fifo(),
            "{CHILD_GATE_ENV}: {} is not a FIFO",
            path.display()
        );
        Some(path)
    }

    fn child_fault(&self) -> bool {
        flag(CHILD_FAULT_ENV)
    }

    fn loop_failure(&self) -> Option<PathBuf> {
        var(LOOP_FAILURE_ENV).map(PathBuf::from)
    }

    fn exhaust_fds(&self) -> bool {
        flag(EXHAUST_FDS_ENV)
    }
}
