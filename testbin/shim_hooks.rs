//! The shim's test seams, read from the environment.
//!
//! Compiled into the test binary and the lib's unit-test binary, never into the library: a host
//! that calls `cosca::init()` has no way to reach a seam, whatever the environment says. Through a
//! front that strips the environment (sudo's `env_reset`, doas, pkexec) a test names a wrapper script
//! that sets these variables and execs the test binary. A seam the environment asks for and that
//! cannot be honoured panics, naming the path or the name and the error.
//!
//! - `COSCA_SEAM_LOG`: a path (a FIFO whose reader is already open, or a file) the shim's log lines
//!   are appended to.
//! - `COSCA_SEAM_GATE_<NAME>`: a FIFO the shim opens and reads one byte from when it reaches the
//!   gate; the test releases the gate by opening the FIFO for writing. `NAME` is the gate's
//!   name in upper case with `_` for `-`.
//! - `COSCA_SEAM_INJECT`: a comma-separated list of injection names.
//! - `COSCA_SEAM_CHILD_GATE`, `COSCA_SEAM_LOOP_FAILURE`: paths, as the hooks' docs say.
//! - `COSCA_SEAM_CHILD_FAULT`: `1`.
//! - `COSCA_SEAM_EXHAUST_FDS`: `1`.
//!
//! [`init`] is what the test binaries call first in `main`. Two variables change what it does:
//!
//! - `COSCA_TEST_SHIM_SHIPPED`: the process runs the shim as a host ships it, through `cosca::init()`
//!   with no hooks, whatever else the environment says.
//! - `COSCA_TEST_INIT_PROBE`: the process prints whether `cosca::installed()` held before and after
//!   `cosca::init()`, and exits.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::fd::{IntoRawFd, RawFd};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::PathBuf;
use std::sync::OnceLock;

use cosca::{Gate, Inject, ShimTestHooks};

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
    if var("COSCA_TEST_INIT_PROBE").is_some() {
        let before = cosca::installed();
        cosca::init();
        println!("installed before={before} after={}", cosca::installed());
        std::process::exit(0);
    }
    if var("COSCA_TEST_SHIM_SHIPPED").is_some() {
        cosca::init();
    } else {
        cosca::init_with_test_hooks(&HOOKS);
    }
}

impl ShimTestHooks for EnvHooks {
    fn gate(&self, gate: Gate) {
        let name = format!("COSCA_SEAM_GATE_{}", gate.name().to_uppercase().replace('-', "_"));
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
        let Some(list) = var("COSCA_SEAM_INJECT") else {
            return false;
        };
        let list = list.to_string_lossy();
        for name in list.split(',') {
            assert!(
                Inject::ALL.iter().any(|known| known.name() == name),
                "COSCA_SEAM_INJECT names {name:?}, which is not an injection: {:?}",
                Inject::ALL.map(Inject::name)
            );
        }
        list.split(',').any(|n| n == what.name())
    }

    fn log_fd(&self) -> Option<RawFd> {
        *self.log.get_or_init(|| {
            let path = var("COSCA_SEAM_LOG")?;
            let file = OpenOptions::new()
                .append(true)
                .custom_flags(libc::O_CLOEXEC)
                .open(&path)
                .unwrap_or_else(|e| panic!("COSCA_SEAM_LOG: cannot open {}: {e}", path.to_string_lossy()));
            Some(file.into_raw_fd())
        })
    }

    fn child_gate(&self) -> Option<PathBuf> {
        let path = PathBuf::from(var("COSCA_SEAM_CHILD_GATE")?);
        // The child opens it with raw calls and cannot report a failure to.
        let meta = std::fs::metadata(&path)
            .unwrap_or_else(|e| panic!("COSCA_SEAM_CHILD_GATE: cannot stat {}: {e}", path.display()));
        assert!(
            meta.file_type().is_fifo(),
            "COSCA_SEAM_CHILD_GATE: {} is not a FIFO",
            path.display()
        );
        Some(path)
    }

    fn child_fault(&self) -> bool {
        flag("COSCA_SEAM_CHILD_FAULT")
    }

    fn loop_failure(&self) -> Option<PathBuf> {
        var("COSCA_SEAM_LOOP_FAILURE").map(PathBuf::from)
    }

    fn exhaust_fds(&self) -> bool {
        flag("COSCA_SEAM_EXHAUST_FDS")
    }
}
