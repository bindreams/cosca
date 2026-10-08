//! The shim's test seams (plan F, D24), read from the environment.
//!
//! Compiled into the test binary and the lib's unit-test binary, never into the library: a host
//! that calls `cosca::init()` has no way to reach a seam, whatever the environment says. Through a
//! front that strips the environment (sudo's `env_reset`, doas, pkexec) a test names a wrapper script
//! that sets these variables and execs the test binary.
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

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::fd::{IntoRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
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

impl ShimTestHooks for EnvHooks {
    fn gate(&self, gate: Gate) {
        let name = format!("COSCA_SEAM_GATE_{}", gate.name().to_uppercase().replace('-', "_"));
        let Some(fifo) = var(&name) else { return };
        // Blocks until the test opens the FIFO for writing, then until it writes or closes.
        if let Ok(mut f) = std::fs::File::open(fifo) {
            let mut byte = [0u8; 1];
            _ = f.read(&mut byte);
        }
    }

    fn inject(&self, what: Inject) -> bool {
        var("COSCA_SEAM_INJECT").is_some_and(|list| list.to_string_lossy().split(',').any(|n| n == what.name()))
    }

    fn log_fd(&self) -> Option<RawFd> {
        *self.log.get_or_init(|| {
            let path = var("COSCA_SEAM_LOG")?;
            let file = OpenOptions::new()
                .append(true)
                .custom_flags(libc::O_CLOEXEC)
                .open(path)
                .ok()?;
            Some(file.into_raw_fd())
        })
    }

    fn child_gate(&self) -> Option<PathBuf> {
        var("COSCA_SEAM_CHILD_GATE").map(PathBuf::from)
    }

    fn child_fault(&self) -> bool {
        var("COSCA_SEAM_CHILD_FAULT").is_some_and(|v| v == "1")
    }

    fn loop_failure(&self) -> Option<PathBuf> {
        var("COSCA_SEAM_LOOP_FAILURE").map(PathBuf::from)
    }

    fn exhaust_fds(&self) -> bool {
        var("COSCA_SEAM_EXHAUST_FDS").is_some_and(|v| v == "1")
    }
}
