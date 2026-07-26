//! Cross-platform privilege elevation. Elevation wraps the CHILD (a
//! `sudo`/`run0`/`doas`/`pkexec` prefix on POSIX; `ShellExecuteEx("runas")` on
//! Windows), never the calling process. See the pure planner in [`plan`].

use zeroize::Zeroize;

/// A password supplied for [`Auth::Stdin`]. Zeroized on drop; its `Debug` is
/// redacted so it never reaches a log line. `expose` is the only readout, used
/// by the POSIX effect layer to feed `sudo -S`.
#[derive(Clone)]
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Secret {
        Secret(bytes.into())
    }
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
#[path = "elevation_tests.rs"]
mod elevation_tests;
