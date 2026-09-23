//! This process's environment block, read once per raw spawn, and once per elevated consent
//! launch for the `PATH` its program is resolved on.

use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::OsStringExt;

use windows::core::PCWSTR;
use windows::Win32::System::Environment::{FreeEnvironmentStringsW, GetEnvironmentStringsW};

use super::env_key::EnvKey;
use crate::error::Error;

/// A copy of this process's environment block, exactly as `GetEnvironmentStringsW` returned it:
/// `KEY=VAL\0` entries in the OS's order, closed by an empty entry. Every environment-dependent
/// step of a raw spawn reads this one copy, so none can see a different environment than the
/// child gets. The elevated consent launch reads only its `PATH`.
pub(crate) struct EnvSnapshot(Vec<u16>);

impl EnvSnapshot {
    pub(crate) fn read() -> Result<Self, Error> {
        // SAFETY: no preconditions; the block is freed below.
        let raw = unsafe { GetEnvironmentStringsW() };
        if raw.is_null() {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        let mut len = 0;
        // SAFETY: the block is a run of NUL-terminated entries closed by an empty one, so every
        // read up to and including that final NUL is in bounds.
        unsafe {
            while *raw.0.add(len) != 0 {
                while *raw.0.add(len) != 0 {
                    len += 1;
                }
                len += 1;
            }
        }
        // SAFETY: `len` units were just read, plus the closing NUL at `len`.
        let block = unsafe { std::slice::from_raw_parts(raw.0, len + 1) }.to_vec();
        // SAFETY: `raw` came from `GetEnvironmentStringsW` and is freed once.
        unsafe { FreeEnvironmentStringsW(PCWSTR(raw.0)) }.map_err(|e| Error::Io(e.into()))?;
        Ok(Self::from_block(block))
    }

    /// Wrap a block: NUL-terminated entries, the last followed by one more NUL. An empty block
    /// (a lone NUL) becomes a double NUL, which `CreateProcessW` takes as "no variables".
    pub(crate) fn from_block(mut block: Vec<u16>) -> Self {
        debug_assert!(
            block.last() == Some(&0) && (block.len() == 1 || block[block.len() - 2] == 0),
            "an environment block ends in an empty entry"
        );
        if block.len() == 1 {
            block.push(0);
        }
        Self(block)
    }

    /// The block, verbatim.
    pub(crate) fn block(&self) -> &[u16] {
        &self.0
    }

    /// The variables, parsed as `std::env::vars_os` parses them (`library/std/src/sys/env/windows.rs`
    /// L33-63): the name runs to the first `=` after its first unit, so `=C:=C:\` names `=C:`, and
    /// an entry with no such `=` is skipped. Duplicates are kept, in block order.
    pub(crate) fn vars(&self) -> impl Iterator<Item = (OsString, OsString)> + '_ {
        self.0[..self.0.len() - 1]
            .split(|&u| u == 0)
            .filter(|entry| !entry.is_empty())
            .filter_map(|entry| {
                let eq = entry[1..].iter().position(|&u| u == u16::from(b'='))? + 1;
                Some((OsString::from_wide(&entry[..eq]), OsString::from_wide(&entry[eq + 1..])))
            })
    }

    /// The value `GetEnvironmentVariableW(name)` would read from this block: the FIRST entry whose
    /// name matches, as `RtlQueryEnvironmentVariable` scans (Wine `dlls/ntdll/env.c`, ReactOS
    /// `sdk/lib/rtl/env.c`), compared as [`EnvKey`] compares. The tests hold this against ntdll.
    pub(crate) fn var(&self, name: &OsStr) -> Option<OsString> {
        let name = EnvKey::new(name);
        self.vars()
            .find(|(key, _)| EnvKey::new(key) == name)
            .map(|(_, val)| val)
    }
}

#[cfg(test)]
#[path = "env_snapshot_tests.rs"]
mod env_snapshot_tests;
