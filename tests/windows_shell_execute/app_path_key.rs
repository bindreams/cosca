//! A volatile registry key that removes every key it created, parents included.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegOpenKeyExW, RegSetValueExW, HKEY, KEY_READ, KEY_WRITE,
    REG_CREATED_NEW_KEY, REG_CREATE_KEY_DISPOSITION, REG_OPEN_CREATE_OPTIONS, REG_SZ,
};

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain([0]).collect()
}

/// Does `path` exist under `hive`? Only "not found" is an answer of no.
pub(crate) fn key_exists(hive: HKEY, path: &str) -> Result<bool, String> {
    let name = wide(OsStr::new(path));
    let mut hkey = HKEY::default();
    // SAFETY: `name` is NUL-terminated and outlives the call; `hkey` is a live local.
    let rc = unsafe { RegOpenKeyExW(hive, PCWSTR(name.as_ptr()), None, KEY_READ, &mut hkey) };
    if rc == ERROR_SUCCESS {
        // SAFETY: `hkey` was opened above and is closed once.
        let _ = unsafe { RegCloseKey(hkey) };
        Ok(true)
    } else if rc == ERROR_FILE_NOT_FOUND {
        Ok(false)
    } else {
        Err(format!("RegOpenKeyExW({path}) failed: {rc:?}"))
    }
}

/// A registry key made by this probe, deleted on drop together with every missing parent it made along the way.
/// Created only if absent, so a key this probe did not make is never touched. A delete that fails fails the test,
/// unless it is already failing.
pub(crate) struct AppPathKey {
    hive: HKEY,
    /// What this guard still has to delete, deepest first: the key, then each parent that did not exist before.
    created: Vec<String>,
}

impl AppPathKey {
    pub(crate) fn register_at(
        hive: HKEY,
        options: REG_OPEN_CREATE_OPTIONS,
        key: &str,
        target: &Path,
    ) -> Result<Self, String> {
        Self::register_at_with(hive, options, key, target, &mut |_| {})
    }

    /// [`register_at`](Self::register_at), calling `before_create` with each level's path just before that level is
    /// created: a seam for another process creating a parent in between.
    ///
    /// Each level is created on its own and only the levels `RegCreateKeyExW` reports as new are recorded, so a
    /// parent that appears concurrently is never taken for this guard's own.
    pub(crate) fn register_at_with(
        hive: HKEY,
        options: REG_OPEN_CREATE_OPTIONS,
        key: &str,
        target: &Path,
        before_create: &mut dyn FnMut(&str),
    ) -> Result<Self, String> {
        // Dropped on every early return below, which deletes what was created so far.
        let mut guard = AppPathKey {
            hive,
            created: Vec::new(),
        };
        let levels: Vec<&str> = key.match_indices('\\').map(|(i, _)| &key[..i]).chain([key]).collect();
        for level in levels {
            before_create(level);
            let name = wide(OsStr::new(level));
            let mut hkey = HKEY::default();
            let mut disposition = REG_CREATE_KEY_DISPOSITION::default();
            // SAFETY: `name` is NUL-terminated and outlives the call; the out-pointers are live locals.
            let rc = unsafe {
                RegCreateKeyExW(
                    hive,
                    PCWSTR(name.as_ptr()),
                    None,
                    PCWSTR::null(),
                    options,
                    KEY_WRITE,
                    None,
                    &mut hkey,
                    Some(&mut disposition),
                )
            };
            if rc != ERROR_SUCCESS {
                return Err(format!("RegCreateKeyExW({level}) failed: {rc:?}"));
            }
            let created = disposition == REG_CREATED_NEW_KEY;
            if created {
                guard.created.insert(0, level.to_owned());
            }
            let is_key = level.len() == key.len();
            let set = if is_key && created {
                let value: Vec<u8> = wide(target.as_os_str()).iter().flat_map(|u| u.to_le_bytes()).collect();
                // SAFETY: `hkey` is open for writing; `value` is a NUL-terminated UTF-16 string as bytes.
                Some(unsafe { RegSetValueExW(hkey, PCWSTR::null(), None, REG_SZ, Some(&value)) })
            } else {
                None
            };
            // SAFETY: `hkey` was opened above and is closed once.
            let _ = unsafe { RegCloseKey(hkey) };
            if is_key && !created {
                return Err(format!(
                    "{key} already existed; refusing to overwrite a key this probe did not make"
                ));
            }
            if let Some(set) = set {
                if set != ERROR_SUCCESS {
                    return Err(format!("RegSetValueExW failed: {set:?}"));
                }
            }
        }
        Ok(guard)
    }

    /// Deletes what is left to delete; keeps what could not be deleted, so a second call tries it again. A key that
    /// is already gone is done.
    pub(crate) fn delete(&mut self) -> Vec<String> {
        let mut failures = Vec::new();
        let mut kept = Vec::new();
        for path in std::mem::take(&mut self.created) {
            let name = wide(OsStr::new(&path));
            // SAFETY: the name is NUL-terminated and outlives the call.
            let rc = unsafe { RegDeleteKeyW(self.hive, PCWSTR(name.as_ptr())) };
            if rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND {
                failures.push(format!("RegDeleteKeyW({path}) failed: {rc:?}"));
                kept.push(path);
            }
        }
        self.created = kept;
        failures
    }

    /// [`delete`](Self::delete), failing the test on a failure unless it is already failing.
    pub(crate) fn finish(&mut self) {
        let failures = self.delete();
        for failure in &failures {
            println!("CLEANUP: {failure}");
        }
        if !failures.is_empty() && !std::thread::panicking() {
            panic!("a registry key was left behind: {failures:?}");
        }
    }
}

impl Drop for AppPathKey {
    fn drop(&mut self) {
        self.finish();
    }
}
