//! The canary's string and buffer logic, free of Win32 so `windows_path_logic` can test it on every
//! host.

/// `path` spelled so the file APIs take it literally: `\\?\` and `\??\` paths as given, a device
/// path `\\.\X` as `\\?\X`, a UNC path under `\\?\UNC\`, anything else behind `\\?\`.
pub fn verbatim_spelling(path: &str) -> String {
    if path.starts_with(r"\\?\") || path.starts_with(r"\??\") {
        path.to_string()
    } else if let Some(rest) = path.strip_prefix(r"\\.\") {
        format!(r"\\?\{rest}")
    } else if let Some(rest) = path.strip_prefix(r"\\") {
        format!(r"\\?\UNC\{rest}")
    } else {
        format!(r"\\?\{path}")
    }
}

/// Length of `path`'s root, the part `..` cannot pop, without a trailing separator: `C:`,
/// `\\srv\share`, `\\?\C:`, `\\?\UNC\srv\share`, `\??\C:`, and `\\.` for a device path, whose
/// device name `..` does pop (measured: `\\.\C:\..` is `\\.\`). `None` for a path with no root.
pub fn root_len(path: &str) -> Option<usize> {
    let component = |s: &str| s.find('\\').unwrap_or(s.len());
    let server_share = |s: &str| {
        let server = component(s);
        match s.get(server + 1..) {
            Some(rest) => server + 1 + component(rest),
            None => s.len(),
        }
    };
    if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        return Some(8 + server_share(rest));
    }
    if path.starts_with(r"\\.\") {
        return Some(3);
    }
    for marker in [r"\\?\", r"\??\"] {
        if let Some(rest) = path.strip_prefix(marker) {
            return Some(4 + component(rest));
        }
    }
    if let Some(rest) = path.strip_prefix(r"\\") {
        return Some(2 + server_share(rest));
    }
    let b = path.as_bytes();
    (b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':').then_some(2)
}

/// What `x\..\..` resolves to from the current directory `cwd`, trailing separators trimmed: the
/// parent of `cwd`, or its root when `cwd` is a root, which `..` cannot leave.
pub fn pop_past_expectation(cwd: &str) -> String {
    let cwd = cwd.trim_end_matches('\\');
    let root = root_len(cwd).unwrap_or(0).min(cwd.len());
    match cwd[root..].rfind('\\') {
        Some(i) => cwd[..root + i].trim_end_matches('\\').to_string(),
        None => cwd[..root].to_string(),
    }
}

/// The root a rooted path (`\…`) lands on from `cwd`: its drive (`C:`) or share (`\\srv\share`),
/// per [`root_len`].
pub fn rooted_prefix(cwd: &str) -> Option<String> {
    root_len(cwd).map(|n| cwd[..n].to_string())
}

/// Compare one shape resolved under an existing root and a missing one, after mapping the missing
/// root's name onto the existing one — in an error message as well as in a result. The roots must
/// be siblings of equal length, so the mapping cannot itself introduce a difference.
pub fn compare_across_roots(
    existing: &Result<String, String>,
    missing: &Result<String, String>,
    root_e: &str,
    root_n: &str,
) -> String {
    // Error messages quote their input with `{:?}`, which doubles each backslash.
    let quoted = |r: &str| format!("{r:?}").trim_matches('"').to_string();
    let (quoted_n, quoted_e) = (quoted(root_n), quoted(root_e));
    let map = |s: &String| s.replace(root_n, root_e).replace(&quoted_n, &quoted_e);
    if missing.as_ref().map(map).map_err(map) == *existing {
        "identical".to_string()
    } else {
        format!("DIFFERS — exists: {existing:?}, missing: {missing:?}")
    }
}

/// `ERROR_MORE_DATA`: the buffer was too small; the call reported the size it needs.
pub const ERROR_MORE_DATA: u32 = 234;

/// Call `read(buffer, bytes)` until the value fits, returning the units it wrote.
///
/// `read` gets the buffer and its size in BYTES, and returns a Win32 error code, setting `bytes` to
/// the size written on success or needed on `ERROR_MORE_DATA` (the `RegGetValueW` contract). On
/// `ERROR_MORE_DATA` the buffer grows to at least that and the call is retried, so a value that
/// grows between calls is still read. Any other code is returned as `Err`.
pub fn read_growing(mut read: impl FnMut(&mut [u16], &mut u32) -> u32) -> Result<Vec<u16>, u32> {
    let mut buf = vec![0u16; 64];
    loop {
        let mut bytes = (buf.len() * 2) as u32;
        match read(&mut buf, &mut bytes) {
            0 => {
                buf.truncate((bytes as usize / 2).min(buf.len()));
                return Ok(buf);
            }
            // Always grow, so a call that under-reports its need still makes progress.
            ERROR_MORE_DATA => {
                let units = (bytes as usize).div_ceil(2).max(buf.len() + 1);
                buf.resize(units, 0);
            }
            rc => return Err(rc),
        }
    }
}

/// How a run of `cosca_testbin_image` (`testbin/image_report.rs`) ended.
#[derive(Debug, PartialEq, Eq)]
pub enum PayloadOutcome<'a> {
    /// Exit 0 with an `image=` line: the file the process was created from.
    Image(&'a str),
    /// The payload's own error signal, exit 2 with `image-error=`: it could not measure its image.
    /// A broken probe, not a platform change.
    PayloadError(&'a str),
    /// Exit 0 without an `image=` line: the payload broke its contract.
    NoImageLine,
    /// Any other exit: whatever ran was not the payload doing its job.
    OtherExit,
}

/// Classify a payload run from its exit code and stdout.
pub fn payload_outcome(code: Option<i32>, stdout: &str) -> PayloadOutcome<'_> {
    let line = |prefix: &str| stdout.lines().find_map(|l| l.strip_prefix(prefix));
    match code {
        Some(0) => line("image=").map_or(PayloadOutcome::NoImageLine, PayloadOutcome::Image),
        Some(2) => line("image-error=").map_or(PayloadOutcome::OtherExit, PayloadOutcome::PayloadError),
        _ => PayloadOutcome::OtherExit,
    }
}

/// `Ok` if every step succeeded, else one error naming every step that failed, so an early
/// failure never hides a later one.
pub fn all_succeeded(steps: impl IntoIterator<Item = (&'static str, Result<(), String>)>) -> Result<(), String> {
    let failed: Vec<String> = steps
        .into_iter()
        .filter_map(|(step, r)| r.err().map(|e| format!("{step}: {e}")))
        .collect();
    if failed.is_empty() {
        Ok(())
    } else {
        Err(failed.join("; "))
    }
}

/// The marker file for the libtest test `test_name`: `::` is not allowed in a Windows file name,
/// so module separators become `.`.
pub fn marker_file_name(test_name: &str) -> String {
    test_name.replace("::", ".")
}

/// Terminate a child, then reap it only if termination succeeded: a child that was not
/// terminated may still be alive, and an unbounded wait on it could block forever. Returns the
/// outcome of each step that ran, for [`all_succeeded`].
pub fn reap_after_terminate(
    terminate: impl FnOnce() -> Result<(), String>,
    reap: impl FnOnce() -> Result<(), String>,
) -> Vec<(&'static str, Result<(), String>)> {
    match terminate() {
        Ok(()) => vec![("terminate", Ok(())), ("reap", reap())],
        Err(e) => vec![("terminate", Err(e))],
    }
}
