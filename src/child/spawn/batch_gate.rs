//! The batch gate: refuse every program token Windows would resolve to a `.bat`/`.cmd`, because
//! `std::process` hands those to cmd.exe, whose escaping this crate does not implement
//! (CVE-2024-24576).

use crate::error::Error;

#[path = "batch_gate/streams.rs"]
mod streams;
#[path = "batch_gate/walk.rs"]
mod walk;

use streams::is_batch_program;
pub(crate) use walk::drive_prefix_len;
use walk::win32_effective_file_name;

/// The prefix Win32 acts on: everything before the first interior NUL, where `CreateProcessW` and
/// `PCWSTR` stop. Equal (and borrowed) when there is no NUL, which is how [`reject_batch_path_on`]
/// detects one without a platform-specific byte view at its own call site.
///
/// Host-independent on purpose — it computes the same prefix everywhere, which is what lets a
/// macOS run exercise the Win32 rule.
fn win32_prefix(prog: &std::path::Path) -> std::borrow::Cow<'_, std::path::Path> {
    use std::borrow::Cow;
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let bytes = prog.as_os_str().as_bytes();
        match bytes.iter().position(|&b| b == 0) {
            Some(i) => Cow::Borrowed(std::path::Path::new(std::ffi::OsStr::from_bytes(&bytes[..i]))),
            None => Cow::Borrowed(prog),
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        let units: Vec<u16> = prog.as_os_str().encode_wide().collect();
        match units.iter().position(|&u| u == 0) {
            Some(i) => Cow::Owned(std::path::PathBuf::from(std::ffi::OsString::from_wide(&units[..i]))),
            None => Cow::Borrowed(prog),
        }
    }
    // Unreachable in any buildable configuration: `crate::wait`'s `compile_error!` rejects every
    // target that is not Linux, macOS or Windows. No portable byte view to split on either.
    #[cfg(not(any(unix, windows)))]
    {
        Cow::Borrowed(prog)
    }
}

const BATCH: &str = "cmd.exe batch escaping is not implemented (CVE-2024-24576); \
                     run it through cmd.exe yourself — .executable(\"cmd.exe\") plus a \
                     .commandline() you have escaped for cmd.exe";
const NO_FILE: &str = "the path names no file of its own, so which image loads is decided by \
                       the current directory or PATH — and a .bat-named directory there makes \
                       std::process substitute cmd.exe (CVE-2024-24576); name the executable";
// A verbatim path resolves against nothing, so NO_FILE's reason does not apply to one.
const VERBATIM_DOTDOT: &str = "a \\\\?\\ path is never normalised, so `..` is a literal file name \
                               here — and no file may be called that; name the executable";

/// Reject a program token carrying an interior NUL, or naming a `.bat`/`.cmd`: Win32 silently
/// truncates at the NUL (`PCWSTR` has no length), and cmd.exe batch escaping is a distinct,
/// unimplemented vector (CVE-2024-24576 / BatBadBut). Shared by every backend — the std path
/// (`build_std_command`), the raw one (`windows_raw::reject_batch_program`), and the elevated
/// `ShellExecuteEx` launch.
///
/// The rule, and why each half is a fact about Win32, is in [`reject_batch_path_on`]; this asks it
/// for the running host's verdict.
pub(crate) fn reject_batch_path(prog: &std::path::Path) -> Result<(), Error> {
    reject_batch_path_on(prog, cfg!(windows))
}

/// PURE given `win32`: the gate's rule with the platform as DATA rather than a `cfg!` buried in
/// it, so one host can ask for either verdict — the same reason `elevation::plan::Host` carries
/// its `Os`. Both are pinned from any host by `spawn_tests`, which matters because the Windows
/// branch — the whole `win32_effective_file_name` -> `is_batch_program` composition, where every
/// subtlety lives — would otherwise be covered by the two Windows CI lanes alone. Reading `cfg!`
/// here would have let a regression back to the extension-based reading pass unnoticed off
/// Windows; see `reject_batch_path_on_windows_refuses_every_spelling_that_reaches_a_batch_file`
/// for the cross-platform harness that catches it.
///
/// This gate is LIVE on the std path today, not merely a guard for some future backend. Rust's
/// own `std::process` detects a `.bat`/`.cmd` program, swaps it for `cmd.exe` and builds a batch
/// command line (`sys/process/windows.rs`'s `is_batch_file` -> `make_bat_command_line`), so
/// anything slipping past here is handed to exactly the quoting layer cosca has not implemented.
/// It goes live a second way once `ShellExecuteEx` is gated, which has no such backstop.
///
/// An interior NUL is refused FIRST, under both verdicts, because `\0` is not a path separator
/// and neither `Path::extension()` nor the component walk below stops at one — so the name tested
/// is the INVERSE of what Win32 loads on each of the two NUL/batch shapes:
///
/// - `setup.bat` + NUL + `junk` → the effective name is `setup.bat\0junk`, yet Win32 loads the
///   real batch file `setup.bat`.
/// - `setup` + NUL + `.bat` → the effective name ends in `.bat`, yet Win32 loads `setup`, which is
///   no batch file — so the batch refusal would blame CVE-2024-24576 for a program that does not
///   carry that vector, and interpolate a raw U+0000 into a message bound for logs and terminals.
///
/// Refusing the NUL outright settles both shapes, and makes this gate SELF-SUFFICIENT rather than
/// a rule each caller must order its own NUL check in front of — the std backend, the DEFAULT
/// Windows path, has none to order. The reason given differs by verdict because the facts do: off
/// Win32 nothing truncates, so the token simply names no file.
///
/// The batch half is `win32`-only, because it too is a fact about Win32 rather than the request:
/// Win32 routes a `.bat`/`.cmd` through cmd.exe, which is what CVE-2024-24576 needs. Elsewhere a
/// clean `deploy.bat` is an ordinary executable the host runs, so refusing it would report "not
/// supported on windows" about a Linux or macOS host that runs it fine — and send its caller to
/// audit a batch vector that cannot reach them.
///
/// A path that resolves to NO NAME of its own is refused too, not accepted. std does not test the
/// string it was given: it runs the program through `GetFullPathNameW` (or the PATH search) and
/// applies `has_bat_extension` to the RESULT. A RELATIVE path that pops past its own first
/// component does not vanish — Win32 goes on popping into the ancestors of the current directory,
/// so with a cwd of `C:\w.bat` (a directory, which Windows permits) `x\..` resolves to `C:\w.bat`
/// and std substitutes `cmd.exe`. That is the hole this refusal closes.
///
/// A ROOTED path never reaches the cwd at all, so it is refused for having the same shape rather
/// than for the same danger — and what it clamps at depends on the root. A drive-rooted or
/// drive-relative path clamps at a root with no name of its own (`C:\`, `\`), which is not a
/// loadable image, and nor does a device path, which clamps at `\\.\`. A UNC path clamps at
/// `\\server\share`, which DOES leave a named final component, and that name is judged like any
/// other — see [`win32_effective_file_name`].
///
/// A verbatim (`\\?\`) path is judged by a rule of its own — see [`verbatim_refusal`].
pub(super) fn reject_batch_path_on(prog: &std::path::Path, win32: bool) -> Result<(), Error> {
    let loaded = win32_prefix(prog);
    if loaded.as_os_str() != prog.as_os_str() {
        // A literal: interpolating the token would put a raw U+0000 into a message bound for logs
        // and terminals, which is half of what this gate is removing.
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            if win32 {
                "the program path contains an embedded NUL, which Win32 would silently truncate"
            } else {
                "the program path contains an embedded NUL, so it names no file"
            },
        )));
    }
    if !win32 {
        return Ok(());
    }
    // Past the early return `loaded` and `prog` are the same string, so the rest reads `prog`.
    let text = prog.as_os_str().to_string_lossy();
    // Only backslashes spell the verbatim prefix; `\\?\` and `//?/` are different paths to
    // Win32, and only the first suppresses resolution. std's other verbatim prefix, `\??\`, is
    // walked below; see `verbatim_refusal` for why that changes no verdict.
    let refusal = if text.starts_with(r"\\?\") {
        verbatim_refusal(&text)
    } else {
        // The name Win32 will actually OPEN, not the one `Path::file_name()` reports: on
        // Windows those differ for any path ending in a `..` component, and the difference is
        // a live bypass.
        match win32_effective_file_name(prog) {
            Some(name) if is_batch_program(&name) => Some(BATCH),
            Some(_) => None,
            None => Some(NO_FILE),
        }
    };
    match refusal {
        None => Ok(()),
        Some(BATCH) => Err(Error::Unsupported {
            op: format!("running {}", prog.display()),
            platform: "windows",
            detail: BATCH.into(),
        }),
        // Refused on its shape before any search, so `InvalidInput`, as `crate::resolve` refuses a
        // name that names no file.
        Some(detail) => Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{detail}: {prog:?}"),
        ))),
    }
}

/// Whether a VERBATIM (`\\?\`) program reaches a batch file. std asks a different question of one
/// than it asks of any other path, and this is that question.
///
/// For an ordinary program std runs the string through `GetFullPathNameW` and tests the RESULT;
/// for a verbatim one `is_batch_file` is a literal test of the last four UTF-16 units of the
/// string. std does call `GetFullPathNameW` on a short `\\?\C:\…` program first (`to_user_path`,
/// on the text after the prefix), but drops the prefix only when the result round-trips — and a
/// string that round-trips reads the same under both tests. So `\\?\C:\x.bat.` keeps its prefix,
/// ends in `bat.`, and cmd.exe is not substituted — while the plain `C:\x.bat.` loses its trailing
/// dot on the way through `GetFullPathNameW` and reaches the batch file. The prefix does not merely
/// spell the same file differently; it selects a different resolution.
///
/// std's `is_verbatim` also accepts `\??\`, which this gate does NOT route here: it walks `\??\…`
/// as an ordinary rooted path. No verdict turns on that. A `\??\` string ending in `.bat`/`.cmd`
/// has a final component ending in it, which the walk refuses; the walk's trimming only
/// over-refuses (`\??\C:\x.bat.`, which std's literal test passes).
///
/// Measured on Windows runners, both architectures: `...`, `....`, `" "` and `"x "` are creatable,
/// listable and openable through the prefix, and both `CreateProcessW` and `std::process` spawn
/// them, while the plain spelling fails with access-denied. Refusing those refused a loadable
/// executable, which is why this is not the component machinery below with the trimming disabled.
///
/// The other refusals are a final component that trims or splits to a batch name, below, and `..`,
/// which no collapse turns into a path operation here: it is a literal file name, and no file may
/// be called that (measured: `ERROR_INVALID_NAME`). Other unloadable spellings — a trailing
/// separator, a final `.` — are left to fail with the OS's own error, which says more about why
/// than a security refusal would.
///
/// # What trims or splits to a batch name is refused, conservatively
///
/// The final component is also judged by the plain rule, [`is_batch_program`], and so is the piece
/// after its last `/`. That refuses `\\?\C:\x.bat.` and `\\?\C:\x.bat ` (one trailing space),
/// which std's literal test passes: the stricter verdict wherever the two rules differ. It also
/// refuses `\\?\C:\x.bat:s`, `\\?\C:\x.bat:` and `\\?\C:\x.bat::$DATA` as their plain
/// spellings are. std hands `CreateProcessW` the same string for each stream pair — each
/// round-trips through `GetFullPathNameW`, so `to_user_path` strips the prefix — and substitutes
/// cmd.exe for neither. What is unmeasured is whether `CreateProcessW`, handed any of these names,
/// launches cmd.exe on its own. ReactOS's `CreateProcessInternalW` says no (it tests the last four
/// characters of the name), which would make all of these refusals over-refusals, but Windows' own
/// kernelbase may read the extension differently.
///
/// The measurement that would license narrowing both: on a Windows runner, write `x.bat` whose
/// default stream and an `s` stream both hold a batch script that leaves a marker file, then
/// spawn all six spellings, plain and prefixed, through a direct `CreateProcessW` (which gets the
/// prefix as written) and through `std::process`. The call failing with `ERROR_BAD_EXE_FORMAT`
/// and no marker for every spelling licenses it; any marker means these refusals close a hole.
fn verbatim_refusal(text: &str) -> Option<&'static str> {
    let lower = text.to_ascii_lowercase();
    if lower.ends_with(".bat") || lower.ends_with(".cmd") {
        return Some(BATCH);
    }
    // `/` is an ordinary filename character under the prefix, so only `\` separates. The piece
    // after the last `/` is judged as well, as the stricter reading.
    let last = text.rsplit('\\').next().expect("rsplit yields at least one piece");
    let after_slash = last.rsplit('/').next().expect("rsplit yields at least one piece");
    if is_batch_program(last) || is_batch_program(after_slash) {
        return Some(BATCH);
    }
    (last == "..").then_some(VERBATIM_DOTDOT)
}

#[cfg(test)]
#[path = "batch_gate_tests.rs"]
mod batch_gate_tests;

#[cfg(test)]
#[path = "batch_gate/oracle_tests.rs"]
mod oracle_tests;
