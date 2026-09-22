//! The batch gate: refuse every program token Windows would resolve to a `.bat`/`.cmd`, because
//! `std::process` hands those to cmd.exe, whose escaping this crate does not implement
//! (CVE-2024-24576).

use crate::error::Error;

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
/// here left it possible to revert this function to the `Path::extension()` rule it replaced and
/// stay green on four of six.
///
/// This gate is LIVE on the std path today, not merely a guard for some future backend. Rust's
/// own `std::process` detects a `.bat`/`.cmd` program, swaps it for `cmd.exe` and builds a batch
/// command line (`sys/process/windows.rs`'s `is_batch_file` -> `make_bat_command_line`), so
/// anything slipping past here is handed to exactly the quoting layer cosca has not implemented.
/// It goes live a second way once `ShellExecuteEx` is gated (#135), which has no such backstop.
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
/// loadable image. A UNC path clamps at `\\server\share`, which DOES leave a named final
/// component, and that name is judged like any other — see [`win32_effective_file_name`].
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
        // a live bypass. Under BOTH readings of an interior dots-and-spaces segment, because
        // either can be the one Win32 applies and each exposes a different component.
        let names = [Interior::Dropped, Interior::Named].map(|reading| win32_effective_file_name(prog, reading));
        if names.iter().flatten().any(|name| is_batch_program(name)) {
            Some(BATCH)
        } else if names.iter().any(Option::is_none) {
            Some(NO_FILE)
        } else {
            None
        }
    };
    if let Some(detail) = refusal {
        return Err(Error::Unsupported {
            op: format!("running {}", prog.display()),
            platform: "windows",
            detail: detail.into(),
        });
    }
    Ok(())
}

/// Whether a VERBATIM (`\\?\`) program reaches a batch file. std asks a different question of one
/// than it asks of any other path, and this is that question.
///
/// For an ordinary program std runs the string through `GetFullPathNameW` and tests the RESULT;
/// for a verbatim one `is_batch_file` is a literal test of the last four UTF-16 units of the
/// string. std does call `GetFullPathNameW` on a short `\\?\C:\…` program first (`to_user_path`,
/// on the text after the prefix), but drops the prefix only when the result round-trips — and a
/// string that round-trips reads the same under both tests. So `\\?\C:\x.bat.` keeps its prefix,
/// ends in `bat.`, cmd.exe is not substituted, and the image loads like any other — while the plain
/// `C:\x.bat.` loses its trailing dot on the way through `GetFullPathNameW` and reaches the batch
/// file. The prefix does not merely spell the same file differently; it selects a different
/// resolution.
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
/// The one other refusal is `..`, which no collapse turns into a path operation here: it is a
/// literal file name, and no file may be called that (measured: `ERROR_INVALID_NAME`). Other
/// unloadable spellings — a trailing separator, a final `.` — are left to fail with the OS's own
/// error, which says more about why than a security refusal would.
///
/// # The stream spellings rest on an unmeasured reading of kernelbase
///
/// `\\?\C:\x.bat:s`, `\\?\C:\x.bat:` and `\\?\C:\x.bat::$DATA` are ACCEPTED while their plain
/// spellings are refused, yet std hands `CreateProcessW` the same string for each pair: each
/// round-trips through `GetFullPathNameW`, so `to_user_path` strips the prefix. One of the two
/// verdicts is wrong. std itself substitutes cmd.exe for neither, so the question is whether
/// `CreateProcessW`, handed a data stream of a batch file, launches cmd.exe on its own. ReactOS's
/// `CreateProcessInternalW` says no — it tests the last four characters of the name — which would
/// make the plain refusal an over-refusal and this acceptance correct. Windows' own kernelbase is
/// unmeasured, so the plain refusal stays. The measurement that settles it: on a Windows runner,
/// write `x.bat` whose default stream and an `s` stream both hold a batch script that leaves a
/// marker file, then spawn all six spellings, plain and prefixed, through both a direct
/// `CreateProcessW` (which gets the prefix as written) and `std::process`, and record whether the marker appears or the call fails with
/// `ERROR_BAD_EXE_FORMAT`. A marker means these acceptances are holes.
fn verbatim_refusal(text: &str) -> Option<&'static str> {
    let lower = text.to_ascii_lowercase();
    if lower.ends_with(".bat") || lower.ends_with(".cmd") {
        return Some(BATCH);
    }
    // `/` is an ordinary filename character under the prefix, so only `\` separates.
    let last = text.rsplit('\\').next().expect("rsplit yields at least one piece");
    (last == "..").then_some(VERBATIM_DOTDOT)
}

/// Whether `file_name` names a batch script to Win32 — every stream piece, not just the name.
///
/// A name reaches a batch file if ANY piece [`ntfs_stream_names`] yields from it does. That
/// covers both ways one can be spelled at once:
///
/// - **As the filesystem resolves it.** `x.bat:s` names `x.bat` through a data stream, and
///   `x.bat ` / `x.bat.` reach it because Win32 strips trailing spaces and dots. The stream half is
///   an over-refusal as far as std goes: `C:\x.bat:s`, `C:\x.bat:` and `C:\x.bat::$DATA` resolve
///   to themselves, which `has_bat_extension` does not read as batch (measured), so std does not
///   substitute cmd.exe. Whether `CreateProcessW` then launches cmd.exe for them itself is
///   unmeasured; see [`verbatim_refusal`], whose prefixed spellings of the same strings are
///   accepted.
/// - **As written.** `ShellExecuteEx` reads the handler off the last `.` anywhere in the string
///   (`PathFindExtension`). std asks a differently-worded question with the same answer: it runs
///   the program through `GetFullPathNameW` — or, for a verbatim `\\?\` path, takes it literally —
///   and tests whether the result ENDS in `.bat`/`.cmd`, case-insensitively
///   (`sys/process/windows.rs`'s `has_bat_extension`). So `x.exe:payload.bat` is a batch file that
///   runs out of the alternate data stream — and it is refused as the PIECE `payload.bat`, not by
///   any separate rule. Testing the whole string for a batch extension beside this adds no
///   refusal; `the_stream_reading_subsumes_the_shell_reading` checks that exhaustively to six
///   characters and keeps it true.
///
/// Reading only the piece before the FIRST separator loosens the gate, because the extension then
/// comes from before the stream name.
///
/// Verbatim (`\\?\`) paths never reach here: nothing is trimmed or collapsed under that prefix,
/// and std tests the string as given, so [`verbatim_refusal`] owns them. Off Win32 nothing reaches
/// here at all — [`reject_batch_path_on`] returns before this, because a `.bat` is an ordinary
/// executable to every other host.
pub(super) fn is_batch_program(file_name: &str) -> bool {
    ntfs_stream_names(file_name).any(is_batch_by_shell)
}

/// The final component of `prog` as Win32 will resolve it, collapsing `.` and `..` and stripping
/// the trailing dots and spaces Win32 removes from every component.
///
/// `Path::file_name()` is not good enough here, and the gap is exploitable. It returns `None` for
/// any path whose last component is `..`, so `x.bat\y\..` slipped the gate untouched — while
/// `GetFullPathNameW` collapses it straight back to `x.bat`, and `std::process` then detects the
/// batch extension and hands the program to `cmd.exe`. The same file refused as `x.bat` was
/// accepted spelled `x.bat\y\..`.
///
/// Only a segment that is exactly `..` pops, and only one that is exactly `.` is skipped. A
/// segment that is only dots and spaces yet is neither (`...`, `.. `, `.. .`, a lone space) is
/// something else, and what depends on where it stands:
///
/// - **Final**, it trims away to nothing and DROPS OUT, popping nothing. Measured on x64 and arm64
///   runners for `...`, `....`, `.. .`, `.. ..`, `" "`, `". "` and `".. "`: `x.bat\y\` plus any
///   of them resolves to `…\x.bat\y\`, so `y` survives and the batch file stays covered.
/// - **Interior**, it is kept as a name — a lone trailing `.` comes off, a run of two or more does
///   not, spaces never do (measured by the Windows path probe's interior-trim table, not yet one of
///   its assertions). Until the probe asserts it, [`reject_batch_path_on`] also asks the
///   [`Interior::Dropped`] reading, and narrowing to [`Interior::Named`] is left to that follow-up.
///
/// `None` means the path named no file of its own: it was empty, was a bare root or drive prefix,
/// or popped its own components away. That last case did NOT collapse to nothing — a relative
/// path goes on popping into the ancestors of the current directory, so `x\..` resolves to
/// whatever the cwd is and `.` resolves to the cwd itself, while a rooted one clamps at its root.
/// The name is real, this gate just cannot see it, which is why [`reject_batch_path_on`] refuses
/// `None` rather than accepting it. A data-stream spelling is not that — `x.bat:` names a file and
/// comes back as one.
///
/// # A UNC root has a NAME, and `..` never pops it
///
/// `\\server\share` is a root the way `C:\` is, but unlike `C:\` its last component is a name.
/// Win32 skips server and share before it collapses anything (ReactOS's `RtlpCollapsePath` calls
/// `RtlpSkipUNCPrefix` first; .NET pins `\\LOCALHOST\share5\..` resolving to `\\LOCALHOST\share5`),
/// so no number of `..` reaches past the share, and a share named `x.bat` stays the effective name.
/// Walk a UNC path as if it had no root and every one of `\\srv\x.bat\..`, `//srv/x.bat/..`,
/// `\/srv\x.cmd\..` and `\\srv\x.bat\y\..\..` reduces to `srv` — not a batch
/// name, so the gate returns `Ok` on a token `std::process` hands straight to `cmd.exe`, and
/// `make_bat_command_line` appends the rest of a `.commandline()` verbatim. `GetFullPathNameW`
/// does no I/O, so the share need not exist for that to happen.
///
/// Server and share are POSITIONAL: Win32 takes the two segments after the `\\` without reading
/// them, so a `.`, `..` or empty segment there is part of the root rather than an operation on it.
/// That position has to be exact, not merely deep enough. A floor set one component too DEEP
/// suppresses a pop Win32 performs, and the final name moves to a later component: skip the
/// dots-only server in `\\...\x.bat\y\..` and the root becomes `x.bat\y`, the pop is clamped
/// away, and the gate judges `y` while Win32 resolves `\\...\x.bat`.
///
/// A `\\.\` or `//?/` device path puts its root in the same two positions (.NET's `GetRootLength`
/// counts `\\.\C:\` as the root of `\\.\C:\x`), so one rule covers both.
///
/// A literal `\\?\` never arrives: [`verbatim_refusal`] owns it.
///
/// # The token, not the resolved path (#144)
///
/// This runs on the program token AS WRITTEN, so it has to predict what that string resolves to
/// instead of resolving it. Two over-refusals are the price, both unchanged by the measurement
/// above. A path that pops past its own first component lands somewhere only the cwd can name, so
/// the gate refuses every one rather than guess. And a path whose final component drops out
/// resolves to a name with a trailing separator — `x.bat\...` is `…\x.bat\`, which std's
/// `has_bat_extension` does NOT read as a batch file — yet the gate judges the exposed `x.bat` and
/// refuses. #144 moves resolution ahead of the gate, at which point both collapse into a suffix
/// test on the resolved path and there is nothing left to predict.
pub(super) fn win32_effective_file_name(prog: &std::path::Path, interior: Interior) -> Option<String> {
    let text = prog.as_os_str().to_string_lossy();
    // Each surviving component, paired with whether it is the path's FIRST segment — the only
    // position a drive prefix can occupy.
    let mut stack: Vec<(&str, bool)> = Vec::new();
    let mut segments = text.split(['/', '\\']).enumerate();
    // A UNC (or `\\.\` device) root: the two segments after the leading pair, taken by POSITION
    // and never collapsed. `None` for a root with no share at all — `\\server` names nothing
    // loadable.
    let root = if starts_with_two_separators(&text) {
        segments.nth(1).expect("two separators are two empty segments");
        let (_, server) = segments.next()?;
        let (_, share) = segments.next()?;
        Some((server, share))
    } else {
        None
    };
    for (position, segment) in segments {
        // A repeated separator, never a component.
        if segment.is_empty() {
            continue;
        }
        if segment == "." {
            continue;
        }
        if segment == ".." {
            // Popping an empty stack under a UNC root is popping into the root, which Win32
            // clamps at; `pop` on an empty stack is exactly that no-op.
            stack.pop();
            continue;
        }
        // Ordinary component: Win32 drops trailing dots and spaces. Nothing left of it means a
        // dots-and-spaces component; see the doc for its two readings. Kept, it is an EMPTY name,
        // which a later `..` can pop and which is never a batch file.
        let name = segment.trim_end_matches([' ', '.']);
        if name.is_empty() && interior == Interior::Dropped {
            continue;
        }
        stack.push((name, position == 0));
    }
    // Whatever is final drops out under either reading, however many of them trail.
    while stack.last().is_some_and(|(name, _)| name.is_empty()) {
        stack.pop();
    }
    if stack.is_empty() {
        if let Some((server, share)) = root {
            return unc_root_name(server, share);
        }
    }
    let (last, leading) = stack.pop()?;
    // A BARE drive prefix names no file — and only the first segment can be one. Elsewhere a
    // component ending in `:` is a data-stream spelling of a real file: `a:` is the file `a`, just
    // as `x.exe:` is the file `x.exe`, and returning `None` for either made the gate refuse a
    // loadable image over a one-character name.
    if leading && is_drive_prefix(last) {
        return None;
    }
    Some(last.to_string())
}

/// How to read a dots-and-spaces segment (`...`, `.. `, a lone space) that is NOT the path's final
/// one. [`Interior::Named`] is the measured reading; see [`win32_effective_file_name`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Interior {
    /// It drops out, as the measured final one does: `y\x.bat\...\..` resolves to `y`.
    Dropped,
    /// It is a name, and a later `..` pops it: `y\x.bat\...\..` resolves to `y\x.bat`. Microsoft's
    /// path-format rules read it this way (only the final segment is trimmed, and three or more
    /// periods are "a valid file/directory name"), as does Wine's `collapse_path`, which also
    /// reproduces every final-position measurement.
    Named,
}

/// The name a path collapsed onto its UNC root resolves to, judged conservatively.
///
/// Win32 resolves it to `\\server\share`, so the share is the name std tests. The server is
/// judged as well: whether `..` spelled INSIDE the root is collapsed is not something this crate
/// has measured, and were it collapsed `\\x.bat\..` would resolve to `\\x.bat`. So a batch-named
/// server is returned in preference to the share, and a share that trims away to nothing names no
/// file — both over-refusals, and both in the direction this gate may err.
fn unc_root_name(server: &str, share: &str) -> Option<String> {
    let server = server.trim_end_matches([' ', '.']);
    if is_batch_program(server) {
        return Some(server.to_string());
    }
    let share = share.trim_end_matches([' ', '.']);
    (!share.is_empty()).then(|| share.to_string())
}

/// Whether the path opens with the two separators that make Win32 read a UNC root. Either
/// separator spells it in either position: `\\srv`, `//srv` and `\/srv` are one path to Win32.
fn starts_with_two_separators(text: &str) -> bool {
    let mut chars = text.chars();
    matches!((chars.next(), chars.next()), (Some('\\' | '/'), Some('\\' | '/')))
}

/// A bare `C:` — two bytes, a drive letter and a colon.
fn is_drive_prefix(component: &str) -> bool {
    matches!(component.as_bytes(), [d, b':'] if d.is_ascii_alphabetic())
}

/// Whether the shell would treat `name` as a batch file: the extension is everything after the
/// LAST `.` anywhere in the name, matching `PathFindExtension` and std's own `has_bat_extension`
/// (a case-insensitive `ends_with(".bat" | ".cmd")`, which is the same predicate).
///
/// Deliberately not `Path::extension()`, which differs in two ways that both matter. It returns
/// `None` for a name that IS `.bat` (a leading dot with no other dot), and it stops at nothing —
/// so `x.exe:payload.bat` reads as extension `exe:payload.bat` rather than the `bat` the shell
/// acts on.
pub(super) fn is_batch_by_shell(name: &str) -> bool {
    match name.rfind('.') {
        Some(dot) => {
            let ext = name[dot + 1..].to_ascii_lowercase();
            ext == "bat" || ext == "cmd"
        }
        None => false,
    }
}

/// The file name and every data-stream name inside a path component, each trimmed the way Win32
/// trims a component.
///
/// Two normalisations, and the ORDER matters: split at the stream separators FIRST, then trim.
/// Note `x.bat:s ` does NOT discriminate — it yields `x.bat` either way, because trim-then-split
/// still splits. The witnesses are a trailing space or dot BEFORE the separator: `x.bat.:s`,
/// `x.bat :s`, `x.bat. :s`. Split-then-trim yields `x.bat` for all three; trim-then-split leaves
/// `x.bat.` / `x.bat ` / `x.bat. `, which the extension check then misses.
///
/// EVERY piece, not just the one before the first separator: taking only the first read
/// `x.exe:payload.bat:` as the file `x.exe`, losing the batch name, while the same stream spelled
/// `x.exe:payload.bat` was refused.
///
/// A leading `C:` is a drive, not a separator. Skipping it changes NO VERDICT — the only piece it
/// suppresses is a bare drive letter, one character with no dot in it, which is never a batch
/// name — and it is kept for the contract rather than the verdict: every piece this yields is a
/// name Win32 would open, and a drive letter is not one. The skip WAS load-bearing when only the
/// first piece was read, which is how `C:x.bat:s` came to be allowed while `x.bat:s` was refused.
pub(super) fn ntfs_stream_names(name: &str) -> impl Iterator<Item = &str> {
    let rest = match name.get(..2) {
        Some(prefix) if is_drive_prefix(prefix) => &name[2..],
        _ => name,
    };
    rest.split(':').map(|part| part.trim_end_matches([' ', '.']))
}
