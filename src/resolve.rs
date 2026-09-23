//! Which file a `Command` loads — on the spawn paths that currently consult it.
//!
//! **Coverage today: only the Windows raw `CreateProcessW` backend (sync and its tokio mirror),
//! and only for a `Search` program** — i.e. one recorded by `Command::executable()`, or the
//! argv[0]/first-token fallback when neither setter was called. That backend is reached when
//! `Command::executable_path()` is set or an fd >= 3 is mapped.
//!
//! An `Exact` program, from `Command::raw_executable()`, deliberately does NOT come through
//! [`resolve`]: "load exactly this file" is the absence of this module's SEARCH policy, not an
//! application of it. Where a sink would search a relative name, it is put in a form no sink
//! searches: on the unelevated POSIX spawn a `./`-anchored name ([`exact::anchor_posix`]), on the
//! POSIX elevation backends an absolute path ([`exact::complete_posix`]), and on the Windows
//! elevated path an absolute path from `windows_raw::resolve::absolutise_exact` — see its doc for
//! why `ShellExecuteEx` forces that step where `CreateProcessW` does not.
//!
//! It does, however, share this module's naming CLASSIFIERS: every `Exact` arm refuses a program
//! that names no file via [`names_no_file`], so the two axes cannot drift apart on what counts as
//! a filename. Classifying is not searching.
//!
//! Every other spawn path resolves a `Search` program itself, ignorant of this module: POSIX
//! spawning calls `execvp`/`posix_spawn`'s own PATH search, and the Windows elevated
//! (`ShellExecuteEx`) path passes a `Search` `lpFile` through unresolved. `src/lib.rs`'s
//! `#[cfg_attr(not(windows), allow(dead_code))]` on this module tracks exactly that: the `allow`
//! goes away once those paths route through [`resolve`] too.
//! Producing an ABSOLUTE path is what would let a backend skip its own search once it is wired
//! up — `execvp` does not search a name containing a separator, and `ShellExecuteEx` skips its
//! directory search for an absolute `lpFile` (though not `PATHEXT`; see
//! [`reject_unloadable_image`]) — but that wiring has not happened yet for either.
//!
//! Classification is byte-level and parameterised by [`ResolveInput::windows`] rather than using
//! `std::path`, whose parsing is host-specific — `Path::new("C:tool").prefix()` is `None` off
//! Windows, so a `Path`-based rule could not be exercised from a POSIX host at all.
//!
//! A bare name is resolved from [`ResolveInput::system_dirs`] (Windows only) and then `PATH` —
//! **never** the current directory. `system_dirs` is likewise taken as a parameter rather than
//! queried from the OS here, for the same host-independence reason; see its doc for what it
//! contains and why it precedes `PATH`.
//!
//! # Which error kind
//!
//! The two kinds [`resolve`] returns answer different questions, and the split is part of the
//! public contract (see [`crate::Command::executable`]):
//!
//! - [`std::io::ErrorKind::InvalidInput`] — the string was NOT ACCEPTED. It was refused on its
//!   shape; no search ran, and no filesystem result is being reported.
//! - [`std::io::ErrorKind::NotFound`] — the string was acceptable, the search ran to this
//!   module's policy, and nothing matched.
//!
//! The operational test for a new rule is **could a different filesystem make this input
//! succeed?** No — the refusal is a property of the string, not of the disk — means
//! `InvalidInput`. Yes means `NotFound`. So `C:tool` (relative to a drive's own current
//! directory, which cosca does not track) and `C:\` (a directory, whatever is on the disk) are
//! refusals, while a missing `tool` or `C:\abs\missing.exe` is a miss. A refusal must be stated
//! explicitly and early, never left to fall out of candidate filtering: that reports the right
//! kind by accident and changes it silently when the filtering does.

use crate::error::Error;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

pub(crate) mod exact;

/// Everything the policy reads. Taken as parameters so the rules are testable without touching
/// the ambient environment.
pub(crate) struct ResolveInput<'a> {
    /// The program as the caller wrote it.
    pub program: &'a Path,
    /// The directory the CHILD will run in: `Command::cwd()` when set, else the parent's.
    pub cwd: &'a Path,
    /// Directories searched for a bare name BEFORE `PATH`, in order. Ignored entirely when
    /// `windows` is `false` — POSIX has no analogous search order to preserve.
    ///
    /// On Windows this reproduces `CreateProcessW`'s documented NULL-`lpApplicationName` search
    /// order — app directory, then the System32 directory, then the Windows directory — MINUS the
    /// parent's current directory, which this crate refuses to search at all (see `cwd`'s own
    /// doc and the module doc above). That framing is what makes prepending these directories
    /// provably monotonic rather than just "probably fine": the old, unpatched order was app dir
    /// -> cwd -> System32 -> Windows dir -> `PATH`; removing the cwd step is a strict narrowing,
    /// but if this crate ALSO silently dropped the system-directory precedence over `PATH` — which
    /// is exactly what happens if `system_dirs` is left empty for a route that has no
    /// `executable()` set — that would be a strict WIDENING on that route: a user-writable
    /// directory placed early on `PATH` (a dev toolchain install, an `%LOCALAPPDATA%\...\WindowsApps`
    /// shim) would then shadow e.g. `System32\find.exe`, a new way to load the wrong binary that
    /// the pre-patch code never had. The caller passes these in (rather than this module calling
    /// `GetSystemDirectoryW`/`GetWindowsDirectoryW`/`current_exe` itself) so the rule stays
    /// testable from a POSIX host, exactly like `windows` below.
    ///
    /// **The monotonicity argument above is stated against the NULL-`lpApplicationName`
    /// baseline**, i.e. the route where `executable()` is unset and `CreateProcessW` did its own
    /// search. It does not transfer wholesale to the `executable()` route, whose pre-patch order
    /// was `base_cwd` -> `PATH` and which never consulted the app directory, `System32` or the
    /// Windows directory at all. On that route the app directory is a NEW search source: a
    /// consumer installed at `...\Programs\MyApp\myapp.exe` calling `executable("tool")` now
    /// prefers `...\Programs\MyApp\tool.exe` over a `tool.exe` on `PATH`. Net-net that route
    /// still narrows, because the cwd step it DID have is gone and the directory holding the
    /// running image is not attacker-writable in any install worth defending — but it is a
    /// behaviour change in both directions, not a pure narrowing, and saying otherwise would
    /// overstate it.
    pub system_dirs: &'a [PathBuf],
    /// The `PATH` the CHILD will see, after `env()`/`env_clear()`.
    pub path_var: Option<&'a OsStr>,
    /// Apply Windows rules: `;` separated `PATH`, `\` a separator, drive prefixes, the `.exe` rule.
    pub windows: bool,
}

/// How the program names its file, which decides whether `PATH` (and, on Windows,
/// `system_dirs`) is consulted at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Shape {
    /// No separator and no drive prefix: the only shape that searches `system_dirs` and `PATH`.
    BareName,
    /// Contains a separator, or carries a drive prefix (`C:tool` means "relative to drive C's
    /// current directory", so a `PATH` search for it would be a lie).
    Located,
}

pub(crate) fn classify(program: &OsStr, windows: bool) -> Shape {
    let bytes = program.as_encoded_bytes();
    if bytes.iter().any(|&b| is_sep(b, windows)) {
        return Shape::Located;
    }
    // `C:tool` names a file relative to drive C's own current directory. It has no separator, so
    // a naive rule calls it bare and searches `PATH` — but joining a directory onto it collapses
    // straight back to `C:tool` (`PathBuf::push` clears for any prefixed path), so the search is
    // a lie that lands in a current directory.
    if windows && has_drive_prefix(bytes) {
        return Shape::Located;
    }
    Shape::BareName
}

fn is_sep(b: u8, windows: bool) -> bool {
    b == b'/' || (windows && b == b'\\')
}

fn has_drive_prefix(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic()
}

/// Whether `program` is DRIVE-RELATIVE: a drive prefix not followed by a separator, as in
/// `C:tool` or `D:sub\x`. Such a name is relative to that drive's own current directory — state
/// cosca does not track, so no filesystem can make it resolve. Refused, never searched; see the
/// module doc's error-kind rule.
fn is_drive_relative(program: &OsStr, windows: bool) -> bool {
    let bytes = program.as_encoded_bytes();
    windows && has_drive_prefix(bytes) && !bytes.get(2).is_some_and(|&b| is_sep(b, windows))
}

/// The length of the Windows PREFIX — the leading run naming a volume, share, device or verbatim
/// namespace rather than anything inside it: `C:`, `\\server\share`, `\\?\C:`,
/// `\\?\UNC\server\share`, `\\?\namespace`, `\\.\device`. `0` when there is none.
///
/// A prefix's own components are not filenames, so nothing may be appended to one: `\\server\share`
/// is a share root exactly as `C:\` is a volume root. `Path::file_name` agrees — it is `None` for
/// every prefix-only path — but only on a Windows HOST, which is why this is parsed byte-wise here.
///
/// `/` and `\` separate components here exactly as they do in [`final_component`], so the whole
/// string is read under ONE separator rule. `std` is deliberately not followed on this point:
/// `parse_next_component(.., verbatim: true)` splits the components of a verbatim prefix on `\`
/// alone, which would let the prefix swallow `srv/shr\a` in `\\?\UNC\srv/shr\a` and leave an empty
/// final component — refusing a path that names the file `a`. `PureWindowsPath` is the reference
/// (see [`names_no_file`]) and it normalises `/` to `\` everywhere.
///
/// Two `std` rules ARE followed, because they decide whether a prefix is present rather than how
/// its components are split: the `\\?\` marker must be spelt with literal backslashes (a `/` among
/// those four bytes means no verbatim prefix), and `\\server` with no share is no prefix at all.
fn windows_prefix_len(bytes: &[u8]) -> usize {
    if !(bytes.len() >= 2 && is_sep(bytes[0], true) && is_sep(bytes[1], true)) {
        return if has_drive_prefix(bytes) { 2 } else { 0 };
    }
    // End offset of the component starting at `at`, exclusive of its separator.
    let component = |at: usize| {
        bytes[at..]
            .iter()
            .position(|&b| is_sep(b, true))
            .map_or(bytes.len(), |i| at + i)
    };
    if bytes.len() >= 4 && bytes[2] == b'?' && is_sep(bytes[3], true) && !bytes[..4].contains(&b'/') {
        // `\\?\UNC\server\share`: server and share belong to the prefix, as they do without it.
        if bytes.len() >= 8 && bytes[4..7].eq_ignore_ascii_case(b"UNC") && is_sep(bytes[7], true) {
            let server = component(8);
            if server >= bytes.len() {
                return bytes.len();
            }
            return component(server + 1);
        }
        // `\\?\C:` — a drive is recognised only EXACTLY here: `\\?\C:x` is the verbatim namespace
        // `C:x`, not drive C. `PureWindowsPath` agrees (`\\?\C:a` names nothing), as does `std`.
        if has_drive_prefix(&bytes[4..]) && bytes.get(6).is_none_or(|&b| is_sep(b, true)) {
            return 6;
        }
        return component(4);
    }
    if bytes.len() >= 4 && bytes[2] == b'.' && is_sep(bytes[3], true) {
        return component(4); // `\\.\device`
    }
    // `\\server\share`. Missing either half is no prefix at all (`std` parses none), leaving the
    // ordinary final-component rule to answer — which refuses `\\` and `\\server\` anyway.
    let server = component(2);
    if server == 2 || server >= bytes.len() {
        return 0;
    }
    let share = component(server + 1);
    if share == server + 1 {
        0
    } else {
        share
    }
}

/// Whether `program` names a DIRECTORY rather than a file, so no search could make it executable.
///
/// True when the final component — taken after the Windows prefix, if any — is empty (a
/// separator-terminated name, a root, a bare prefix such as `\\server\share`, or the empty
/// string) or is `.`/`..`. NOTHING ELSE, on either platform.
///
/// On what counts as a NAME, `PureWindowsPath` agrees: `C:\dir\...` is named `...`, `C:\dir\tool.`
/// is named `tool.`, a lone space is a name. Win32's trimming of trailing dots and spaces is not
/// modelled, because it describes what an API does to a path STRING on its way in and not what may
/// exist on disk — Microsoft's own rule concedes a trailing-space name can be created, so trimming
/// here would refuse names that name real files.
///
/// It is not the authority on what is REFUSED, because it normalises the string first, and each of
/// the three shapes has inputs where that shows: it collapses `C:\dir\y\` to `y`, it drops the `.`
/// in `C:\dir\.` to give `dir`, and it reports `..` as an ordinary name. This module reads the RAW
/// string, where each of those final components survives, and refuses all three. (On the commonest
/// spellings it does agree — a lone `.`, a root, a bare prefix and `""` are all nameless there
/// too; it is the longer forms that diverge.)
///
/// `Path::file_name` answers the same question, but host-specifically: off Windows it sees neither
/// `\` nor any prefix, so a `Path`-based rule could not be exercised from a POSIX host at all.
/// Byte-level and parameterised, like every other classifier here — see the module doc.
///
/// `pub(crate)` for `windows_raw::resolve::reject_unnameable_program`: the `Exact` arms refuse the
/// same shapes, and sharing the predicate is what stops the two axes drifting apart on what counts
/// as a filename.
pub(crate) fn names_no_file(program: &OsStr, windows: bool) -> bool {
    matches!(final_component(program, windows), b"" | b"." | b"..")
}

/// The run after the last separator, with any Windows prefix taken off first. Shared so that
/// "which component does the rule read" has ONE answer: `names_no_file` classifies on it and
/// [`takes_the_exe_fallback`] tests its extension, and a separator set or prefix rule that changed
/// in only one of them would leave the two judging different bytes.
///
/// BOTH halves are gated on `windows`, not just the prefix: off Windows `\` is an ordinary
/// filename character, so `final_component(r"C:\dir\tool", false)` is the whole string. Byte-level
/// and parameterised, like every other classifier here — see the module doc.
fn final_component(program: &OsStr, windows: bool) -> &[u8] {
    let bytes = program.as_encoded_bytes();
    let rest = if windows {
        &bytes[windows_prefix_len(bytes)..]
    } else {
        bytes
    };
    let start = rest.iter().rposition(|&b| is_sep(b, windows)).map_or(0, |i| i + 1);
    &rest[start..]
}

/// The filenames tried in each candidate directory, in order.
///
/// **`.exe` is a property of names that get SEARCHED, not of files that get LOADED.** That split
/// is what the two shapes encode, and it is the platform's own, not this crate's invention:
///
/// - The PE/COFF format makes no extension normative — an image is identified by `MZ`, the `PE\0\0`
///   signature at the offset in `0x3c`, and header flags such as `IMAGE_FILE_DLL`. A valid PE
///   named `myapp` or `payload.tmp` is a valid PE.
/// - `CreateProcessW` documents, for the `lpApplicationName` this resolver actually feeds: "This
///   parameter must include the file name extension; **no default extension is assumed**." Its
///   command-line mode agrees the moment a path is involved: ".exe is appended" only "if the file
///   name does not contain a directory path".
/// - `PATHEXT` is a `cmd.exe` feature, and it cannot express "no extension" — there is no entry
///   meaning "try the bare name". That, not the loader, is why an extensionless image is
///   unreachable by bare name.
/// - Microsoft's current app model draws the same line: `uap5:ExecutionAlias`/`uap8:ExecutionAlias`
///   require the `Alias` — the name a user TYPES — to end in `.exe`, while the manifest's
///   `Executable=` path, which names the file, carries no such constraint.
///
/// # The rule
///
/// - POSIX (`windows` is `false`): `name` unchanged, always, either shape. POSIX has no
///   loader-level notion of an "executable extension" for this crate to reproduce.
/// - Windows, final path component already ending in `.exe`/`.com` (compared CASE-INSENSITIVELY,
///   so `TOOL.EXE` is never doubled into `TOOL.EXE.exe`): `name` unchanged, either shape. There is
///   nothing to append that would not name a file the caller did not write.
/// - Windows, [`Shape::BareName`]: `name` + `.exe`, and ONLY that, appended to the name AS
///   WRITTEN. `tool.` yields `tool..exe` and `...` yields `....exe` — odd-looking, but the one
///   rule unbranched, and appending to anything but what the caller wrote would search for a file
///   they did not name. See the monotonicity note, which counts this as a widening.
/// - Windows, [`Shape::Located`]: `name` first, always. `name` + `.exe` follows ONLY when the
///   name carries no extension at all AND names a file — see [`takes_the_exe_fallback`], which is
///   what keeps this axis from widening against `main`.
///
/// # Why `Located` tries the exact name first
///
/// A located name visits exactly one directory: the one the caller named. There is no search to
/// bias, so the ordering answers only "did the caller mean this file?" — and they wrote it, so yes.
/// Refusing it would make `executable()` unable to name a perfectly loadable image (a staged
/// `payload.tmp`, a content-addressed cache entry, a `.scr`, anything named by hash), a restriction
/// neither the format, the loader, nor the app model imposes.
///
/// The `.exe` fallback stays because it is the reason the rule exists at all: someone writing
/// `executable("bin/my-program")` for code that builds on both platforms must not be forced to
/// append `.exe` conditionally themselves.
///
/// One consequence, stated plainly: where both `bin/tool` and `bin/tool.exe` exist, the
/// extensionless one wins. A writer who can create files in that directory but not overwrite a
/// locked, running `tool.exe` can therefore decide the outcome. This is the ordering `main`
/// shipped, kept deliberately — the alternative loses the ability to name an exact file, which is
/// the whole point of the located axis.
///
/// # Why `.exe` *and* `.com`
///
/// `.exe` and `.com` are exactly the two extensions `CreateProcessW` loads directly as a PE image.
/// A `.com` file on a modern Windows install (`more.com`, `chcp.com`, `tree.com`, all shipped in
/// `System32`) is an ordinary PE whose extension is cosmetic; leaving `.com` off the allowlist
/// would turn `args(["more.com"])` into a search for the nonexistent `more.com.exe`, breaking
/// resolution of a name the system-directory search makes work today.
///
/// Script extensions (`.bat`/`.cmd`) are deliberately NOT in the allowlist — but NOT because this
/// crate treats a script as an illegitimate target. Resolving a bare name to a script is a
/// SEPARATE, CURRENTLY UNIMPLEMENTED feature: batch support needs its own `cmd.exe`
/// metacharacter quoter (alongside the existing MSVCRT one) plus PATHEXT-based resolution, and is
/// planned as its own follow-up PR. This is unrelated to — and does not weaken — this crate's
/// existing, separate batch-path rejection (see `reject_batch_path`'s own message: "cmd.exe batch
/// escaping is not implemented (CVE-2024-24576)").
///
/// # Monotonicity of the BARE-name rule — stated honestly, in both directions
///
/// This section justifies the single candidate for [`Shape::BareName`] ONLY. It is measured on the
/// surfaces that resolve a bare name, and deliberately does not reach the located axis above.
///
/// Measured on real Windows CI (amd64 and arm64 alike): `CreateProcessW` with a NULL
/// `lpApplicationName`, and `cmd.exe`, `pwsh` 7, and Windows PowerShell 5.1 alike, all refuse to
/// run an extensionless PE by bare name — a directory holding only `tool` (no extension) yields
/// `ERROR_FILE_NOT_FOUND`/"not recognized" from every one of them. So this NARROWS for a bare
/// extensionless name: the old rule tried `tool.exe` then `tool`, and that second candidate never
/// actually ran on any of those four surfaces — dropping it removes a candidate nothing on the
/// platform could launch anyway, and removes the hazard of an ambient extensionless file winning
/// in some directory the search visits.
///
/// Those same three shells (unlike `CreateProcessW` itself) resolve a bare DOTTED name via
/// PATHEXT — typing `foo.bar` runs `foo.bar.exe` when that file exists — while the OLD has-a-dot
/// heuristic here refused to append `.exe` to anything already containing a `.`, so `python3.11`
/// could never resolve even though every one of those shells finds `python3.11.exe`. So this rule
/// also WIDENS for a dotted bare name: it now appends `.exe` where it used to leave the name alone.
/// That widening is deliberate and matches the three shells, measured — it does NOT match
/// `CreateProcessW`'s own NULL-`lpApplicationName` behaviour, and is not meant to: that parity is
/// already given up on for `.bat`/`.cmd`, above.
///
/// Membership in that widening set is `Path::extension().is_some()` and nothing else — never a
/// judgement about where the dot sits. `tool.`, `...`, `.. ` and `tool. ` are all in it, and are
/// worth calling out because they are the plantable ones: `main` searched only for the literal
/// `tool.`, which Win32 opens as `tool`, whereas this rule searches for `tool..exe`, a name `main`
/// never looked for and a writer of any searched directory can create. Kept anyway, because
/// trimming is worse: it searches for `tool.exe`, a name the caller did not write EITHER, and buys
/// the refusal of `...` — which names a file, so refusing it reports `InvalidInput` for an input
/// some filesystem satisfies, breaking this module's own kind rule. The shells' PATHEXT behaviour
/// was measured on `foo.bar` and on none of these; that they fall under the same rule is an
/// argument from uniformity, not a measurement.
///
/// # Not a permanent rule
///
/// The one-candidate rule for a BARE name is expected to be superseded by proper PATHEXT-based
/// resolution once batch support lands (see the `.bat`/`.cmd` note above) — a future reader should
/// not assume it is permanent. The `Located` behaviour is expected to survive that change
/// unchanged, because PATHEXT is a search mechanism and the located axis does not search.
fn filename_candidates(name: &OsStr, windows: bool, shape: Shape) -> Vec<std::ffi::OsString> {
    if !windows || has_loadable_extension(name) {
        return vec![name.to_os_string()];
    }
    match shape {
        // Nothing to append to: `.exe` would become the whole name (`.` -> `..exe`), a plant under
        // a name the caller never wrote. `resolve` refuses this shape before reaching here, so the
        // guard is defence in depth for a future caller that bypasses it — the located axis asks
        // the same question, through [`takes_the_exe_fallback`].
        Shape::BareName if names_no_file(name, windows) => vec![name.to_os_string()],
        Shape::BareName => vec![push_exe(name.as_encoded_bytes())],
        // A located name with SOME extension gets exactly one candidate, the name as written.
        // `main` keyed its `.exe` fallback on `Path::extension().is_none()`, so appending to a
        // dotted name here would be a WIDENING on the located axis: `executable(r"C:\t\thing.bin")`
        // would newly resolve to `thing.bin.exe` when `thing.bin` is absent, loading a file a
        // writer of that directory could plant where `main` returned `NotFound`. The monotonicity
        // argument below is measured on the SEARCHED axis and does not license that.
        Shape::Located if takes_the_exe_fallback(name, windows) => {
            vec![name.to_os_string(), push_exe(name.as_encoded_bytes())]
        }
        Shape::Located => vec![name.to_os_string()],
    }
}

fn push_exe(bytes: &[u8]) -> std::ffi::OsString {
    // SAFETY: both callers pass a whole `as_encoded_bytes` slice, unsliced, which round-trips by
    // definition.
    let mut out = unsafe { OsStr::from_encoded_bytes_unchecked(bytes) }.to_os_string();
    out.push(".exe");
    out
}

/// Whether a LOCATED name gets the second, `.exe` candidate.
///
/// Distinct from [`has_loadable_extension`], which asks the narrower "is it already `.exe`/`.com`".
/// This decides the fallback, and it exists to keep the located axis from WIDENING against `main`,
/// which keyed on `Path::extension().is_none()` and appended via `Path::with_extension`.
///
/// Two ways to get that wrong, both of which this rules out: a name whose final component already
/// carries an extension must not gain `name.exe` (`main` refused it), and a name that names no
/// file must not gain one either — there `.exe` becomes the whole final component, naming a
/// dotfile INSIDE the directory (`C:\tools\dir\` -> `C:\tools\dir\.exe`) or a sibling of it
/// (`C:\t\.` -> `C:\t\..exe`), either of which a writer of that directory can plant and which
/// `main` — whose `Path::with_extension` is a no-op on a path with no file name — never looked
/// for. That second question is [`names_no_file`]'s, and is asked by calling it rather than by
/// re-deriving it here, because the bare axis asks the same question and two spellings of one rule
/// drift apart.
///
/// [`resolve`] refuses such a name before reaching here, so this is defence in depth for any
/// future caller of this function that does not go through it.
fn takes_the_exe_fallback(name: &OsStr, windows: bool) -> bool {
    if names_no_file(name, windows) {
        return false;
    }
    // Otherwise: only when there is no extension, matching `Path::extension()`'s rule that a
    // LEADING dot is part of the stem (`.bashrc` has none) — which is what `main` keyed on.
    let rposition = final_component(name, windows).iter().rposition(|&b| b == b'.');
    matches!(rposition, Some(0) | None)
}

/// Whether `name` already ends in `.exe` or `.com`, compared case-insensitively — `TOOL.EXE` must
/// not become `TOOL.EXE.exe`. These are the two extensions `CreateProcessW` loads directly as a PE
/// image; see `filename_candidates`'s doc for why exactly these two and no others.
///
/// Unlike its sibling classifiers this does NOT split off the final component first, and so takes
/// no `windows` flag. Neither suffix contains a separator, so for every input that REACHES here
/// the two readings coincide: both callers ([`resolve`] and [`reject_unloadable_image`]) refuse a
/// [`names_no_file`] name first, and only such a name can have its final component swallowed by a
/// prefix (`\\server\share.exe` ends in `.exe` while its final component is empty). A future
/// caller bypassing that refusal would get the whole-string answer; compare
/// `final_component(name, windows)` instead if it needs the other.
fn has_loadable_extension(name: &OsStr) -> bool {
    let bytes = name.as_encoded_bytes();
    ends_with_ignore_ascii_case(bytes, b".exe") || ends_with_ignore_ascii_case(bytes, b".com")
}

/// Refuse an image whose name does not end in `.exe`/`.com` — the ELEVATED path's allowlist.
///
/// `ShellExecuteEx` does not open `lpFile`, it RESOLVES it, and it applies `PATHEXT` even when
/// `lpFile` is absolute. Measured on both CI architectures and on a real desktop: `PATHEXT`
/// OUTRANKS AN EXISTING FILE, so an absolute `C:\dir\tool` with a planted `C:\dir\tool.bat`
/// beside it runs the batch file even when `tool` is a real PE. From an unelevated caller that
/// child runs at High integrity, and the consent dialog reads "Windows Command Processor",
/// Microsoft Corporation (verified) — the batch resolves to its signed handler, so the bypass
/// launders the one thing the user is being asked to judge.
///
/// Existence therefore cannot be the test; only the NAME can be. An ALLOWLIST rather than a
/// denylist of script extensions, because `ShellExecuteEx` resolves any registered association:
/// `.lnk`, `.vbs`, `.ps1`, `.js`, `.hta` and `.msi` are all refused here by construction, where
/// a denylist would have to enumerate a registry the caller's machine controls. `.lnk` is the
/// sharp case — a shortcut's target can be `cmd.exe /c ...`, elevating a program never named.
///
/// Those measurements are of a launch without a class. cosca launches as `exefile`
/// (`SEE_MASK_CLASSNAME`), and whether that launch applies `PATHEXT` on the consent route an
/// unelevated caller takes is unmeasured.
///
/// The allowlist closes the extensionless case only, whatever that answer is. Whether
/// `ShellExecuteEx` applies `PATHEXT` to an `lpFile` that already ends in `.exe` — a real
/// `tool.exe` beside a planted `tool.exe.bat` — is unmeasured on every route, and this rule makes
/// no claim about it.
///
/// # Deliberately stricter than an unelevated spawn
///
/// `CreateProcessW` does NOT extend `lpApplicationName` ("no default extension is assumed"), so
/// it loads an extensionless PE by absolute path quite safely; `ShellExecuteEx` does extend, so
/// the same name is plantable there. The asymmetry is the platform's, and this rule follows it
/// rather than papering over it: `.elevate()` refuses names an ordinary spawn accepts.
/// `raw_executable("tool").elevate()` wants `tool.exe`.
///
/// Over-rejection is the safe direction and is taken where the two disagree: `tool.exe.` (trailing
/// dot) resolves to `tool.exe` on Windows but is refused here, because a trailing dot does NOT
/// suppress `PATHEXT` (measured) and reasoning about which spellings Windows silently trims is
/// how the plantability bug got in.
pub(crate) fn reject_unloadable_image(program: &Path, windows: bool) -> Result<(), Error> {
    // `names_no_file` first: it is what makes `has_loadable_extension`'s whole-string reading the
    // final component's (see its doc).
    if !names_no_file(program.as_os_str(), windows) && has_loadable_extension(program.as_os_str()) {
        return Ok(());
    }
    Err(Error::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "elevation requires an image named .exe or .com, because ShellExecuteEx may apply \
             PATHEXT to any other name and a planted script would then outrank it: {program:?}"
        ),
    )))
}

fn ends_with_ignore_ascii_case(bytes: &[u8], suffix: &[u8]) -> bool {
    bytes.len() >= suffix.len() && bytes[bytes.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

/// Split a `PATH` value on the simulated platform's separator.
///
/// On Windows a `"` toggles quoting, so a `;` inside quotes does not split — letting a directory
/// that contains a literal `;` (or leading/trailing space) survive as ONE element rather than
/// being torn in half by a naive byte-level `;` split. `"C:\a;b"` is one element, `C:\a;b`; a
/// plain, unquoted `C:\bin` passes through unchanged.
///
/// Every `"` is consumed as a delimiter wherever it appears, not only a wrapping pair: an
/// interior `C:\Pro"gram Files"\bin` yields `C:\Program Files\bin`, with the quotes removed and
/// the remainder concatenated. That matches `std::env::split_paths`'s own Windows parser, which
/// this replaced, so the behaviour is deliberate — but it does mean a `"` is never preserved as
/// a literal path character on Windows.
///
/// Stripping is what keeps a quoted entry alive at all: leaving the quotes IN would fail the
/// `is_absolute()` filter the caller applies afterwards (a leading `"` is not a recognised drive
/// prefix), so the entry would be SILENTLY DROPPED rather than erroring.
///
/// On POSIX, `"` is an ordinary filename character and `;` is not a separator: quoting is
/// deliberately NOT applied there — only `:` splits, and any quote characters in an element are
/// preserved literally, matching every POSIX shell's own (quote-free) `PATH` handling.
fn split_path_var(var: Option<&OsStr>, windows: bool) -> Vec<PathBuf> {
    let Some(var) = var else { return Vec::new() };
    let bytes = var.as_encoded_bytes();
    if windows {
        split_path_var_windows(bytes)
    } else {
        split_path_var_posix(bytes)
    }
}

fn split_path_var_posix(bytes: &[u8]) -> Vec<PathBuf> {
    bytes
        .split(|&b| b == b':')
        // SAFETY: the bytes came from `as_encoded_bytes` and are split on an ASCII byte, which
        // is the documented-safe way to slice an `OsStr`'s encoded form.
        .map(|part| PathBuf::from(unsafe { OsStr::from_encoded_bytes_unchecked(part) }))
        .collect()
}

/// Windows `PATH` splitting with quote handling — see [`split_path_var`]'s doc for the rule.
fn split_path_var_windows(bytes: &[u8]) -> Vec<PathBuf> {
    let mut parts: Vec<Vec<u8>> = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    let mut in_quotes = false;
    for &b in bytes {
        match b {
            b'"' => in_quotes = !in_quotes,
            b';' if !in_quotes => parts.push(std::mem::take(&mut current)),
            _ => current.push(b),
        }
    }
    parts.push(current);
    parts
        .into_iter()
        // SAFETY: the bytes came from `as_encoded_bytes`; dropping quote bytes and splitting on
        // an ASCII byte are both the documented-safe way to slice an `OsStr`'s encoded form.
        .map(|part| PathBuf::from(unsafe { OsStr::from_encoded_bytes_unchecked(&part) }))
        .collect()
}

/// Whether a candidate is a file this platform could actually exec.
///
/// On POSIX the execute bit is part of the answer: `execvp` skips a readable-but-non-executable
/// match and keeps searching (measured), so keying on existence alone stops at a file that would
/// have been passed over and hands it to exec, turning a working command into `EACCES`.
/// `faccessat(AT_EACCESS)` asks for the ids that will actually exec, unlike `access`.
///
/// That argument is about the `PATH` SEARCH, and it is applied to a [`Shape::Located`] name too,
/// where `execvp` does not search and would report `EACCES` rather than skipping. So once the
/// POSIX spawn path routes through this module (see the module doc), `resolve("./tool")` against
/// a non-executable `./tool` will report `NotFound` where the platform reports
/// `PermissionDenied`. That is deliberate — one predicate for "can this be exec'd" beats a
/// shape-dependent one, and the caller learns the file is unusable either way — but the error
/// KIND diverges, and anything matching on it should know that before the POSIX path lands.
///
/// Note the `windows` parameter is a runtime flag while the `faccessat` call sits behind
/// `#[cfg(unix)]`: simulating POSIX on a Windows HOST therefore skips the execute-bit check
/// entirely. See #143 — that mismatch is the concrete motivation for replacing this flag with a
/// platform trait.
fn is_execable(path: &Path, windows: bool) -> bool {
    if !path.is_file() {
        return false;
    }
    #[cfg(unix)]
    if !windows {
        use std::os::unix::ffi::OsStrExt;
        let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
            return false;
        };
        // SAFETY: a read-only permission query on a valid NUL-terminated path.
        return unsafe { libc::faccessat(libc::AT_FDCWD, c.as_ptr(), libc::X_OK, libc::AT_EACCESS) == 0 };
    }
    let _ = windows;
    true
}

pub(crate) fn resolve(input: ResolveInput<'_>) -> Result<PathBuf, Error> {
    let name = input.program.as_os_str();
    // A name with no stem does not merely fail to resolve, it INVENTS one: the `.exe` rule turned
    // `""` into the candidate `.exe`, `.` into `..exe`, and `C:\t\.` into `C:\t\..exe` — each a
    // file that a writer of the searched directory can plant under a name the caller never wrote.
    // Guarding one candidate rule at a time leaves the next spelling open, so the shape is refused
    // outright. `InvalidInput`, not `NotFound`: nothing was looked for.
    if names_no_file(name, input.windows) {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("program does not name a file: {:?}", input.program),
        )));
    }
    // Refused EXPLICITLY, and before any search. `C:tool` did report `NotFound`, but only as a
    // side effect of candidate filtering — `PathBuf::push` clears for a prefixed path, so every
    // candidate failed the `is_absolute()` check below and the loop fell through to the trailing
    // error. Nothing stated the intent, and the kind would have changed silently with that check.
    if is_drive_relative(name, input.windows) {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "program is relative to a drive's own current directory, which cosca does not track: {:?}",
                input.program
            ),
        )));
    }
    // Classify FIRST: the candidate filenames depend on the shape (a located name also tries the
    // exact name the caller wrote, a searched one does not — see `filename_candidates`).
    let shape = classify(name, input.windows);
    let candidates = filename_candidates(name, input.windows, shape);

    // The cwd is absolutised BEFORE joining. A relative one would otherwise be applied twice:
    // the resolver joins it, and std chdirs the child into it as well, so `./tool` with
    // `current_dir("sub")` would exec `sub/sub/tool` (measured).
    let cwd_owned;
    let cwd: &Path = if input.cwd.is_absolute() {
        input.cwd
    } else {
        cwd_owned = std::env::current_dir().map_err(Error::Io)?.join(input.cwd);
        &cwd_owned
    };

    let dirs: Vec<PathBuf> = match shape {
        Shape::Located => vec![cwd.to_path_buf()],
        // System directories precede `PATH` — never the cwd, which is deliberately absent from
        // this list; see `ResolveInput::system_dirs`'s doc for why that ordering is what keeps
        // this change a strict narrowing of the pre-patch `CreateProcessW` search rather than
        // trading one hazard for another. Ignored outright off Windows: `system_dirs` is always
        // empty there in practice, but the `input.windows` guard makes that a hard rule rather
        // than a convention a future POSIX caller could violate by accident.
        Shape::BareName => {
            let mut dirs = if input.windows {
                input.system_dirs.to_vec()
            } else {
                Vec::new()
            };
            dirs.extend(split_path_var(input.path_var, input.windows));
            dirs
        }
    };

    for dir in dirs {
        for candidate in &candidates {
            let joined = dir.join(candidate);
            // Only an absolute `joined` is accepted — this is what actually keeps a relative or
            // empty `PATH` element from resolving through the current directory (an empty element
            // means "the current directory", and a relative one such as `.`/`tools` resolves
            // against it just as surely). A drive-relative name (`C:tool`) survives the join
            // unchanged too, because `PathBuf::push` clears for any prefixed path — so it would
            // otherwise resolve through drive C's own current directory, which cosca does not
            // track. This single check is also what keeps the contract every backend relies on:
            // the answer is always absolute.
            if joined.is_absolute() && is_execable(&joined, input.windows) {
                return Ok(joined);
            }
        }
    }
    Err(Error::Io(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("could not resolve executable: {}", input.program.display()),
    )))
}

#[cfg(test)]
#[path = "resolve_tests.rs"]
mod resolve_tests;
