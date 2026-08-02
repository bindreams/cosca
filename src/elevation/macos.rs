//! macOS graphical elevation: the `osascript … with administrator privileges`
//! effect path for [`Auth::Gui`](super::Auth::Gui).
//!
//! Everything here is PURE — no syscalls, no `cfg!` — so the whole module is
//! compiled and unit-tested on every platform, exactly like [`super::plan`].
//!
//! # The two quoting layers
//!
//! `do shell script` hands its argument to `/bin/sh -c`, and the argument is itself
//! an AppleScript string literal. So a command crosses two grammars:
//!
//! 1. argv -> `/bin/sh` word-quoting ([`crate::quote::posix::join`]);
//! 2. that text -> AppleScript literal body ([`crate::quote::applescript::escape_literal`]).
//!
//! There is deliberately no third layer: the finished script is handed to
//! `osascript` as ONE `-e` argv element through `std::process::Command`, which never
//! involves a shell. Layer 2 is applied in exactly one place,
//! [`wrap_do_shell_script`].

use std::ffi::{OsStr, OsString};
use std::path::Path;

use super::{ElevatedStdio, ElevatedVia, ElevationReport};
use crate::command::{Command, CommandInput};
use crate::error::Error;
use crate::stdio::{Fd, ResolvedStdio};

fn unsupported(op: &str, detail: String) -> Error {
    Error::Unsupported {
        op: op.into(),
        platform: "macos",
        detail,
    }
}

/// The raw bytes of an `OsStr`. Exact on unix. Off-unix an `OsStr` is WTF-16 and
/// may hold unpaired surrogates with no byte form — a TYPED error, never a panic
/// and never a lossy substitution, per the crate's rule. (Production only ever
/// reaches this on unix, because `posix.rs` is the sole caller and is `cfg(unix)`,
/// but that is a structural coincidence, not a guarantee, and this module is
/// compiled and tested on Windows.)
fn os_bytes(s: &OsStr) -> Result<&[u8], Error> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(s.as_bytes())
    }
    #[cfg(not(unix))]
    {
        if let Some(valid) = s.to_str() {
            return Ok(valid.as_bytes());
        }
        // A REAL offset, not a fabricated zero: `QuoteError.pos` is documented as a
        // byte offset, and the crate's other constructors all measure one. Decode
        // the WTF-16 and accumulate the UTF-8 length of everything that decoded
        // cleanly, so `pos` points at the first code unit with no byte form.
        use std::os::windows::ffi::OsStrExt;
        let pos = char::decode_utf16(s.encode_wide())
            .take_while(|c| c.is_ok())
            .map(|c| c.expect("take_while kept only Ok").len_utf8())
            .sum();
        Err(Error::Quote(crate::error::QuoteError::new(
            pos,
            crate::error::QuoteErrorKind::NonUtf8,
        )))
    }
}

/// Does `s` name a POSIX-absolute path? A leading-`/` BYTE test, deliberately not
/// `Path::is_absolute`: the target grammar is `/bin/sh`'s, not the build host's, and
/// on Windows `Path::is_absolute("/usr/bin/id")` is `false` (no drive prefix) while
/// `Path::is_absolute(r"C:\tool.exe")` is `true` — both backwards here.
fn is_posix_absolute(s: &OsStr) -> Result<bool, Error> {
    Ok(os_bytes(s)?.first() == Some(&b'/'))
}

/// The `/bin/sh` command text: an optional `cd`, then `exec` of the quoted argv.
///
/// `exec` replaces the shell so the payload is the trampoline's direct child rather
/// than sitting under an idle `sh`. The cwd is stated rather than inherited: `do
/// shell script` does not carry the caller's working directory across the
/// authorization trampoline.
///
/// Requiring the cwd to be absolute makes osascript's directory and the script's
/// `cd --` resolve the same PATH. It does not make them resolve the same OUTCOME:
/// the `cd` runs as root on the far side of the trampoline, so a directory the
/// caller can traverse but root cannot (NFS `root_squash`) fails there, `&&`
/// short-circuits, and the payload never runs. That surfaces as a bare non-zero
/// exit, since [`ElevatedStdio::OsascriptRelay`] never relays the payload's stderr.
///
/// Precondition: `program` and `cwd` are POSIX-absolute — enforced by
/// [`reject_structural_gui_config`].
pub(crate) fn build_shell_command(program: &OsStr, args: &[OsString], cwd: Option<&Path>) -> Result<Vec<u8>, Error> {
    debug_assert!(
        matches!(is_posix_absolute(program), Ok(true)),
        "the structural gate must reject a non-absolute program before composition"
    );
    debug_assert!(
        cwd.is_none_or(|d| matches!(is_posix_absolute(d.as_os_str()), Ok(true))),
        "the structural gate must reject a non-absolute cwd before composition"
    );
    let mut words: Vec<&[u8]> = Vec::with_capacity(args.len() + 2);
    words.push(b"exec".as_slice());
    words.push(os_bytes(program)?);
    let arg_bytes: Vec<&[u8]> = args.iter().map(|a| os_bytes(a)).collect::<Result<_, _>>()?;
    words.extend(arg_bytes.iter().copied());

    let mut out = Vec::new();
    if let Some(dir) = cwd {
        out.extend_from_slice(b"cd -- ");
        out.extend_from_slice(&crate::quote::posix::quote(os_bytes(dir.as_os_str())?));
        out.extend_from_slice(b" && ");
    }
    out.extend_from_slice(&crate::quote::posix::join(&words));
    Ok(out)
}

/// Wrap a `/bin/sh` command as the complete AppleScript statement.
///
/// `without altering line endings` is mandatory: without it `do shell script`
/// rewrites the payload's newlines to carriage returns before relaying them.
///
/// No `with timeout of …` clause is emitted. Per the AppleScript Language Guide,
/// `with timeout` governs commands sent to *application objects*; `do shell script`
/// under `osascript` is executed by the running script's own application, so neither
/// the default event timeout nor an explicit clause applies to it. A clause here
/// would be a silent no-op.
///
/// Non-ASCII passes through. `osascript(1)` documents no encoding for `-e`, but that
/// is a documentation gap, not a behavior gap, and it is closed by measurement:
/// `both_quoting_layers_survive_a_real_osascript_round_trip` drives CJK, combining
/// marks, astral-plane codepoints and mixed scripts through the REAL osascript on
/// macOS CI and compares byte-exact hex. Refusing the class instead would reject a
/// CJK-named file argument on a UTF-8 filesystem.
///
/// `arg_max` is the detected `kern.argmax`. The check is a LOWER bound: the script is
/// the dominant argv element of the `osascript` exec, but argv and the environment
/// share the same budget, so a script under the cap can still overflow. `None` (the
/// sysctl failed) disables the check rather than substituting a guess. Overflow is
/// [`crate::error::ElevationErrorKind::CommandTooLong`], NOT `Unsupported`: the
/// crate reserves `Unsupported` for "can never work on this platform", and this
/// verdict is derived from a runtime sysctl reading.
pub(crate) fn wrap_do_shell_script(shell_command: &[u8], arg_max: Option<usize>) -> Result<String, Error> {
    let body = crate::quote::applescript::escape_literal(shell_command).map_err(Error::Quote)?;
    let script = format!("do shell script \"{body}\" with administrator privileges without altering line endings");
    if let Some(max) = arg_max {
        if script.len() > max {
            return Err(Error::Elevation {
                kind: crate::error::ElevationErrorKind::CommandTooLong,
                detail: format!(
                    "the composed AppleScript is {} bytes; this system's kern.argmax is {max}. \
                     Shorten the command, or write the arguments to a file the elevated program reads",
                    script.len()
                ),
            });
        }
    }
    Ok(script)
}

/// Program + args, honoring `executable()`. `exec`ing the program sets argv[0] to
/// its own path, so an argv[0] distinct from a set `executable()` cannot survive.
pub(crate) fn program_and_args(cmd: &Command) -> Result<(OsString, Vec<OsString>), Error> {
    // `Empty` is matched FIRST. A fresh `Command` is `CommandInput::Empty`, not
    // `Argv(vec![])`, so folding it into the commandline arm would answer "no
    // program set" with a message about re-quoting a command line.
    let argv = match cmd.input() {
        CommandInput::Argv(argv) => argv,
        CommandInput::Empty => {
            return Err(unsupported(
                "macOS graphical elevation of an empty command",
                "set a program via .args([...]) before .elevate()".into(),
            ))
        }
        CommandInput::CommandLine(_) => {
            return Err(unsupported(
                "macOS graphical elevation of a commandline() command",
                "the command must be an argv (set .args([...])); a raw command line cannot be \
                 re-quoted for /bin/sh without guessing its word boundaries"
                    .into(),
            ))
        }
    };
    let Some(first) = argv.first() else {
        return Err(unsupported(
            "macOS graphical elevation of an empty command",
            "set a program via .args([...]) before .elevate()".into(),
        ));
    };
    match cmd.executable_path() {
        Some(exe) => {
            if first.as_os_str() != exe.as_os_str() {
                return Err(unsupported(
                    "macOS graphical elevation with an argv[0] distinct from executable()",
                    "`do shell script` execs the program, which sets argv[0] to its own path; \
                     a separate argv[0] cannot survive elevation"
                        .into(),
                ));
            }
            Ok((exe.as_os_str().to_os_string(), argv[1..].to_vec()))
        }
        None => Ok((first.clone(), argv[1..].to_vec())),
    }
}

/// The honest capability matrix for macOS graphical elevation. Every rejection below
/// is a thing Authorization Services genuinely cannot do — reported loudly rather
/// than half-honored.
///
/// Returns `Error::Unsupported { platform: "macos", .. }` for a capability mismatch,
/// and `Error::Quote(NonUtf8)` for a program or directory with no byte form
/// (reachable only off-unix, where an `OsStr` is WTF-16). Both are typed; neither is
/// a panic.
pub(crate) fn reject_structural_gui_config(cmd: &Command) -> Result<(), Error> {
    let (program, _) = program_and_args(cmd)?;
    // root's /bin/sh resolves a bare name against ITS OWN PATH, so a relative
    // program would let the environment choose which binary runs as root. The crate
    // closes the same hole for its POSIX backends by carrying absolute paths.
    if !is_posix_absolute(&program)? {
        return Err(unsupported(
            "macOS graphical elevation of a non-absolute program",
            format!(
                "{program:?} would be resolved by the elevated shell's own PATH, not the caller's, \
                 so the binary that runs as root is not the one you selected; pass an absolute path"
            ),
        ));
    }
    // Same hole, for the directory. The caller's cwd is applied twice — to osascript,
    // and as `cd --` inside the script — and the trampoline does not carry a cwd
    // across, so a RELATIVE path resolves against two different bases and the two
    // silently disagree. Absolute makes them name the same directory.
    if let Some(dir) = cmd.cwd() {
        if !is_posix_absolute(dir.as_os_str())? {
            return Err(unsupported(
                "macOS graphical elevation with a relative current_dir()",
                format!(
                    "{dir:?} would resolve against this process's directory for osascript but \
                     against whatever the authorization trampoline hands the elevated shell for \
                     the command itself; pass an absolute path"
                ),
            ));
        }
    }
    for (&slot, resolved) in cmd.fds() {
        if slot.raw() >= 3 {
            return Err(unsupported(
                "fd >= 3 on a macOS graphically-elevated child",
                "the authorization trampoline passes no descriptors, so fd >= 3 cannot reach the \
                 elevated program"
                    .into(),
            ));
        }
        // fd1/fd2 are osascript's own streams and carry the relay, so any resolution
        // is honest there (see ElevatedStdio::OsascriptRelay). fd0 is not: osascript
        // never reads it and the elevated program never sees it, so anything with
        // content behind it silently goes nowhere. Written as an ALLOW-list so a
        // future `ResolvedStdio` variant (or `Stdio::merge`, which resolves to
        // `Merge` and would otherwise slip through) defaults to a loud rejection.
        if slot == Fd::STDIN && !matches!(resolved, ResolvedStdio::Inherit | ResolvedStdio::Null) {
            return Err(unsupported(
                "a pipe or file on stdin for a macOS graphically-elevated child",
                "the elevated program's stdin comes from Authorization Services; osascript never \
                 reads fd0, so anything written there would be silently discarded. Use null() or \
                 inherit()"
                    .into(),
            ));
        }
    }
    if !cmd.env_ops().is_empty() {
        return Err(unsupported(
            "env forwarding to a macOS graphically-elevated child",
            "the authorization trampoline builds the root environment; the only way to pass a \
             variable would be an assignment in the command text, which is visible to anyone \
             inspecting the running processes"
                .into(),
        ));
    }
    if cmd.contain_request().mode.is_some() {
        return Err(unsupported(
            ".contain() + macOS graphical elevation",
            "the elevated program runs under the authorization trampoline, parented to launchd \
             and outside this process's tree; containment cannot span it"
                .into(),
        ));
    }
    // kill_on_drop is deliberately NOT rejected. `Command::default()` sets it to
    // `true` and offers no way to distinguish that default from an explicit request,
    // so rejecting it would reject every default-constructed command and make this
    // path unreachable. Its real reach (the osascript front-end only) is documented
    // on `ElevatedVia::MacosOsascript` instead.
    Ok(())
}

/// Build the DERIVED command (`osascript -e <script>`) plus the report to attach to
/// the resulting child. The caller's `Command` keeps its `input`/`env_ops`; its fd
/// 0-2 stdio is MOVED (`ResolvedStdio::File` is not `Clone`), matching the POSIX
/// rewrite's contract.
///
/// Precondition: [`reject_structural_gui_config`] has already passed, so the program
/// and cwd are absolute, and there are no env ops and no containment. `kill_on_drop`
/// is NOT gated (see that function), so it is transferred like the POSIX rewrite
/// transfers it.
pub(crate) fn build_rewrite(
    cmd: &mut Command,
    osascript: &Path,
    arg_max: Option<usize>,
) -> Result<(Command, ElevationReport), Error> {
    // Contracts the upstream gate owns, mirroring `build_shell_command`'s own
    // precondition asserts. Zero-cost in release; a loud failure in debug if a
    // second call site ever reaches here without passing the gate.
    debug_assert!(
        cmd.env_ops().is_empty(),
        "reject_structural_gui_config must reject env ops before build_rewrite"
    );
    debug_assert!(
        cmd.contain_request().mode.is_none(),
        "reject_structural_gui_config must reject containment before build_rewrite"
    );
    debug_assert!(
        cmd.fds().keys().all(|s| s.raw() < 3),
        "reject_structural_gui_config must reject fd >= 3 before build_rewrite"
    );
    let (program, args) = program_and_args(cmd)?;
    let shell_command = build_shell_command(&program, &args, cmd.cwd())?;
    let script = wrap_do_shell_script(&shell_command, arg_max)?;

    let mut derived = Command::new();
    derived.set_input_argv(vec![
        osascript.as_os_str().to_os_string(),
        OsString::from("-e"),
        OsString::from(script),
    ]);
    // The cwd is set on osascript AS WELL AS stated in the script: setting it here
    // turns a bogus directory into a precise spawn-time `Io` error instead of an
    // opaque non-zero exit, and the script's `cd --` makes the payload's cwd
    // deterministic either way. The two name the same directory by construction.
    if let Some(d) = cmd.cwd() {
        derived.current_dir(d);
    }
    // kill_on_drop MUST be carried, exactly as `posix::transfer_process_attrs`
    // carries it: the async spawn recurses with `spawn(&mut derived)` and re-reads
    // the flag off the DERIVED command, so leaving it at `Command::default()`'s
    // `true` would silently discard a caller's `.kill_on_drop(false)` on the tokio
    // path while honoring it on the sync one.
    derived.kill_on_drop(cmd.kill_on_drop_flag());
    // …and when it is set, SAY SO — the default must not be silent (see
    // `ElevatedVia::MacosOsascript` for why killing the front-end can't stop the
    // payload). The program is named so a test can assert on its OWN record in the
    // process-global capture buffer.
    if cmd.kill_on_drop_flag() {
        log::warn!(
            "kill_on_drop is set on a macOS graphically-elevated child ({program:?}): killing or \
             dropping it reaches only the osascript front-end, and the root program keeps running \
             with its exit status unobservable. Call .kill_on_drop(false) and wait() if that matters."
        );
    }
    // Containment IS rejected by the structural gate, so there is nothing else to carry.
    for (slot, resolved) in std::mem::take(cmd.fds_mut()) {
        derived.fds_mut().insert(slot, resolved);
    }

    let report = ElevationReport {
        via: ElevatedVia::MacosOsascript,
        // Nothing is forwarded (env ops are rejected outright), so the sanitizer has
        // nothing to strip. Reporting an empty list is the truth, not a stub.
        stripped_env: Vec::new(),
        stdio: ElevatedStdio::OsascriptRelay,
    };
    Ok((derived, report))
}

#[cfg(test)]
#[path = "macos_tests.rs"]
mod macos_tests;
