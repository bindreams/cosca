//! Unit tests for the raw `CreateProcessW` backend's pre-spawn program gate
//! ([`super::reject_batch_program`]) and command-line builder
//! ([`super::raw_program_and_line`]), which run before resolution and decide what a malformed
//! program token or argument is BLAMED on. Driven directly rather than through `spawn_raw`, so no
//! child is created and the verdict is the checks' alone.

use super::*;
use crate::command::Command;
use crate::error::Error;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

/// A token carrying an interior NUL — `PCWSTR` truncates at it, so `prefix` is what Win32 acts on.
fn nul_between(prefix: &str, suffix: &str) -> OsString {
    OsString::from_wide(
        &prefix
            .encode_utf16()
            .chain([0])
            .chain(suffix.encode_utf16())
            .collect::<Vec<u16>>(),
    )
}

/// The `Display` of an `Io(InvalidInput)` refusal; panics on anything else, naming what came back.
fn invalid_input_message(via: &str, r: Result<(), Error>) -> String {
    match r {
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::InvalidInput => e.to_string(),
        other => panic!("{via}: expected Io(InvalidInput), got {other:?}"),
    }
}

/// Every way a caller can name a program, in one place: `reject_batch_program` reads
/// `executable()` when set and otherwise the argv[0] / command-line first token, so each arm needs
/// its own leg.
fn commands_with_token(token: &OsString) -> Vec<(&'static str, Command)> {
    let mut by_argv = Command::new();
    by_argv.args([token.clone()]);

    // argv[0] is deliberately clean and DIFFERENT from `token`: with the probe in both fields a
    // passing leg would not say which one the gate read.
    let mut by_executable = Command::new();
    by_executable.executable(token).args(["ordinary.exe"]);

    let mut by_commandline = Command::new();
    by_commandline.commandline(token.clone());

    vec![
        ("argv[0]", by_argv),
        ("executable()", by_executable),
        ("commandline()", by_commandline),
    ]
}

/// `C:\tools\setup` + NUL + `.bat`. Win32 truncates it to `C:\tools\setup`, which is no batch file
/// at all, so neither gate may blame CVE-2024-24576 — the caller would be sent to audit a vector
/// they do not carry, over a token that launches a program they did not name.
#[test]
fn a_nul_before_a_batch_extension_is_diagnosed_as_a_nul_not_a_batch_refusal() {
    let token = nul_between(r"C:\tools\setup", ".bat");
    // Premise: the shared gate refuses this as a NUL as well, never as a batch file — so an
    // `Unsupported` reaching the caller could only be the batch rule misfiring.
    invalid_input_message(
        "the shared gate",
        crate::child::spawn::reject_batch_path(std::path::Path::new(&token)),
    );
    for (via, c) in commands_with_token(&token) {
        // An `Ok`, or any downstream error kind, panics in the helper.
        let msg = invalid_input_message(via, reject_batch_program(&c));
        assert!(
            !msg.contains('\0'),
            "{via}: the refusal must not carry a raw NUL into logs: {msg:?}"
        );
    }
}

/// The batch gate must still refuse a clean `.bat`. Without this leg the ordering could be
/// "satisfied" by deleting the gate outright and every NUL test here would stay green.
#[test]
fn a_clean_batch_token_is_still_refused_as_a_batch() {
    for (via, c) in commands_with_token(&OsString::from(r"C:\tools\setup.bat")) {
        assert!(
            matches!(reject_batch_program(&c), Err(Error::Unsupported { .. })),
            "{via}: a clean .bat must still be refused by the batch gate"
        );
    }
}

/// A NUL in the PROGRAM TOKEN must be blamed on the program token. The raw backend shares one NUL
/// checker with the environment-block builder, so a message hardcoded to the environment sends the
/// caller off to audit `env()` over a defect in `args()` or `executable()` — the same class of
/// misattribution the NUL-before-batch ordering exists to prevent, one field over.
#[test]
fn a_nul_in_the_program_token_is_not_blamed_on_the_environment() {
    let token = nul_between("setup.bat", "junk");
    // Premise: the shared gate refuses this too, so the assertions below are about WHICH FIELD the
    // refusal names and not about whether one arrives.
    invalid_input_message(
        "the shared gate",
        crate::child::spawn::reject_batch_path(std::path::Path::new(&token)),
    );
    for (via, c) in commands_with_token(&token) {
        let msg = invalid_input_message(via, reject_batch_program(&c));
        assert!(
            msg.contains("program token"),
            "{via}: must name the program token, got {msg}"
        );
        assert!(
            !msg.contains("environment"),
            "{via}: a program token is not the environment, got {msg}"
        );
    }
}

/// A NUL in a middle argv element must name WHICH element. By the time `CreateProcessW` reads it
/// the command line is one joined string, so an unindexed label leaves the caller to bisect
/// `args([..])` by hand — and `args(["a", "b\0c", "d"])` would name no element at all.
#[test]
fn a_nul_in_an_argument_is_blamed_on_its_index() {
    let mut c = Command::new();
    c.args([OsString::from("a"), nul_between("b", "c"), OsString::from("d")]);
    let msg = invalid_input_message("argv", super::raw_program_and_line(&c).map(|_| ()));
    assert!(msg.contains("argument 1"), "must name the offending element, got {msg}");
}

// ===== command-line builder: a usable first token when executable() is unset =====

// ── `lpApplicationName` must never silently end up NULL ────────────────────────────────
//
// `CreateProcessW` performs its OWN image search when `lpApplicationName` is NULL, including
// the CALLING process's current directory — the exact binary-planting hole this module's
// resolution otherwise closes (see `program_token`'s doc). `spawn_raw` keeps `lpApplicationName`
// non-NULL by falling back to `program_token(cmd)` when `executable()` is unset, but
// `program_token`'s `CommandLine` arm calls `first_token_wide`, which is documented to return
// `None` for an empty or whitespace-only line. `raw_program_and_line`'s sibling arms (`Empty`,
// `Argv`) both already error out loudly when `executable()` is unset and they have no usable
// token; the `CommandLine` arm had no matching check, so an empty/whitespace `commandline()`
// with no `executable()` silently produced `app_name: None` (`lpApplicationName == NULL`)
// instead of erroring.

#[test]
fn raw_program_and_line_rejects_an_empty_command_line_with_no_executable_set() {
    let mut cmd = Command::new();
    cmd.commandline("");
    let err = raw_program_and_line(&cmd).unwrap_err();
    assert!(matches!(err, Error::Io(_)), "{err:?}");
}

#[test]
fn raw_program_and_line_rejects_a_whitespace_only_command_line_with_no_executable_set() {
    let mut cmd = Command::new();
    cmd.commandline("   ");
    let err = raw_program_and_line(&cmd).unwrap_err();
    assert!(matches!(err, Error::Io(_)), "{err:?}");
}

#[test]
fn raw_program_and_line_allows_an_empty_command_line_when_executable_is_set() {
    let mut cmd = Command::new();
    // executable() alone still supplies lpApplicationName, so an empty command line here is not
    // the NULL-lpApplicationName hazard the check above exists to close — matches the existing
    // `Empty` arm's own "executable() alone" case.
    cmd.executable(std::path::PathBuf::from(r"C:\some\app.exe"));
    cmd.commandline("");
    assert!(raw_program_and_line(&cmd).is_ok());
}

#[test]
fn raw_program_and_line_allows_a_non_empty_command_line_with_no_executable_set() {
    let mut cmd = Command::new();
    cmd.commandline("tool --flag");
    assert!(raw_program_and_line(&cmd).is_ok());
}

/// The containment marker is an op after the user's, so it takes the name std gives it: after a
/// user's `env_remove("__cosca_group_root")`, that spelling, as on the std path.
#[test]
fn the_containment_marker_is_named_as_std_names_it() {
    let removed = "__cosca_group_root";
    let mut std_cmd = std::process::Command::new("unused");
    std_cmd.env_remove(removed).env(crate::containment::NESTED_ENV, "1");
    let std_name: Vec<_> = std_cmd.get_envs().map(|(k, _)| k.to_os_string()).collect();
    assert_eq!(std_name, [OsString::from(removed)], "std control");

    let snapshot = env_snapshot::EnvSnapshot::from_block("A=1\0\0".encode_utf16().collect());
    let user_ops = [EnvOp::Remove(removed.into())];
    let ops = child_ops(&user_ops, true);
    let block = resolve::ChildEnv::capture(&snapshot, &ops).into_block().unwrap();
    assert_eq!(String::from_utf16(&block).unwrap(), "A=1\0__cosca_group_root=1\0\0");
}
