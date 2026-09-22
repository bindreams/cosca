//! Unit tests for the raw `CreateProcessW` backend's pre-spawn program gate
//! ([`super::reject_batch_program`]), which runs before resolution and decides what a malformed
//! program token is BLAMED on. Driven directly rather than through `spawn_raw`, so no child is
//! created and the verdict is the gate's alone.

use super::reject_batch_program;
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

    let mut by_executable = Command::new();
    by_executable.executable(token).args(["setup.bat"]);

    let mut by_commandline = Command::new();
    by_commandline.commandline(token.clone());

    vec![
        ("argv[0]", by_argv),
        ("executable()", by_executable),
        ("commandline()", by_commandline),
    ]
}

/// The shape the batch gate is BLIND to: `setup.bat` + NUL + `junk`. Win32 truncates it back to
/// `setup.bat`, a real batch file, but `Path::extension()` reads `bat\0junk`, so
/// `reject_batch_path` does not fire — see
/// `crate::child::spawn::spawn_tests::the_batch_gate_fires_on_one_nul_shape_and_is_blind_to_the_other`,
/// which pins that on any host. Delete the NUL check and this gate returns `Ok`, handing the token
/// on to resolution to fail as a `NotFound` that names neither the NUL nor the batch file.
#[test]
fn a_nul_after_a_batch_extension_is_refused_where_the_batch_gate_is_blind() {
    let token = nul_between("setup.bat", "junk");
    for (via, c) in commands_with_token(&token) {
        // The helper IS the assertion: an `Ok` or a downstream error kind panics here.
        invalid_input_message(via, reject_batch_program(&c));
    }
}

/// The mirror shape, and the one the ORDER fixes: `C:\tools\setup` + NUL + `.bat`. `\0` is not a
/// path separator, so `Path::extension()` reads `bat` straight through it and `reject_batch_path`
/// would fire — on a prefix (`C:\tools\setup`) that is not a batch file. That refusal points the
/// caller at CVE-2024-24576 over a NUL defect AND interpolates a raw U+0000 into a message bound for
/// logs and terminals. Running the NUL check first prevents both.
#[test]
fn a_nul_before_a_batch_extension_is_diagnosed_as_a_nul_not_a_batch_refusal() {
    let token = nul_between(r"C:\tools\setup", ".bat");
    for (via, c) in commands_with_token(&token) {
        // `Unsupported` here — the batch gate winning the race — panics in the helper.
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
    for (via, c) in commands_with_token(&nul_between("setup.bat", "junk")) {
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
