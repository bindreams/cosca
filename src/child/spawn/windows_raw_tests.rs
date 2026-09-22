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

/// A NUL in the PROGRAM TOKEN must be blamed on the program token. The raw backend shares one NUL
/// checker with the environment-block builder, so a message hardcoded to the environment sends the
/// caller off to audit `env()` over a defect in `args()` or `executable()` — the same class of
/// misattribution the NUL-before-batch ordering exists to prevent, one field over.
#[test]
fn a_nul_in_the_program_token_is_not_blamed_on_the_environment() {
    let token = nul_between("setup.bat", "junk");

    let mut by_argv = Command::new();
    by_argv.args([token.clone()]);

    let mut by_executable = Command::new();
    by_executable.executable(&token).args(["setup.bat"]);

    let mut by_commandline = Command::new();
    by_commandline.commandline(token.clone());

    for (via, c) in [
        ("argv[0]", &by_argv),
        ("executable()", &by_executable),
        ("commandline()", &by_commandline),
    ] {
        let msg = invalid_input_message(via, reject_batch_program(c));
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
