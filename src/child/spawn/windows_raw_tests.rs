use super::*;

// Item 5: `lpApplicationName` must never silently end up NULL ──────────────────────────
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
