use super::*;

/// A failed `ShellExecuteEx(runas)` did not start the program only on an error that comes before
/// any process is created. A DDE failure comes from a conversation with an application the shell
/// already launched, and an error not known to come first is not taken to.
///
/// Mutants: a DDE failure (by code, or by `hInstApp`) answers that the program did not start; an
/// unlisted error answers that it did not; a declined prompt answers otherwise.
#[skuld::test]
fn a_shell_execute_failure_says_whether_the_program_may_have_started() {
    assert_eq!(classify(ERROR_CANCELLED, 0), RunasFailure::Declined);
    for code in [
        ERROR_FILE_NOT_FOUND,
        ERROR_PATH_NOT_FOUND,
        ERROR_ACCESS_DENIED,
        ERROR_SHARING_VIOLATION,
        ERROR_NO_ASSOCIATION,
        ERROR_DLL_NOT_FOUND,
        ERROR_BAD_EXE_FORMAT,
        ERROR_EXE_MACHINE_TYPE_MISMATCH,
    ] {
        assert_eq!(classify(code, 2), RunasFailure::BeforeLaunch, "{code:#x}");
    }
    assert_eq!(classify(ERROR_DDE_FAIL, 0), RunasFailure::MayHaveLaunched);
    for se in [SE_ERR_DDEFAIL, SE_ERR_DDEBUSY, SE_ERR_DDETIMEOUT] {
        assert_eq!(
            classify(ERROR_FILE_NOT_FOUND, se),
            RunasFailure::MayHaveLaunched,
            "hInstApp {se}"
        );
    }
    assert_eq!(classify(ERROR_NOT_ENOUGH_MEMORY, 8), RunasFailure::MayHaveLaunched);
}

#[cfg(windows)]
#[skuld::test]
fn the_codes_are_windows_own() {
    use windows::core::HRESULT;
    use windows::Win32::Foundation as f;
    use windows::Win32::UI::Shell as sh;
    let pairs = [
        (ERROR_FILE_NOT_FOUND, f::ERROR_FILE_NOT_FOUND),
        (ERROR_PATH_NOT_FOUND, f::ERROR_PATH_NOT_FOUND),
        (ERROR_ACCESS_DENIED, f::ERROR_ACCESS_DENIED),
        (ERROR_NOT_ENOUGH_MEMORY, f::ERROR_NOT_ENOUGH_MEMORY),
        (ERROR_SHARING_VIOLATION, f::ERROR_SHARING_VIOLATION),
        (ERROR_BAD_EXE_FORMAT, f::ERROR_BAD_EXE_FORMAT),
        (ERROR_EXE_MACHINE_TYPE_MISMATCH, f::ERROR_EXE_MACHINE_TYPE_MISMATCH),
        (ERROR_CANCELLED, f::ERROR_CANCELLED),
        (ERROR_NO_ASSOCIATION, f::ERROR_NO_ASSOCIATION),
        (ERROR_DDE_FAIL, f::ERROR_DDE_FAIL),
        (ERROR_DLL_NOT_FOUND, f::ERROR_DLL_NOT_FOUND),
    ];
    for (ours, theirs) in pairs {
        assert_eq!(ours, HRESULT::from_win32(theirs.0).0, "{theirs:?}");
    }
    assert_eq!(SE_ERR_DDETIMEOUT, sh::SE_ERR_DDETIMEOUT as isize);
    assert_eq!(SE_ERR_DDEFAIL, sh::SE_ERR_DDEFAIL as isize);
    assert_eq!(SE_ERR_DDEBUSY, sh::SE_ERR_DDEBUSY as isize);
}
