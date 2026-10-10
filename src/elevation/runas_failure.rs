//! What a failed `ShellExecuteExW(runas)` means for the program it was to launch.
//!
//! Pure over the error's numbers, so it is tested on every platform; only the Windows launch
//! (`windows::launch_runas_with_host`) calls it.

/// A Win32 error as the `HRESULT` `ShellExecuteExW` fails with (`HRESULT_FROM_WIN32`).
const fn from_win32(code: u32) -> i32 {
    (0x8007_0000 | code) as i32
}

pub(crate) const ERROR_FILE_NOT_FOUND: i32 = from_win32(2);
pub(crate) const ERROR_PATH_NOT_FOUND: i32 = from_win32(3);
pub(crate) const ERROR_ACCESS_DENIED: i32 = from_win32(5);
#[cfg(test)]
pub(crate) const ERROR_NOT_ENOUGH_MEMORY: i32 = from_win32(8);
pub(crate) const ERROR_SHARING_VIOLATION: i32 = from_win32(32);
pub(crate) const ERROR_BAD_EXE_FORMAT: i32 = from_win32(193);
pub(crate) const ERROR_EXE_MACHINE_TYPE_MISMATCH: i32 = from_win32(216);
pub(crate) const ERROR_CANCELLED: i32 = from_win32(1223);
pub(crate) const ERROR_NO_ASSOCIATION: i32 = from_win32(1155);
/// Not matched: like any error not known to come before the launch, it may come after.
#[cfg(test)]
pub(crate) const ERROR_DDE_FAIL: i32 = from_win32(1156);
pub(crate) const ERROR_DLL_NOT_FOUND: i32 = from_win32(1157);
/// `hInstApp` values a DDE failure leaves.
pub(crate) const SE_ERR_DDETIMEOUT: isize = 28;
pub(crate) const SE_ERR_DDEFAIL: isize = 29;
pub(crate) const SE_ERR_DDEBUSY: isize = 30;

/// What the failure means for the program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunasFailure {
    /// The user declined the consent prompt, which comes before the launch: it did not start.
    Declined,
    /// An error that comes before any process is created: it did not start.
    BeforeLaunch,
    /// It may have started.
    MayHaveLaunched,
}

/// Classifies a failed `ShellExecuteExW(runas)` by its error `code` and its `hInstApp`.
///
/// Before any process is created:
///
/// - `ERROR_CANCELLED`: the user declined the consent prompt;
/// - `ERROR_FILE_NOT_FOUND`, `ERROR_PATH_NOT_FOUND`, `ERROR_ACCESS_DENIED`, `ERROR_SHARING_VIOLATION`:
///   the file to launch could not be found or opened;
/// - `ERROR_NO_ASSOCIATION`, `ERROR_DLL_NOT_FOUND`: no handler for the verb could be loaded;
/// - `ERROR_BAD_EXE_FORMAT`, `ERROR_EXE_MACHINE_TYPE_MISMATCH`: the image could not be loaded, so
///   the process was never created.
///
/// A DDE failure (`ERROR_DDE_FAIL`, or `SE_ERR_DDEFAIL`, `SE_ERR_DDEBUSY`, `SE_ERR_DDETIMEOUT` in
/// `hInstApp`) comes from the conversation with an application the shell already launched; a user's
/// own `exefile` `runas` verb can add one. It, and any error not listed above, may come after the
/// program started.
///
/// The list assumes the stock `HKCR\exefile\shell\runas` verb. A `DelegateExecute` handler a
/// same-user `HKCU` override installs could launch the program and then report one of the errors
/// above; such an override is the caller's own configuration, inside its trust boundary (the same
/// user), so its errors are read as the stock verb's would be.
pub(crate) fn classify(code: i32, inst_app: isize) -> RunasFailure {
    if code == ERROR_CANCELLED {
        return RunasFailure::Declined;
    }
    let dde = matches!(inst_app, SE_ERR_DDETIMEOUT | SE_ERR_DDEFAIL | SE_ERR_DDEBUSY);
    let before_launch = matches!(
        code,
        ERROR_FILE_NOT_FOUND
            | ERROR_PATH_NOT_FOUND
            | ERROR_ACCESS_DENIED
            | ERROR_SHARING_VIOLATION
            | ERROR_NO_ASSOCIATION
            | ERROR_DLL_NOT_FOUND
            | ERROR_BAD_EXE_FORMAT
            | ERROR_EXE_MACHINE_TYPE_MISMATCH
    );
    if before_launch && !dde {
        RunasFailure::BeforeLaunch
    } else {
        RunasFailure::MayHaveLaunched
    }
}

#[cfg(test)]
#[path = "runas_failure_tests.rs"]
mod runas_failure_tests;
