//! Where the tests' temp directories go: the system's, or a root the developer names.
//!
//! The tests take every temp directory and file from `tempfile`, so one process-wide setting moves them
//! all. A developer sets it to keep the many short-lived executables the tests write out of a directory an
//! antivirus scans on every write.

use std::ffi::OsString;
use std::path::PathBuf;

/// Names the directory the tests make their temp directories in. A relative path is taken from the
/// directory the test binary starts in (the package's, under nextest and cargo). Unset or empty: the
/// system's temp directory.
pub const TEMP_ROOT_ENV: &str = "COSCA_TESTING_TEMP_ROOT";

/// The file in the starting directory whose [`TEMP_ROOT_ENV`] line, when it has one, replaces the
/// environment's value. Nothing else in it is read.
const DOTENV: &str = ".env";

/// Points `tempfile` at [`TEMP_ROOT_ENV`]'s directory, for this process and the ones it starts. A test
/// binary's `main` calls it first, before any thread exists and before any temp file is made.
///
/// `tempfile` names each directory it makes there apart from every other, as it does in the system's.
pub fn apply() {
    let Some(root) = configured() else { return };
    let root = std::path::absolute(&root)
        .unwrap_or_else(|error| panic!("{TEMP_ROOT_ENV}={root:?} is not a usable path: {error}"));
    std::fs::create_dir_all(&root).unwrap_or_else(|error| panic!("{TEMP_ROOT_ENV}: cannot create {root:?}: {error}"));
    // A test child that starts in another directory must take the same root, so it gets the absolute path.
    std::env::set_var(TEMP_ROOT_ENV, &root);
    tempfile::env::override_temp_dir(&root)
        .unwrap_or_else(|set| panic!("{TEMP_ROOT_ENV}: the temp directory was already set to {set:?}"));
}

/// The root the developer named: the `.env` file's value where it has one, else the environment's.
fn configured() -> Option<PathBuf> {
    let value = from_dotenv().or_else(|| std::env::var_os(TEMP_ROOT_ENV))?;
    (!value.is_empty()).then(|| PathBuf::from(value))
}

/// [`TEMP_ROOT_ENV`]'s value in the starting directory's `.env`, if the file exists and names it.
fn from_dotenv() -> Option<OsString> {
    let lines = match dotenvy::from_path_iter(DOTENV) {
        Ok(lines) => lines,
        Err(error) if error.not_found() => return None,
        Err(error) => panic!("cannot read {DOTENV}: {error}"),
    };
    lines
        .map(|line| line.unwrap_or_else(|error| panic!("cannot read {DOTENV}: {error}")))
        .find_map(|(key, value)| (key == TEMP_ROOT_ENV).then(|| OsString::from(value)))
}
