//! Windows path-resolution canary: how Windows and `std::process` normalise path strings, checked
//! on a real Windows runner.
//!
//! cosca's `.bat`/`.cmd` gate (CVE-2024-24576) rests on a model of how Windows normalises path
//! strings, and that model depends on platform facts like these: how trailing dots and spaces,
//! `.`/`..`, verbatim `\\?\` prefixes, UNC and device roots and stream suffixes resolve.
//! `windows-latest` is a floating label: a Windows build can change those facts with no commit
//! here, so the `Test (windows/...)` jobs of `ci.yaml` run this file on every pull request, and the
//! `windows-probes` workflow runs it weekly and on demand.
//!
//! This file describes the platform only. It does not say what any gate in the tree does.
//!
//! # Two kinds of test
//!
//! **Canaries** assert a platform fact and FAIL when Windows disagrees, when an asserted
//! measurement could not be taken, or when they checked nothing at all. A failure means any code
//! modelling that fact must be re-derived from the new behaviour; do not loosen the assertion.
//!
//! **Surveys**, and the rows a canary prints without asserting, only print. A Win32 error there is
//! printed as the measurement, not raised, so a change in behaviour nothing asserts on never turns
//! the run red. They fail only if their own scaffolding (a temp directory) cannot be set up.
//!
//! The `m<n>_` surveys are the single-backend measurements: what `main`'s two Windows routes
//! do today, printed as `M<n> <key>=<value>` lines for the change that unifies them to assert.
//!
//! Every test stamps its output with the OS build it ran on.
//!
//! # How to run it
//!
//! ```text
//! COSCA_TEST_PATH_PROBES_CONSENT=1 cargo nextest run --test windows_path_resolution --no-capture
//! ```
//!
//! The canaries and surveys are the `PATH_PROBES` group (principle 9), so an ordinary run
//! never mistakes a platform measurement for coverage of cosca. The canary's own string logic and
//! verdict are tested by `windows_path_logic`, which runs by default on every host. `GetFullPathNameW` works on the string alone and touches no disk
//! or network, so UNC and device inputs here reach no server or device. The file and spawn tests
//! write inside a `tempfile` directory of their own and launch `cosca_testbin` and its image
//! copies, with these exceptions: one canary has std create `cmd.exe` SUSPENDED and terminates it
//! before it runs; `m5_what_std_loads` runs `whoami` and `find` from System32, launches `winget
//! --version` and reaches its temp directory through `\\localhost\<drive>$`;
//! `m19_app_execution_aliases` also launches `winget --version` and makes a directory of its own
//! beside `%LOCALAPPDATA%\Microsoft\WindowsApps`, which it removes explicitly: a failed removal
//! fails the test. The symlink rows of `m19_` need the symlink privilege or Developer Mode, and
//! record a refusal. Nothing here runs a batch file. Temp directories are removed on drop and
//! planted files explicitly, but a removal failure is only printed; whatever it leaves goes with
//! the ephemeral runner.

#[cfg(windows)]
#[path = "windows_path_resolution/aliases.rs"]
mod aliases;
#[cfg(windows)]
#[path = "windows_path_resolution/backend.rs"]
mod backend;
#[cfg(windows)]
#[path = "common/mod.rs"]
mod common;
#[cfg(windows)]
#[path = "windows_path_resolution/devices.rs"]
mod devices;
#[cfg(windows)]
#[path = "windows_path_resolution/dots_and_spaces.rs"]
mod dots_and_spaces;
#[cfg(windows)]
#[path = "windows_path_resolution/env_set.rs"]
mod env_set;
#[cfg(windows)]
#[path = "windows_path_resolution/harness.rs"]
mod harness;
#[cfg(windows)]
#[path = "windows_path_resolution/measure.rs"]
mod measure;
#[cfg(windows)]
#[path = "windows_path_resolution/provenance.rs"]
mod provenance;
#[cfg(windows)]
#[path = "windows_path_resolution/pure.rs"]
mod pure;
#[cfg(windows)]
#[path = "windows_path_resolution/spawn.rs"]
mod spawn;
#[cfg(windows)]
#[path = "windows_path_resolution/std_loads.rs"]
mod std_loads;
#[cfg(windows)]
#[path = "windows_path_resolution/streams.rs"]
mod streams;
#[cfg(windows)]
#[path = "windows_path_resolution/surveys.rs"]
mod surveys;
#[cfg(windows)]
#[path = "windows_path_resolution/unc_and_device.rs"]
mod unc_and_device;
#[cfg(windows)]
#[path = "windows_path_resolution/verdict.rs"]
mod verdict;
#[cfg(windows)]
#[path = "windows_path_resolution/winapi.rs"]
mod winapi;

#[cfg(windows)]
use common::test_groups;
#[path = "../src/test_harness.rs"]
mod test_harness;

fn main() {
    let mut runner = skuld::TestRunner::new();
    runner.libtest_names();
    runner.require_known_labels();
    runner.run()
}
