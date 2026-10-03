//! Windows path-resolution canary: how Windows and `std::process` normalise path strings, checked
//! on a real Windows runner.
//!
//! cosca's `.bat`/`.cmd` gate (CVE-2024-24576) rests on a model of how Windows normalises path
//! strings, and that model depends on platform facts like these: how trailing dots and spaces,
//! `.`/`..`, verbatim `\\?\` prefixes, UNC and device roots and stream suffixes resolve.
//! `windows-latest` is a floating label: a Windows build can change those facts with no commit
//! here, so the `windows-probes` workflow runs this file on pull requests touching the code that
//! depends on it, weekly, and on demand.
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
//! write only inside a `tempfile` directory of their own and launch only `cosca_testbin_image`,
//! except that one canary has std create `cmd.exe` SUSPENDED and terminates it before it runs.
//! Nothing here runs a batch file or needs elevation. Temp directories are removed on drop and
//! planted files explicitly, but a removal failure is only printed; whatever it leaves goes with
//! the ephemeral runner.

#[cfg(windows)]
#[path = "common/mod.rs"]
mod common;
#[cfg(windows)]
#[path = "windows_path_resolution/dots_and_spaces.rs"]
mod dots_and_spaces;
#[cfg(windows)]
#[path = "windows_path_resolution/harness.rs"]
mod harness;
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

#[path = "../src/test_groups.rs"]
mod test_groups;
#[path = "../src/test_harness.rs"]
mod test_harness;

fn main() {
    let mut runner = skuld::TestRunner::new();
    runner.libtest_names();
    runner.require_known_labels();
    runner.run()
}
