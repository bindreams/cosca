//! Platform probes: what `ShellExecuteEx` actually does with an `lpFile`.
//!
//! cosca's Windows elevated path hands `lpFile` to `ShellExecuteExW`, and the resolution policy
//! around it rests on measured facts rather than documentation — the docs do not say, for
//! instance, whether an ABSOLUTE but extensionless `lpFile` still gets `PATHEXT` applied. Guessing
//! wrong there is the difference between "the search hazard is closed" and "a planted `.bat` runs".
//!
//! These are **probes, not assertions about cosca**. They measure the platform and print what they
//! found, so a maintainer can write a policy against evidence. Every one of them still FAILS if the
//! measurement itself could not be taken: the shell refused to launch anything for a reason other
//! than `ERROR_FILE_NOT_FOUND` (a genuine negative measurement — see `LaunchOutcome::NotLaunched`),
//! a helper could not be written, or a launch this probe waited on left no self-report behind. An
//! inconclusive run is now a hard failure everywhere it is genuinely inconclusive. That handoff
//! (`LaunchOutcome::LaunchedNoHandle`) is NOT inconclusive at all: `SEE_MASK_NOASYNC` is always set
//! on every call (see `harness::shell_execute_in_apartment`'s doc), so `ShellExecuteExW` does not
//! return until the shell has finished invoking whatever it handed `lpFile` off to — a synchronous,
//! measured fact, not a race. For an EXTENSIONLESS `lpFile` it is itself the measured answer —
//! `ShellExecuteEx` never runs an extensionless file as a program, existing or not, so getting no
//! process handle back is exactly what should happen, and every probe that plants an extensionless
//! target says so explicitly at that arm. What is still unmeasured is only what the handler the
//! shell handed off to does AFTERWARD; whatever the shell hands off to this way can never be
//! contained by cosca either, since no process handle is ever returned to assign to a Job Object.
//! No probe below reads a marker after a no-handle result to try to catch that handoff running
//! later: such a read would race the handoff itself, and no wait, sleep or poll can turn that race
//! into proof — see `pathext.rs`, `trailing_dot.rs` and `precedence.rs`'s doc comments for where
//! this applies.
//!
//! Every call sets `SEE_MASK_FLAG_NO_UI` — production (`src/elevation/windows.rs`) does not. These
//! probes measure `lpFile` RESOLUTION, not a human's answer to a picker dialog, and must run
//! unattended on a CI runner where no one is there to click one; the flag is kept here for exactly
//! that reason, even though it makes these probes not a byte-for-byte rehearsal of production's own
//! call. Where the flag suppresses a picker the shell would otherwise show, the shell instead
//! returns `ERROR_NO_ASSOCIATION` synchronously — so that code, exactly like `ERROR_FILE_NOT_FOUND`,
//! is a genuine measured negative for a probe whose target is itself extensionless, not a harness
//! failure; each such probe's `NotLaunched` arm says so explicitly.
//!
//! `ShellExecuteExW` can also fail to return at all rather than ever completing, for an EXISTING
//! extensionless target — measured intermittently, on both `x64` and `arm64` (see the PR
//! description's Verification section for run history; not repeated here to keep it in one place).
//! `OpenWith.exe` has been observed present during a hang. Beyond that, the cause is UNMEASURED: not
//! established to be UI-related, not established to be architecture-specific, not established to
//! depend on `SEE_MASK_NOASYNC` (the hang was first observed with that flag always set, before this
//! file ever dropped it for any call, so setting it unconditionally again is not expected by itself
//! to fix the hang), and — contrary to an earlier hypothesis — NOT explained by a missing COM
//! apartment: initializing one before every `ShellExecuteExW` call (`harness::shell_execute_with`)
//! did not stop a later run from hanging on both architectures at once. One candidate was that a
//! leftover `OpenWith.exe` instance from one of the three probes below that hand `ShellExecuteExW`
//! an EXISTING extensionless target blocks a LATER `ShellExecuteExW` call — possibly one belonging
//! to a DIFFERENT probe in a later process, since `cargo nextest` gives each test its own OS process
//! but every process on the same runner still shares the same shell state. Those three probes
//! therefore each run in their own nextest invocation, consecutively, after all other probes, with a
//! read-only diagnostic printing which `OpenWith.exe` instances exist before and after — see
//! `.github/workflows/windows-probes.yaml`'s `executing` job — rather than enumerating or killing
//! anything from inside the test binary itself. That isolation does NOT, on its own evidence,
//! support the leftover-handler theory: a dispatch run against it found one `OpenWith.exe` instance
//! carried across both LATER probes, on BOTH architectures, and neither probe hung — the leftover
//! was present exactly when the theory says it should have blocked the next call, and it did not.
//! Running each probe as its own OS process isolates the TEST PROCESS, not OS-level shell/handler
//! state, so this was never going to rule the theory in or out on its own; this run is evidence
//! against it. Every such call site still bounds the whole call, via `harness::shell_execute_bounded`
//! and `harness::SHELL_EXECUTE_BOUND` — see their docs — as a failure surface, not a synchronisation
//! device: hitting that bound is always a FAILURE to measure, never a passing answer. Whether to
//! keep these three probes at all, if the hang persists under this change too, is the repo owner's
//! call.
//!
//! # The lpClass divergence
//!
//! Production's actual elevated launch (`launch_runas_with_host`, `src/elevation/windows.rs`)
//! always sets `SEE_MASK_CLASSNAME` with `lpClass = "exefile"` — forcing the shell to skip its own
//! class-detection step and dispatch straight to `HKCR\exefile\shell\<verb>\command`. None of the
//! probes here set that, except `pathext::does_shellexecute_search_lpdirectory_for_a_pathless_lpfile_as_exefile`,
//! added specifically to measure it: forcing the class is itself a variable in `lpFile` resolution,
//! not incidental to it, so the "same `PathResolve` step for every verb" premise below does not by
//! itself cover a divergence in `lpClass`. An existing comment inside `plan_runas`
//! (`src/elevation/windows.rs`), beside production's own call, records, for an ELEVATED caller under
//! that forced class: "no App Paths, no bare-name search, % literal" — see that probe's doc for how
//! its measurement reconciles with this file's no-class conclusion.
//!
//! # Why they are `#[ignore]`d
//!
//! Most of them execute a batch file. That is the exact vector `reject_batch_path` exists to
//! refuse, so it must never happen incidentally during `cargo nextest run`. Opt in explicitly:
//!
//! ```text
//! cargo nextest run --test windows_shell_resolution --run-ignored only --no-capture
//! ```
//!
//! Or, from any host OS and without a local Windows VM, dispatch the `windows-probes` workflow with
//! `run_executing_probes` — see `.github/workflows/windows-probes.yaml`. A GitHub-hosted Windows
//! runner is an ephemeral VM destroyed after the job; these must not run against a development
//! machine.
//!
//! # Why no elevation is involved
//!
//! The open question is how `ShellExecuteEx` RESOLVES `lpFile`, which is the same `PathResolve`
//! step for every verb. Using the default verb instead of `runas` measures the same thing with no
//! UAC prompt and no elevated child — so these run unattended, and a failed probe cannot leave an
//! elevated process behind.
#![cfg(windows)]

#[path = "common/windows_probe.rs"]
mod windows_probe;

#[path = "windows_shell_resolution/harness.rs"]
mod harness;
#[path = "windows_shell_resolution/pathext.rs"]
mod pathext;
#[path = "windows_shell_resolution/precedence.rs"]
mod precedence;
#[path = "windows_shell_resolution/trailing_dot.rs"]
mod trailing_dot;
