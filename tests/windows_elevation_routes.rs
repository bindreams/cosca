//! Platform probes: can an UNELEVATED Windows process start an ELEVATED child without
//! `ShellExecuteEx("runas")`?
//!
//! cosca's Windows elevated path is `ShellExecuteExW` + the `runas` verb, which costs it stdio
//! handles, `fd >= 3`, environment control and — as `windows_shell_resolution.rs` measured —
//! control over which image actually loads. The documented alternatives (`CreateProcessAsUserW`,
//! `CreateProcessWithTokenW`, `CreateProcessWithLogonW`) all take an `lpApplicationName` that is
//! documented NOT to search and NOT to append an extension, and all take a `STARTUPINFOW`. If any
//! of them can produce an elevated child from a medium-integrity caller, cosca can leave
//! `ShellExecuteEx` behind.
//!
//! These are **probes, not assertions about cosca**. They print what they measured. Each still
//! FAILS if the measurement could not be taken, so an inconclusive run is never a silent pass.
//!
//! # Integrity level is part of every result
//!
//! The question is about an UNELEVATED caller, and every machine these run on (a GitHub-hosted
//! Windows runner, an OpenSSH admin session) hands the test an ELEVATED token. A measurement taken
//! at high integrity does not answer the question, so every report line carries the integrity RID
//! it was taken at.
//!
//! Two probes reach the unelevated case, and only one of them is trustworthy on every host:
//!
//! - `logon_routes::does_create_process_with_logon_elevate` logs a throwaway administrator on and
//!   runs the whole report inside the resulting child. That child is a REAL process from a REAL
//!   logon, and it is where the unelevated answers come from. It needs a disposable host.
//! - `token_filtering::unelevated_caller_view` derives a medium token from this process's own and
//!   starts a child under it, needing no account. On a desktop over SSH the lowered-integrity child
//!   can fail to open the caller's window station and die in loader init (0xC0000142); on a GitHub
//!   runner it instead SUCCEEDS and produces a full report, so 0xC0000142 is a possible failure of
//!   this route, not its guaranteed outcome, and the probe fails loudly rather than reporting a
//!   misleading negative if it happens. Succeeding is not the same as measuring an unelevated
//!   caller, though: `TokenIsElevated` is fixed at token creation from the source logon's elevation
//!   type, so on a Default (non-split) admin token — what run 35850159223's GitHub runner has —
//!   synthesis cannot clear it, and the resulting child is a lowered-integrity ELEVATED caller, not
//!   an unelevated one. The probe prints and labels which case it measured; read its output before
//!   trusting its report as the unelevated answer.
//!
//! # Why they are `#[ignore]`d, and the two safety gates
//!
//! They create processes with derived tokens, and two of them change machine state. Opt in:
//!
//! ```text
//! cargo nextest run --test windows_elevation_routes --run-ignored only --no-capture
//! ```
//!
//! Three probes additionally refuse to run — loudly, by panicking, never by skipping — unless an
//! environment variable says the host is disposable:
//!
//! - `COSCA_PROBE_ALLOW_ACCOUNTS=1` — creates and deletes a local user account. Required by
//!   `logon_routes::does_create_process_with_logon_elevate` and
//!   `token_filtering::which_logon_types_return_a_filtered_token`.
//! - `COSCA_PROBE_ALLOW_STATE=1` — registers and deletes a scheduled task. Required by
//!   `scheduled_task::can_this_caller_register_a_runlevel_highest_task`.
//!
//! `does_create_process_with_logon_elevate` and `which_logon_types_return_a_filtered_token` both
//! create their scratch accounts under the same two fixed names (`coscaprobeadm`,
//! `coscaprobestd`), so they must never run concurrently with each other; `--no-capture` already
//! forces nextest to run every test in this invocation serially, and the `windows-elevation-routes`
//! test group capped at one thread in `.config/nextest.toml` gives the same guarantee independent
//! of that flag.
//!
//! Both are set by the `executing` job of `.github/workflows/windows-probes.yaml`, which runs only
//! when dispatched with `run_executing_probes`, on a GitHub-hosted runner: an ephemeral VM
//! destroyed after the job. They must never be set on a machine anyone depends on.
#![cfg(windows)]

#[path = "common/windows_probe.rs"]
mod windows_probe;

#[path = "windows_elevation_routes/harness.rs"]
mod harness;
#[path = "windows_elevation_routes/logon_routes.rs"]
mod logon_routes;
#[path = "windows_elevation_routes/scheduled_task.rs"]
mod scheduled_task;
#[path = "windows_elevation_routes/token_filtering.rs"]
mod token_filtering;
