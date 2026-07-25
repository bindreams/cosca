# Plan-review panel findings (round 2) + dispositions

Gate: REJECTED (17 findings). ALL accepted as real (none disputed). The updated
spec (`2026-07-25-elevation-design.md`) now encodes the structural decisions —
read it first; it governs. Fix every finding.

## STRUCTURAL DECISION 1 — drop the `env K=V` wrapper entirely (kills 005f7450, effae5f1, 64adc456, d6fb845a)

The `env` wrapper is irredeemable (verified live by the panel: `env A=1 -- true` →
exit 127; `env -- /opt/we=ird` dumps the environment and exits 0; unqualified
`env` reopens PATH-hijack). Replace with backend-native forwarding (spec
"Forwarding mechanism"):
- **sudo:** set forwarded vars in the SUDO CHILD's own environment (crate controls
  it via the normal env-op mechanism on the derived backend command), name them in
  `--preserve-env=NAME,…`. Validate each NAME matches `[A-Za-z_][A-Za-z0-9_]*`;
  a comma/`=`/non-ASCII name → `Error::Unsupported` (no lossy join). Program is
  sudo's own arg after `--`. NO `env` binary anywhere.
- **run0:** `--setenv=NAME=VALUE` per var.
- **doas / pkexec:** `.env()`/`.envs()` → `Error::Unsupported` (no forwarding
  mechanism exists).
- **`.env_remove()` / `.env_clear()` + elevate → `Error::Unsupported`** on every
  backend (the backend builds the base env; the crate can add but not subtract).
- Sanitizer denylist still applies to the forwarded set (load-bearing for run0's
  `--setenv`, defense-in-depth + report-accuracy for sudo).
- 64adc456: no more `env`, so no unqualified-`env` PATH hole. (The BACKEND binary
  is already resolved to an absolute path — keep that.)
- Rewrite the Task 7 (`build_argv`) and Task 11 (`rewrite`) asserted argvs to the
  new shapes. Add tests: sudo name validation reject (comma/`=`/non-ASCII);
  doas/pkexec `.env()` → Unsupported; `.env_remove`/`.env_clear` → Unsupported.

## STRUCTURAL DECISION 2 — write the Stdin password AFTER spawn (kills 41e5c4bf, a398122d)

Pre-spawn `write_all` into a pipe whose reader (the child) does not exist yet
deadlocks for any secret larger than the kernel pipe buffer. FIX: retain the pipe
write-end; spawn the child (its fd0 = the read-end); THEN write the
password+newline to the write-end (the child is now draining via `sudo -S`), then
drop the write-end (EOF). Post-spawn there is always a reader, so the write
completes regardless of length — no pipe-buffer assumption. Propagate write errors
as `Error::Elevation`; log at debug. Applies to BOTH sync (Task 11/15) and async
(Task 16) — post-spawn write on the std/blocking end is fine in the sync tokio
`spawn` fn (no `.await`).

## STRUCTURAL DECISION 3 — Windows runas child gets its own non-blocking-kill handle wrapper (kills e148ec21, 0dd20e72, 94ab6dc1)

`RawChild::kill()` treats `ERROR_ACCESS_DENIED` as "already exiting" and blocks in
`wait()` — valid for a `CreateProcessW` child, WRONG for a higher-integrity runas
child a medium-integrity parent cannot `PROCESS_TERMINATE`. With `kill_on_drop`
default true, `Drop`→`kill()`→`wait()` hangs forever. FIX:
- Do NOT wrap the runas child in `ProcHandle::Raw(RawChild)`. Give it a dedicated
  wrapper (or a `RawChild` flag) whose `kill()` calls `TerminateProcess`, CHECKS
  the result, and on `ACCESS_DENIED` returns a real `Error` (kill genuinely
  denied) — never blocks in `wait()`.
- `kill_on_drop` for a runas child is best-effort: attempt terminate, and if it
  fails, do NOT block — log and move on (the higher-integrity child may be
  unkillable; that is honest, documented behavior).
- 0dd20e72/94ab6dc1: the `Untracked` (identity-unresolvable) path must CHECK the
  `TerminateProcess` result and report terminated-vs-still-running distinctly;
  the `ElevationErrorKind::Untracked` Display must not assert "it was terminated"
  when terminate failed.

## STRUCTURAL DECISION 4 — non-destructive rewrite (kills f67cb114)

`set_input_argv`/`set_env_ops` mutate the caller's reusable `Command` in place →
a second spawn double-wraps (`sudo … sudo … id`) and destroys the caller's env
ops. FIX: build the backend invocation into a DERIVED/temporary command consumed
by spawn; leave the caller's `Command` untouched. (The crate supports `Command`
reuse — `status()` docs reference it.) Add a test spawning the same elevated
`Command` twice and asserting identical argv both times (or that the caller's
`input()`/`env_ops` are unchanged after spawn).

## STRUCTURAL DECISION 5 — fd>=3 on POSIX elevated → Unsupported (kills 429dc04f)

sudo/pkexec `closefrom` and run0-via-PID1 drop fds >2, so `.fd(3, pipe).elevate()`
silently loses fd3 on POSIX while Windows rejects it. FIX: reject `fd >= 3` on
POSIX elevated commands with `Error::Unsupported` (mirror the Windows gate).
Narrow the `ElevatedStdio::Passthrough` doc to fds 0-2. Test per platform.

## STRUCTURAL DECISION 6 — launch_runas_with_host injection seam (kills c500d201, 6d749b0d)

`launch_runas` calls `Host::detect()` internally, so on an already-elevated runner
(GitHub Windows runners run elevated!) the gate never runs and the reject tests
invert. FIX: add `launch_runas_with_host(cmd, &Host)` mirroring `rewrite_with_host`;
drive Windows gate tests through an injected NON-elevated Windows `Host`.
- 6d749b0d: tests asserting "process is NOT elevated" gated only by
  `SUBPROCESS_TEST_ELEVATION` absence are wrong (that var ≠ "not root"; CI
  containers/elevated shells/Windows runners break them). FIX: assert
  `is_elevated()` against an INDEPENDENT ground truth (`geteuid()==0` on unix /
  token query on windows), or branch on the detected state — never assume.

## Localized fixes

- 4ce88387: `SHELLEXECUTEINFOW`/`ShellExecuteExW` are gated behind
  `Win32_System_Registry` in windows 0.62.2 (HKEY field). ADD `"Win32_System_Registry"`
  to the windows feature list in the Cargo.toml edit (Task 12).
- 5cf8665a: `CoInitializeEx` — `S_FALSE` means already-init WITH refcount
  incremented → REQUIRES a matching `CoUninitialize`. FIX: `uninit = true` for both
  `S_OK` and `S_FALSE`; only `RPC_E_CHANGED_MODE` skips `CoUninitialize`.
- ffba0943: `/dev/tty` probe blocks on a carrier-less serial console. FIX: add
  `O_NONBLOCK` to the `open` flags (probe only needs open to succeed).
- 948c8e5c: `libc::access(X_OK)` answers for the REAL uid and is check-then-act.
  FIX: use `libc::faccessat(AT_FDCWD, path, X_OK, AT_EACCESS)` (effective ids), treat
  the result as a HINT, and surface an exec failure of the resolved backend path as
  `ElevationErrorKind::BackendUnavailable` (not a raw `Io` error).
- dc2568da: Windows `is_elevated()`/`integrity_level()` collapse token-query
  FAILURE into "not elevated" with no log. FIX: log at debug/warn to distinguish
  "determined not-elevated" from "could-not-determine, assuming not-elevated" on
  every query-failure path.
- f7897d84: the impossible cross-OS `Transition` arms (`ElevateWindows` on POSIX,
  `ElevatePosix` on Windows) return a misleading `BackendUnavailable`. FIX: these
  are planner-guaranteed-impossible → `unreachable!()` / `debug_assert!(false, …)`
  (contract enforcement), NOT a caller-visible `Err` with a wrong kind.

## Test fixes

- 2127d01b: the `/dev/tty`-probe-stable-across-stdin-redirection test never
  redirects fd0 → vacuous (would pass even with the buggy `isatty(STDIN)`). FIX:
  actually redirect fd0 (`libc::dup2(devnull, 0)`) or run the probe via a testbin
  subcommand with `Stdio` stdin redirected, then assert the probe result is
  unchanged.
- 1a9d5259 (dup of c500d201/0ebcb079 test): the stdin-auth test asserts
  `ResolvedStdio::Pipe(_)` but the impl uses `Stdio::from_file` → resolves to
  `ResolvedStdio::File(_)`. FIX: assert `Some(ResolvedStdio::File(_))` (or change
  the impl to a pipe-in that resolves to `Pipe`). Make impl and assertion agree.
- f9409471: the "FULL Auth×backend matrix" test omits `(Backend::Run0, Auth::Gui)`.
  FIX: add that cell.
- 77027ea9: Task 9's stated security fixes (X_OK not is_file; skip empty PATH
  elements = CWD) have NO direct test. FIX: unit-test `resolve_on_path`
  (make it `pub(super)`): (a) a dir with a non-executable `sudo` is skipped;
  (b) a PATH with an empty element never resolves a backend from CWD.

## Conciseness cuts (apply all — localized doc/comment trims)

- ff57880d occurrences: remove the `(Task 16)`/`(S2)` task-refs from permanent doc
  comments (lines ~2641, 2842); strip the backtick hash-token prefixes
  (`ffad4627`, `60eb2f86`, …) from bullet lists (line ~2927); strip the
  `f3f0608c:`/`Decision #2:`/`Decision #3 / S5:` labels (line ~3079); delete the
  redundant doc lines at ~885, ~927, ~1387; drop the `// GATED:` narration
  (line ~3150) down to a plain description.

## Convergence note
Round 1: 36 findings. Round 2: 17. The env-wrapper redesign (Decision 1) and
post-spawn write (Decision 2) remove the last structural hazards; the remainder are
localized. This round should converge to conditionally-approved/approved.
