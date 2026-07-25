# Plan-review panel findings (round 3) + dispositions

Gate: REJECTED (22 findings). ALL accepted (none disputed). The updated spec
(`2026-07-25-elevation-design.md`) now encodes the unifying decisions — read it
first; it governs. Fix every finding.

## DECISION A — universal elevated-child teardown (kills b2775561, d9ed83c3; unifies the Windows runas kill from r2)

An unprivileged parent cannot kill its elevated child on ANY platform (POSIX
`kill`→EPERM; Windows runas→ACCESS_DENIED). Apply ONE principle everywhere (spec
"Killing an elevated child"):
- Add `ElevationErrorKind::Unkillable`.
- `kill()`/`kill_tree()` on a `Some(Wrapped(..))` child map EPERM/ACCESS_DENIED →
  `Error::Elevation { kind: Unkillable, .. }` (typed, not raw `Io`).
- `Drop`/`kill_on_drop`/`teardown_on_drop` NEVER block: attempt signal, on
  EPERM/ACCESS_DENIED do `try_wait()` + `log::warn!`, never a blocking `wait()`.
  Apply to BOTH the POSIX `Std` teardown arm (b2775561 — currently `let _ =
  s.kill(); let _ = s.wait();` blocks forever) AND the Windows runas arm.
- d9ed83c3: split the capability-matrix kill row per backend; note `.contain()`
  (cgroup.kill) is what restores reliable kill on Linux; map POSIX `kill()` EPERM to
  the typed error.
- Tests (BOTH platforms): drop a non-contained elevated long-lived child and assert
  `Drop` RETURNS (bounded, no hang); `kill()` returns the typed `Unkillable` error.

## DECISION B — race-harden the Auth::Stdin post-spawn write (kills f42bfed5, 0117c966, e629c0d1, dd9323ff, ee4ecd94)

The whole `PendingPassword` mechanism (spec "Auth::Stdin post-spawn write"):
- f42bfed5: NOPASSWD/cached-cred means sudo never reads fd0 → the write races the
  child's exit. FIX: non-blocking writer; `EPIPE`/`WouldBlock` → "backend didn't
  need the password" → `log::debug!` + return `Ok`, NOT `AuthFailed`. Delete the
  "completes for any secret length" claim. Only a genuine error on a still-open
  pipe is a failure.
- 0117c966: `secret.expose().to_vec()` then `push(b'\n')` reallocs → un-zeroized
  plaintext left in the freed buffer. FIX: `Vec::with_capacity(len+1)` +
  `extend_from_slice` + `push`; test that capacity never grows.
- e629c0d1/dd9323ff/ee4ecd94: `pw.write_after_spawn()?` drops the already-running
  child on error → orphan/hang. FIX (sync Task 15 AND async Task 16): on genuine
  write failure, explicitly `kill()` + `try_wait()` the child and fold the outcome
  into the `Error::Elevation` detail (mirror Windows `Untracked`). A bare `?` must
  never decide the child's fate.
- Live test (0e3cb1ba): add a gated `Auth::Stdin(Secret::new(pw))` live test vs real
  `sudo -S` asserting uid 0, and one `Auth::Askpass` live test with a trivial
  askpass script.

## DECISION C — config gates BEFORE the already-elevated short-circuit (kills bb78e1cc)

Structural request-validation (fd>=3, env ops on unsupporting backends,
contain+run0/windows, commandline, elevated-Windows captured stdio) is a property of
the REQUEST, privilege-independent. FIX: run these gates BEFORE the `RunAsIs`
short-circuit in BOTH `rewrite_with_host` and `launch_runas_with_host`, so the same
`Command` yields the same verdict regardless of ambient privilege. Only `NoTty`/
`BackendUnavailable` (environmental) stay after. Update the Task 5 contract text to
say exactly this. Add tests asserting a structurally-invalid elevated request is
rejected with `elevated: true` too.

## DECISION D — single-source the sync/async dispatch (kills 52f92d90)

The elevation-dispatch flow + the `AlreadyElevated` report literal are hand-copied
across sync/async spawn (≥5 copies). FIX: factor shared helpers used by both paths:
- `fn already_elevated_report(stdio: ElevatedStdio) -> ElevationReport` (used by
  Task 11 POSIX, Task 14 Windows, Task 16 async).
- `fn remap_derived_spawn_error(r, backend_path) -> Result<Child, Error>` (used by
  Task 15 sync AND Task 16 async) — see Decision F for its correct body.
- Add a test injecting the same failure through BOTH `Command` and `tokio::Command`
  asserting identical `Error::Elevation` (parity-by-construction).

## DECISION E — pkexec argv (kills f23584ab, 6e02709c)

- f23584ab: pkexec's hand-rolled option loop does NOT understand `--` (breaks on
  first unknown → treats `--` as the program). FIX: do NOT push `--` for
  `Backend::Pkexec`. Fix the `pkexec_gui_no_env` test to `["/usr/bin/pkexec","id"]`.
  A leading-dash program under pkexec → `Unsupported`.
- 6e02709c: no flag → pkexec falls back to a TEXT agent that blocks on a TTY prompt.
  FIX: pass `--disable-internal-agent` for pkexec so a missing graphical agent fails
  loud → `AuthFailed`. Argv test pins the flag.

## DECISION F — honest error remap (kills 18eb73b3)

`Error::Io(NotFound|PermissionDenied)` from the derived spawn is remapped to
`BackendUnavailable`, but the derived command carries the caller's `current_dir()`
— a bad cwd yields the same kinds. FIX: only remap when the failure is attributable
to the resolved BACKEND path (validate the backend path / or check cwd first);
ALWAYS embed the underlying `io::Error` + backend path in `detail` so the cause
survives. Applies sync (Task 15) and async (Task 16).

## Localized honesty (21c28450)

`--preserve-env` is filtered by sudoers `env_check`/`env_delete`/`secure_path` — the
crate can't know the residual filter. FIX: matrix cell + `ElevationReport` doc say
"forwarded, subject to sudoers policy" (do NOT promise delivery). Optionally a gated
live test forwarding PATH + a custom var under a `secure_path` sudoers config.

## Test fixes

- aa2d3463 + 2127d01b (same test): the `/dev/tty` stdin-redirection-independence test
  is vacuous under `cargo test` (no controlling terminal in CI). FIX: run it under a
  PTY (repo HAS a `pty` feature + CI leg) so `/dev/tty` opens and the null-vs-inherit
  stdin runs genuinely discriminate a correct probe from `isatty(STDIN)`. If a PTY
  harness is too heavy, gate it to the pty CI leg; do NOT ship a CI-vacuous assertion.
- cb1534b6: the run0 kill-propagation test asserts the CLIENT is reaped (always true
  after `wait()`), never the transient unit. FIX: elevated payload writes its own pid
  to a file (or scan for the `sleep 600` descendant); after killing the client, assert
  THAT is gone. Else drop the test.
- 8cf4be21: the runas non-blocking-kill path (`RawChild`/`RawAsyncChild` runas arms)
  has ZERO coverage. FIX: unit test constructing a `new_runas`-flagged wrapper around a
  REAL non-elevated child, call `kill()`/`teardown_on_drop()`/`reap_blocking()`, assert
  it returns promptly and reaps (proves the runas flag routes correctly even though the
  ACCESS_DENIED corner needs a manual elevated run).
- e7c9d39b: `rewrite_with_host`/`launch_runas_with_host` `RunAsIs` (already-elevated,
  requested) branch untested. FIX: one test per effect layer with `elevated: true`
  asserting `derived.is_none()`/`AlreadyElevated` and `report.via ==
  ElevatedVia::AlreadyElevated`.
- 8db73f0c: `is_elevated_agrees_with_integrity_level` is vacuous when
  `integrity_level()` returns `None`. FIX: assert `integrity_level().is_some()`
  unconditionally (fail loud if unanswerable on the runner).
- 9515f4d2: `elevated_pipe_routes_through_the_gate` branches on ambient privilege with
  no `elevation()` assertion on the elevated branch. FIX: split into deterministic
  tests via the host-injection seam (inject `Host{elevated:true,..}`), assert the
  allowed-spawn path's `child.elevation()`.
- 4c785f26 + e7c9d39b: no async Windows elevation test at all. FIX: a manual-tier
  `#[cfg(all(windows, feature="tokio"))]` test mirroring the sync Windows marker test,
  OR explicitly note the gap in `TODO.md` (Task 18) CI-provisioning section.

## Dropped-but-worth-pinning (run0 non-interactive)

The panel DROPPED but flagged: `Auth::NonInteractive`+`Backend::Run0` emits
`--no-ask-password` (a systemd-run flag) but run0 auths via polkit, not systemd's
agent — unverified that it suppresses the polkit prompt. FIX: verify `run0(1)` for the
pinned systemd; if it does NOT suppress polkit, either reject `Run0+NonInteractive`
structurally OR use the polkit-non-interactive mechanism. Pin with the gated run0 live
test.

## Conciseness cuts (apply all)
Strip the dangling opaque hash-ID / `Decision #` / `(Task N)` / `(S2)` prefixes from
the permanent doc comments and bullet lists at the flagged lines (ids 4f6b3e02,
3b0e38df, 42cf255c, cf1a3ced, 287d9455, 1b5beb81, e05f68a6) — keep the bullet text,
drop the prefix.

## Convergence note
Rounds: 36 → 17 → 22. The bump is round-2's NEW mechanisms coming under review, not
churn. Decisions A-F are the natural completion of the design (universal teardown,
robust Stdin, gate placement, DRY); they should not spawn a new fundamental cluster.
Target: conditionally-approved/approved.
