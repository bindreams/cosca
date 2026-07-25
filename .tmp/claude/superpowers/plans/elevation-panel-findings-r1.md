# Plan-review panel findings (round 1) + dispositions

Gate: REJECTED (36 findings). All are ACCEPTED as real (none disputed). Fix every
one. Decisions on genuine design forks are recorded in the updated spec
(`2026-07-25-elevation-design.md`) — read it first; it now governs.

## Structural reworks (fix these together — they compound)

### S1. Task sequencing / forward references (ids 457a6fb5, fee7114b, ab933ae1)
- Task 10's `spawn()` edit calls `crate::elevation::windows::spawn_elevated`/`spawn_unelevated`, but those + `src/elevation/windows.rs` don't exist until Tasks 11/13 → Windows build red for Tasks 10-12.
- FIX: Resequence. Land Windows detection (Task 11) and the `spawn_unelevated` extraction BEFORE the `spawn()` elevation branch that references them. The `spawn_unelevated` extraction must be its OWN explicit TDD step with a concrete before/after diff of `spawn()` and a FULL `cargo test --lib` regression run (not just elevation tests) immediately after — it refactors the shared non-elevated spawn path.
- ab933ae1: `ElevatedStdio` Interfaces block (line ~255) still lists `{Piped,Inherited,OwnConsole,Hidden}` and the Self-Review type table (line ~2481) re-asserts the 4-variant list, but code+tests use `{Passthrough,OwnConsole}`. Make Interfaces + Self-Review table read `{Passthrough, OwnConsole}` everywhere. Note run0 may later need a pty-aware variant (non_exhaustive covers it).

### S2. fd-take ordering (ids bacc2546, 81d3da56)
- `src/child/spawn.rs:23` does `let fds = std::mem::take(cmd.fds_mut())` BEFORE the point Task 10 inserts the elevation branch. So the branch's `cmd.stdin(pipe())` writes a map nobody reads, and `reject_unsupported_config(cmd)` iterating `cmd.fds()` sees an EMPTY map → the honest-contract Windows stdio gate passes vacuously (silent lie: `.elevate().stdout(pipe())` on Windows silently discards output).
- FIX: The elevation branch (and the fds inspection + any stdin-pipe injection) must run BEFORE `std::mem::take`, OR the taken `fds` map is threaded INTO `reject_unsupported_config`/`spawn_elevated`/`rewrite` (`&BTreeMap<Fd, ResolvedStdio>`). Add a unit test asserting `fds[STDIN]` is a pipe after the branch, and an INTEGRATION test through `Command::spawn()` (not the effect fn directly) asserting `Unsupported` for elevated+pipe on Windows.

### S3. Auth accepted-then-ignored (ids b5d785f1, bff8870d, 290bc5c2, c09921ab, 3e877153, af49a25b)
- Planner must validate the FULL Auth×backend×platform matrix (see spec "Auth × backend × platform validity") BEFORE the already-elevated `RunAsIs` short-circuit (b5d785f1: currently the elevated short-circuit precedes structural validation, so combos pass under root and fail for normal users).
- Windows (bff8870d, 290bc5c2): `plan_windows` accepts every Auth then `spawn_elevated` ignores it. Reject `NonInteractive`/`Askpass`/`Stdin` → `Unsupported`; only `Interactive`/`Gui` reach the UAC gate. Add planner tests per Auth.
- POSIX NonInteractive (3e877153): only sudo emits `-n`. Emit `doas -n`, `run0 --no-ask-password`; `pkexec` (no non-interactive) → `Unsupported`. build_argv tests for NonInteractive on every backend.
- POSIX Askpass (c09921ab): sudo `-A` needs `SUDO_ASKPASS=path` set in the child env (must survive sanitizer/env threading). Reject Askpass for run0/pkexec/doas. Test the path is carried.
- POSIX Stdin (af49a25b): only sudo emits `-S`. `stdin_secret` currently computed for EVERY backend → feeds password to non-sudo target's stdin (credential leak). Reject `Auth::Stdin` for non-sudo backends in the planner. Only produce `stdin_secret` on the sudo path. Planner rejection test per backend.

### S4. RunAsIs drops achieved-elevation state (ids a7095601, 47df88f5 — SAME root cause, fix once)
- Already-elevated `.elevate()` → `RunAsIs` → `report: None` on both POSIX (`rewrite`) and Windows (`spawn_elevated`→`spawn_unelevated`) → `Child::elevation()` returns `None` ("not elevated") for a genuinely-elevated child.
- FIX (per updated spec): `Child::elevation()` is `Some(..)` IFF elevation was REQUESTED. Report carries `via: ElevatedVia::{Wrapped(Backend), AlreadyElevated}`. The `RunAsIs` transition, when `cmd.elevation_request().enabled`, must carry enough info to attach an `AlreadyElevated` report. (Change `ElevationReport.backend: Backend` → `via: ElevatedVia`.)

### S5. run0 process model (ids 10b50c0f, c3e5013a — one backend-semantics pass)
- Per updated spec: run0 REMOVED from `Auto` (Auto = sudo>doas). `Backend::Run0` explicit-only, force `--pipe` (honest Passthrough, not silent pty merge), `.contain()`+run0 → `Unsupported`, kill/id target the run0 client (documented+reported), client→unit kill propagation pinned by a gated live test.
- Task 15 live test used `Auth::NonInteractive` + `Auto`; with run0 gone from Auto it resolves to sudo (fine) — but ensure the gated live test does not hang on a prompt (use `-n`, expect failure-or-success deterministically).

## POSIX argv / detection correctness

- 7e16da0e: `env` invocation missing `--` terminator before the program → a program path containing `=` is swallowed as an assignment (silent no-op success), a `-`-leading program parsed as a flag. FIX: push `"--"` after assignments, before program. Tests: program with `=`, program leading with `-`.
- 8b6d5a75: DROP `--preserve-env` entirely — `env K=V program` already sets vars after sudo's scrub; the flag is redundant AND buggy (lossy comma-join splits keys with commas, mangles non-UTF8, empty-list form unverified). Remove it and the two tests asserting `--preserve-env=`.
- 7d08fa81: check-then-act on the backend binary. `on_path` uses `is_file()` (ignores exec bit); empty PATH element → `join` yields CWD-relative `sudo`; build_argv pushes BARE name so exec re-resolves (validated ≠ executed; CWD hijack). FIX: `detect()`/`BackendSet` records the RESOLVED ABSOLUTE path (checking X_OK via `nix::unistd::access(...,AccessFlags::X_OK)`), skips empty PATH elements; build_argv emits that absolute path as argv[0].
- ea0643ee: `.env_clear()` intent discarded — `explicit_env` keeps only surviving Set values then `clear_env_ops()` drops the `EnvOp::Clear`, so the outer `sudo` inherits the parent env. FIX: preserve the clear intent so the BACKEND process itself starts from an empty environment. Test `.env_clear()+.env()+.elevate()` env ops.
- f3f0608c: `program_and_args` uses argv[0] and ignores `cmd.executable_path()`; `set_input_argv` clears `executable`. The crate supports independent executable+argv0 (commit de1b062). FIX: use `executable_path()` as the program when set; keep `executable` intact. If the caller ALSO set a distinct argv[0] that elevation can't preserve through the backend, return `Unsupported`. Fix Task 15 `posix_child_self_detects_elevation` accordingly (it sets `.executable(&exe)`).
- 6841c2d1: `has_tty = isatty(STDIN)` is the wrong predicate (fails for redirected stdin / `.output()`, wrongly accepts post-setsid). FIX: probe the controlling terminal — `open("/dev/tty", O_RDWR|O_CLOEXEC)` then close. Unit-test redirected-stdin-with-tty and setsid cases.
- 74f4de94 (build_argv Auto invariant): `Backend::Auto` arm guarded only by `debug_assert!(false)` → release silently recurses to Sudo. FIX: `unreachable!()` or a real contract error (Auto must be resolved by the planner before build_argv).

## Auth::Stdin plumbing (sync + async)

- ffad4627: async secret snippet uses `.await` inside the SYNC `tokio::spawn` fn (`pub fn spawn`) → compile error. FIX: deliver the password via the std/blocking write end BEFORE handing the pipe to tokio (no await in a sync fn).
- ef880aab: Stdin clobbers caller's fd0 and closes it (child stdin EOF); write result discarded. FIX (per spec): `Auth::Stdin` consumes fd0 — error if the caller configured fd0; propagate the write error; log it.
- d84c0808: password write discarded (`let _ = w.write_all`) with NO logging (sync comment-only; async worse — both write+shutdown discarded). FIX: log write/shutdown errors at debug (mirror `EnvSanitizer::apply`'s logging).
- 60eb2f86: `spawn_elevated_async` calls `crate::tokio::child::Child::from_parts` which is `pub(super)` (private outside `crate::tokio`) → won't compile. Also passes `BTreeMap::new()`/`FdPipes::new()` unverified. FIX: put the async child construction in `src/tokio/spawn.rs` (inside `crate::tokio`); `spawn_elevated_async` returns only `(OwnedHandle, pid, ElevationReport)`. Verify `FdPipes::new()` exists.

## Windows spawn correctness

- 0811a315: `spawn_elevated` runs `reject_unsupported_config` BEFORE `host.plan` decides `RunAsIs`. FIX: plan FIRST; apply the ShellExecuteEx capability gate ONLY on the `ElevateWindows` arm. `RunAsIs` → straight to `spawn_unelevated`, no restrictions.
- db7b76d0 / 74eb2ea5: gate rejects only `ResolvedStdio::Pipe` on fd<3. `ResolvedStdio` also has `File(File)` and `Merge(Fd)` (src/stdio.rs:145-151), and fd>=3 is excluded. ShellExecuteEx passes NO handles. FIX: reject EVERY non-`Inherit` slot AND every slot>=3 for an elevated Windows child. Test per `ResolvedStdio` variant + fd>=3.
- 4460395b: after `ShellExecuteExW` succeeds, `ProcessId::of(pid)` does a fresh `OpenProcess` that can fail → returns `AuthFailed` and DROPS `proc` → elevated process leaked with no Child. FIX: derive identity from the OWNED handle (`GetProcessId(proc)`), no second open; if identity still unobtainable, KILL the child before returning and use a kind that says so (not AuthFailed — auth SUCCEEDED).
- c5ef56dc: `ShellExecuteExW` called with no `CoInitializeEx` (docs require COM init; shell extensions may need STA). FIX: `CoInitializeEx(None, COINIT_APARTMENTTHREADED|COINIT_DISABLE_OLE1DDE)` on the thread before the call (tolerate `RPC_E_CHANGED_MODE`/`S_FALSE`), cite the doc. Verify `nShow` type: `SHOW_WINDOW_CMD` is u32 but `nShow` is i32 in windows 0.62.
- cd2a1032: `TOKEN_MANDATORY_LABEL` read from a `vec![0u8;..]` (align 1) then reinterpreted via `&*(ptr as *const TOKEN_MANDATORY_LABEL)` → misaligned reference UB (contains a pointer field needing 8-byte align; aarch64-windows CI leg). FIX: aligned buffer (`Vec<u64>`/`#[repr(align(8))]` wrapper) + `ptr::read_unaligned`/`addr_of!` — never form a misaligned reference.
- 7d5cd2f1: `integrity_is_high_or_above` is dead code (never called) → `cargo clippy --all-targets --locked -- -D warnings` (prek.toml:26) hard-fails at Task 11. Also `let mut child`/`let mut stdin_secret` unused-mut on Windows. FIX: wire `integrity_is_high_or_above` into detection/a test OR drop it; fix the `mut` bindings (cfg-gate).
- (Windows lpDirectory + argv0 — folded into db7b76d0's row in the report): `SHELLEXECUTEINFOW.lpDirectory` left null → `cmd.cwd()` ignored (child runs in System32). FIX: set `lpDirectory` from `cmd.cwd()`. And argv[0] ≠ executable → `Unsupported` (ShellExecuteEx can't set an independent argv0). Test both.

## EnvSanitizer

- cbab2bd0: `allowlist([...]).keep([...])` silently becomes a denylist (fail-closed → fail-open). FIX (per spec): `keep` is additive WITHIN the current policy — widen an allowlist, add holes to a denylist — never downgrade. Prefer moving `keep` onto a denylist-only builder type OR match policy and widen in place. Tests: `allowlist(..).keep(..)` and `filter(..).keep(..)`.

## Test gaps

- 9d24398a: the pure rewrite test silently `return`s if sudo isn't at `/usr/bin/sudo`|`/bin/sudo` → no-silent-skip violation. FIX: make the pure rewrite logic testable WITHOUT the sudo binary existing (inject a resolved backend path into the planner/rewrite, don't shell out), OR gate with the explicit marker. Prefer the former — the argv construction is pure.
- 8d18c6d8: `tokio_elevate_forwards_to_inner_request` has ZERO assertions (defers to live tier). FIX: assert against the inner `Command::elevation_request()` (pub(crate)).
- 0eccf04d: `explicit_env` Remove/Clear paths untested. FIX: posix_tests for Set+Remove and Set+Clear through `rewrite()`.
- 22e4adb7: `commandline()`-built (non-argv) elevated command rejection untested on both platforms. FIX: a test per platform building via `commandline()` asserting `Error::Elevation{BackendUnavailable}` (or the chosen rejection).

## Conciseness cuts (apply all — independently valid)

Remove task-number references from PERMANENT doc/module comments and redundant restatements:
- 47177b07 (line 589): delete `/// Pure decision. No side effects, no privileges.`
- 29359394 (617): remove `// (Rejection combos land in Task 5.)` — describe the missing guard, not a task number.
- 715c39fa (1712): drop `(Task 13)` from the windows.rs module doc.
- 0b3dbb28 (887): drop the "See the design spec's ..." dead link clause.
- 0704bfd5 (900): delete `/// Prefix families: any var starting with one of these is a loader footgun.`
- 4b612c7e (371): delete `/// How stdio was actually wired.`
- 54690bbf (336): trim `neither is reachable in this plan, so neither is defined yet (no dead variants)` from ElevatedStdio doc.
- e8e17252 (343): cut `Honest precisely because it does NOT claim Inherited when you actually piped.`
- 0d501885 (1993): drop the numbered-step narration comments in spawn_elevated; keep only why-carrying trailing notes.
- 3b519e0c (2254): cut `Tiers 1-5 ... cover all logic unconditionally; only the privilege-gain is gated here` from the test module doc.
- 870f1bed (2353): `// Print whether this process is elevated.`
