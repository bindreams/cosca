# Elevation (elevate-to-admin/root) — design spec

Date: 2026-07-25
Status: approved in brainstorming; pending spec review, then implementation plan.
Scope owner decision: the admin/root vertical only (see Scope).

## Goal

Add cross-platform privilege elevation to the `subprocess` crate. The headline
design constraint is **DX honesty**: user-friendly by default, never lying about
capabilities that differ across OSes, and flexible enough that a sophisticated
user can reach every knob. Every capability gap is a loud error at spawn or a
reported degrade — never a silent lie.

## Scope

**In scope (this plan): the core elevate-to-admin/root vertical, sync + async.**

- Declarative elevation on the `Command` builder (flat methods).
- A pure `Host::plan(target) -> Transition` planner, exhaustively cross-OS tested.
- Per-OS effect layers that reject wrong-platform variants loudly.
- POSIX backend detection (`run0` > `sudo` > `doas`; GUI `pkexec`), an
  auth-strategy enum, and env-as-a-security-boundary.
- Windows `ShellExecuteEx("runas")` UAC path + elevation detection
  (`TokenElevation` / integrity level).
- An honest, queryable stdio + capability contract.
- Full sync **and** async (tokio) parity in this one plan.

**Deferred (already their own TODO bullets, out of this plan):** run-as-specific-user,
elevate-to-SYSTEM, de-elevation / privilege drop, the signed-broker
"elevation-that-also-pipes", the un-killable-elevated-child teardown contract,
and macOS GUI elevation (osascript / `SMAppService`).

## Core principle: elevation wraps the CHILD, never the calling process

A library must never re-launch its own host process (that is an
application/CLI concern — the `hole` xtask prior art self-re-launches via
`SelfElevateProcess`; a library must not). On every platform,
`.elevate().spawn()` produces a **separate elevated child** the parent controls:

- **POSIX:** a `sudo`/`run0`/`doas`/`pkexec` prefix — the elevated program is an
  ordinary child of the (unprivileged) parent.
- **Windows:** `ShellExecuteEx("runas")`, returning a child process handle the
  parent waits on / kills.

## Public API surface

Flat builder methods, matching the crate's existing idiom
(`.contain()` / `.contain_with()` / `.nesting()`), not a nested config struct.

```rust
// ── Detection: free functions, no spawn needed ─────────────────────────────
subprocess::elevation::is_elevated() -> bool;   // am I root / elevated right now?

// ── Builder: friendly default + flat expert overrides ──────────────────────
let mut cmd = subprocess::Command::new();
cmd.args(["systemctl", "restart", "nginx"])
   .elevate()                              // sugar: Elevated target, Backend::Auto,
                                           //        Auth::Interactive, EnvSanitizer::default()
   // all optional overrides:
   .elevation_backend(Backend::Doas)       // Auto (default) | Run0 | Sudo | Doas | Pkexec
   .elevation_auth(Auth::NonInteractive)   // Interactive (default) | NonInteractive
                                           //   | Askpass(PathBuf) | Stdin(Secret) | Gui
   .sanitize_env(EnvSanitizer::default().keep(["LD_LIBRARY_PATH"]));

// ── EnvSanitizer: the consent gradient ─────────────────────────────────────
EnvSanitizer::default();                       // denylist (sudo env_check/delete + loader family)
EnvSanitizer::default().keep(["LD_LIBRARY_PATH"]); // named hole; everything else still stripped
EnvSanitizer::filter(|key, val| /* -> Keep/Drop */); // arbitrary closure
EnvSanitizer::allowlist(["PATH", "LANG"]);     // opt-in fail-closed
EnvSanitizer::none();                          // full foot-gun (greppable in source)

// ── Achieved report on Child, mirroring Child::containment() ───────────────
// Some(..) IFF elevation was REQUESTED (redefine None = "elevation not requested"),
// so an already-elevated child is never mis-reported as un-elevated.
child.elevation() -> Option<ElevationReport>;
struct ElevationReport {
    via: ElevatedVia,             // Wrapped(Backend) | AlreadyElevated (no wrapper needed)
    stripped_env: Vec<OsString>,  // vars the sanitizer dropped (also logged)
    stdio: ElevatedStdio,         // how stdio was actually wired (Windows honesty)
}
pub enum ElevatedVia { Wrapped(Backend), AlreadyElevated }
```

### Enum spellings

```rust
pub enum Backend { Auto, Run0, Sudo, Doas, Pkexec }
pub enum Auth { Interactive, NonInteractive, Askpass(PathBuf), Stdin(Secret), Gui }
// achieved stdio disposition, reported never faked; #[non_exhaustive]
// (broker adds `Piped`, an SW_HIDE knob adds `Hidden` — both deferred, so
// neither variant is defined yet — no dead variants):
pub enum ElevatedStdio { Passthrough, OwnConsole }
//   Passthrough — POSIX: stdio wired exactly as configured (no elevation change).
//   OwnConsole  — Windows runas: child got its own console; parent streams not shared.
// internal planner target, public for introspection/testing, #[non_exhaustive]
pub enum Privilege { Unprivileged, Elevated }
```

- `Secret` wraps a password supplied for `Auth::Stdin`; it is zeroized on drop
  and never logged (its `Debug` is redacted).
- `Privilege` is `#[non_exhaustive]` so run-as-user / SYSTEM can extend it later.

### Default policies (confirmed)

- **`Backend::Auto` = `sudo` > `doas`** (by availability). run0 is **excluded
  from `Auto`** and `pkexec`/GUI is explicit-only. A default backend must honor
  the `Child` contract (identity/kill/kill_on_drop/contain); run0 spawns a
  PID-1-parented transient systemd unit — not our descendant — so it cannot be
  the default (see "run0's process model" below). A library must also not pop a
  polkit dialog unbidden.
- **Default `auth = Interactive`** (prompt on the controlling TTY, probed via
  `/dev/tty` — NOT `isatty(stdin)`, which is wrong for a redirected-stdin
  pipeline and for a post-`setsid` process). With no controlling terminal and
  `Interactive`, spawn is a loud `Error::Elevation { kind: NoTty }` — never a
  hang, never a silent askpass surprise.

### Auth × backend × platform validity (planner-enforced, loud on violation)

The planner validates the whole matrix BEFORE the already-elevated short-circuit,
so verdicts never depend on ambient privilege. Structurally-impossible
combinations are `Error::Unsupported`; each backend emits its real non-interactive
/ askpass flag rather than silently ignoring the request:

- **POSIX auth flags:** `NonInteractive` → `sudo -n` / `doas -n` /
  `run0 --no-ask-password`; `pkexec` has no non-interactive mode → `Unsupported`.
  `Askpass(path)` → sudo only, delivered via `SUDO_ASKPASS=path` in the child env
  (surviving the sanitizer/`env` threading); run0/pkexec/doas reject it. `Gui` →
  `pkexec` only. `Stdin(Secret)` → **sudo only** (`sudo -S`); doas/run0/pkexec
  reject it (`Unsupported`) — doas has no `-S`, and feeding a password to a
  non-sudo target's stdin is a credential leak.
- **`Auth::Stdin` consumes the child's stdin:** the crate writes the password +
  newline then closes fd0 (EOF). It is therefore an `Error::Unsupported` to
  combine `Auth::Stdin` with a caller-configured fd0. Password-write errors are
  propagated as `Error::Elevation` and logged (never a silently-swallowed write).
- **Windows auth:** `ShellExecuteEx("runas")` has no non-interactive / askpass /
  stdin-credential mechanism, so the planner accepts only `Interactive`/`Gui`
  (both map to the UAC consent gate); `NonInteractive`/`Askpass`/`Stdin` →
  `Error::Unsupported`.

### run0's process model (why explicit-only, and how it stays honest)

`run0` runs the target as a **transient systemd unit forked off by the service
manager (PID 1)** — the elevated process is not a descendant of the `run0`
client the crate holds a `Child` for, and run0 allocates a **pseudo-TTY** when
all of stdio is a TTY (merging stdout/stderr, translating line endings). So for
`Backend::Run0` (explicit opt-in only):

- Force `--pipe` so fds pass through directly (honest `Passthrough` stdio rather
  than a silent pty merge).
- `.contain()` + run0 → `Error::Unsupported` (the unit lives in its own scope
  cgroup, outside ours).
- Identity/`kill`/`kill_on_drop` apply to the run0 **client**; documented, and
  the report reflects it. The client→unit kill propagation is pinned by a gated
  live test; if it does not hold, that is surfaced as a blocker.

## The stdio + capability contract (the "don't lie" heart)

A UAC-elevated child launched with `ShellExecuteEx("runas")` cannot inherit
arbitrary pipe handles (no stdio-handle mechanism) and cannot receive an
arbitrary environment. That is exactly why the ecosystem builds a signed broker
(the deferred item). So in this plan:

| Capability | POSIX sudo/doas/pkexec | POSIX run0 (explicit) | Windows (`runas`) |
|---|---|---|---|
| Elevate a child; wait; exit code; kill | ✓ | ✓ (kill/id target the run0 client — documented) | ✓ |
| Captured stdio (`pipe` / `.output()`) | ✓ (sudo is a normal parent) | ✓ (via forced `--pipe`) | ✗ `Unsupported` → broker (deferred) |
| Inherited stdio | ✓ | ✓ | best-effort own-console, **reported** |
| Forward env (`.env`, sanitized) | ✓ | ✓ | ✗ `Unsupported` (no mechanism without broker) |
| `.contain()` + elevate | ✓ (whole subtree contained) | ✗ `Unsupported` (unit in its own scope cgroup) | ✗ `Unsupported` (job across integrity boundary) |

- **Windows elevation in this plan = "fire an elevated action, get its exit
  code"** (installers, service restarts, protected writes). Useful and honest;
  piping/env is what the broker later unlocks.
- **`ElevatedStdio` is reported, never faked.** On Windows-elevated, `inherit()`
  is accepted but the achieved disposition is honestly `OwnConsole` — the report
  tells the truth rather than pretending the parent stream was shared. On POSIX
  the disposition is `Passthrough` (stdio wired exactly as configured; it does
  NOT falsely claim `Inherited` when you piped). Captured stdio on Windows stays a
  hard `Unsupported`. (`Piped` across the boundary and `Hidden`/`SW_HIDE` arrive
  with the deferred broker and a future hide knob; `ElevatedStdio` is
  `#[non_exhaustive]` so adding them is non-breaking.)
- **Empirical pin (implementation, not guessed here):** the precise
  `ShellExecuteEx` console behavior (own console vs. inheritable) is pinned by a
  test, per the crate's empirical-facts culture; the report reflects whatever is
  measured.

## Environment as a security boundary

Elevating crosses a trust boundary (unprivileged parent → root child), so the env
cannot be forwarded wholesale the way an ordinary spawn inherits it.

### Two layers

1. **Inheritance policy — clean default (fail-closed).** An elevated spawn does
   NOT auto-inherit the parent's ambient environment. It gets the backend's own
   `env_reset` minimal base (`PATH HOME USER SHELL TERM …` — we do not fight the
   tools), plus **only** what the user explicitly set via `.env()` / `.envs()`.
   "Inherit everything" is the explicit `.envs(std::env::vars())`, threaded like
   any other explicit set. (Normal, same-privilege spawns keep today's std
   inherit-then-apply-`env_ops` behavior unchanged — the sanitizer is a no-op
   there; the danger only exists across a privilege boundary.)

2. **Sanitizer — denylist over the explicitly-forwarded set.** Its job is to
   catch known footguns among vars the user deliberately forwards, not to filter
   untrusted ambient input (layer 1 already did that). Default is a **denylist**,
   seeded from sudo's battle-tested `env_check`/`env_delete` lists plus the
   loader family (`LD_*`, `DYLD_*`, `_RLD*`, `LDR_*`, `LIBPATH`, `SHLIB_PATH`) and
   the classic injection set (`IFS`, `BASH_ENV`, `ENV`, `PS4`, `TERMINFO`/`TERMCAP`,
   `HOSTALIASES`, `RES_OPTIONS`, higher-runtime loaders `GCONV_PATH`, `PYTHONPATH`,
   `PERL5LIB`, `NODE_OPTIONS`, …).

### Why denylist is the right default here

The classic "allowlist beats denylist" wisdom is satisfied at **layer 1** (clean
default = allowlist/fail-closed on inheritance). That frees **layer 2** to be the
ergonomic denylist: it operates only on vars the user *deliberately chose* to
forward, where an allowlist would be both hostile (it would strip benign custom
vars like `MY_APP_CONFIG`) and impossible to specify (benign app vars are
unbounded). Footguns, by contrast, are finite and documented. Fail-closed
remains one call away for the paranoid via `EnvSanitizer::allowlist([…])`.

### Why the denylist is needed at all (the re-injection hole)

`ld.so` strips loader vars from setuid binaries (`sudo`/`doas`/`pkexec`), and
each tool's `env_reset` handles the rest — for **inherited** env. But the crate
forwards explicit `.env()` by **re-injecting past the scrub**:
`sudo --preserve-env=… env K=V prog`, `doas env K=V prog`, `pkexec env K=V prog`,
or `run0 --setenv=K=V`. That `env K=V prog` runs a *non-setuid* `env` as root, so
`ld.so` no longer scrubs `prog`; `run0 --setenv` injects directly. **The crate's
own forwarding path is exactly the hole setuid + `env_reset` closed** — so the
denylist guards that forwarding step, uniformly across all backends.

### Consent model (no accidental unsafe; explicit on-purpose)

- **No accidental unsafe:** the default sanitizer strips the danger family, and
  every strip is **logged** (`log` at info/debug: "sanitize_env dropped
  LD_LIBRARY_PATH before elevating") and surfaced in `ElevationReport.stripped_env`.
  So a strip is never invisible. Behavior is **strip-and-report**, not a hard
  error — because the dominant benign case is `.envs(std::env::vars())` sweeping
  up a legit `LD_LIBRARY_PATH`, which we *want* dropped, and erroring would make
  whole-env inheritance fail on most dev machines.
- **Explicit on-purpose:** to forward a danger var, the user weakens the
  sanitizer — `EnvSanitizer::default().keep([…])`, `::filter(closure)`, or
  `::none()`. Each is a visible, greppable token at the call site — the Rust
  `unsafe`-block equivalent. You cannot forward a loader var without one of them
  appearing in your source.
- **`keep()` is additive WITHIN the current policy, never a silent downgrade.**
  `keep([…])` on a denylist adds holes; on an allowlist it *widens* the allowlist.
  It must never convert a fail-closed `allowlist(…)` into a fail-open denylist
  (the type/impl enforces this — e.g. `keep` lives on a denylist-only builder or
  matches the policy and widens in place), so a paranoid caller's fail-closed
  choice cannot be accidentally reversed.

## Internal architecture

### Module layout (crate conventions: `foo.rs` + `foo/`, sibling `_tests.rs`)

```
src/elevation.rs          // public surface + re-exports; is_elevated()
src/elevation_tests.rs
src/elevation/
    plan.rs               // PURE: Host (data) + detect() + plan(target) -> Transition
    plan_tests.rs         // cross-OS: fake Host on any runner
    sanitize.rs           // EnvSanitizer + DEFAULT_DENYLIST
    sanitize_tests.rs
    posix.rs              // cfg(unix): backend detection, argv build, auth priming
    posix_tests.rs
    windows.rs            // cfg(windows): token detection, ShellExecuteEx, reduced Child
    windows_tests.rs
```

### Pure planner (cross-OS-testable spine)

`Host` is plain data (`elevated: bool`, `has_tty: bool`, `available: BackendSet`,
`os`). `detect()` fills it per-OS; `plan(target, backend, auth) -> Transition` is
a pure function with no syscalls, so a Linux test host asserts the *Windows*
decision by constructing a Windows-shaped `Host` — the `Containment`
host-testing pattern.

```rust
enum Transition {
    RunAsIs,
    ElevatePosix { backend: Backend, auth: Auth },
    ElevateWindows { auth: Auth },
    Reject { error: Error }, // structural rejection surfaced at spawn
}
```

### Two effect layers, two integration styles

- **POSIX = command rewrite.** Rewrite the `Command` into a
  `sudo`/`doas`/`run0`/`pkexec` invocation (program + args + sanitized env), then
  hand to the **existing** spawn path unchanged. Piping, containment (the whole
  sudo subtree lands in the process group / cgroup), wait, and kill reuse current
  machinery for free.
- **Windows = a distinct spawn backend.** `ShellExecuteEx("runas")` returns only
  an `hProcess` (no stdio handles, no thread handle, no env mechanism). It builds
  a **reduced** `Child`: wait / exit-code / kill work; capture and env forwarding
  do not (they are the `Unsupported` rows above).

### Error taxonomy — split static vs dynamic

- **`Error::Unsupported`** (existing) for *structural* rejections that can never
  work here: captured stdio / `.env` / `.contain` on elevated-Windows;
  `Backend::Doas` on Windows (wrong platform); `Doas`+`Askpass` or
  `Pkexec`+non-`Gui` (impossible combos).
- **New `Error::Elevation { kind: ElevationErrorKind, detail: String }`** for
  *runtime* failures (stepstool's `{SudoNotFound, AuthFailed, NoTty}`
  generalized):

```rust
enum ElevationErrorKind {
    BackendUnavailable, // forced backend not on PATH
    AuthFailed,         // wrong password / `sudo -n` credential miss
    AuthDeclined,       // UAC prompt cancelled (ERROR_CANCELLED)
    NoTty,              // Interactive auth requested but no controlling terminal
}
```

Rule: `Unsupported` = "can never work on this platform"; `Elevation` = "could
work but failed now."

## Async (tokio) parity — in this plan

- **POSIX async** reuses the command rewrite + the existing async spawn path
  (the sudo child is spawned via tokio like any child) — nearly free.
- **Windows async** wraps the blocking `ShellExecuteEx` launch in
  `spawn_blocking`, then rides the existing event-based async wait.
- `tokio::Child::elevation()` mirrors the sync report; every sync rejection and
  achieved-report has an async twin.

## Testing strategy (TDD throughout; almost everything host-testable)

The design pushes all logic into host-testable pure code so the gated tier
covers only the irreducible privilege-*gain*.

1. **Planner tests — pure, all OS, unconditional.** Fake `Host` values assert
   every `Transition` on any runner. Zero privileges.
2. **Sanitizer tests — pure, unconditional.** Default denylist strips the danger
   set; `.keep([…])` pokes exactly one hole; `.allowlist([…])` is fail-closed;
   `.none()` noop; `.filter(closure)` runs; stripped-vars list correct.
3. **Backend argv-construction tests — host-testable, unconditional.** Assert the
   exact `sudo`/`doas`/`run0`/`pkexec` argv + env-threading (`--preserve-env` +
   `env K=V` ordering, sanitizer applied). Building argv needs no installed
   backend.
4. **Rejection tests — host-testable, unconditional.** Every honest-contract
   boundary asserts its *specific* error (wrong-platform → `Unsupported`;
   `Doas`+`Askpass` → `Unsupported`; captured-stdio/`.env`/`.contain` on
   elevated-Windows → `Unsupported`; forced-absent backend →
   `Elevation::BackendUnavailable`).
5. **Detection tests — unconditional.** Unelevated process: `is_elevated()==false`;
   Windows integrity reads Medium.
6. **Live elevation tier — gated (cgroup precedent).** Only the privilege-*gain*
   is behind `SUBPROCESS_TEST_ELEVATION=1`: **no-op when absent, FAIL LOUDLY when
   set but elevation unavailable** (identical to `SUBPROCESS_TEST_CGROUP`).
   Because tiers 1–5 cover all logic unconditionally, the gate skips no decision
   path. Live assertions:
   - POSIX: elevated child runs `id -u`, parent **captures** `"0"`.
   - Windows: capture unavailable → elevated child does an admin-only action
     (protected write / marker file); parent asserts **exit code** + reads marker.
   - Self-detection: the test binary launched elevated asserts
     `is_elevated()==true`.
7. **Async parity** — every sync tier has a tokio twin, sharing the
   `SUBPROCESS_TEST_ELEVATION` gate for live tests.
8. **CI provisioning** documented in `TODO.md` (passwordless `sudo` for the
   Linux live job; the Windows live tier needs an elevated/UAC-auto-approve
   context, else a documented manual-run tier).

## Salvage from prior art

- **`hole` xtask/src/privilege (git `b62d0ea63`):** the pure `Host::plan()`
  planner shape; POSIX drop discipline and the Windows token/`ShellExecuteEx`
  code (elevation half only — de-elevation is deferred).
- **`stepstool` (`crates/stepstool`):** `prime_sudo` (TTY/no-TTY credential
  priming), `preserve_env_arg` single-owner, the `{SudoNotFound, AuthFailed,
  NoTty}` taxonomy.
- **qodana-cli `sudo/`** (Apache-2.0) — inspect for POSIX patterns (attribution
  if any code is ported).

## Workflow (per CLAUDE.local.md)

- Create a GitHub issue for the feature; branch `azhukova/<issue>` (never main).
- Open a PR against main; verify CI passes on the PR.
- Squash-merge on user approval (per git-workflow memory).
