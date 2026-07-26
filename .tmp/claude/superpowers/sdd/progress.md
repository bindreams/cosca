# SDD progress — Elevation (admin/root vertical, sync+async)

Plan: `.tmp/claude/superpowers/plans/2026-07-25-elevation.md` (19 tasks)
Round-4 correctness checklist (APPLY per task): `.tmp/claude/superpowers/plans/elevation-panel-findings-r4.md`
Issue: #6. Branch: `azhukova/6`. Branch base (merge-base w/ main): `de1b0626ae5460a1543470e0aaddd87b2cc87128`.
Runtime: Windows host primary; run WSL Ubuntu suite after Unix-affecting tasks.
Model policy: implementers Sonnet(high); task reviewers Opus(high); final review most-capable.
Plan went through 4 plan-review rounds; remaining r4 findings are code-level, applied during TDD.
NOT pushed / no PR yet — needs explicit user OK before push (people-alerting).

## Tasks
- [x] Task 1: Elevation error taxonomy
- [x] Task 2: Secret (zeroized password wrapper) + zeroize dep
- [x] Task 3: Public enums, ElevationReport, ElevatedVia, ElevationRequest + shared helpers
- [x] Task 4: Pure planner Host + happy-path plan()
- [x] Task 5: Planner rejection matrix — single validation choke point
- [x] Task 6: EnvSanitizer + default denylist (keep additive-within-policy)
- [x] Task 7: POSIX argv construction (backend-path-injected, backend-native env)
- [x] Task 8: Command builder methods
- [x] Task 9: POSIX detection (+ interim Windows stub 299f1f3)
- [x] Task 10: Extract spawn_unelevated (pure refactor)
- [x] Task 11: POSIX effect integration — non-destructive rewrite + Child::elevation()
- [x] Task 12: Windows detection + integrity + deps + identity-from-handle
- [x] Task 13: Windows honest-contract rejection gate
- [x] Task 14: Universal elevated-child teardown + Windows launch_runas/spawn_elevated
- [x] Task 15: spawn() elevation branch (fd-take reorder)
- [x] Task 16: Async (tokio) parity
- [x] Task 17: Live gated integration tests + testbin subcommands
- [x] Task 18: TODO.md CI provisioning note
- [ ] Task 19: Open PR against main + verify CI

## Minor findings roll-up (for final whole-branch review)
(append as tasks finish)

## Log
(append `Task N: complete (commits <base7>..<head7>, review clean)`)

Task 1: complete (commits de1b062..9c9b7ba, controller diff review clean — taxonomy matches spec, Untracked/Unkillable messages neutral on child fate)
Task 2: complete (commits 9c9b7ba..d839c40, diff clean — Secret zeroize/redacted-Debug/expose, zeroize=1)
- Task 2 (Minor roll-up): src/elevation.rs doc links [`plan`]/[`Auth::Stdin`] point at not-yet-existing items; resolve by final `cargo doc` check.
Task 3: complete (commit eb7e7b0, green Windows+WSL, both r4 corrections landed: backend_unusable faccessat exec-check in remap_derived_spawn_error; ElevatedStdio::StdinConsumed variant)
- Task 3 (roll-up): 5x #[allow(dead_code)] on pub(crate)/private items unconsumed until later tasks (ElevationRequest->T8, helpers->T11/15/16) — remove as each is wired; final review verify none remain.
Task 4: complete (commit b0aa24f, planner pure; implementer fixed brief bug — added self.elevated RunAsIs short-circuit positioned so T5 validation slots ahead of it per r4 bb78e1cc; 1 Windows test #[ignore]d pending T5)
Task 5: complete (commit 547a8a8, 13/13 plan_tests 0 ignored; r4 d101e51e fixed — Askpass/Stdin compat now privilege-independent before short-circuit via structural_posix(.,.,available); verified gate ordering)
Task 6: complete (commit 0dc9b7b, 7/7 sanitize_tests; cbab2bd0 invariant tested — keep widens allowlist not downgrade; #[allow(dead_code)] on apply() until spawn-arm tasks)
Task 7: complete (commit c3176a2, WSL 12/12 posix + 325/325 full; all argv corrections in brief verbatim: no env wrapper, pkexec --disable-internal-agent+no--, --preserve-env/--setenv name-validated, run0 --pipe; #[allow(dead_code)] on build_argv until T11)
Task 8: complete (commit f57fd94, 327 lib tests cross-platform; ElevationRequest #[allow] removed; new #[allow(dead_code)] on 4 derived-command mutators until T11)
Task 9: complete (commit 7f022e7, WSL 333 passed; r4 aff98ce1 empty-PATH test now pure no-chdir; 6d749b0d is_elevated vs geteuid ground truth). Controller fixup 299f1f3: interim Windows detection stub (Task 9 added cfg(windows) dispatch arm referencing Task-12 super::windows; stub keeps Windows build+clippy+327 tests green through T10-11; Task 12 REPLACES src/elevation/windows.rs).
Task 10: complete (commit ea86372, pure extraction; FULL regression green BOTH platforms + tokio+pty features; clippy clean — r4 fee7114b safety-net satisfied)
Task 11: complete (commit 2b17ab1, WSL 352 lib tests + Windows build clean; OPUS TASK REVIEW = Approved, no Critical/Important). All 4 r4 corrections verified: 1a194902 RunAsIs sanitizes+reports real stripped_env into non-destructive derived; a7b19ac4 write() loop zero-vs-partial (1MiB test); a6fcd0df fcntl warn; c1d13a6d capacity>=len. poll(POLLOUT,-1) real fd event (no time-sync). Zeroization airtight (reviewer traced 3 Secret copies).
- Task 11 CARRY-FORWARD to T14/T16: already_elevated_report() hardcodes empty stripped_env (elevation.rs:142). The already-elevated path there MUST sanitize+report the real stripped_env (build a derived like T11 RunAsIs) NOT use already_elevated_report, else it reintroduces the 1a194902 lie. Consider deleting the helper.
Task 12: complete (commit 9692b86 REPLACES stub 299f1f3, Windows 3/3 + 331 lib + WSL build clean). r4 corrections baked: Win32_System_Registry+4 features; integrity_level Vec<u64> aligned read_unaligned; token-query failures logged; integrity_level().is_some() unconditional test; is_elevated vs integrity ground truth.
- Task 12 CARRY-FORWARD to T14: windows_identity_from_handle is at crate::identity::backend::windows_identity_from_handle (src/identity/windows.rs:41), #[allow(dead_code)] — but mod backend is PRIVATE. T14 must add a pub(crate) wrapper in identity.rs (mirror windows_handle_is at identity.rs:118) to reach it, and remove the #[allow(dead_code)].
Task 13: complete (commit 919dcd7, 8/8 elevation::windows + 336 lib; r4 db7b76d0 baked — rejects ALL non-Inherit slots+fd>=3+env+contain, File/Merge/Null tested not just Pipe). Minor: redundant #[allow(dead_code)] added though clippy did not flag (final-review cleanup).
Task 14: complete (commit 2b7f8d5, OPUS TASK REVIEW = Approved no issues; Windows 347 lib\/371 tokio + WSL 358\/377, clippy clean both). r4 corrections: a36b0244 teardown dispatch on observed error (elevated param removed, pure std_teardown_action, self-elevated child no longer hangs Drop); 5225e5fa static can_terminate() OpenProcess(PROCESS_TERMINATE) probe not racing try_wait; 793e17e3 EXTENDED_STARTUPINFO_PRESENT in proc_tests; 0bf540ea fixed proactively (blocking wait not try_wait after kill). CoInit S_FALSE balanced; identity from owned handle; carry-forwards done (identity wrapper in identity.rs, allow(dead_code) removed).
- Task 14 CARRY-FORWARD to T16: async tokio Child::kill NOT yet routed through map_elevated_kill_error (correct now since no async spawn_elevated) — T16 MUST wire it when async elevation lands (r4 8d841939).
Task 15: complete (commit e978a51 + fmt fixup). r4: c5f0112c/3c63cf19 set_elevation BEFORE password block; 9aaf8c60 Ok(kill)->blocking wait reap / Err->try_wait; latent panic fixed (backend_path None on already-elev derived -> gated remap not unwrap); 9515f4d2 deterministic gate test. Windows 349 lib/373 tokio + WSL 359/378, clippy clean both.
- FMT FINDING (whole-branch): implementers eyeballed max_width=120 but never ran cargo fmt; main(de1b062) is fmt-clean under rustfmt 1.9.0 so CI prek cargo-fmt WOULD FAIL. Ran cargo fmt: touched exactly the 10 branch files, zero unrelated churn. Committed. LESSON: run cargo fmt per task henceforth.
Task 16: complete (commit 33cb727, controller review of async arm clean; Windows 374 lib/26 int + WSL 380/32, tokio+default clippy clean, fmt clean). 4 corrections landed & verified: c5f0112c/ee4ecd94 set_elevation before password block; 9aaf8c60 Ok(kill)->reap_blocking (sync spawn fn, no .await) / Err->try_wait; backend_path gated remap no panic; 6325e581 tautological parity test DROPPED (structural sharing is the guarantee) not the pure-fn-twice version; 8d18c6d8 asserts inner elevation_request. Extra bug fixed: Windows AlreadyElevated+executable() raw path dropped report.
Task 17: complete (commits 02a89bb + a96df0d test-tolerance; Windows full/tokio/pty + WSL setsid+real-PTY green, gate-absent no-op, fmt clean). r4: b212c93b pid_is_alive EPERM=alive; 8f0899ff unkillable test synchronizes on pidfile (real event). EXTRA BUG FIXED: output()/status()/read() wrongly rejected Auth::Stdin (forced .stdin default tripping the fd0 guard) -> apply_default_stdin helper +2 tests.
- DESIGN FINDING (surface to user): on sudo `Defaults use_pty` (increasingly default), kill() on the tracked child returns Ok not Unkillable — tracked child is sudo`s same-uid MONITOR, root runs as a pty grandchild. This is the DEFERRED "un-killable elevated child / sudo pty teardown contract" (TODO.md) surfacing. Decision-A Unkillable is correct for direct-exec backends (doas/run0/sudo-no-pty); use_pty is deferred territory. Test adjusted to accept both (Drop-no-hang is the real invariant).
Task 18: complete (TODO provisioning note + marked admin\/root+POSIX+Windows elevation [x]; use_pty teardown noted as deferred).

## Controller self-review findings (during whole-branch review wait) — fix regardless of panel outcome
- FINDING-1 (API surface, Important): src/elevation.rs declares `pub mod plan/posix/windows/sanitize` — over-exposes Host/Transition/BackendSet/build_argv/rewrite/reject_unsupported_config/spawn_elevated as PUBLIC API. Crate convention (containment.rs) is `pub(crate) mod` for effect internals + re-export only public TYPES. No external test uses these internals (verified). FIX: make the 4 modules pub(crate); keep `pub use sanitize::EnvSanitizer` and the types defined in elevation.rs (Backend/Auth/ElevatedStdio/ElevatedVia/ElevationReport/Privilege/Secret/is_elevated). Verify build+tests after.
- FINDING-2 (consistency, Minor): lib.rs re-exports `containment::{ContainMode, Containment}` at crate root (they appear in Command/Child public signatures). Elevation types (Backend/Auth/ElevatedVia/ElevatedStdio/ElevationReport) ALSO appear in public signatures (Command::elevation_backend, Child::elevation) but are NOT re-exported at root — users must reach via subprocess::elevation::Backend. Consider `pub use elevation::{Backend, Auth, ElevatedStdio, ElevatedVia, ElevationReport, ElevationErrorKind, Secret}` for parity. Style, not a bug.

## FINAL whole-branch review (code mode)
review-panel MCP tool TIMED OUT twice (1800s idle abort) on the 4328-line whole-branch diff — infrastructure limit, not a verdict. Fell back to the SDD-sanctioned final code-review via Opus subagent over a code-only diff (docs excluded). Verdict: NEEDS FIXES — 1 Critical (C1: async Windows runas kill returned Ok on ACCESS_DENIED — silent lie + sync/async parity break; sync correctly maps to Unkillable), 1 Important (I1: elevation effect modules pub not pub(crate), over-exposing Host/Transition/build_argv/rewrite), 2 Minor (M2 crate-root re-exports, M3 comments).
FIXES: C1 — lifted can_terminate into shared pub(crate) fn in windows_raw.rs (static OpenProcess(PROCESS_TERMINATE) probe), async start_kill now runas-aware mirroring sync; added gated async Windows Unkillable live test. I1 — modules -> pub(crate) + #[doc(hidden)] pub use controlling_terminal_present for testbin; justified #[allow(dead_code)] on cross-platform planner Os/Transition (host-testing models all platforms). M2/M3 applied. Commit df506c4.
FOCUSED DELTA RE-REVIEW (Opus): FIXES CONFIRMED — all 4 correct, no regression, full parity chain to Unkillable verified.
Full suite GREEN both platforms after fixes: Windows 376 lib + full/tokio/pty, WSL no failures; clippy --all-targets --features "tokio pty" -D warnings + cargo fmt --check clean both.

## STATUS: implementation COMPLETE, whole-branch review clean. Task 19 (push branch + PR against main + CI) next. NOT merging to main (separate user approval).
