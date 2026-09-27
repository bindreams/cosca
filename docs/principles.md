# Design principles

The rules every cosca change follows. Where `main` does not follow a rule yet, a **Being brought
into line** note says where, so the gap is not mistaken for the design.

## 1. No unowned state

cosca is a library, not a service. It holds no process-lifetime background threads, pools, static
queues or retries carried across calls. A helper, even a thread, is allowed only if a handle the
caller holds owns it and that handle's `Drop` tears it down deterministically.

**Why:** state no caller owns cannot be released by any caller, and does its work at moments none of
them chose.

**Applies to:** anything that happens later, such as reaps, drain waits, `rmdir`, watchers, retries.
The cgroup leaf's drain pump ([`watcher.rs`](../src/containment/cgroup/watcher.rs)) is the compliant
shape: the leaf's first blocking wait starts it, and the leaf's `Drop` stops and joins it.

**Being brought into line:**

- The async `Child`'s process-lifetime reaper pool
  ([`src/tokio/child/reaper.rs`](../src/tokio/child/reaper.rs), added in [#120]) is being removed.
- `reap_in_background` in [`src/child/spawn.rs`](../src/child/spawn.rs) and
  [`src/containment/cgroup/leaf.rs`](../src/containment/cgroup/leaf.rs) detaches a thread per child
  a failed spawn could not kill. [#165] (open) hands that child back to the caller instead.

## 2. Never block a tokio runtime thread; async drop does only bounded work

Async `Drop` may send a bounded number of signals, and may write `cgroup.kill`, which is one bounded
file write. It never waits for a process exit or a cgroup drain. Completion is explicit and async:
`wait().await`, `wait_tree().await`. A bare drop that leaves work unfinished leaves the resource
behind and logs a warning naming it. A dropped, still-running async root goes to tokio's own orphan
queue, which is tokio's state, not cosca's. Sync code may block, as sync Rust normally does.

**Why:** a kill is not an exit (a process in D state or on a hung NFS mount outlives `SIGKILL`), so
any wait in `Drop` is unbounded. tokio's predecessor removed blocking from `Drop` for this reason,
tokio itself panics rather than block inside a runtime, and embeddable libraries (sd-event,
libcontainer, GLib) refuse global reapers, which only process-owning daemons use.

**Applies to:** `Drop` of [`cosca::tokio::Child`](../src/tokio/child.rs) and everything it owns, and
every async spawn and teardown path under [`src/tokio/`](../src/tokio/). The sync
[`Child`](../src/child.rs) kills and reaps in its `Drop`, which is allowed.

**Being brought into line:**

- The async `Drop` hands the wait to the reaper pool (principle 1) rather than to tokio.
- `Attached::hard_kill()` does unbounded work on the dropping thread ([#111]), and the same sweeps
  run on the caller's runtime worker in the sync `kill_tree()`/`terminate_tree()` of
  [`tokio::Child`](../src/tokio/child.rs) and [`tokio::Process`](../src/tokio/process.rs), including
  from the async `graceful_shutdown_tree`.
- The async `Drop` blocks on a cgroup leaf's drain when the root is already reaped, its kill fails,
  or the reaper pool cannot start (see [`Command::kill_on_drop`](../src/command.rs)'s rustdoc).
- Async spawn error paths reap on the caller's runtime worker ([#112]), and elevation's setup blocks
  it ([#176]). When a contained spawn's placement is undecidable, `fail_closed` in
  [`leaf.rs`](../src/containment/cgroup/leaf.rs) waits for the child's exit and the leaf's drain on
  that worker too.

## 3. Don't act on a bare PID after it may be reused

On Unix a PID is pinned only while its process is an unreaped child (a zombie at worst); on Windows,
while a handle to the process is open. Signal and wait through a handle that names the process:

- on Linux, a `pidfd` opened while the child is provably ours, or the child's own pidfd from before
  `exec`;
- a cgroup, since `cgroup.kill` names no PID;
- on Windows, a process handle or Job Object.

Where a group ID must be used (process-group or fd-marker containment), keep the root an unreaped
zombie until the group kill is done.

**Why:** once the process is reaped its number can belong to anyone, and a signal sent to it hits an
unrelated process.

**Applies to:** every kill, signal and wait on a process.

**Being brought into line:**

- `kill_tree()` after the root is reaped can `killpg` a recycled group ([#54]), and so can `Drop`
  ([#107]). The root is reaped by `wait()`, or already inside `spawn` for a fast-exiting child (see
  `kill_tree` in [`src/child.rs`](../src/child.rs)).
- The cgroup graceful signal goes to bare PIDs ([#106]).
- Kill-by-identity re-verifies and then signals non-atomically ([#55], [#64]); macOS has an
  identity-bound signal cosca does not use yet ([#55]).
- These signal by number, which is safe only if nothing else reaps the child (principle 4):
  - the single-process kill of an owned Unix child (`Child::kill()`, both `Drop` impls,
    `kill_unadopted` in [`src/child/spawn.rs`](../src/child/spawn.rs)), which goes through std's
    `Child::kill`, `SharedChild::kill` or tokio's `start_kill` to `kill(2)`;
  - `fail_closed` in [`leaf.rs`](../src/containment/cgroup/leaf.rs), for the child and its group;
  - `end_child` in the same file, for the child's group, and for the child itself when
    `pidfd_send_signal` is refused.
- These wait by number, so after a foreign reap they can wait on, and reap, another child of ours:
  - sync `Child::wait` and `Drop` ([`proc_handle.rs`](../src/child/proc_handle.rs)), and
    `reap_unadopted` and `reap_in_background` in [`src/child/spawn.rs`](../src/child/spawn.rs),
    through `SharedChild::wait` or std's `Child::wait`;
  - `fail_closed`, and `end_child` and `reap_in_background` without a pidfd, in
    [`leaf.rs`](../src/containment/cgroup/leaf.rs);
  - `wait_and_reap` in [`src/tokio/child.rs`](../src/tokio/child.rs).
- `ReportChannel::wait` ([`channel.rs`](../src/containment/cgroup/channel.rs)) opens its pidfd from
  a bare PID, which names the child only if nothing else reaped it.

## 4. A foreign reap is a handled case, not a contract violation

The application or another library may reap cosca's children (`SIGCHLD` set to `SIG_IGN`, or
`waitpid(-1)`), and init and supervisor programs must. cosca detects it where it can (`ECHILD`,
`ESRCH`), releases the child without signalling it, and never debug-asserts on it.

After a foreign reap:

- On Linux, cgroup plus pidfd stays exact; only the exit status is lost.
- Process-group and fd-marker kills are unsafe (principle 3).
- macOS has no pidfd, and cosca has no exact kill there.

**Why:** a library cannot require the whole process to leave its children alone, and processes that
reap everything are legitimate hosts.

**Applies to:** every reap and every wait on a child.

**Being brought into line:** [`Command::contain`](../src/command.rs) documents a foreign reap as a
forbidden precondition. These debug-assert on it:

- `fail_closed` and `end_child` in [`leaf.rs`](../src/containment/cgroup/leaf.rs);
- `ReportChannel::wait` in [`channel.rs`](../src/containment/cgroup/channel.rs);
- `teardown_unadopted` in [`src/child/spawn.rs`](../src/child/spawn.rs), which runs without
  `contain()` too;
- `reap_now` and `wait_and_reap` in [`src/tokio/child.rs`](../src/tokio/child.rs).

## 5. Good defaults, with escape hatches for advanced users

Defaults are safe: a child is killed on drop, and `contain()` picks the strongest mechanism by
default. Don't forbid what advanced users legitimately need; document exactly what holds when they
opt out.

**Why:** a library that refuses a legitimate use gets replaced by hand-rolled code with no
guarantees at all.

**Applies to:** the public API. Existing hatches include `kill_on_drop(false)`, `contain_with()`,
`nesting()`, `raw_executable()` and `creation_flags()` on [`Command`](../src/command.rs), and
`detach()` on [`Child`](../src/child.rs).

## 6. Assert contracts in debug; never assert on real OS outcomes

An outcome the OS can really produce, such as `EACCES` from a privilege drop, `ECHILD`, `ESRCH` or a
failed `cgroup.kill` write, is handled, not `debug_assert!`ed. A contract violation that is
genuinely unreachable is asserted in debug, not merely documented.

**Why:** an assert on a reachable outcome panics debug builds on correct behaviour, while a
documented-only contract breaks silently when a future caller violates it.

**Applies to:** all code.

**Being brought into line:**

- Both `Child::drop` impls ([`src/child.rs`](../src/child.rs),
  [`src/tokio/child.rs`](../src/tokio/child.rs)) debug-assert that the tree kill did not fail with
  `Error::Io` (such as a failed `cgroup.kill` write) or an `Error::Unassessable` carrying an OS
  error.
- `kill_tree` and `terminate_tree` debug-assert that the root's PID was not recycled, which their
  own comments say is reachable.
- `take_owned_out`, `take_owned_in`, `fd_read_end` and `fd_write_end` on Unix in
  [`src/tokio/child.rs`](../src/tokio/child.rs) debug-assert that registering a pipe with tokio's
  reactor succeeded, which the kernel can refuse (`ENOMEM`, `ENOSPC`).
- The foreign-reap asserts in principle 4 are the same kind.

## 7. Synchronise on events, not time

No sleep-then-check, and no timeout chosen by cosca on code cosca controls. A timeout is allowed
only as a failure bound on something outside our control, and its expiry is never evidence of a
state. A nextest `terminate-after` ([`.config/nextest.toml`](../.config/nextest.toml)) counts as
such a bound. A backoff that re-checks a real condition is fine. No arbitrary retry or loop caps.

**Why:** a sleep is a bet that something has happened by then, and loses on a slow or loaded
machine.

**Applies to:** all code and tests.

**Being brought into line:** in [`marker_eof_tests.rs`](../src/containment/marker_eof_tests.rs):

- `async_wait_never_drains_past_the_low_water_clamp` takes a `tokio::time::timeout` expiring on
  cosca's own wait as proof that it never resolves.
- `a_sustained_writer_never_exceeds_the_deadline` asserts on wall-clock time.
- `a_quiet_live_holder_blocks_without_spending_cpu` measures over a fixed window and calls itself an
  exception this principle does not grant.
- `an_unbounded_wait_against_a_sustained_writer_blocks_without_spending_cpu` borrows its reasoning,
  and sleeps for the window before killing.

Elsewhere:

- `windows_async_treewalk_grants_no_grace_window_once_the_backend_has_reaped`
  ([`graceful_tests.rs`](../src/tokio/child/graceful_tests.rs)) asserts on wall-clock time.
- `cgroup_wait_drained_tracks_two_real_members_through_exit`
  ([`leaf_tests.rs`](../src/containment/cgroup/leaf_tests.rs)) describes its bounded wait as
  settling time for the membership checks that follow.

## 8. Tests fail loudly and never silently skip

A test that can't establish its precondition fails with a message that names the precondition and
how to opt out explicitly. A test that mutates process-wide state (fds 0–2, rlimits, credentials,
signal dispositions) runs in its own re-exec'd process (`alone()` in
[`test_support.rs`](../src/containment/cgroup/test_support.rs), `run_fixture_with_cwd()` in
[`src/test_child.rs`](../src/test_child.rs)), or relies on nextest's process-per-test and asserts
that it does.

**Why:** a skipped test reports the same pass as a working one, and a process-wide mutation corrupts
whichever tests share the process.

**Applies to:** all tests.

**Being brought into line:**

- `cgroup_wait_drained_tracks_two_real_members_through_exit` and
  `cgroup_leaf_procs_fd_is_not_inherited_across_exec`
  ([`leaf_tests.rs`](../src/containment/cgroup/leaf_tests.rs)) pass without running when
  `COSCA_TEST_CGROUP` is unset (the pattern [#80] tracks).
- The gated tests in [`tests/elevation.rs`](../tests/elevation.rs) pass without running when their
  `COSCA_TEST_ELEVATION*` variable is unset, or when the runner's elevation doesn't suit them.
- The suite accepts degraded containment as a pass ([#154]).
- These mutate process-wide state without isolating themselves or asserting process-per-test:
  - `RestoreStdio` and `RestoreRlimitNofile` in [`tests/common/mod.rs`](../tests/common/mod.rs), and
    `RestoreFd2` in [`fd_map_tests.rs`](../src/child/spawn/fd_map_tests.rs) ([#196], [#201]);
  - `EnvVar::set` in [`windows_shell_execute.rs`](../tests/windows_shell_execute.rs), isolated only
    by an in-binary mutex;
  - `drop_se_debug_privilege` in [`windows_fixture.rs`](../src/identity/windows_fixture.rs), which
    removes a privilege from the test process's own token;
  - `a_disarmed_leaf_whose_tree_survived_terminate_is_not_reported_as_a_leak`
    ([`leaf_tests.rs`](../src/containment/cgroup/leaf_tests.rs)), whose pipe lacks close-on-exec and
    so leaks into concurrently spawned children ([#205]).

## 9. System-affecting tests run in a sandbox

Cgroup, process-group signal and elevation tests run in a container, VM or CI, never against a
developer's host services.

**Why:** a bug in such a test reaches whatever machine it runs on, so the sandbox, not the test's
correctness, has to be what protects it.

**Applies to:** local runs, which use [devvm](../scripts/README.md), and CI, whose cgroup lane runs
in a fresh cgroup on a throwaway runner ([`ci.yaml`](../.github/workflows/ci.yaml)).

## 10. Prefer a dependency over hand-rolled code

A dependency's bugs that don't affect cosca are its to fix, not a reason to avoid it. A bug that
does affect cosca can disqualify it.

**Why:** rejecting dependencies over bugs that don't touch cosca ends with writing everything by
hand.

**Applies to:** all code.

## 11. Small PRs, split along clean seams

Split a plan or PR wherever it has a clean seam. Stack dependent pieces, and keep every intermediate
step consistent with these principles.

**Why:** a small PR is easier to get right and to review, and a defect fails only its own part.

**Applies to:** plans and PRs.

[#54]: https://github.com/bindreams/cosca/issues/54
[#55]: https://github.com/bindreams/cosca/issues/55
[#64]: https://github.com/bindreams/cosca/issues/64
[#80]: https://github.com/bindreams/cosca/issues/80
[#106]: https://github.com/bindreams/cosca/issues/106
[#107]: https://github.com/bindreams/cosca/issues/107
[#111]: https://github.com/bindreams/cosca/issues/111
[#112]: https://github.com/bindreams/cosca/issues/112
[#120]: https://github.com/bindreams/cosca/pull/120
[#154]: https://github.com/bindreams/cosca/issues/154
[#165]: https://github.com/bindreams/cosca/pull/165
[#176]: https://github.com/bindreams/cosca/issues/176
[#196]: https://github.com/bindreams/cosca/issues/196
[#201]: https://github.com/bindreams/cosca/pull/201
[#205]: https://github.com/bindreams/cosca/pull/205
