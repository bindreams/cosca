# Design principles

The rules every cosca change follows. Known places where `main` doesn't follow them yet are tracked
as issues labelled
[`tech-debt`](https://github.com/bindreams/cosca/issues?q=is%3Aissue+is%3Aopen+label%3Atech-debt),
grouped by module.

## 1. No unowned state

cosca is a library, not a service. It holds no process-lifetime background threads, pools, static
queues or retries carried across calls. A helper, even a thread, is allowed only if a handle the
caller holds owns it and that handle's `Drop` tears it down deterministically.

The same goes for log deduplication. Every event is logged at its natural level each time it
happens; rate-limiting belongs to the application's log handler.

**Why:** state no caller owns cannot be released by any caller, and does its work at moments none of
them chose.

**Applies to:** anything that happens later, such as reaps, drain waits, `rmdir`, watchers, retries.
The cgroup leaf's drain pump ([`watcher.rs`](../src/containment/cgroup/watcher.rs)) is the compliant
shape: the first wait that blocks starts it, and the leaf's `Drop` stops and joins it.

## 2. Never block a tokio runtime thread

cosca's async methods, and the sync methods of its async types, never block the runtime thread they
run on: no wait for a process exit or a cgroup drain, and no sweep of unbounded length. Work that
must wait is an `async fn`. Sync code may block, as sync Rust normally does.

One exception: spawning blocks until `exec`, as tokio's own `Command::spawn` does. That includes
cosca's placement report ([`ReportChannel::wait`](../src/containment/cgroup/channel.rs)), which
completes before `exec`. The wait is bounded by the child's own progress to `exec`; a child stopped
or stuck in D state between `fork` and `exec` holds the thread.

**Why:** a blocked worker stops every task scheduled on it, and on a `current_thread` runtime it
stops the runtime. tokio itself panics rather than block when a `Runtime` is dropped in async
context ([tokio shutdown.rs]).

**Applies to:** every spawn, control and teardown path under [`src/tokio/`](../src/tokio/).

## 3. Async `Drop` does only bounded work

Async `Drop` may send a bounded number of signals, and may write `cgroup.kill`, which is one bounded
file write. It never waits for a process exit or a cgroup drain. Completion is explicit and async:
`wait().await` for the root, plus `wait_tree().await` for the tree where the mechanism has a drain
edge (cgroup, Job Object, fd marker). A bare drop that leaves work unfinished leaves the resource
behind and logs it as principle 7 says.

A dropped, still-running async root is left to tokio's drop of its `Child`: an in-drop `try_wait`
([tokio reap.rs], [tokio pidfd_reaper.rs]), then tokio's orphan queue. Both are tokio's state, not
cosca's, and both reap with `waitpid(pid)`, the one by-number reap cosca accepts (principle 4); the
alternatives are a reaper cosca would own (principle 1) or a wait in `Drop`. The orphan queue is
best-effort: it drains only while some tokio runtime parks ([tokio runtime/process.rs]), and until
then the root stays a zombie.

On evidence of a foreign reap at drop time, cosca instead takes the child's stdio out, forgets
tokio's `Child`, and logs what the forget leaks as principle 7 says: on Linux the pidfd and its
reactor registration ([tokio unix/mod.rs]), otherwise the `SIGCHLD` watch. That leak is tracked in
[#174] and open with the owner.

tokio discards a PID that is already reaped: the queue drops it on `ECHILD` ([tokio orphan.rs]).
Neither step can detect a foreign reap followed by the number's reuse for another child of ours,
which it would then reap, and cosca's drop-time check can't close the window between itself and
tokio's `try_wait`.

**Why:** a kill is not an exit (a process stuck in uninterruptible I/O can outlive `SIGKILL`), so
any wait in `Drop` is unbounded. Global reapers (`waitpid(-1)`, a subreaper) belong to programs
that own the whole process, such as tini and the containerd shim. Embeddable libraries decline the
role: sd-event avoids `waitid(P_ALL)` ([sd-event.c]), and runc's Go `libcontainer` requires its
embedder to supply the reaper for containers without their own PID namespace ([runc CHANGELOG]).

**Applies to:** `Drop` of [`cosca::tokio::Child`](../src/tokio/child.rs) and everything it owns. The
sync [`Child`](../src/child.rs) kills and reaps in its `Drop`, which is allowed.

## 4. Don't act on a bare PID after it may be reused

On Unix cosca can rely on a PID only while its process is an unreaped child (a zombie at worst); on
Windows, only while a handle to the process is open. Signal and wait through a handle that names the
process:

- on Linux, a `pidfd` opened while the child is provably ours, or the child's own pidfd from before
  `exec`;
- a cgroup, since `cgroup.kill` names no PID;
- on Windows, a process handle or Job Object.

Where a group ID must be used (process-group or fd-marker containment), keep the root an unreaped
zombie until the group kill is done.

One by-number reap is accepted: tokio's reap of a dropped async root, with the gap principle 3
states.

**Why:** once the process is reaped its number can belong to anyone, and a signal sent to it hits an
unrelated process.

**Applies to:** every kill, signal and wait on a process.

## 5. A foreign reap is a handled case, not a contract violation

The application or another library may reap cosca's children (`SIGCHLD` set to `SIG_IGN`, or
`waitpid(-1)`), and init and supervisor programs must. cosca detects it where it can (`ECHILD`,
`ESRCH`), releases the child without signalling it, logs it as principle 7 says, and never
debug-asserts on it.

After a foreign reap:

- On Linux, cgroup plus pidfd stays exact; only the exit status is lost.
- Process-group and fd-marker kills are unsafe (principle 4).
- macOS has no pidfd, and cosca has no exact kill there.

**Why:** a library cannot require the whole process to leave its children alone, and processes that
reap everything are legitimate hosts.

**Applies to:** every reap and every wait on a child.

## 6. Good defaults, with escape hatches for advanced users

Defaults are safe: a child is killed on drop, and `contain()` picks the strongest mechanism by
default. Don't forbid what advanced users legitimately need; document exactly what holds when they
opt out.

**Why:** a library that refuses a legitimate use gets replaced by hand-rolled code with no
guarantees at all.

**Applies to:** the public API. Existing hatches include `kill_on_drop(false)`, `contain_with()`,
`nesting()`, `raw_executable()` and `creation_flags()` on [`Command`](../src/command.rs), and
`detach()` on [`Child`](../src/child.rs).

## 7. Assert contracts in debug; never assert on real OS outcomes

An outcome the OS can really produce, such as `EACCES` from a privilege drop, `ECHILD`, `ESRCH` or a
failed `cgroup.kill` write, is handled, not `debug_assert!`ed. A contract violation that is
genuinely unreachable is asserted in debug, not merely documented. Handled outcomes are logged by
class:

- A foreign reap, anywhere, logs at `debug`.
- A failed kill or signal logs at least at `warn` and names the resource. A mechanism failure may
  log at `error`.
- A drop that leaves behind something the caller did not ask to keep logs at least at `warn` and
  names it. A deliberate `detach()` or `kill_on_drop(false)` is not such a leftover.

**Why:** an assert on a reachable outcome panics debug builds on correct behaviour, while a
documented-only contract breaks silently when a future caller violates it.

**Applies to:** all code.

## 8. Synchronise on events, not time

No sleep-then-check, and a timeout's expiry is never taken as proof of a state. A timeout is allowed
only as a failure bound, whose expiry fails the test or reports an error, like a nextest
`terminate-after` ([`.config/nextest.toml`](../.config/nextest.toml)); library code sets none on
work cosca controls. A timeout a caller passes to cosca is the caller's policy: cosca honours it,
re-reads state at expiry and reports what it finds (`wait_timeout` returns `Ok(None)` (`Ok(false)`
on `Process`), `wait_tree_timeout` returns `MembersRemain`, and `graceful_shutdown`'s grace
escalates to a kill). A backoff that re-checks a deterministic condition, with no cap, is fine. No
arbitrary retry or loop caps.

**Why:** a sleep is a bet that something has happened by then, and loses on a slow or loaded
machine.

**Applies to:** all code and tests.

## 9. Tests fail loudly and never silently skip

A test that can't establish its precondition fails with a message that names the precondition and
how to opt out explicitly. A test that mutates process-wide state (fds 0–2, rlimits, credentials,
signal dispositions) runs in its own re-exec'd process (`alone()` in
[`test_support.rs`](../src/containment/cgroup/test_support.rs), `run_fixture_with_cwd()` in
[`src/test_child.rs`](../src/test_child.rs)), under either test runner, and asserts that it does
through the process-per-test gate ([#201], [#210]), which checks the re-exec's argv shape, not just
an environment variable. `RestoreFd2` is brought under it by [#201] and tracked in [#223].

`#[ignore]` marks only a specific, temporary regression on `main`: the owner (a human) accepts the
known failure and disables that one test until it's fixed. Never for a group.

A test group whose environment support varies by host (root, cgroups, and the like) instead
declares its own `COSCA_TEST_<GROUP>` variable, on by default: any value but the literal `0` runs
the group. Only an explicit `COSCA_TEST_<GROUP>=0` disables it, reported as `ignored` with a
reason: the shape a `requires` predicate gives in [skuld](https://github.com/bindreams/skuld), the
test harness cosca is migrating to ([#151]). Without that explicit `0` the test runs for real and
fails on whatever an environment without support produces: a failed support check never turns into
a skip.

Today's gates take three shapes, none matching this: some are `#[ignore]`d and opted into with
`--run-ignored` alone, with no `COSCA_TEST_*` variable at all (the Windows probes and canaries,
`windows_process_cwd`, the elevation routes, and `dir_tests.rs`'s unshare test); some also assert
an opt-in variable (`COSCA_TEST_CGROUP`, `COSCA_TEST_SETUID_HELPER`, `COSCA_TEST_ELEVATION*`); and
some return early instead (every `gated()` caller in `tests/elevation.rs`, and `leaf_tests.rs`).
[#234] tracks the migration and is the authoritative inventory of what's left.

**Why:** a skipped test reports the same pass as a working one, a gate that defaults to skip hides a
whole group nobody decided to disable, and a process-wide mutation corrupts whichever tests share
the process.

**Applies to:** all tests.

## 10. System-affecting tests run in a sandbox

Tests that touch real system state run in a container, VM or CI, never on a developer's host:
cgroups, Job Objects, elevation, process-group and session signals, `kqueue` or `waitpid` teardown
of trees, signals to processes the test didn't spawn, and anything under `sudo`. The only exemption
is a test that spawns this repo's own short-lived children and signals them only through the `Child`
handle cosca returned for each, before that handle reaps the child, never by process group, session
or a PID the test computed. On Unix that kill reaches `kill(2)` by number, which is safe while the
child is unreaped.

Every group this principle covers declares its own `COSCA_TEST_<GROUP>` (principle 9), even where
host support doesn't vary: `=0` says this host can't support or run the group. Consent is a
separate gate, `COSCA_TEST_<GROUP>_CONSENT`: disabling a group with `=0` is itself an explicit
decision, so consent is only asked of an enabled group, and nothing else stands in for it. Only an
explicit `COSCA_TEST_<GROUP>_CONSENT=1` gives consent; any other value, unset included, fails the
test rather than running it. The check may be a skuld fixture, but either way a missing consent is
a hard failure (a panic or an assertion), never a return. For example, a CI step that cannot run
the group sets `COSCA_TEST_ROOT=0`; a sandboxed lane sets `COSCA_TEST_ROOT=1` and
`COSCA_TEST_ROOT_CONSENT=1`. No consent variable exists yet, and some system-affecting groups have
no `COSCA_TEST_<GROUP>` at all; see [#234].

**Why:** a bug in such a test reaches whatever machine it runs on, so the sandbox, not the test's
correctness, has to be what protects it. A group signal can reach an unrelated process ([principle
4](#4-dont-act-on-a-bare-pid-after-it-may-be-reused)). Principle 9 turns every group on by default,
so a bare test run would touch real system state without a second, explicit opt-in.

**Applies to:** all tests. CI's cgroup lane runs in a fresh cgroup on a throwaway runner
([`ci.yaml`](../.github/workflows/ci.yaml)).

## 11. Prefer a dependency over hand-rolled code

A dependency's bugs that don't affect cosca are its to fix, not a reason to avoid it. A bug that
does affect cosca can disqualify it.

**Why:** rejecting dependencies over bugs that don't touch cosca ends with writing everything by
hand.

**Applies to:** all code.

## 12. Small PRs, split along clean seams

Split a plan or PR wherever it has a clean seam. Stack dependent pieces, and keep every intermediate
step consistent with these principles.

**Why:** a small PR is easier to get right and to review, and a defect fails only its own part.

**Applies to:** plans and PRs.

## 13. A deadline is never early, and never late by its own choice

Every caller-supplied deadline cosca accepts (`wait_timeout`, `wait_tree_timeout`,
`graceful_shutdown`'s grace) gets exactly two promises, both checked against a monotonic clock:

- **Never early.** cosca never reports a timeout outcome (`wait_timeout`'s `Ok(None)`/`Ok(false)`,
  `wait_tree_timeout`'s `MembersRemain`, a grace escalating to a kill) before `now >= deadline`.
  Tests assert `elapsed >= deadline` exactly, with no slack: scheduling can only push a call later,
  never earlier, so a passing test never needed a tolerance band.
- **Never late by cosca's own choice.** Every block is armed with the caller's deadline itself,
  passed through the waiting primitive's own deadline API — an absolute instant, not a duration
  cosca computed earlier and reused — and no new round of work starts once the deadline has
  passed. That API is the boundary of cosca's responsibility: kqueue's per-round recompute of the
  remaining time, `event_listener::wait_deadline`, tokio's `timeout_at`, and their equivalents all
  take the caller's `Instant` directly. What happens BELOW that API is not cosca's choice: parking
  through a futex, a timer wheel rounded to its own tick (tokio: up to 1 ms), and OS scheduling all
  introduce lateness cosca neither causes nor controls. This is proved structurally, not by timing:
  a `#[cfg(test)]` seam reports the instant (or the deadline) a wait was actually armed with, or
  whether a blocking call happened at all, and a test clock advanced past the deadline shows the
  next check returning without another round.

cosca promises no upper bound on how late after the deadline it actually reports the outcome —
scheduler, load, a suspended process, or a waiting primitive's own rounding below its API can delay
that by any amount. No test may assert one, including a "returns promptly" check: an assertion of
the shape "elapsed is small" or "elapsed is less than X" is the forbidden upper bound regardless of
how generous X is or how the assertion is phrased.

**Why:** a wall-clock assertion with a tolerance band (`elapsed <= deadline + slack`, or "returns
promptly") is a bet that the test machine, and the waiting primitive's own internals, are fast
enough that day — it passes by luck and fails under load, and the slack itself is exactly wide
enough to hide the busy-poll and early-return bugs it exists to catch. A structural check proves
the property regardless of machine speed or of what a dependency does below its own API.

**Applies to:** every caller-supplied deadline and every wait that arms one.

[tokio shutdown.rs]: https://github.com/tokio-rs/tokio/blob/tokio-1.53.1/tokio/src/runtime/blocking/shutdown.rs#L51-L54
[sd-event.c]: https://github.com/systemd/systemd/blob/885fe07ee37cff7316680b5088d11081e01813b1/src/libsystemd/sd-event/sd-event.c#L3753-L3765
[runc CHANGELOG]: https://github.com/opencontainers/runc/blob/41b74772b651b3b42a1f04a43a803db16f0e7e9b/CHANGELOG.md?plain=1#L1217-L1220
[tokio reap.rs]: https://github.com/tokio-rs/tokio/blob/tokio-1.53.1/tokio/src/process/unix/reap.rs#L122-L128
[tokio pidfd_reaper.rs]: https://github.com/tokio-rs/tokio/blob/tokio-1.53.1/tokio/src/process/unix/pidfd_reaper.rs#L203-L209
[tokio orphan.rs]: https://github.com/tokio-rs/tokio/blob/tokio-1.53.1/tokio/src/process/unix/orphan.rs#L118-L124
[tokio runtime/process.rs]: https://github.com/tokio-rs/tokio/blob/tokio-1.53.1/tokio/src/runtime/process.rs#L30-L39
[tokio unix/mod.rs]: https://github.com/tokio-rs/tokio/blob/tokio-1.53.1/tokio/src/process/unix/mod.rs#L124
[#151]: https://github.com/bindreams/cosca/issues/151
[#174]: https://github.com/bindreams/cosca/issues/174
[#201]: https://github.com/bindreams/cosca/pull/201
[#210]: https://github.com/bindreams/cosca/pull/210
[#223]: https://github.com/bindreams/cosca/issues/223
[#234]: https://github.com/bindreams/cosca/issues/234
