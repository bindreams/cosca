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
behind and logs a warning naming it.

A dropped, still-running async root is left to tokio's drop of its `Child`: an in-drop `try_wait`
([tokio reap.rs], [tokio pidfd_reaper.rs]), then tokio's orphan queue. Both are tokio's state, not
cosca's, and both reap with `waitpid(pid)`, the one by-number reap cosca accepts (principle 4); the
alternatives are a reaper cosca would own (principle 1) or a wait in `Drop`. The orphan queue is
best-effort: it drains only while some tokio runtime parks ([tokio runtime/process.rs]), and until
then the root stays a zombie.

On evidence of a foreign reap at drop time, cosca instead takes the child's stdio out, forgets
tokio's `Child`, and logs a warning naming what the forget leaks: on Linux the pidfd and its reactor
registration ([tokio unix/mod.rs]), otherwise the `SIGCHLD` watch. That leak is tracked in [#174]
and open with the owner.

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
`ESRCH`), releases the child without signalling it, and never debug-asserts on it.

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
genuinely unreachable is asserted in debug, not merely documented. In `Drop`, a failed kill or
signal logs a warning naming the resource. A foreign reap itself logs at `debug`, and a resource it
forces cosca to leak gets a warning (principle 3).

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
[`src/test_child.rs`](../src/test_child.rs)), or relies on nextest's process-per-test and asserts
that it does, through the `alone()`/`require_process_per_test` gate ([#201], [#210]). The gate
accepts nextest's `NEXTEST_EXECUTION_MODE=process-per-test`, or `alone()`'s `COSCA_TEST_ALONE`
marker together with its exact argv. `RestoreFd2` is brought under it by [#201] and tracked in
[#223].

**Why:** a skipped test reports the same pass as a working one, and a process-wide mutation corrupts
whichever tests share the process.

**Applies to:** all tests.

## 10. System-affecting tests run in a sandbox

Tests that touch real system state run in a container, VM or CI, never on a developer's host:
cgroups, Job Objects, elevation, process-group and session signals, `kqueue` or `waitpid` teardown
of trees, signals to processes the test didn't spawn, and anything under `sudo`. The only exemption
is a test that spawns this repo's own short-lived children and signals them only through the `Child`
handle cosca returned for each, before that handle reaps the child, never by process group, session
or a PID the test computed. On Unix that kill reaches `kill(2)` by number, which is safe while the
child is unreaped.

**Why:** a bug in such a test reaches whatever machine it runs on, so the sandbox, not the test's
correctness, has to be what protects it. A group signal can reach an unrelated process ([principle
4](#4-dont-act-on-a-bare-pid-after-it-may-be-reused)).

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

[tokio shutdown.rs]: https://github.com/tokio-rs/tokio/blob/tokio-1.53.1/tokio/src/runtime/blocking/shutdown.rs#L51-L54
[sd-event.c]: https://github.com/systemd/systemd/blob/885fe07ee37cff7316680b5088d11081e01813b1/src/libsystemd/sd-event/sd-event.c#L3753-L3765
[runc CHANGELOG]: https://github.com/opencontainers/runc/blob/41b74772b651b3b42a1f04a43a803db16f0e7e9b/CHANGELOG.md?plain=1#L1217-L1220
[tokio reap.rs]: https://github.com/tokio-rs/tokio/blob/tokio-1.53.1/tokio/src/process/unix/reap.rs#L122-L128
[tokio pidfd_reaper.rs]: https://github.com/tokio-rs/tokio/blob/tokio-1.53.1/tokio/src/process/unix/pidfd_reaper.rs#L203-L209
[tokio orphan.rs]: https://github.com/tokio-rs/tokio/blob/tokio-1.53.1/tokio/src/process/unix/orphan.rs#L118-L124
[tokio runtime/process.rs]: https://github.com/tokio-rs/tokio/blob/tokio-1.53.1/tokio/src/runtime/process.rs#L30-L39
[tokio unix/mod.rs]: https://github.com/tokio-rs/tokio/blob/tokio-1.53.1/tokio/src/process/unix/mod.rs#L124
[#174]: https://github.com/bindreams/cosca/issues/174
[#201]: https://github.com/bindreams/cosca/pull/201
[#210]: https://github.com/bindreams/cosca/pull/210
[#223]: https://github.com/bindreams/cosca/issues/223
