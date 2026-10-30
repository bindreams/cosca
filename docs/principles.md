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

The armed async `Drop` is an exception: it blocks until what it killed is reaped and drained
(principle 3). A destructor cannot await. So are the places a destructor runs inside an `async fn`:
a run-to-completion teardown (`status`, `output`, `read` failing after the spawn) dropped mid-reap
or mid-drain finishes as the `Drop` does, and one whose exit or drain cannot be watched (the
reactor refuses the registration, or the handle reports an error) waits for it in place instead of
forgetting a child that is ours. Both warn past 1 s, as principle 3 says. A failed async spawn's
teardown waits in place too. Exactly these of its blocking waits for something it killed warn once
past 1 s, as the drop's does, each naming what it waits for:

- the wait for the root, once the spawn has a child handle (on Linux and Windows, and on macOS
  including the teardown of a child whose unique-id report came after the spawn returned,
  [`reap_unreported`](../src/tokio/child/proc_source.rs));
- on Windows, the wait for a process the raw backend's teardown terminated
  (`raw_spawn_teardown` in [`windows_raw.rs`](../src/child/spawn/windows_raw.rs));
- on Linux, the waits for a child it killed in the pidfd handshake
  ([`conclude`](../src/child/spawn/pidfd_handshake.rs) and `await_unexecuted_exit`), and in a cgroup
  leaf's abandonment: `end_child` for a child that named itself, and the pidfd teardown of one that
  never did (`abandon_before_verdict` in [`leaf.rs`](../src/containment/cgroup/leaf.rs));
- on Linux, the wait for an elevation front its leaf's kill ended, in the teardown after the handle
  exists and in the leaf's abandonment (`end_front` in [`leaf.rs`](../src/containment/cgroup/leaf.rs));
- on Linux, the wait for a cgroup leaf's drain, in the leaf's `Drop`, in `finish_elevated`'s
  cleanup, and in the leaf's abandonment (`abandon_before_verdict` and `abandon_front` in
  [`leaf.rs`](../src/containment/cgroup/leaf.rs)).

Each runs through [`wait_warning`](../src/wait/teardown_warn.rs), as the armed drop's reap and
drain do on Unix: it takes the wait as an argument and warns before it if what it waits for has not
ended within the threshold.

Spawning is the other exception: it blocks until `exec`, as tokio's own `Command::spawn` does.
That includes cosca's placement report
([`ReportChannel::wait`](../src/containment/cgroup/channel.rs)), which completes before `exec`. The
wait is bounded by the child's own progress to `exec`; a child stopped or stuck in D state between
`fork` and `exec` holds the thread. The wait for macOS's unique-id report
([`unique_report::await_report`](../src/child/spawn/unique_report.rs)) is bounded the same way, with
accepted residuals: if something else reaps the child and another child of this process takes its
pid before the wait registers its watch, the wait lasts as long as that process; and a tracer
holding the child's zombie keeps it waiting until the tracer hands the zombie back. It runs after
`spawn_lock` is released, so it holds up only its own spawn.

[`SuspendedChild::resume`](../src/tokio/child/suspended.rs) is the deferred second half of a spawn,
so the exception covers it, and it is a sync `fn`. On Windows it walks the system's thread snapshot
to resume the child's initial thread, as a contained `spawn` already does, and waits for no process
exit.

**Why:** a blocked worker stops every task scheduled on it, and on a `current_thread` runtime it
stops the runtime. tokio itself panics rather than block when a `Runtime` is dropped in async
context ([tokio shutdown.rs]).

**Applies to:** every spawn, control and teardown path under [`src/tokio/`](../src/tokio/).

## 3. Async `Drop` waits only for what it killed

With `kill_on_drop` set, an async `Drop` kills the contained tree and the root through their
handles, then blocks until the root's exit shows through its handle and is collected, and a cgroup
leaf has drained and been removed, as the sync `Drop` does. The collect is tokio's `try_wait`, a
reap by the root's number (principle 4). It waits in place on the dropping thread, on every
runtime, never in `block_in_place`: tokio panics in it inside a `LocalSet`, even on a multi-thread
runtime, and offers no way to ask first. Once the wait passes 1 s, the drop logs one `warn` naming
the root's pid, and keeps waiting. The 1 s is for that message only: no wait ends on it. Failed
async spawns wait the same way, with the warns principle 2 lists.

The kills bound the wait, except for a process stuck in uninterruptible I/O (D state) or a root
whose zombie a foreign tracer holds; either holds the dropping thread, which may be a tokio worker.
`kill()` then `wait().await`, plus `wait_tree().await` for a tree, before the drop is the path that
never blocks: the drop then finds nothing to wait for.

A drop that kills nothing does bounded work only: disarmed (`detach()`, `kill_on_drop(false)`), or
armed with a root kill that failed or could not be sent, so the root may still run. It may send a
bounded number of signals and write `cgroup.kill`, one bounded file write, and never waits for a
process exit or a cgroup drain. On Linux 6.9+ the signals include the signal-0 send through the
root's pidfd that decides whether a reaped root's process group is killed (principle 4). A leaf it
leaves undrained stays behind, logged as principle 7 says.
A leaf whose `cgroup.kill` fails twice, in the tree kill and again before the drain, is given up the
same way, though the drop still reaps a root its kill reached.
Its still-running root is left to tokio's drop of its `Child`: an in-drop `try_wait`
([tokio reap.rs], [tokio pidfd_reaper.rs]), then tokio's orphan queue. Both are tokio's state, not
cosca's, and both reap with `waitpid(pid)`. That by-number reap is tokio's (principle 4). The orphan
queue is best-effort: it drains only while some tokio runtime parks ([tokio runtime/process.rs]),
and until then the root stays a zombie.

On evidence of a foreign reap at drop time, armed or not (`detach()` and `kill_on_drop(false)`
included), cosca instead takes the child's stdio out, forgets tokio's `Child`, and logs what the
forget leaks as principle 7 says: on Linux the pidfd and its reactor registration
([tokio unix/mod.rs]), otherwise the `SIGCHLD` watch. That leak is tracked in
[#174] and open with the owner.

tokio discards a PID that is already reaped: the queue drops it on `ECHILD` ([tokio orphan.rs]).
Neither step can detect a foreign reap followed by the number's reuse for another child of ours,
which it would then reap, and cosca's drop-time check can't close the window between itself and
tokio's `try_wait`.

On Windows the async `Drop` terminates the tree and the root, and waits for neither.

**Why:** a kill the drop delivered makes the wait as bounded as the kernel makes it, the same wait
the sync `Drop` already does, and a drop that returns early leaks the zombie and the cgroup leaf.
A kill that failed bounds nothing, so that drop stays bounded.
Global reapers (`waitpid(-1)`, a subreaper) belong to programs that own the whole process, such as
tini and the containerd shim. Embeddable libraries decline the role: sd-event avoids
`waitid(P_ALL)` ([sd-event.c]), and runc's Go `libcontainer` requires its embedder to supply the
reaper for containers without their own PID namespace ([runc CHANGELOG]).

**Applies to:** `Drop` of [`cosca::tokio::Child`](../src/tokio/child.rs) and everything it owns,
which includes an unresumed [`cosca::tokio::SuspendedChild`](../src/tokio/child/suspended.rs): its
drop is its `Child`'s. The sync [`Child`](../src/child.rs) kills and reaps in its `Drop`, which is
allowed.

## 4. Don't act on a bare PID after it may be reused

On Unix cosca can rely on a PID only while its process is an unreaped child (a zombie at worst); on
Windows, only while a handle to the process is open. Signal and wait through a handle that names the
process:

- on Linux, a `pidfd` opened while the child is provably ours, or the child's own pidfd from before
  `exec`. A failed spawn's warn opens one by number for a child that sent only its `/proc`
  directory, and keeps it only if that directory shows the child unreaped after the open;
- a cgroup, since `cgroup.kill` names no PID;
- on macOS, for a process named by a `ProcessId` (`Process`), its audit token: the pid with its
  `p_idversion`, which `proc_signal_with_audittoken` checks in the kernel. A process that took a
  reused pid gets no signal;
- on Windows, a process handle or Job Object.

On Linux cosca requires a pidfd for every child it spawns. When `pidfd_open` is refused (a kernel
before 5.3, or a seccomp profile that blocks it), spawn fails with `Error::Unsupported`, and cosca
itself never reaps by pid on Linux; `main` doesn't do this yet ([#341]). macOS has no pidfd, so it
reaps by pid, only while the process is an unreaped child. A macOS `Drop` that cannot confirm its
child is ours leaks the child with a `warn` naming the pid; it never reaps on a guess. `main`
doesn't do this yet either ([#341]).

Where a group ID must be used (process-group or fd-marker containment), keep the root an unreaped
zombie until the group kill is done. On Linux 6.9+ the root's pidfd names its group exactly, whoever
reaped the root: the group is signalled through it (`PIDFD_SIGNAL_PROCESS_GROUP`), and a signal-0
send through it shows whether the group still has a member; while it has one, its number cannot be
reissued. So a tree call, a drop and a failed spawn's cleanup (a spawn that fails at its identity
read, an elevated spawn that cannot finish, an abandoned spawn whose cgroup leaf did not take its
root, a tokio spawn that fails after its fork) still kill the group of a reaped root while it has a
member, whoever reaped the root, and send nothing once it has none; that signal-0 send is also the
check before each send by the group's number. A tokio handle keeps its pidfd when it forgets tokio's
`Child`, so that holds after it too.
cosca detects the flag by acting, and an older kernel's `EINVAL` is handled per path. A tree call, a
drop and the cleanup of an elevated spawn that cannot finish fall back to the group's number,
checked against the root's state, and send nothing once that check fails. The cleanup of an
abandoned spawn does the same while its child is unreaped, and sends the group of a reaped child
nothing. The cleanups of a spawn that fails at its identity read and of a tokio spawn that fails
after its fork send the group nothing, whatever the root's state. These last three `warn` once that
members of the root's process group may be left running. On macOS, which has no exact kill of a
group, the cleanup of a group root whose spawn fails at its identity read warns the same.
On 6.9+ a member's resend still goes by its pid when the member's own `pidfd_open` fails (`EMFILE`,
say), right after a check of its identity. Below 6.9 and on macOS a reaper elsewhere in the process
can reap the root between the check and a send by its number, which then reaches whoever holds it: a
standing property of process-group and fd-marker containment. A program with such a reaper should
use cgroup containment.

Where a check of a PID cannot be made atomic with its use, keep the window as small as it can be:
check and use are two back-to-back actions. Every send by number has its own check right before it,
never one check for several sends (a `killpg`, its resends, a walk), and no field or variable holds
a checked PID for later use.

The by-number reaps outside this rule are all tokio's `waitpid(pid)`. One is its reap of an async
root cosca did not kill and leaves to it: a dropped root whose drop killed nothing, disarmed
(`detach()`, `kill_on_drop(false)`) or armed with a failed kill (principle 3), or, on macOS, a
child whose async spawn failed and whose kill did not end it, which cosca releases to tokio's
orphan queue rather than forget it and leave a zombie nothing collects
(`ProcSource::reap_now_noting` and `ProcSource::reap_unreported` in
[`proc_source.rs`](../src/tokio/child/proc_source.rs), and the attach-failure arm of
`spawn_uncommitted` in [`tokio/spawn.rs`](../src/tokio/spawn.rs)). The other is every collect of an
async root, which is tokio's `try_wait` right after cosca's own look through the root's handle
showed the exit. A collect never goes without its look: an async wait whose look finds nothing to
collect, as for a zombie a foreign tracer holds, waits for the handle's next event (on macOS, or for
a tracer's event or a re-check timer) and looks again.
The root is then an unreaped zombie of ours, but a foreign reap between a look and its collect is
not detected.

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
- On Linux 6.9+ a process-group kill, by a tree call, a drop or a failed spawn's cleanup, stays
  exact through the root's pidfd (principle 4). Below 6.9 and on macOS, process-group kills, and an
  fd marker's kills by the
  root's number (its group and its ppid walk), are unsafe. The marker's holders are named by the
  pipe they hold and are still killed exactly.
- macOS has no pidfd: a child's kill by its number, and a process-group kill, are not exact after
  the reap. A `Process` named by `ProcessId` stays exact through its audit token (principle 4).

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
[`src/test_child.rs`](../src/test_child.rs)), and asserts that it does
through the process-per-test gate ([#201], [#210]), which checks the re-exec's argv shape, not just
an environment variable. `RestoreFd2` is brought under it by [#201] and tracked in [#223].

`#[ignore]` marks only a specific, temporary regression on `main`: the owner (a human) accepts the
known failure and disables that one test until it's fixed. Never for a group.

A test group whose environment support varies by host (root, cgroups, and the like) instead
declares its own `COSCA_TEST_<GROUP>` variable, on by default: any value but the literal `0` runs
the group. Only an explicit `COSCA_TEST_<GROUP>=0` disables it, reported as `ignored` with a
reason: the shape a `requires` predicate gives in [skuld](https://github.com/bindreams/skuld), the
test harness every target runs on. Without that explicit `0` the test runs for real and
fails on whatever an environment without support produces: a failed support check never turns into
a skip.

A group names an environment, not a mechanism. `CGROUP` means the unconfined cgroup lane: a
delegated cgroup with `unshare` permitted.

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
test rather than running it. The check is a skuld fixture, and a missing consent is
a hard failure (a panic or an assertion), never a return. For example, a CI step that cannot run
the group sets `COSCA_TEST_ROOT=0`; a sandboxed lane sets `COSCA_TEST_ROOT=1` and
`COSCA_TEST_ROOT_CONSENT=1`. `COSCA_TEST_NAMESPACES` (tests that unshare mount and pid
namespaces) has a consent variable too. Both it and `COSCA_TEST_ROOT` (tests that need a DAC
bypass) are `test_group!` rows in `src/test_groups.rs`, which gives their tests the off-switch, the
consent check and a `SKULD_LABELS` label. A test joins with `#[fixture(namespaces)] _group: &Group`, not by name. So does `COSCA_TEST_SETUID` (tests that run a setuid-root
copy of `cosca_testbin`, named by `COSCA_TEST_SETUID_HELPER`): CI provisions the helper only in the
Linux `test` job and the macOS root lane, each behind `setuid-lane-check.sh`, and opts in there.
`SKULD_LABELS=setuid` selects its tests, and `setuid_root` the one the Linux root-run step also
runs. So does
`COSCA_TEST_UID_SWITCH` (the tests that run as real root and switch to other real uids), a
`test_group!` row joined with `#[fixture(uid_switch)] _group: &Group`: CI turns it off
workflow-wide and opts in only in the root lanes that can `setuid` to those uids, which select it
with `SKULD_LABELS=root`. So does `COSCA_TEST_TRACER` (the tests that attach a tracer to their own
children, as a debugger does), joined with `#[fixture(tracer_group)] _group: &Group`: CI turns it
off workflow-wide, and the two tracer steps of the `test` job (debug and release) opt in, selected
by `SKULD_LABELS=tracer`; the cgroup step opts in too, for the `namespaces` tests that also trace.
So does `COSCA_TEST_CGROUP` (the tests that need the unconfined cgroup lane), a `test_group!` row joined
with `#[fixture(cgroup)] _group: &Group`: CI turns it off workflow-wide and the cgroup step opts
in. So does
`COSCA_TEST_DRIVE_MAPPING` (the two drive-mapping tests of `windows_process_cwd`), a `test_group!` row joined with
`#[fixture(drive_mapping)] _group: &Group`, selected by `SKULD_LABELS=drive_mapping`. So does
`COSCA_TEST_ELEVATION` (tests that run commands with real administrator or root privileges), a `test_group!` row
joined with `#[fixture(elevation)] _group: &Group`, selected by `SKULD_LABELS=elevation`. So do the other
Windows groups: `COSCA_TEST_PATH_PROBES` (the `windows_path_resolution` canaries and surveys),
`COSCA_TEST_SHELL_EXECUTE` (`windows_shell_execute`), `COSCA_TEST_SHELL_PROBES`
(`windows_shell_resolution`) and `COSCA_TEST_ELEVATION_ROUTES` (`windows_elevation_routes`), which
are `test_group!` rows like `namespaces`. The `Test (windows/...)` jobs of `ci.yaml` select them by label, as does `windows-probes.yaml` (weekly, on dispatch).
CI turns each off workflow-wide and opts in only in the step or job that runs it.

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

Every caller-supplied deadline cosca accepts (for example `wait_timeout`, `wait_tree_timeout`,
`graceful_shutdown`'s grace) gets exactly two promises, both checked against a monotonic clock:

- **Never early.** cosca never reports a timeout outcome (`wait_timeout`'s `Ok(None)`/`Ok(false)`,
  `wait_tree_timeout`'s `MembersRemain`, a grace escalating to a kill) before `now >= deadline`, or
  `elapsed >= timeout` for an API expressed as a relative timeout instead of an absolute deadline.
  Tests assert this exactly, with no slack: scheduling can only push a call later, never earlier,
  so a passing test never needed a tolerance band.
- **Never late by its own choice.** Every block is armed from the caller's deadline at the moment
  of arming: through the primitive's absolute-deadline API where it has one (tokio's `timeout_at`,
  `event_listener::wait_deadline`), otherwise a remaining time recomputed from that deadline
  immediately before each blocking call — `kevent`, `ppoll` and `WaitFor*` all take a relative
  timeout, not an absolute deadline, so this is the common case, not the exception. Never a
  duration computed earlier and reused. No new round of work starts once the deadline has passed.
  A single non-blocking final check at expiry (principle 8's "re-reads state at expiry and reports
  what it finds") is required and is not itself a new round of work: it looks once, at most, and
  reports what it finds, without starting further work contingent on the answer. This is proved
  structurally, not by timing: a `#[cfg(test)]` seam reports the deadline (or remaining time) a
  wait was actually armed with, or whether a blocking call happened at all, and a test clock
  advanced past the deadline shows the next check returning without another round. That seam is
  introduced by [#240] (the macOS kqueue wait) and [#207] (the cgroup drain waits); [#242] tracks
  the gap until they land.

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

`main` does not fully follow this yet: [#242] tracks the known violations, each closed by the
stacked fix PR that resolves it.

**Applies to:** every caller-supplied deadline and every wait that arms one.

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
[#207]: https://github.com/bindreams/cosca/pull/207
[#210]: https://github.com/bindreams/cosca/pull/210
[#223]: https://github.com/bindreams/cosca/issues/223
[#240]: https://github.com/bindreams/cosca/pull/240
[#242]: https://github.com/bindreams/cosca/issues/242
[#341]: https://github.com/bindreams/cosca/issues/341
