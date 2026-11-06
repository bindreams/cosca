# Architecture

How cosca is divided into parts, and the rules that decide where new code goes. This describes the
target. Where `main` still differs, the difference is debt, tracked in the issues linked below, and
new code follows this document, not the old shape.

## Rules

1. **One mechanism per concern.** A second copy of a mechanism, helper or seam is a defect, even
   when each copy is correct. Before adding one, find the existing one and extend it, or replace it.
2. **Where code branches on "which kind is this", an abstraction is missing.** The fix is a
   boundary that hides the kinds: a black box with operations and properties, which callers use
   without asking what it is. Elevation backends, containment mechanisms and per-OS process
   handling are each such a boundary.
3. **`#[cfg]` goes only where the consumer is itself platform code.**
   - A method or type that only platform code uses is behind `#[cfg]`, so the compiler rules out
     using it on the wrong platform.
   - A result variant that shared code matches on exists on every platform, with a doc line naming
     the OS that produces it. Shared code then needs no `#[cfg]` arms.
   - Platform is a build-time fact: never check for it at runtime (no downcasts to a platform type).
4. **Sync and async differ only in how they wait.** Policy is written once. The sync and async
   halves are drivers that block on, or register, the same OS objects.
5. **Tests stand at boundaries.** A fake implements a boundary's trait as a table of stated answers
   and models no OS. OS behaviour is tested against real processes on the platform that has it. A
   thread-local hook that answers in the OS's place means a boundary is missing.

## Processes

A question about a _pid_ and a question about a _process you hold_ go to different places:

| Layer                         | Is                                                                                                                                  | Answers                                                                                                         |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| identity module (`ProcessId`) | who a process is: pid plus key (Linux 6.9+: the pidfd's inode, else the start time). `Copy`, serializable                           | questions about a number at the time of the read: `exists`, `is_alive`, `created_at`, `parent`, `children`      |
| `OsProcess`                   | one black box per OS: any process, named so that pid reuse cannot misdirect an act on it (pidfd, process handle, macOS audit token) | signal, "has it exited, and if not, what to wait on". Never blocks, never caches                                |
| `OsChild: OsProcess`          | a process this process is the parent of                                                                                             | what only the parent gets: the exit status, the reap, the process group (Linux)                                 |
| `OwnedChild`                  | the parent's policy, written once                                                                                                   | reap once, "already reaped is gone", whether the root is still ours, holding off reaps across a check-then-send |
| drivers                       | sync and async                                                                                                                      | the one wait loop: look, else wait on what the look returned                                                    |

The identity module asks the kernel through one interface, `Kernel` (`HostKernel` makes the calls;
tests pass a `FakeKernel` of stated answers). The trait exists on every platform, so shared code
takes `&dyn Kernel` with no `#[cfg]`; Linux's has the methods, and macOS's and Windows's have none
yet. A method enters with its first caller. A read that a test answers takes `&dyn Kernel`; code
that runs between fork and exec never does, and stays raw.

The public types follow the same line:

- `ProcessId` is an identity;
- `Process` is an open handle on any process;
- `Child` is a process you are the parent of.

`OsProcess` exposes something platform-specific in one of three ways, and no other:

- an operation every platform has, as a plain method;
- the platform's native handle, through `os_handle()`, or a `pidfd()` view of it (Linux `Some`,
  macOS `None`) for the consumers that take an optional fd on both Unixes;
- a consumer's own knowledge (cgroup membership, Job Object assignment), which stays with that
  consumer and uses the borrowed handle.

## Boundaries still to draw

Each one gets the same treatment before any code:

- a map of what exists;
- the problem, stated in terms of the code;
- an interface;
- real call sites rewritten against it;
- the pieces it replaces.

In order:

1. **Processes:** the stack above, in place for the sync `Child`: it reaches its process through one
   `OwnedChild` over a per-OS `OsChild`, and the holder's waits for the root process (its `try_reap`
   loop and `exited_by`) run through `drive::run`. A waiter that is not the holder blocks on the
   handle's `Condvar`, and the waits for the tree to drain (`wait_tree`, the graceful drains) in
   `Attached::wait_drained`.
   [#839](https://github.com/bindreams/cosca/issues/839) records the owner decisions and the PR
   plan. What is still the old shape, and which step takes it:
   - The async `Child` (the PR that moves it onto the stack): `terminate_by_id`, which its
     graceful path sends through; `GroupRoot::new` with no `ReapHold`; its tests' hooks,
     `exit_only::seams` and `signal::seams`, which `Process::kill`'s tests share.
   - Spawn (the spawn-time slice): `exit_only::Target` and `exit_only::Reap`, which spawn
     identity, `kill_and_reap_*` and `unique_report` still take by handle or number;
     `await_reapable` and its kqueue round hooks (macOS), which spawn teardown still waits
     through; `GroupRoot::new` at the failed-spawn identity check (`spawn.rs`); the
     `exit_only::seams` their tests use. `OwnedChild::tear_down`
     is the one kill-then-settle policy, and `Child::drop` uses it. On Linux it also ends every
     sync spawn failure (the handshake's `conclude`, and the identity and attach arms,
     `held_teardown.rs`) and, in the async spawn, the failures of a child the handshake holds by
     pidfd (`conclude`'s `(Err, Opened)` and unexecuted arms), an elevation front at the identity
     and attach arms (`ProcSource::leave_front_noting`), the second teardown of a refused kill
     (`ProcSource::tear_down_forgotten`), and the cgroup leaf's abandonment of every child it is
     left (`CgroupLeaf::abandon_before_verdict`: the group a child that exec'd outside the leaf
     leads, through `OwnedChild::hold`, then the leaf, then `tear_down` with the leaf's kill as
     its `Kill` tree, or `look_at_front` for a front). The sync spawn builds the `OwnedChild` once when the handshake succeeds. On Windows it
     ends every failure of the std and raw spawns (`held_teardown::tear_down_failed_spawn`), in
     the async raw spawn too; a refused kill comes back in the sync spawn's failure as an
     `Unreaped`, and the async raw spawn leaves the child, warned. Both spawns build their
     `OwnedChild` once, right after the process is created. Until the
     async-child slice, tokio's own code ends the rest of the async spawn. `conclude`'s
     `Ok(child)` arms are `Spawned` for tokio's `Child`: `reap_unexecuted` kills through the
     pidfd and collects with tokio's `try_wait`, leaving a zombie it cannot yet collect to
     tokio's orphan queue, and `abandon_unreported` leaves the child to that queue, which
     `waitpid`s by pid. The async non-front attach arm and the
     identity arms that are not unknown (`ProcSource::reap_now_noting`) make the first kill the
     backend's. A refused kill goes on to `tear_down`, through `after_refused_kill`, once tokio's
     `Child` is forgotten; `reap_now_noting` collects with tokio's `try_wait`, so it reaps by pid.
     The unknown identity arm (`teardown_through_pidfd`) forgets tokio's `Child` and goes straight
     to `tear_down`, sending no kill of its own. A teardown through a pidfd
     (`held_teardown::tear_down_pidfd`) is told once what its caller knows became of the pidfd
     (`Past`, in `child::owned::teardown`); what the handle allows is its constructor's
     (`OsChild::kill_refusal`: a pidfd is refused for permission alone, a `CreateProcess` handle
     never, a UAC handle by the access it was granted), and the two make the `Expect` that
     `warn_teardown`, which logs the teardown's warn, asserts (the Windows spawns' teardown,
     `held_teardown::tear_down_failed_spawn`, is told the same, and logs through it too); a child
     spawned for a leaf (`ToLeaf`), front or not, hands the leaf its pidfd with the `Past`, and the
     leaf is its one owner; the leaf's abandonment carries the `Expect` with the clause (`Left`) to
     where it is logged. No spawn starts a background reaping thread.
     `Settlement` is the one
     classification of what a wait or look answered (the fate, and a clause for every answer: a
     child left uncollected has only a warn, so no clause of one can be built at another level);
     the teardowns,
     `finish_elevated` and `Unreaped` all ask it. A teardown that cannot end a child, a
     refused kill or a running elevation front, hands it back as `Unreaped`, in
     `Error::MayHaveStarted`: the sync Linux spawn does, and so does the sync `finish_elevated`;
     the `Command::{status, output, read}` do through `Child::tear_down_or_hand_back`.
     `SuspendedChild::resume` runs it too but leaves the child, since a frozen thread may never run.
     Windows and macOS still tear down by themselves.
   - Under `MacChild` ([#877](https://github.com/bindreams/cosca/issues/877), the macOS
     kernel-view slice): `exit_only::{peek, peek_verified, peek_traced}` still consult the
     `exit_only::seams` hook; five macOS tests need it, and `MacChild::event_pending` (a `cfg(test)`
     accessor) goes with it. `LinuxProcess` no longer does. The macOS arm of the `unreadable` test
     helper still answers through the thread-local `force_unknown` hook until that slice gives
     macOS `Kernel` methods. That slice also removes
     `block_probe::on_round` and `on_every_round`, the `cfg(test)` round hooks of `wait.rs`.
2. **Elevation backends:** a black box that says what the tracked process is (the program, or a
   wrapper that outlives it) and what may be signalled. `Child` asks it; it stops knowing sudo,
   doas or osascript.
3. **Containment mechanisms:** today an enum whose callers ask which mechanism they hold. It
   becomes operations on the tree, taking the root as an `OwnedChild`.
4. **The `Child` core:** with 1–3 done, the sync and async `Child` become one policy and two
   drivers. It also removes `child::fault::force_root_reads` and `force_next_root_read`, a
   thread-local hook that answers the root's identity read (`root_identity_now`) beside
   `FakeKernel`: the root's read moves into `OwnedChild`, through the kernel it was built with, and
   those tests state `FakeKernel` rows (owner, 2026-11-05: kept until then; needs
   [#877](https://github.com/bindreams/cosca/issues/877) on macOS). Beside them goes the Windows
   exiting-refusal hook (`identity::windows_fault::refuse_next_terminate_as_exiting`), which answers
   in the OS's place (`TerminateProcess` refusing as an exit under way); the Windows `Kernel` methods
   enter with their first caller, and those tests state rows (owner, 2026-11-06). The sweep bodies of
   the sync and tokio `kill_tree_after` (the front gate, the root check, the refusal to walk, the
   cgroup-front arm, the handle backstop and `SweepFailure::of`) merge there: today each is written
   twice.
5. **Spawn:** produces an `OsChild`, its pipes, its containment and its elevation, for both halves.
