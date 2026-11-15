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
takes `&dyn Kernel` with no `#[cfg]`; Linux's and macOS's have the methods, and Windows's has
`terminate` (`TerminateProcess`). A method enters with its first caller. A read that a test answers
takes `&dyn Kernel`; code that runs between fork and exec never does, and stays raw.

The OS layer owns the kernel it asks, on every platform. `os_process::open_with(kernel, id)` checks
`id` through `&kernel` and moves the same kernel into the process it returns (`LinuxProcess<K>`,
`WindowsProcess<K>`, `MacosProcess<K>`); each child box (`OsChild`) takes its kernel the same way and
lends it through `OsChild::kernel()`. A spawn starts with one kernel (`spawn_with(cmd, kernel)`;
production passes `HostKernel`), erased once at its entry into a `SpawnKernel`, an `Arc<dyn Kernel +
Send>`, so the spawn body below the entry is not generic. The child's box owns it, and the cgroup
leaf and the placement probe's box each own a clone of the `Arc`; the spawn's own reads ask it as
`&dyn Kernel`. A borrow, a `Box` and an `Arc` of a kernel are kernels, so the walks, which open one
process per member from one borrowed kernel, pass `&dyn Kernel`, and tests move a `FakeKernel` in.
`Process` and `OwnedChild` hold a `Box<dyn OsProcess>` or `Box<dyn OsChild>`: the kernel's type stops
at the OS layer.

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
   `DrainEdge::wait`.
   [#839](https://github.com/bindreams/cosca/issues/839) records the owner decisions and the PR
   plan. What is still the old shape, and which step takes it:
   - Spawn: each spawn builds one `OwnedChild` where its handle first exists, and every later
     read, kill and reap of the child goes through it, the identity check
     (`resolve_identity`) and the cgroup placement probe's child included. Linux: in the
     handshake's `conclude`, over the pidfd the child sent, for every arm that has it. macOS:
     right after the child's unique id is adopted; a child whose id came late gets a box of its
     own, its tree swept around the root's kill (`late_child.rs`). Windows: right after the
     process is created, a UAC launch right after `ShellExecuteEx` returns. Two reads are by
     number, through `exit_only::Target`: macOS's `unique_report`, before a unique id exists, and
     the Linux handshake's pre-report watch (a pidfd opened by number until
     [#383](https://github.com/bindreams/cosca/issues/383) S2). `OwnedChild::tear_down`
     is the one kill-then-settle policy, split at its one wait (`begin_tear_down` returns the
     teardown's end or a pending wait, which `settle` blocks on and `settle_async` awaits), and
     `Child::drop` uses it. The async spawn is the sync spawn, run whole on tokio's blocking pool,
     told the async `SpawnPolicy` (the warn threshold of its waits, and what an `Unreaped` it
     hands back does when dropped). On
     Linux the teardown also ends every spawn failure (the handshake's `conclude`, and the
     identity and attach arms, `held_teardown.rs`), while a cgroup leaf a failed spawn drops
     ends its own exchange with the child (`CgroupLeaf::abandon_without_child`: killed through if
     the child entered it, then removed, the child sent nothing). On macOS the identity and
     attach arms tear down through `held_teardown` as Linux's do (a refused kill, or a front
     still running, comes back as an `Unreaped`). On Windows `held_teardown::tear_down_failed_spawn`
     ends every failure of the std and raw spawns; a refused kill comes back in the spawn's
     failure as an `Unreaped`, and so does a UAC child whose pid or identity cannot be read (ended
     by the same teardown and waited for). An identity read the OS refuses fails no spawn: the
     child is kept with no identity, and only a containment that needs one fails the attach. A
     teardown over a handle
     (`held_teardown::tear_down_expecting`) is told once what its caller knows became of the handle
     (`Past`, in `child::owned::teardown`); what the handle allows is its constructor's
     (`OsChild::kill_refusal`: a pidfd is refused for permission alone, a `CreateProcess` handle
     never, a UAC handle by the access it was granted), and the two make the `Expect` that
     `warn_teardown`, which logs the teardown's warn, asserts (the Windows spawns' teardown,
     `held_teardown::tear_down_failed_spawn`, is told the same, and logs through it too; a macOS
     kill is refused for any reason, `KillRefusal::Any`, since the identity read it is checked
     by is refused with any errno). No spawn starts a background reaping thread.
     `Settlement` is the one
     classification of what a wait or look answered (the fate, and a clause for every answer: a
     child left uncollected has only a warn, so no clause of one can be built at another level);
     the teardowns,
     `finish_elevated` and `Unreaped` all ask it. A teardown that cannot end a child, a
     refused kill or a running elevation front, hands it back as `Unreaped`, in
     `Error::MayHaveStarted`: the Linux and macOS spawns do, and so does `finish_elevated`; the
     `Command::{status, output, read}` do through `Child::tear_down_or_hand_back` (awaited, for
     the async ones), and so does the Windows `kill_on_drop(false)` disarm refusal
     (`Child::commit_kill_on_drop`). `SuspendedChild::resume` runs it too; `# Errors` there has the
     split by arm.
   - macOS children with no box are stated limits: one whose id was never read is left; one whose
     kqueue the kernel refused is killed through its unique id, its marker's holders swept, warned
     of and never waited on.
   - Under `MacosChild` ([#877](https://github.com/bindreams/cosca/issues/877), the macOS
     kernel-view slice): macOS's `Kernel` has its methods and is threaded through. macOS tests
     state `FakeKernel` rows. Hooks remain only where the code still holds `HostKernel` (the
     spawn-time code, the fd-marker sweep) or no row can state the answer (`uniq_fault`,
     `ppid_fault`, `force_parents`, `force_links`, `by_pid_reads`). `HostKernel`'s own `sysctl`
     read states no row, so what a sysctl result means (`ESRCH`, `EPERM`/`EACCES` quiet; any other
     errno or a record of another size a `contract_violation`) is the pure `kinfo::classify`,
     tested directly. The one peek seam, `exit_only::seams` (`force_peek_once`, `force_peeks`),
     answers a box's peek in the OS's place under `cfg(test)`: on macOS in
     `exit_only::{peek, peek_verified, peek_traced}`, on Linux in `LinuxProcess::peek`. The tests
     that need it run a whole spawn, whose box a test cannot reach, and the macOS spawn-time code
     also holds `HostKernel`. The Linux peek is a `waitid(P_PIDFD, WNOHANG)` on our own child's
     pidfd, which the kernel (`kernel/exit.c`, `kernel_waitid`, `__do_wait`) answers only with
     `ECHILD` (a foreign reap, `Foreign::Gone`) or, for a closed or non-pidfd descriptor,
     `EBADF`/`EINVAL` (debug-asserted); the seam states what a sandbox policy may answer. No
     Windows test forces a peek. A registration (an exit watch's, a reap waiter's) is a `subscribe`
     row: refused with `ESRCH`, or made and never firing.
2. **Elevation backends:** a black box that says what the tracked process is (the program, or a
   wrapper that outlives it) and what may be signalled. `Child` asks it; it stops knowing sudo,
   doas or osascript.
3. **Containment mechanisms:** a `Child` holds a `Tree`: none, delegated, or contained by one
   `Mechanism` (a cgroup leaf, a Job Object, a process group, an fd marker, a tree walk), which a
   caller drives through the `Contains` trait (send a kill or a terminate, its drain edge, disarm,
   would a kill reach a pid, did it reach the child, release) and never asks which it is: no code
   in `Tree` or the drop teardown asks which mechanism it holds. The members a walk
   left stay in the settlement (`TreeKilled`, one lock), which asks the mechanism for them
   (`Contains::kill_left`: a walk kills them again, every other mechanism hands the result back);
   the cgroup leaf's awaitable steps go through `Contains::awaitable_release` from both the Linux
   awaited drop teardown (`Tree::await_release_steps`) and `Release::wait_async`; every mechanism
   answers it and only the leaf has steps. A mechanism's `Contains::kill` returns a `TreeKill`: its
   outcome, and the identities of the members it reached, which `kill_tree` re-opens by identity, one
   at a time, to wait for each (then the root through its owner's handle, then the tree's own drain
   edge, where its kill landed on one); the async `kill_tree`s and the async `graceful_shutdown_tree`
   escalations await the same wait (`KillWait::wait_async`, which shares everything but the awaited calls
   with `wait`). The send-only callers (the drop, `send_kill_tree`, sync or async) call
   `Contains::send_kill`, which returns the outcome alone: the same kill, and for a cgroup leaf and a
   Job Object no listing of the members before it. `Tree`'s only matches on the kind of mechanism are its
   `_for_test` accessors. A release ends only what a mechanism owns (the cgroup leaf, which its
   `Release` takes, and the fd marker's read end, which the release closes); any other mechanism is given back and stays in
   the tree, so a walk's settlement after a release still has its identities. A released tree is
   sent nothing and has no drain edge, whichever mechanism stays. The two `debug_assert`s on the `CgroupOnly` gate
   (`kill_sent_gated`, `graceful_shutdown`) state a contract there, not a branch. The per-OS async drivers of the drain waits live in the drain edge
   (`containment/drain_edge.rs`), beside `DrainEdge::wait_async`, which calls them; they use the
   async waits' primitives in `tokio/wait.rs` (the clock, the armed deadline, the readiness loop).
4. **The `Child` core:** the sync and async `Child` are one policy and two drivers: the async
   `Child` holds the sync one and only drives its waits (`wait_async`, `settle_async`).
   `graceful_shutdown` and `graceful_shutdown_tree` are each one `async fn` (`shutdown_lone` and
   `shutdown_tree`, in `child/graceful/shutdown.rs`) over a `Waits` trait of their waits: the sync
   `Child` runs them with blocking waits through `run_ready` (one poll, a panic on `Pending`), and
   the async `Child` awaits them. The root's identity read by number, after our own reap, is
   `OsChild::number_holder`. The OS box reads the number through the kernel it owns
   (`OsChild::kernel()`). `OwnedChild` asks the box, and a policy that holds a `Root` asks the root
   (`Root::number_holder`, which `ReapHold` answers through its child). A test states the read on
   the fake of the layer it holds, as it states peeks. For a spawned child that is its
   `FakeProcess`: `number_reads` answers one read each, and `number_reads_always` answers every
   later one. For a stated root it is `StatedRoot::holding`. Only the identity read's own tests
   state `FakeKernel` rows for it, and the one helper that gives a policy test a real read's
   cause: `test_support::emfile_number_read` runs `ProcessId::of_with` over a refused
   `pidfd_open` row.
5. **Spawn:** produces an `OsChild`, its pipes, its containment and its elevation, for both halves.
   On Linux the one fork that execs is `child::spawn::fork_exec` ([#383](https://github.com/bindreams/cosca/issues/383)
   S2): a clone kind (vfork without `CLONE_VM`, or plain), the env block built in the parent, the
   caller's async-signal-safe steps, and a status channel of errno and ready records read without
   blocking. The elevation shim uses it. The ordinary spawn is std's `Command` and the handshake;
   both go when it moves onto the core.
