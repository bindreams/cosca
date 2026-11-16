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

| Layer                         | Is                                                                                                                                  | Answers                                                                                                    |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| identity module (`ProcessId`) | who a process is: pid plus key (Linux 6.9+: the pidfd's inode, else the start time). `Copy`, serializable                           | questions about a number at the time of the read: `exists`, `is_alive`, `created_at`, `parent`, `children` |
| `OsProcess`                   | one black box per OS: any process, named so that pid reuse cannot misdirect an act on it (pidfd, process handle, macOS audit token) | signal, "has it exited, and if not, what to wait on". Never blocks, never caches                           |
| `OsChild: OsProcess`          | a process this process is the parent of                                                                                             | what only the parent gets: the exit status, the reap, the process group (Linux)                            |
| `OwnedChild`                  | the parent's policy, written once                                                                                                   | observe the exit (a wait reaps nothing), reap once when the handle drops, whether the root is still ours   |
| drivers                       | sync and async                                                                                                                      | the one wait loop: look, else wait on what the look returned                                               |

The identity module asks the kernel through one interface, `Kernel` (`HostKernel` makes the calls;
tests pass a `FakeKernel` of stated answers). The trait exists on every platform, so shared code
takes `&dyn Kernel` with no `#[cfg]`; Linux's and macOS's have the methods, and Windows's has
`terminate` (`TerminateProcess`) and `creation_token` (`GetProcessTimes` of a handle the caller
holds). A method enters with its first caller. A read that a test answers takes `&dyn Kernel`; code
that runs between fork and exec never does, and stays raw.

The OS layer owns the kernel it asks, on every platform. `os_process::open_with(kernel, id)` checks
`id` through `&kernel` and moves the same kernel into the process it returns (`LinuxProcess<K>`,
`WindowsProcess<K>`, `MacosProcess<K>`); each child box (`OsChild`) takes its kernel the same way and
lends it through `OsChild::kernel()`. A spawn starts with one kernel (`spawn_with(cmd, kernel)`;
production passes `HostKernel`), erased once at its entry into a `SpawnKernel`, an `Arc<dyn Kernel +
Send>`, so the spawn body below the entry is not generic. The child's box owns it, and the cgroup
leaf, the placement probe's box, the macOS fd marker and the tree walk (`Walker`) each own a clone of
the `Arc`: a tree outlives the box, and still reads through the spawn's kernel. The spawn's own reads
ask it as `&dyn Kernel`. A foreign `Process`'s graceful call makes one kernel for the call and every
read of it goes through that. A borrow, a `Box` and an `Arc` of a kernel are kernels, so the walks,
which open one process per member from one borrowed kernel, pass `&dyn Kernel`, and tests move a
`FakeKernel` in. `Process` and `OwnedChild` hold a `Box<dyn OsProcess>` or `Box<dyn OsChild>`: the
kernel's type stops at the OS layer.

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
     (`resolve_identity`) and the cgroup placement probe's child included. Linux: in
     `fork_spawn`, over the pidfd the clone gave it, for every arm. macOS:
     right after the child's unique id is adopted; a child whose id came late gets a box of its
     own, its tree swept around the root's kill (`late_child.rs`). Windows: right after the
     process is created, a UAC launch right after `ShellExecuteEx` returns. One read is by
     number, through `exit_only::Target`: macOS's `unique_report`, before a unique id exists. `OwnedChild::tear_down`
     is the one kill-then-settle policy, split at its one wait (`begin_tear_down` returns the
     teardown's end or a pending wait, which `settle` blocks on and `settle_async` awaits), and
     `Child::drop` uses it. The async spawn is the sync spawn, run whole on tokio's blocking pool,
     told the async `SpawnPolicy` (the warn threshold of its waits, and what an `Unreaped` it
     hands back does when dropped). On
     Linux the teardown also ends every spawn failure (`fork_spawn`'s `conclude`, and the
     identity and attach arms, `held_teardown.rs`), while a cgroup leaf a failed spawn drops
     takes its verdict without a child (`CgroupLeaf::abandon_without_child`: killed through if
     the child's recorded report says it entered, then removed). The report is a record the child
     wrote on the spawn core's status channel, which `fork_spawn` reads and records on the leaf. On
     macOS the identity and attach arms tear down through `held_teardown` as Linux's do (a refused
     kill, or a front still running, comes back as an `Unreaped`). On Windows `held_teardown::tear_down_failed_spawn`
     ends every failure of the std and raw spawns after their identity read; a refused kill comes back
     in the spawn's failure as an `Unreaped`, and so does a UAC child whose pid cannot be read (ended by the same
     teardown and waited for: a `Child` has a pid). An identity read the OS refuses fails no spawn,
     a UAC launch's included: the child is kept with no identity, `id()` is `None`, and only a
     containment that needs one fails the attach. A Windows spawn reads the identity of the handle
     its box holds, through the one `resolve_identity` and `Kernel::creation_token` (the UAC launch
     too, which a by-pid open could not read, as an elevated child's can be refused); that read
     finds the child or cannot say, so no Windows spawn fails on it. A
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
     kernel-view slice): macOS's `Kernel` is threaded through the spawn: the box and the fd
     marker's sweeps ask the kernel the spawn started with.
     Tests state `FakeKernel` rows, a whole spawn's too (`spawn_with` over
     `FakeKernel::over(&HostKernel)`; a row about a pid no test knows before the spawn is stated
     from a spawn hook, `FakeKernel::state_*`). No test hook answers a read in the kernel's place.
     The Linux peek and consume are `Kernel::peek`/`consume` (see their docs). `HostKernel`'s own
     `sysctl` read states no row, so what a sysctl result means (`ESRCH`, `EPERM`/`EACCES` quiet;
     any other errno or a record of another size a `contract_violation`) is the pure
     `kinfo::classify`, tested directly. No Windows test forces a peek. A registration (an exit
     watch's, a reap waiter's) is a `subscribe` row: refused with `ESRCH`, or made and never
     firing.
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
   sent nothing and has no drain edge, whichever mechanism stays. The `debug_assert` on a front the kill rule leaves
   to its cgroup (`Child::kill_sent`) states a contract there, not a branch. The per-OS async drivers of the drain waits live in the drain edge
   (`containment/drain_edge.rs`), beside `DrainEdge::wait_async`, which calls them; they use the
   async waits' primitives in `tokio/wait.rs` (the clock, the armed deadline, the readiness loop).
4. **The `Child` core:** the sync and async `Child` are one policy and two drivers: the async
   `Child` holds the sync one and only drives its waits (`wait_async`, `settle_async`).
   `graceful_shutdown` and `graceful_shutdown_tree` are each one `async fn` (`shutdown_lone` and
   `shutdown_tree`, in `child/graceful/shutdown.rs`) over a `Waits` trait of their waits: the sync
   `Child` runs them with blocking waits through `run_ready` (one poll, a panic on `Pending`), and
   the async `Child` awaits them. The root's identity read by number, which a drop uses to catch a
   reap by another that the handle cannot report, is `OsChild::number_holder`. The OS box reads the
   number through the kernel it owns (`OsChild::kernel()`), and `OwnedChild` asks the box. A test
   states the read on the fake of the layer it holds, as it states peeks. For a spawned child that
   is its `FakeProcess`: `number_reads` answers one read each, and `number_reads_always` answers
   every later one. Only the identity read's own tests state `FakeKernel` rows for it, and the one
   helper that gives a policy test a real read's cause: `test_support::emfile_number_read` runs
   `ProcessId::of_with` over a refused `pidfd_open` row.
5. **Spawn:** produces an `OsChild`, its pipes, its containment and its elevation, for both halves.
   On Linux the one fork that execs is `child::spawn::fork_exec` ([#383](https://github.com/bindreams/cosca/issues/383)
   S2): a clone kind (vfork without `CLONE_VM`, or plain), the env block built in the parent, the
   caller's async-signal-safe steps, and a status channel of errno, ready and report records read
   without blocking. The elevation shim uses it, and so does the ordinary spawn
   (`child::spawn::fork_spawn`, the vfork kind): its outcome is the core's records alone. Every unix
   spawn finds its program in the parent, by the one search `resolve::posix::lookup` (the POSIX
   grammar of `crate::resolve`: the child's `PATH` only, the first file that exists, an entry that
   cannot be examined ends the search). So does elevation's detection of its front (`sudo`, `doas`,
   `pkexec`) on this process's `PATH`: a miss is an absent front, and an entry that cannot be examined
   is kept as the cause of the `BackendUnavailable` for a front the plan picks. The Linux child only
   `execve`s the path it is given (and the `PATH` entries after it that are files, if that file is
   gone at the `execve`), and macOS hands std the path. macOS still
   launches through std, whose `execvp` gives a file with no `#!` to `/bin/sh` until macOS forks itself.
