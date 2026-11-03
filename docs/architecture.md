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
| identity module (`ProcessId`) | who a process is: pid plus start token. `Copy`, serializable                                                                        | questions about a number at the time of the read: `exists`, `is_alive`, `created_at`, `parent`, `children`      |
| `OsProcess`                   | one black box per OS: any process, named so that pid reuse cannot misdirect an act on it (pidfd, process handle, macOS audit token) | identity, signal, "has it exited, and if not, what to wait on". Never blocks, never caches                      |
| `OsChild: OsProcess`          | a process this process is the parent of                                                                                             | what only the parent gets: the exit status, the reap, the process group (Linux)                                 |
| `OwnedChild`                  | the parent's policy, written once                                                                                                   | reap once, "already reaped is gone", whether the root is still ours, holding off reaps across a check-then-send |
| drivers                       | sync and async                                                                                                                      | the one wait loop: look, else wait on what the look returned                                                    |

The public types follow the same line:

- `ProcessId` is an identity;
- `Process` is an open handle on any process;
- `Child` is a process you are the parent of.

`OsProcess` exposes something platform-specific in one of three ways, and no other:

- an operation every platform has, as a plain method;
- the platform's native handle, through `os_handle()`;
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

1. **Processes:** the stack above. [#839](https://github.com/bindreams/cosca/issues/839) records the
   owner decisions and the PR plan.
2. **Elevation backends:** a black box that says what the tracked process is (the program, or a
   wrapper that outlives it) and what may be signalled. `Child` asks it; it stops knowing sudo,
   doas or osascript.
3. **Containment mechanisms:** today an enum whose callers ask which mechanism they hold. It
   becomes operations on the tree, taking the root as an `OwnedChild`.
4. **The `Child` core:** with 1–3 done, the sync and async `Child` become one policy and two
   drivers.
5. **Spawn:** produces an `OsChild`, its pipes, its containment and its elevation, for both halves.
