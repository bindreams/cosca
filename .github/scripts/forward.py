#!/usr/bin/env python3
"""Run a command in a session of its own, and pass INT, TERM and HUP on to its whole process tree.

Usage: forward.py <command> [args...]

The runner enforces a step's `timeout-minutes` on Unix by signalling only the step's top-level
process (`actions/runner`, `ProcessInvoker.SendSignal`), so a child it is waiting on never hears
about it and outlives the step. A step `exec`s this script, so the signal lands here.

The command starts in a new session (`start_new_session`: `setsid` in the child before `exec`, and
`Popen` returns only once the `exec` has happened), with an empty signal mask and default
dispositions for the signals this script handles. A signal that arrives is relayed as SIGTERM to the
command's process group, `kill(-pid, SIGTERM)`: INT, TERM and HUP all become TERM, and the status
of this script is still the command's own. Exactness comes from three facts:

- INT, TERM, HUP and CHLD are blocked from before the spawn until this script exits, so none is
  handled, with its default action or otherwise, before the group exists or after the command is
  reaped. They are awaited without being consumed by `sigwait` on Linux, and by a kqueue
  `EVFILT_SIGNAL` on macOS, where `sigwait` loses a signal and returns garbage when a second, different
  one arrives during the wait, and can leave a stopped process suspended (the mask `sigwait` sets
  while it waits holds SIGCONT back). Neither wait masks SIGCONT, and neither leaves this script
  suspended by its own mask. After every wake-up the command is asked about with `waitpid(WNOHANG)`,
  whatever the signal was.
- The group id is the command's pid. The command is reaped only in this loop, at the top of an
  iteration, and no signal is relayed after the reap, so while a signal is being relayed the pid, and
  the group id with it, is held and cannot belong to a stranger.
- The command is its own session leader, so its group holds only its own tree: not this script, and
  not another stage of a pipeline this script is a member of.

Exit status: the command's exit status, or 128 plus the number of the signal that killed it. `run`
also reports whether a signal was relayed, for callers that must tell a command that ended on its
own from one that was told to stop. A relayed signal is logged on stderr. A relay that fails because
no live member is left to signal is not an error: the reap decides the status.
"""

import os
import select
import signal
import subprocess
import sys

RELAYED = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
BLOCKED = RELAYED + (signal.SIGCHLD,)


class SpawnError(Exception):
    """The command could not be started."""


def _child_setup():
    """Runs in the child after `setsid`, before `exec`: default dispositions, then an empty mask.

    A signal sent to the group of this script before the child left it is pending here. The
    dispositions go first so that it meets the default action when the mask opens, never a handler
    inherited from this interpreter (whose `KeyboardInterrupt` would abort the spawn).
    """
    for number in BLOCKED:
        signal.signal(number, signal.SIG_DFL)
    signal.pthread_sigmask(signal.SIG_SETMASK, set())


def _sigwait_waiter():
    """Linux: `sigwait` takes one blocked signal at a time, exactly."""
    return lambda: [int(signal.sigwait(BLOCKED))]


def _kqueue_waiter():
    """macOS: a kqueue reports every delivery of a blocked signal and consumes none of them.

    The kqueue is registered after the signals are blocked, so a signal that arrived before it
    shows in `sigpending()` and is reported first; one that arrives after is reported by the queue.
    """
    queue = select.kqueue()
    queue.control(
        [select.kevent(number, select.KQ_FILTER_SIGNAL, select.KQ_EV_ADD | select.KQ_EV_CLEAR) for number in BLOCKED],
        0,
        0,
    )
    early = [int(number) for number in BLOCKED if number in signal.sigpending()]

    def wait():
        nonlocal early
        if early:
            taken, early = early, []
            return taken
        return [event.ident for event in queue.control(None, len(BLOCKED), None)]

    return wait


def make_waiter():
    return _sigwait_waiter()


def run(
    argv,
    *,
    popen=subprocess.Popen,
    make_wait=make_waiter,
    kill=os.kill,
    waitpid=os.waitpid,
    log=lambda message: print(message, file=sys.stderr, flush=True),
):
    """Run `argv`; return `(status, signalled)`. The keyword arguments let tests script the OS."""
    signal.pthread_sigmask(signal.SIG_BLOCK, BLOCKED)
    # A signal with a handler is not discarded while blocked, where a default-ignored one may be.
    signal.signal(signal.SIGCHLD, lambda *_: None)
    wait = make_wait()
    try:
        child = popen(argv, start_new_session=True, close_fds=False, preexec_fn=_child_setup)
    except OSError as error:
        raise SpawnError(f"cannot run {argv[0]}: {error}") from error
    signalled = False
    pending = []
    woken_by_exit = False
    while True:
        # Whether the command has exited is asked of the kernel at every wake-up, not inferred from
        # SIGCHLD alone: a signal that comes with an exit decides nothing, the reap does.
        reaped, raw = waitpid(child.pid, os.WNOHANG)
        if reaped == child.pid:
            break
        if woken_by_exit:
            log(f"forward.py: SIGCHLD, and the command {child.pid} is still running")
        while not pending:
            pending = list(wait())
        number = pending.pop(0)
        woken_by_exit = number == signal.SIGCHLD
        if woken_by_exit:
            continue
        signalled = True
        try:
            kill(-child.pid, signal.SIGTERM)
        except OSError:
            # No live member is left to signal (macOS refuses a group of zombies with EPERM, Linux
            # accepts it; a group that is gone gives ESRCH). The command's exit decides the status,
            # not the relay, so there is nothing to do and the reap is next.
            log(f"forward.py: nothing left to signal in the process group of {child.pid} (received {signal.Signals(number).name})")
            continue
        log(f"forward.py: relayed SIGTERM to the process group of {child.pid} (received {signal.Signals(number).name})")
    child.returncode = 0  # reaped here, not by Popen
    if os.WIFEXITED(raw):
        return os.WEXITSTATUS(raw), signalled
    return 128 + os.WTERMSIG(raw), signalled


def main(argv):
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        status, _ = run(argv)
    except SpawnError as error:
        print(f"forward.py: {error}", file=sys.stderr)
        return 127
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
