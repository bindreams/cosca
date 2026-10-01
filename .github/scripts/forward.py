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

- From before the spawn until this script exits, INT, TERM, HUP and CHLD can neither act on this
  script nor be missed. On Linux they are blocked and taken one at a time with `sigwait`. On macOS
  `sigwait` is not usable: when a second, different signal arrives during the wait it loses the
  first one and returns garbage, and the mask it sets while it waits holds SIGCONT back, which can
  leave a stopped process suspended for good. There INT, TERM and HUP are ignored and a kqueue
  `EVFILT_SIGNAL`, which reports every attempt to deliver a signal even when it is ignored, tells this
  script about all four; nothing is masked, so nothing keeps this script suspended. After every
  wake-up the command is asked about with `waitpid(WNOHANG)`, whatever the signal was.
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
    """Linux: the signals are blocked and `sigwait` takes one at a time, exactly."""
    signal.pthread_sigmask(signal.SIG_BLOCK, BLOCKED)
    return lambda: [int(signal.sigwait(BLOCKED))]


def _kqueue_waiter(kq=select):
    """macOS: a kqueue reports every attempt to deliver a signal, even one that is ignored.

    INT, TERM and HUP are ignored, so none acts on this script, during the spawn or ever, and none
    stays pending; the kqueue still reports each. CHLD is left at its default, which discards it,
    and the kqueue reports that too. Nothing is waited for with `sigwait`, and once this returns
    nothing is blocked. `kq` is the module with `kqueue` and `kevent`, so tests can stand in for it.

    The signals are blocked while the kqueue is registered, so none acts on this script before it
    is. A signal that arrived before the registration is pending and shows in `sigpending()`; one
    that arrives after it is reported by the queue and, until the signals are ignored, is pending
    as well. So the pending set and the events already queued are merged, as a set, before the
    signals are unblocked: one arrival, one report. Whatever arrives later is reported by the queue
    alone, since an ignored signal is not pending.
    """
    signal.pthread_sigmask(signal.SIG_BLOCK, BLOCKED)
    queue = kq.kqueue()
    queue.control(
        [kq.kevent(number, kq.KQ_FILTER_SIGNAL, kq.KQ_EV_ADD | kq.KQ_EV_CLEAR) for number in BLOCKED],
        0,
        0,
    )
    pending = signal.sigpending()
    seen = {int(number) for number in BLOCKED if number in pending}
    for number in RELAYED:
        signal.signal(number, signal.SIG_IGN)
    seen |= {int(event.ident) for event in queue.control(None, len(BLOCKED), 0)}
    signal.pthread_sigmask(signal.SIG_UNBLOCK, BLOCKED)
    early = sorted(seen)

    def wait():
        nonlocal early
        if early:
            taken, early = early, []
            return taken
        return [int(event.ident) for event in queue.control(None, len(BLOCKED), None)]

    return wait


def make_waiter():
    return _kqueue_waiter() if hasattr(select, "kqueue") else _sigwait_waiter()


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
    # An ignored SIGCHLD, inherited from the caller, makes Linux reap the command by itself and send
    # no SIGCHLD, and this script would wait for it forever.
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
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
