"""The elevated program (THROWAWAY). argv: prog.py <siglog> <mode> [args].

Logs every HUP/INT/QUIT/TERM/USR1/USR2 it receives (one line each) and keeps running.
Modes:
  block|plain <ready>                (plain: no handlers) report "READY <pid> <uid>", wait for signals
  release <ready> <rel> N            report READY, wait for one byte on rel, exit N
  exit N                             exit N at once (after a 'ran' line)
  ping <ready> <req> <reply> [drop]  report READY (after dropping to uid/gid 65534 with 'drop'), then
                                     answer each '?' line on req with 'alive', exit 42 on 'q'. Its
                                     liveness is observable without a pidfd: a write to req fails
                                     (EPIPE) or the reply reads EOF once it is gone.
"""
import os, signal, sys

log = os.open(sys.argv[1], os.O_WRONLY | os.O_APPEND)
os.write(log, b"ran %d\n" % os.getpid())


def h(s, _f):
    os.write(log, b"sig %d\n" % s)


mode = sys.argv[2]
for s in () if mode == "plain" else (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM, signal.SIGUSR1, signal.SIGUSR2):
    signal.signal(s, h)
if mode == "exit":
    sys.exit(int(sys.argv[3]))
if mode == "ping" and len(sys.argv) > 6 and sys.argv[6] == "drop":
    os.setgroups([]); os.setgid(65534); os.setuid(65534)
with open(sys.argv[3], "w") as f:
    f.write("READY %d %d %d\n" % (os.getpid(), os.getuid(), os.getegid()))
if mode in ("block", "plain"):
    while True:
        signal.pause()
if mode == "ping":
    req = open(sys.argv[4], "rb", buffering=0)
    rep = open(sys.argv[5], "wb", buffering=0)
    for line in req:
        if line.strip() == b"q":
            os._exit(42)  # no finalisation: the kernel closes the fds at exit, so EOF on reply means exited
        rep.write(b"alive\n")
    sys.exit(0)
fd = os.open(sys.argv[4], os.O_RDONLY)
os.read(fd, 1)
sys.exit(int(sys.argv[5]))
