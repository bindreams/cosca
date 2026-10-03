import os, signal, sys
# argv: payload.py <ready-fifo> [release-fifo]
def log(m): print(f"payload[{os.getpid()}]: {m}", file=sys.stderr, flush=True)
for s in (signal.SIGHUP, signal.SIGINT, signal.SIGUSR1):
    signal.signal(s, lambda n, f: log(f"caught {signal.Signals(n).name}"))
r = os.getresuid() if hasattr(os, "getresuid") else (os.getuid(), os.geteuid())
with open(sys.argv[1], "w") as f:
    f.write(f"READY {os.getpid()} uids={r}\n")
log(f"ready uids={r} ppid={os.getppid()} cwd={os.getcwd()}")
if len(sys.argv) > 2:
    with open(sys.argv[2]) as rel:
        rel.read()  # EOF when the driver releases
    log("released; exiting 0")
    sys.exit(0)
while True:
    signal.pause()
