# Baseline (no shim): SIGKILL the tracked front, then report whether the root payload survived.
import json, os, signal, subprocess, sys, tempfile
front = json.loads(sys.argv[1])
here = os.path.dirname(os.path.abspath(__file__))
d = tempfile.mkdtemp(); os.chmod(d, 0o777); r = os.path.join(d, "r"); os.mkfifo(r, 0o666); os.chmod(r, 0o666)
p = subprocess.Popen(front + [sys.executable, os.path.join(here, "payload.py"), r], stdin=subprocess.DEVNULL)
line = open(r).readline().split(); pid = int(line[1])
print("baseline: tracked front pid", p.pid, "payload pid", pid, "same:", p.pid == pid, flush=True)
try: os.kill(p.pid, signal.SIGKILL); print("baseline: kill(front, SIGKILL) ok")
except PermissionError as e: print("baseline: kill(front, SIGKILL):", e)
p.wait()
try: os.kill(pid, 0); alive = True
except PermissionError: alive = True
except ProcessLookupError: alive = False
print("baseline: front reaped; root payload alive:", alive, flush=True)
if alive: subprocess.run(["sudo", "-n", "kill", "-KILL", str(pid)])
