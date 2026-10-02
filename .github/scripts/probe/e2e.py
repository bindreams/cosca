"""The root-step chain end to end: run-nextest.py -> sudo -E python3 forward.py -> bash; SIGINT the top, as the runner's timeout does."""
import os, subprocess, sys, signal, tempfile
scripts = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
work = tempfile.mkdtemp()
up = os.path.join(work, "up"); os.mkfifo(up)
fd = os.open(up, os.O_RDWR)
inner = 'trap "echo inner bash got TERM >&2; exit 9" TERM; echo $$ > ' + up + '; sleep 1000 & wait'
p = subprocess.Popen([sys.executable, f"{scripts}/run-nextest.py", "root", "sudo", "-E", sys.executable, f"{scripts}/forward.py", "bash", "-c", inner],
                     env={**os.environ, "RUNNER_TEMP": work}, cwd=work)
print("inner bash", int(os.read(fd, 32)), flush=True)
p.send_signal(signal.SIGINT)
rc = p.wait(timeout=60)
left = subprocess.run(["pgrep", "-lf", "^sleep 1000$"], capture_output=True, text=True).stdout
print("status", rc, "leftover sleep:", repr(left), flush=True)
