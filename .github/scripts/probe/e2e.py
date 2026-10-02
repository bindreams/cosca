"""The root-step chain end to end: run-nextest.py -> sudo -E python3 forward.py -> bash -> a grandchild that announces itself after exec; SIGINT the top, as the runner's timeout does."""
import os, subprocess, sys, signal, tempfile
scripts = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
work = tempfile.mkdtemp()
up, bg = os.path.join(work, "up"), os.path.join(work, "bg")
os.mkfifo(up); os.mkfifo(bg)
fd = os.open(up, os.O_RDWR)
grand = "import os, signal, sys; os.write(os.open(sys.argv[1], os.O_RDWR), b'x\\n'); signal.pause()"
inner = (f'trap "echo inner bash got TERM >&2; exit 9" TERM; "{sys.executable}" -c "{grand}" {bg} adv455jgrand & '
         f'read -r _ < {bg}; echo $$ > {up}; wait')
p = subprocess.Popen([sys.executable, f"{scripts}/run-nextest.py", "root", "sudo", "-E", sys.executable, f"{scripts}/forward.py", "bash", "-c", inner],
                     env={**os.environ, "RUNNER_TEMP": work}, cwd=work)
print("inner bash", int(os.read(fd, 32)), flush=True)
p.send_signal(signal.SIGINT)
rc = p.wait(timeout=60)
left = subprocess.run(["pgrep", "-f", "adv455jgrand"], capture_output=True, text=True).stdout
print("status", rc, "leftover grandchild:", repr(left), flush=True)
