"""Waiting.test_a_signal_that_arrives_as_the_command_exits..., printing the forwarder's log: is the TERM relayed on this OS?"""
import os, select, signal, subprocess, sys, tempfile
here = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, here)
from forward_tests import exit_event
work = tempfile.mkdtemp()
for n in ("up", "release"):
    os.mkfifo(f"{work}/{n}")
up, release = os.open(f"{work}/up", os.O_RDWR), os.open(f"{work}/release", os.O_RDWR)
code = ("import os, signal, sys\nwork = sys.argv[1]\nsignal.signal(signal.SIGTERM, lambda *_: os._exit(9))\n"
        "os.write(os.open(work + '/up', os.O_RDWR), str(os.getpid()).encode() + b'\\n')\n"
        "os.read(os.open(work + '/release', os.O_RDWR), 1)\nsys.exit(7)\n")
p = subprocess.Popen([sys.executable, f"{here}/forward.py", sys.executable, "-c", code, work], stderr=subprocess.PIPE)
command = int(os.read(up, 32))
exited = exit_event(command)
p.send_signal(signal.SIGSTOP); os.waitpid(p.pid, os.WUNTRACED)
os.write(release, b"x")
assert select.select([exited], [], [], 30)[0]
p.send_signal(signal.SIGTERM); p.send_signal(signal.SIGCONT)
_, err = p.communicate(timeout=30)
print(p.returncode, repr(err.decode()), flush=True)
