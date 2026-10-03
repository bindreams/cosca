import json, os, socket, subprocess, sys, tempfile, time, platform
front = json.loads(sys.argv[1]); scenario = sys.argv[2]
shim = os.environ.get("SHIM", "/probe/shim2")
password = os.environ.get("PW")
here = os.path.dirname(os.path.abspath(__file__))
L = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
if os.environ.get("ABSTRACT") and sys.platform.startswith("linux"):
    name = "cosca-elev-" + os.urandom(8).hex(); L.bind("\0" + name); addr = "@" + name
else:
    d = tempfile.mkdtemp(prefix="cosca-elev-"); addr = os.path.join(d, "s"); L.bind(addr)
L.listen(4); L.setblocking(False)
d2 = tempfile.mkdtemp(prefix="cosca-probe-"); os.chmod(d2, 0o777)
ready = os.path.join(d2, "ready"); os.mkfifo(ready, 0o666); os.chmod(ready, 0o666)
release = os.path.join(d2, "release"); os.mkfifo(release, 0o666); os.chmod(release, 0o666)
armed = "0" if scenario == "unarmed" else "1"
py = sys.executable if not os.environ.get("PYPAYLOAD") else os.environ["PYPAYLOAD"]
pl = os.path.join(here, "payload.py")
payload = {"exit42": ["/bin/sh", "-c", "exit 42"],
           "stdio": ["/bin/sh", "-c", "cat; echo to-stderr >&2; exit 3"],
           "detach": [py, pl, ready, release], "unarmed": [py, pl, ready, release]}.get(scenario, [py, pl, ready])
inner = [shim, addr, str(os.getpid()), armed, "--"] + payload
if front and front[0] == "OSA":
    import shlex
    cmd = "exec " + " ".join(shlex.quote(a) for a in inner)
    esc = cmd.replace("\\", "\\\\").replace('"', '\\"')
    argv = front[1:] + ["/usr/bin/osascript", "-e", 'do shell script "%s" with administrator privileges without altering line endings' % esc]
else:
    argv = front + inner
print("driver: argv:", " ".join(argv), flush=True)
p = subprocess.Popen(argv, stdin=subprocess.PIPE if (password or scenario == "stdio") else subprocess.DEVNULL,
                     stdout=subprocess.PIPE if scenario == "stdio" else None, stderr=subprocess.PIPE, cwd="/tmp")
conn = None
def accept():
    global conn
    if conn is None:
        try: c, _ = L.accept()
        except BlockingIOError: return False
        if sys.platform.startswith("linux"):
            import struct
            pid, uid, gid = struct.unpack("3i", c.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        else:
            uid = os.getuid() if False else None
            pid = None
        print(f"driver: accepted shim connection, peer pid={pid} uid={uid}", flush=True)
        conn = c
    return True
def stderr_until(needle):
    for line in p.stderr:
        line = line.decode(errors="replace").rstrip(); print("  front stderr:", line, flush=True)
        if needle and needle in line: return
def finish():
    rc = p.wait(); stderr_until(None)
    print("driver: front exit status", rc, flush=True)
    if accept():
        conn.setblocking(True); data = conn.recv(64)
        print("driver: status reported over the socket:", data.decode().strip() or "(none: EOF)", flush=True)
    else:
        print("driver: no shim connection was ever made", flush=True)
if scenario == "prestart":
    # cosca kills before authentication finished: nothing accepted yet, so close the listener.
    print("driver: accept before auth:", accept(), flush=True)
    L.close(); [os.unlink(addr) if not addr.startswith("@") else None]
    p.stdin.write((password + "\n").encode()); p.stdin.close()
    rc = p.wait(); stderr_until(None); print("driver: front exit", rc, flush=True)
    sys.exit(0)
if scenario == "hijack":
    # A same-uid process replaces the socket path before the shim connects.
    os.unlink(addr)
    evil = subprocess.Popen([sys.executable, "-c", "import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); s.listen(1); print('bound', flush=True); sys.stdin.read()", addr],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    print("driver: impostor (pid %d) says:" % evil.pid, evil.stdout.readline().decode().strip(), flush=True)
    if password: p.stdin.write((password + "\n").encode()); p.stdin.close()
    rc = p.wait(); stderr_until(None); print("driver: front exit", rc, flush=True); sys.exit(0)
if password:
    p.stdin.write((password + "\n").encode()); p.stdin.close()
if scenario in ("exit42",):
    finish(); sys.exit(0)
if scenario == "stdio":
    out, err = p.communicate(b"hello through the shim\n")
    print("driver: stdout:", out, "stderr:", err.decode().splitlines()[-2:], "front exit", p.returncode, flush=True)
    accept(); conn.setblocking(True); print("driver: status over socket:", conn.recv(64).decode().strip()); sys.exit(0)
with open(ready) as f: line = f.readline().strip()
print("driver: payload says:", line, flush=True)
ppid = int(line.split()[1])
assert accept(), "the shim connected before the payload could report READY"
if scenario == "kill": conn.send(b"K")
elif scenario == "term": conn.send(b"T")
elif scenario == "lifeline": conn.close(); conn = None; L.close(); L = None
elif scenario in ("detach", "unarmed"):
    if scenario == "detach": conn.send(b"D")
    conn.close(); conn = None
    stderr_until("EOF while disarmed")
    alive = subprocess.run(["kill", "-0", str(ppid)], capture_output=True).returncode == 0 or b"ermitted" in subprocess.run(["kill", "-0", str(ppid)], capture_output=True).stderr
    print("driver: payload alive after the connection closed:", alive, flush=True)
    os.close(os.open(release, os.O_WRONLY))
if L is None:
    rc = p.wait(); stderr_until(None); print("driver: front exit status", rc, flush=True)
else:
    finish()
r = subprocess.run(["kill", "-0", str(ppid)], capture_output=True)
print("driver: payload gone after front exit:", r.returncode != 0 and b"ermitted" not in r.stderr, flush=True)
