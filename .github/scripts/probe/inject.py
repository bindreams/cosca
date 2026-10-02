"""Real-kqueue probe of _kqueue_waiter: raise one SIGTERM right before or right after its sigpending() call."""
import json, os, signal, sys, threading
sys.path.insert(0, sys.argv[1])
mode = sys.argv[2]
import forward
real, fired = signal.sigpending, []
def wrapped():
    if mode == "before" and not fired:
        fired.append(1); os.kill(os.getpid(), signal.SIGTERM)
    result = real()
    if mode == "after" and not fired:
        fired.append(1); os.kill(os.getpid(), signal.SIGTERM)
    return result
signal.sigpending = wrapped
wait = forward._kqueue_waiter()
reports = []
for _ in range(2):
    t = threading.Thread(target=lambda: reports.append([int(n) for n in wait()]), daemon=True)
    t.start(); t.join(3)
    if t.is_alive():
        break
print(json.dumps({"mode": mode, "fired": bool(fired), "reports": reports}), flush=True)
os._exit(0)
