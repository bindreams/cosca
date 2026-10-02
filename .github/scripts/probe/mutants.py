# name -> (file, old, new)
F, R = "forward.py", "run-nextest.py"
M = {
 "no-setsid": (F, "start_new_session=True", "start_new_session=False"),
 "relay-to-pid": (F, "kill(-child.pid, signal.SIGTERM)", "kill(child.pid, signal.SIGTERM)"),
 "relay-after-reap": (F, "        if reaped == child.pid:\n            break", "        if reaped == child.pid:\n            if signalled:\n                kill(-child.pid, signal.SIGTERM)\n            break"),
 "no-mask-reset": (F, "    signal.pthread_sigmask(signal.SIG_SETMASK, set())\n", "    pass\n"),
 "no-disposition-reset": (F, "    for number in BLOCKED:\n        signal.signal(number, signal.SIG_DFL)\n    signal.pthread_sigmask(signal.SIG_SETMASK", "    signal.pthread_sigmask(signal.SIG_SETMASK"),
 "unmask-first": (F, "    for number in BLOCKED:\n        signal.signal(number, signal.SIG_DFL)\n    signal.pthread_sigmask(signal.SIG_SETMASK, set())", "    signal.pthread_sigmask(signal.SIG_SETMASK, set())\n    for number in BLOCKED:\n        signal.signal(number, signal.SIG_DFL)"),
 "no-128": (F, "return 128 + os.WTERMSIG(raw)", "return os.WTERMSIG(raw)"),
 "raw-status": (F, "return 128 + os.WTERMSIG(raw)", "return raw"),
 "sigkill-relay": (F, "kill(-child.pid, signal.SIGTERM)", "kill(-child.pid, signal.SIGKILL)"),
 "relay-as-is": (F, "kill(-child.pid, signal.SIGTERM)", "kill(-child.pid, number)"),
 "blocking-waitpid": (F, "waitpid(child.pid, os.WNOHANG)", "waitpid(child.pid, 0)"),
 "chld-not-blocked": (F, "    signal.pthread_sigmask(signal.SIG_BLOCK, BLOCKED)\n    return lambda", "    signal.pthread_sigmask(signal.SIG_BLOCK, RELAYED)\n    return lambda"),
 "block-after-popen": (F, "    wait = make_wait()\n    try:\n        child = popen(argv, start_new_session=True, close_fds=False, preexec_fn=_child_setup)\n    except OSError as error:\n        raise SpawnError(f\"cannot run {argv[0]}: {error}\") from error\n", "    try:\n        child = popen(argv, start_new_session=True, close_fds=False, preexec_fn=_child_setup)\n    except OSError as error:\n        raise SpawnError(f\"cannot run {argv[0]}: {error}\") from error\n    wait = make_wait()\n"),
 "no-sigchld-reset": (F, "    signal.signal(signal.SIGCHLD, signal.SIG_DFL)\n    wait = make_wait()", "    wait = make_wait()"),
 "fatal-relay-error": (F, "        except OSError:\n", "        except ZeroDivisionError:\n"),
 "inverted-reap": (F, "        if reaped == child.pid:\n            break", "        if reaped != child.pid:\n            break"),
 "kq-empty-pending": (F, "    seen = {int(number) for number in BLOCKED if number in pending}", "    seen = set()"),
 "kq-no-drain": (F, "    seen |= {int(event.ident) for event in queue.control(None, len(BLOCKED), 0)}\n", ""),
 "kq-dup-merge": (F, "    seen = {int(number) for number in BLOCKED if number in pending}", "    seen = [int(number) for number in BLOCKED if number in pending]"),
 "kq-ign-before-reg": (F, "    signal.pthread_sigmask(signal.SIG_BLOCK, BLOCKED)\n    queue = kq.kqueue()", "    for number in RELAYED:\n        signal.signal(number, signal.SIG_IGN)\n    queue = kq.kqueue()"),
 "kq-drain-before-pending": (F, "    pending = signal.sigpending()\n    seen = {int(number) for number in BLOCKED if number in pending}\n    for number in RELAYED:\n        signal.signal(number, signal.SIG_IGN)\n    seen |= {int(event.ident) for event in queue.control(None, len(BLOCKED), 0)}\n", "    drained = {int(event.ident) for event in queue.control(None, len(BLOCKED), 0)}\n    pending = signal.sigpending()\n    seen = {int(number) for number in BLOCKED if number in pending} | drained\n    for number in RELAYED:\n        signal.signal(number, signal.SIG_IGN)\n"),
 "kq-pending-before-reg": (F, "    queue = kq.kqueue()\n    queue.control(\n        [kq.kevent(number, kq.KQ_FILTER_SIGNAL, kq.KQ_EV_ADD | kq.KQ_EV_CLEAR) for number in BLOCKED],\n        0,\n        0,\n    )\n    pending = signal.sigpending()\n", "    queue = kq.kqueue()\n    pending = signal.sigpending()\n    queue.control(\n        [kq.kevent(number, kq.KQ_FILTER_SIGNAL, kq.KQ_EV_ADD | kq.KQ_EV_CLEAR) for number in BLOCKED],\n        0,\n        0,\n    )\n"),
 "kq-oneshot": (F, "kq.KQ_EV_ADD | kq.KQ_EV_CLEAR", "kq.KQ_EV_ADD | kq.KQ_EV_ONESHOT"),
 "kq-no-ignore": (F, "    for number in RELAYED:\n        signal.signal(number, signal.SIG_IGN)\n    seen |=", "    seen |="),
 "kq-no-chld-kevent": (F, "for number in BLOCKED],\n", "for number in RELAYED],\n"),
 "always-sigwait": (F, "return _kqueue_waiter() if hasattr(select, \"kqueue\") else _sigwait_waiter()", "return _sigwait_waiter()"),
 "w-shared-profile": (R, "    profile = f\"ci-{name}\"", "    profile = \"ci\""),
 "w-no-stop-check": (R, "    if signalled:\n        print(\"::warning::the run was told to stop; its JUnit file is not published\")\n        return status or 1\n", ""),
 "w-no-unlink": (R, "    junit.unlink(missing_ok=True)\n", ""),
 "w-copy": (R, "shutil.move(str(junit), published / f\"{name}.xml\")", "shutil.copy(str(junit), published / f\"{name}.xml\")"),
 "w-move-keeps-status": (R, "            print(f\"::error::could not move {junit} to {published / (name + '.xml')}: {error}\")\n            return 1", "            print(f\"::error::could not move {junit} to {published / (name + '.xml')}: {error}\")\n            return status"),
}
import sys, pathlib
if __name__ == "__main__":
    name, d = sys.argv[1], pathlib.Path(sys.argv[2])
    if name == "none": sys.exit(0)
    f, old, new = M[name]
    p = d / f
    t = p.read_text()
    assert t.count(old) == 1, (name, t.count(old))
    p.write_text(t.replace(old, new))
