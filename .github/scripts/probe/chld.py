"""Is a blocked, default-disposition SIGCHLD pending (sigpending) after a child exits? Knoted?"""
import json, os, select, signal
signal.signal(signal.SIGCHLD, signal.SIG_DFL)
signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGCHLD})
kq = select.kqueue()
kq.control([select.kevent(signal.SIGCHLD, select.KQ_FILTER_SIGNAL, select.KQ_EV_ADD | select.KQ_EV_CLEAR)], 0, 0)
pid = os.fork()
if pid == 0:
    os._exit(3)
ex = select.kqueue()
ex.control([select.kevent(pid, select.KQ_FILTER_PROC, select.KQ_EV_ADD | select.KQ_EV_ONESHOT, select.KQ_NOTE_EXIT)], 0, 0)
ex.control(None, 1, 5)
os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT)
print(json.dumps({"pending_chld": signal.SIGCHLD in signal.sigpending(), "knoted": [e.ident for e in kq.control(None, 4, 0)]}))
