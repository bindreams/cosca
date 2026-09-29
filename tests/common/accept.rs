//! The death-watched accept: wait for a connection on a listener, but fail loudly instead of
//! hanging if the process that should make it dies first.
//!
//! # Contract
//!
//! - `target_pid` must be a child the caller has NOT reaped (and, on Windows, the caller still
//!   holds its handle). A pid is only a stable name while its process is an unreaped child (a
//!   zombie at worst) or a handle to it is open (docs/principles.md, principle 4); once it is
//!   reaped the number can name a stranger and the watch would wait on the wrong process.
//! - `also`, when given, is a live descendant of `target_pid` whose parent is still alive: the
//!   parent keeps it an unreaped zombie (Unix) or holds a handle to it (Windows). Opening it
//!   after `target_pid` died is harmless: `target_pid` is in the same wait set, its death is
//!   observed at once, and that wins.
//! - A caller must not close a member's control socket before the remaining accepts: a member that
//!   exits because its socket was closed is an ordinary exit that these functions report as
//!   "died before it connected".

use std::net::{TcpListener, TcpStream};

/// [`accept_or_die_also`] watching only `target_pid`.
pub fn accept_or_die(listener: &TcpListener, target_pid: u32) -> TcpStream {
    accept_or_die_also(listener, target_pid, None)
}

/// Blocks until either `listener` gets an incoming connection, or `target_pid` (or `also`) exits
/// first — via the OS's own process-exit notification (a `pidfd` on Linux, a `kqueue`'s
/// `EVFILT_PROC`/`NOTE_EXIT` on macOS, a process HANDLE via `WaitForMultipleObjects` on
/// Windows), never a pipe. A pipe's EOF is hidden by any descendant still holding its write end
/// open: measured, `sh -c 'sleep 8 & exit 3'` reports its OWN exit only 8s later through a
/// pipe-EOF proxy. A plain blocking `accept()` would hang forever if the target dies first, for
/// the same reason; this doesn't.
///
/// No thread, no reconnect: an earlier revision death-watched the target on a thread and, on
/// death, RECONNECTED to `listener`'s own address to signal it, which is unsound: once the target
/// and this function have moved on, nothing keeps that port reserved, and the OS can and does
/// reissue it (observed on macOS) to an unrelated later listener.
///
/// The exit notification is a PROMPT to check again, not proof by itself: a target that connects
/// and then exits immediately races its own exit signal against the connection already sitting in
/// the listener's backlog. Every platform resolves that race in [`final_peek_or_die`]: once an
/// exit notification fires, a final NON-BLOCKING `accept()` is the authority, and wins if a
/// connection is there. Only an empty backlog at that instant is "died before connecting".
///
/// `also` exists for a tree whose root is alive but whose grandchild died before connecting:
/// watching the root alone would wait forever. See the module doc for both pids' contracts.
#[cfg(target_os = "linux")]
pub fn accept_or_die_also(listener: &TcpListener, target_pid: u32, also: Option<u32>) -> TcpStream {
    use std::os::fd::OwnedFd;

    debug_assert_ne!(Some(target_pid), also, "the two watched pids must differ");

    fn open(pid: u32) -> Result<OwnedFd, rustix::io::Errno> {
        let raw = rustix::process::Pid::from_raw(pid as i32).expect("a watched pid is never 0");
        rustix::process::pidfd_open(raw, rustix::process::PidfdFlags::empty())
    }

    // An unreaped zombie still opens, so ESRCH for the target means it was already REAPED: the
    // caller broke the contract, and the pid may by now name a stranger. Not a "died" report.
    let target_fd = match open(target_pid) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::SRCH) => panic!(
            "pid {target_pid} was already reaped before accept_or_die watched it: the target must be an unreaped child"
        ),
        Err(e) => panic!(
            "pidfd_open({target_pid}) for the death-watch: {}",
            std::io::Error::from(e)
        ),
    };
    let mut watched = vec![(target_pid, target_fd)];
    let mut gone_already = None;
    if let Some(pid) = also {
        match open(pid) {
            Ok(fd) => watched.push((pid, fd)),
            // A descendant whose parent is gone is reaped by init: it is dead, but there may
            // still be a connection it made first.
            Err(rustix::io::Errno::SRCH) => gone_already = Some(pid),
            Err(e) => panic!("pidfd_open({pid}) for the death-watch: {}", std::io::Error::from(e)),
        }
    }
    let event = match gone_already {
        Some(pid) => WatchEvent::Died(pid),
        None => wait_linux(listener, &watched),
    };
    match event {
        WatchEvent::Connection => listener.accept().expect("accept a control connection").0,
        WatchEvent::Died(pid) => final_peek_or_die(listener, pid),
    }
}

/// What ended a death-watched wait. Every platform funnels a death into the one
/// [`final_peek_or_die`] call site, so a test that reaches it through any path covers the site.
enum WatchEvent {
    Connection,
    Died(u32),
}

#[cfg(target_os = "linux")]
fn wait_linux(listener: &TcpListener, watched: &[(u32, std::os::fd::OwnedFd)]) -> WatchEvent {
    use std::os::fd::AsRawFd;

    let mut fds = vec![libc::pollfd {
        fd: listener.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    }];
    fds.extend(watched.iter().map(|(_, fd)| libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    }));
    loop {
        // SAFETY: `fds` is a valid, correctly-sized array for the call's duration.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            panic!("poll while waiting for a control connection: {e}");
        }
        // POLLNVAL would mean this function handed poll() a bad fd, a contract it owns end to
        // end, so a violation is a bug here, not a runtime condition.
        for f in &fds {
            debug_assert_eq!(f.revents & libc::POLLNVAL, 0, "a polled fd went invalid mid-wait");
        }
        // An error on the LISTENER is a real, externally-caused condition, surfaced in every build.
        if fds[0].revents & (libc::POLLERR | libc::POLLHUP) != 0 {
            panic!(
                "the control listener reported an error while waiting for a connection (revents={:#x})",
                fds[0].revents
            );
        }
        // Exits are checked BEFORE the listener on purpose. poll() samples its fds one after the
        // other, so a target that connects and exits mid-call can show up as an exit with the
        // listener still sampled empty; and when both are visible, either order is correct. Routing
        // every exit through `final_peek_or_die`, which prefers a queued connection, gives one path
        // to reason about instead of two.
        for (i, (pid, _)) in watched.iter().enumerate() {
            if fds[i + 1].revents & libc::POLLIN != 0 {
                return WatchEvent::Died(*pid);
            }
        }
        if fds[0].revents & libc::POLLIN != 0 {
            return WatchEvent::Connection;
        }
    }
}

/// macOS sibling of the Linux `accept_or_die_also`: same contract, via one `kqueue` carrying an
/// `EVFILT_PROC`/`NOTE_EXIT` watch per pid and an `EVFILT_READ` watch on the listener.
#[cfg(target_os = "macos")]
pub fn accept_or_die_also(listener: &TcpListener, target_pid: u32, also: Option<u32>) -> TcpStream {
    use std::os::fd::AsRawFd;

    use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue};

    debug_assert_ne!(Some(target_pid), also, "the two watched pids must differ");

    let kq = Kqueue::new().expect("kqueue() for the death-watch");
    let mut changes: Vec<KEvent> = std::iter::once(target_pid)
        .chain(also)
        .map(|pid| {
            KEvent::new(
                pid as usize,
                EventFilter::EVFILT_PROC,
                EvFlags::EV_ADD | EvFlags::EV_RECEIPT,
                FilterFlag::NOTE_EXIT,
                0,
                0,
            )
        })
        .collect();
    changes.push(KEvent::new(
        listener.as_raw_fd() as usize,
        EventFilter::EVFILT_READ,
        EvFlags::EV_ADD | EvFlags::EV_RECEIPT,
        FilterFlag::empty(),
        0,
        0,
    ));
    let mut receipts = vec![changes[0]; changes.len()];
    let mut event = None;
    kq.kevent(&changes, &mut receipts, None)
        .expect("kevent(EV_ADD) to arm the death-watch and the listener watch");
    for r in &receipts {
        // EV_RECEIPT makes EV_ADD synchronous and always reports EV_ERROR, with the outcome (0 =
        // armed OK) in `data`: the ONLY way to observe an EV_ADD failure at all.
        assert!(
            r.flags().contains(EvFlags::EV_ERROR),
            "EV_RECEIPT should always report EV_ERROR: {r:?}"
        );
        let errno = r.data() as i32;
        if r.filter() == Ok(EventFilter::EVFILT_PROC) && errno == libc::ESRCH {
            // Gone by the time we tried to arm the watch. This is also what an exited but
            // UNREAPED child looks like here (measured: EV_ADD on a zombie reports ESRCH), so it
            // is the ordinary path for a target that connected and exited before this call.
            event = Some(WatchEvent::Died(r.ident() as u32));
            continue;
        }
        assert_eq!(
            errno,
            0,
            "kevent(EV_ADD) receipt for {:?} reported errno {errno}",
            r.filter()
        );
    }

    let event = match event {
        Some(event) => event,
        None => wait_macos(&kq, changes[0], changes.len()),
    };
    match event {
        WatchEvent::Connection => listener.accept().expect("accept a control connection").0,
        WatchEvent::Died(pid) => final_peek_or_die(listener, pid),
    }
}

#[cfg(target_os = "macos")]
fn wait_macos(kq: &nix::sys::event::Kqueue, template: nix::sys::event::KEvent, len: usize) -> WatchEvent {
    use nix::sys::event::{EvFlags, EventFilter};

    let mut events = vec![template; len];
    loop {
        let n = kq
            .kevent(&[], &mut events, None)
            .expect("kevent while waiting for a control connection");
        for ev in &events[..n] {
            // An armed kevent reporting EV_ERROR would mean the kernel hit a problem delivering a
            // notification this function already armed: not a condition either filter describes.
            debug_assert!(
                !ev.flags().contains(EvFlags::EV_ERROR),
                "an armed kevent reported EV_ERROR: {ev:?}"
            );
            match ev.filter() {
                Ok(EventFilter::EVFILT_READ) => return WatchEvent::Connection,
                Ok(EventFilter::EVFILT_PROC) => return WatchEvent::Died(ev.ident() as u32),
                _ => {}
            }
        }
    }
}

/// Windows sibling of the Linux/macOS `accept_or_die_also`: same contract, via
/// `WaitForMultipleObjects` over a `WSAEVENT` armed for `FD_ACCEPT` on the listener and one process
/// HANDLE per watched pid (opened fresh by pid, so any caller that knows the pid can use this).
///
/// Opening a handle by pid is only sound while the pid still names the process the caller means.
/// For `target_pid` that is the caller's contract (see the module doc): it holds the child's
/// handle, so the number cannot be reissued. For `also` it holds while its parent lives (the parent
/// holds a handle to it), and if the parent died first `target_pid`'s own handle is signalled,
/// which wins the wait.
#[cfg(windows)]
pub fn accept_or_die_also(listener: &TcpListener, target_pid: u32, also: Option<u32>) -> TcpStream {
    use std::os::windows::io::AsRawSocket;

    use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_FAILED, WAIT_OBJECT_0};
    use windows::Win32::Networking::WinSock::{WSACloseEvent, WSACreateEvent, WSAEventSelect, FD_ACCEPT, SOCKET};
    use windows::Win32::System::Threading::{OpenProcess, WaitForMultipleObjects, INFINITE, PROCESS_SYNCHRONIZE};

    debug_assert_ne!(Some(target_pid), also, "the two watched pids must differ");

    let pids: Vec<u32> = std::iter::once(target_pid).chain(also).collect();
    let mut processes: Vec<HANDLE> = Vec::new();
    for &pid in &pids {
        // SAFETY: opens the process by pid with only SYNCHRONIZE, enough to wait for its exit.
        match unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) } {
            Ok(h) => processes.push(h),
            Err(e) => {
                for h in &processes {
                    // SAFETY: closes only handles opened above.
                    let _ = unsafe { CloseHandle(*h) };
                }
                panic!("OpenProcess({pid}, SYNCHRONIZE) for the death-watch: {e}");
            }
        }
    }

    // SAFETY: creates an unnamed, unowned manual-reset event; closed explicitly below.
    let accept_event = unsafe { WSACreateEvent() }.expect("WSACreateEvent for the listener's accept-readiness watch");
    let sock = SOCKET(listener.as_raw_socket() as usize);
    // SAFETY: `sock` is the listener's own live socket; `accept_event` was just created above.
    let rc = unsafe { WSAEventSelect(sock, Some(accept_event), FD_ACCEPT as i32) };
    assert_eq!(
        rc,
        0,
        "WSAEventSelect(FD_ACCEPT) on the control listener: {}",
        std::io::Error::last_os_error()
    );

    // Process handles come BEFORE the accept event: with bWaitAll false, when several handles are
    // signalled the lowest index wins, and routing every exit through `final_peek_or_die` (which
    // prefers a queued connection) keeps one path to reason about, as on Linux.
    let mut handles = processes.clone();
    handles.push(HANDLE(accept_event.0 as *mut _));
    // SAFETY: every handle is live and owned by this function for the call's duration.
    let woken = unsafe { WaitForMultipleObjects(&handles, false, INFINITE) };

    // WSAEventSelect(s, None, 0) cancels the association and is documented to return the socket to
    // blocking mode. Measured in CI to NOT be reliable: a real run hit WSAEWOULDBLOCK on the next
    // `accept()` without the explicit `set_nonblocking(false)` after it. Both stay: the first
    // cancels the FD_ACCEPT association (leaving it armed was its own source of spurious wakeups),
    // the second is what the socket's blocking mode has actually been observed to need.
    // SAFETY: `sock` is still the listener's own live socket.
    let rc = unsafe { WSAEventSelect(sock, None, 0) };
    assert_eq!(
        rc,
        0,
        "WSAEventSelect(0) to cancel the accept-readiness association: {}",
        std::io::Error::last_os_error()
    );
    listener
        .set_nonblocking(false)
        .expect("restore the control listener to blocking mode");
    // SAFETY: closes only the handles this function opened above.
    unsafe {
        let _ = WSACloseEvent(accept_event);
        for h in &processes {
            let _ = CloseHandle(*h);
        }
    }

    if woken == WAIT_FAILED {
        panic!(
            "WaitForMultipleObjects while waiting for a control connection failed: {}",
            std::io::Error::last_os_error()
        );
    }
    match woken.0.wrapping_sub(WAIT_OBJECT_0.0) as usize {
        i if i < pids.len() => panic!("the control target (pid {}) died before it connected", pids[i]),
        i if i == pids.len() => listener.accept().expect("accept a control connection").0,
        _ => panic!("WaitForMultipleObjects while waiting for a control connection returned {woken:?}"),
    }
}

/// Shared by every platform's `accept_or_die_also`: once an exit notification fires, a
/// non-blocking `accept()` is the actual authority (see there for why).
fn final_peek_or_die(listener: &TcpListener, dead_pid: u32) -> TcpStream {
    listener
        .set_nonblocking(true)
        .expect("set the listener nonblocking for the final accept peek");
    let peek = listener.accept();
    listener
        .set_nonblocking(false)
        .expect("restore the listener to blocking mode after the peek");
    match peek {
        Ok((stream, _)) => {
            // BSD-derived stacks let an accepted socket inherit the listener's non-blocking flag.
            stream
                .set_nonblocking(false)
                .expect("restore the accepted stream to blocking mode");
            stream
        }
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            panic!("the control target (pid {dead_pid}) died before it connected")
        }
        Err(e) => panic!("accept during the final peek before declaring pid {dead_pid} died: {e}"),
    }
}

/// Async sibling of [`accept_or_die`]: [`accept_or_die_async_also`] watching only `child`.
#[cfg(feature = "tokio")]
pub async fn accept_or_die_async(listener: &::tokio::net::TcpListener, child: &mut cosca::tokio::Child) -> TcpStream {
    accept_or_die_async_also(listener, child, None).await
}

/// Async sibling of [`accept_or_die_also`], for the `tokio`-feature helpers: a biased
/// `tokio::select!` between accepting and the SAME exit watches cosca itself implements
/// (`cosca::tokio::Child::wait`, `cosca::tokio::Process::wait`), so there is no per-platform
/// plumbing here.
///
/// The accept arm is first, so a connection tokio already knows about wins. But tokio only learns
/// of readiness from its reactor: a freshly registered listener is NOT ready on its first poll,
/// while `wait()` on an already-exited child completes immediately. So a target that connected and
/// exited can reach the exit arm first with its connection still in the backlog. Whenever an exit
/// arm fires, a final non-blocking accept on a dup of the listener, which bypasses tokio's
/// readiness, is the authority, exactly like [`final_peek_or_die`].
#[cfg(feature = "tokio")]
pub async fn accept_or_die_async_also(
    listener: &::tokio::net::TcpListener,
    child: &mut cosca::tokio::Child,
    also: Option<u32>,
) -> TcpStream {
    let target_pid = child.id().pid();
    let also_exit = async {
        let Some(pid) = also else {
            return std::future::pending().await;
        };
        match cosca::tokio::Process::from_pid(pid) {
            cosca::identity::Resolved::Found(p) => {
                if let Err(e) = p.wait().await {
                    panic!("watching pid {pid}'s exit while waiting for a connection: {e}");
                }
            }
            // Gone: reaped, so dead. See the module doc for why the pid still names it.
            cosca::identity::Resolved::Gone => {}
            cosca::identity::Resolved::Unknown => {
                panic!("the OS refused to identify pid {pid} for the death-watch")
            }
        }
        pid
    };
    let dead_pid = ::tokio::select! {
        biased;
        accepted = listener.accept() => {
            let (stream, _) = accepted.expect("accept a control connection");
            return blocking_std(stream.into_std().expect("convert the accepted tokio stream to std"));
        }
        status = child.wait() => match status {
            Ok(_) => target_pid,
            // An error watching the exit is reported as exactly that, never folded into "died",
            // which would misattribute a wait-mechanism failure to the target.
            Err(e) => panic!("watching the control target's exit while waiting for a connection: {e}"),
        },
        pid = also_exit => pid,
    };
    match try_accept_now(listener) {
        Some(stream) => stream,
        None => panic!("the control target (pid {dead_pid}) exited before it connected"),
    }
}

/// `into_std` does NOT reset blocking mode (it rewraps the same fd/socket, which tokio keeps
/// non-blocking), and every caller does ordinary BLOCKING std reads and writes on the result.
#[cfg(feature = "tokio")]
fn blocking_std(stream: TcpStream) -> TcpStream {
    stream
        .set_nonblocking(false)
        .expect("restore the accepted stream to blocking mode");
    stream
}

/// One non-blocking accept, straight against the socket: tokio's own `accept` would first ask
/// its reactor whether the listener is ready, which is the very thing that can lag.
#[cfg(feature = "tokio")]
fn try_accept_now(listener: &::tokio::net::TcpListener) -> Option<TcpStream> {
    #[cfg(unix)]
    let dup = std::os::fd::AsFd::as_fd(listener).try_clone_to_owned();
    #[cfg(windows)]
    let dup = std::os::windows::io::AsSocket::as_socket(listener).try_clone_to_owned();
    // The dup shares the listener's file description, so it is already non-blocking.
    let std_listener = TcpListener::from(dup.expect("duplicate the listener for the final accept"));
    match std_listener.accept() {
        Ok((stream, _)) => Some(blocking_std(stream)),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => None,
        Err(e) => panic!("accept during the final peek before declaring the target dead: {e}"),
    }
}
