//! Windows backend of the death-watched accept: `WaitForMultipleObjects` over a `WSAEVENT` armed
//! on the source and one process HANDLE per watched pid.
//!
//! Opening a handle by pid is only sound while the pid still names the process the caller means.
//! For the target that is the caller's contract (see the `accept` module doc): it holds the
//! child's handle, so the number cannot be reissued. For `also`, the handle is confirmed against
//! its `ProcessId` after the open.

use std::os::windows::io::{AsRawSocket, RawSocket};

use cosca::identity::{Existence, ProcessId};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_INVALID_PARAMETER, HANDLE, WAIT_ABANDONED_0, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Networking::WinSock::{
    WSACloseEvent, WSACreateEvent, WSAEventSelect, FD_ACCEPT, FD_CLOSE, FD_READ, SOCKET,
};
use windows::Win32::System::Threading::{OpenProcess, WaitForMultipleObjects, INFINITE, PROCESS_SYNCHRONIZE};

use super::{notify_armed, Source, WatchEvent};

/// Waits for any of `handles`; returns the index of the one that signalled. A failed wait reports
/// the OS error captured immediately, before anything else can overwrite it.
pub fn wait_handles(handles: &[HANDLE]) -> std::io::Result<usize> {
    // SAFETY: the caller passes handles it owns for the duration of the call.
    let woken = unsafe { WaitForMultipleObjects(handles, false, INFINITE) };
    if woken == WAIT_FAILED {
        return Err(std::io::Error::last_os_error());
    }
    let index = woken.0.wrapping_sub(WAIT_OBJECT_0.0) as usize;
    assert!(
        woken != WAIT_TIMEOUT && woken.0 < WAIT_ABANDONED_0.0 && index < handles.len(),
        "WaitForMultipleObjects returned {woken:?} for {} handles",
        handles.len()
    );
    Ok(index)
}

fn close_all(handles: &[HANDLE]) {
    for h in handles {
        // SAFETY: closes only handles this backend opened.
        let _ = unsafe { CloseHandle(*h) };
    }
}

pub(super) fn wait(source: Source<'_>, target_pid: u32, also: Option<ProcessId>) -> WatchEvent {
    let (raw, mask): (RawSocket, u32) = match source {
        Source::Listener(l) => (l.as_raw_socket(), FD_ACCEPT),
        Source::Stream(s) => (s.as_raw_socket(), FD_READ | FD_CLOSE),
    };
    let pids: Vec<u32> = std::iter::once(target_pid).chain(also.map(|id| id.pid())).collect();
    let mut processes: Vec<HANDLE> = Vec::new();
    for &pid in &pids {
        // SAFETY: opens the process by pid with only SYNCHRONIZE, enough to wait for its exit.
        match unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) } {
            Ok(h) => processes.push(h),
            // No such process: gone, which is the same disposition as on Linux and macOS.
            Err(e) if e.code() == ERROR_INVALID_PARAMETER.to_hresult() => {
                close_all(&processes);
                return WatchEvent::Died(pid);
            }
            Err(e) => {
                close_all(&processes);
                panic!("OpenProcess({pid}, SYNCHRONIZE) for the death-watch: {e}");
            }
        }
    }
    // Opened by pid, so confirm the descendant's handle is the process its identity names.
    if let Some(id) = also {
        match id.exists() {
            Existence::Present => {}
            Existence::Gone => {
                close_all(&processes);
                return WatchEvent::Died(id.pid());
            }
            Existence::Unknown => {
                close_all(&processes);
                panic!(
                    "the OS refused to confirm the identity of pid {} for the death-watch",
                    id.pid()
                );
            }
        }
    }

    // SAFETY: creates an unnamed, unowned manual-reset event; closed explicitly below.
    let event = unsafe { WSACreateEvent() }.expect("WSACreateEvent for the source's readiness watch");
    let sock = SOCKET(raw as usize);
    // SAFETY: `sock` is the source's own live socket; `event` was just created above.
    let rc = unsafe { WSAEventSelect(sock, Some(event), mask as i32) };
    assert_eq!(
        rc,
        0,
        "WSAEventSelect on the watched socket: {}",
        std::io::Error::last_os_error()
    );
    notify_armed();

    // Process handles come BEFORE the event: the lowest signalled index wins, so an exit beats a
    // ready source.
    let mut handles = processes.clone();
    handles.push(HANDLE(event.0 as *mut _));
    let woken = wait_handles(&handles);

    // Cancel the association, then restore blocking mode explicitly: cancelling alone does not
    // reliably leave the socket blocking.
    // SAFETY: `sock` is still the source's own live socket.
    let rc = unsafe { WSAEventSelect(sock, None, 0) };
    assert_eq!(
        rc,
        0,
        "WSAEventSelect(0) to cancel the readiness association: {}",
        std::io::Error::last_os_error()
    );
    match source {
        Source::Listener(l) => l.set_nonblocking(false),
        Source::Stream(s) => s.set_nonblocking(false),
    }
    .expect("restore the watched socket to blocking mode");
    // SAFETY: the event was created above and is no longer in use.
    let _ = unsafe { WSACloseEvent(event) };
    close_all(&processes);

    let index = woken.unwrap_or_else(|e| panic!("WaitForMultipleObjects while waiting for a control connection: {e}"));
    match pids.get(index) {
        Some(&pid) => WatchEvent::Died(pid),
        None => WatchEvent::Ready,
    }
}
