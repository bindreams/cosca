//! macOS backend of the death-watched accept: one `kqueue` carrying an `EVFILT_PROC`/`NOTE_EXIT`
//! watch per pid and an `EVFILT_READ` watch on the source.

use std::os::fd::AsRawFd;

use cosca::identity::{Existence, ProcessId};
use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue};

use super::{notify_armed, Source, WatchEvent};

pub(super) fn wait(source: Source<'_>, target_pid: u32, also: Option<ProcessId>) -> WatchEvent {
    let source_fd = match source {
        Source::Listener(l) => l.as_raw_fd(),
        Source::Stream(s) => s.as_raw_fd(),
    };
    let kq = Kqueue::new().expect("kqueue() for the death-watch");
    let also_pid = also.map(|id| id.pid());
    let mut changes: Vec<KEvent> = std::iter::once(target_pid)
        .chain(also_pid)
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
        source_fd as usize,
        EventFilter::EVFILT_READ,
        EvFlags::EV_ADD | EvFlags::EV_RECEIPT,
        FilterFlag::empty(),
        0,
        0,
    ));
    let mut receipts = vec![changes[0]; changes.len()];
    kq.kevent(&changes, &mut receipts, None)
        .expect("kevent(EV_ADD) to arm the death-watch and the source watch");
    for r in &receipts {
        // EV_RECEIPT makes EV_ADD synchronous and always reports EV_ERROR, with the outcome (0 =
        // armed OK) in `data`: the ONLY way to observe an EV_ADD failure at all.
        assert!(
            r.flags().contains(EvFlags::EV_ERROR),
            "EV_RECEIPT should always report EV_ERROR: {r:?}"
        );
        let errno = r.data() as i32;
        if r.filter() == Ok(EventFilter::EVFILT_PROC) && errno == libc::ESRCH {
            // Gone by the time the watch was armed; EV_ADD on an exited but unreaped child also
            // reports ESRCH.
            return WatchEvent::Died(r.ident() as u32);
        }
        assert_eq!(
            errno,
            0,
            "kevent(EV_ADD) receipt for {:?} reported errno {errno}",
            r.filter()
        );
    }
    // Armed on the pid. Confirm it is the descendant the identity names and not a stranger that
    // was issued the same pid: a stranger is reported as the descendant being gone.
    if let Some(id) = also {
        match id.exists() {
            Existence::Present => {}
            Existence::Gone => return WatchEvent::Died(id.pid()),
            Existence::Unknown => panic!(
                "the OS refused to confirm the identity of pid {} for the death-watch",
                id.pid()
            ),
        }
    }

    notify_armed(target_pid, also);
    let mut events = vec![changes[0]; changes.len()];
    loop {
        // macOS returns EINTR from `kevent` even under SA_RESTART, e.g. for the SIGCHLD handler
        // tokio installs when any test in this process spawns a child.
        let n = match kq.kevent(&[], &mut events, None) {
            Ok(n) => n,
            Err(nix::errno::Errno::EINTR) => {
                panic!("mutant: no EINTR retry");
            }
            Err(e) => panic!("kevent while waiting for a control connection: {e}"),
        };
        for ev in &events[..n] {
            debug_assert!(
                !ev.flags().contains(EvFlags::EV_ERROR),
                "an armed kevent reported EV_ERROR: {ev:?}"
            );
        }
        // An exit among the events returned together wins over a ready source, as on Linux.
        if let Some(ev) = events[..n]
            .iter()
            .find(|ev| ev.filter() == Ok(EventFilter::EVFILT_PROC))
        {
            return WatchEvent::Died(ev.ident() as u32);
        }
        if events[..n].iter().any(|ev| ev.filter() == Ok(EventFilter::EVFILT_READ)) {
            return WatchEvent::Ready;
        }
    }
}
