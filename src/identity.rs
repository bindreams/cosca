//! Stable-across-time process identity.
//!
//! A bare PID is unsafe: the OS recycles PIDs, so the same number can name a
//! different process minutes later. [`ProcessId`] pairs the PID with a raw
//! kernel *key* — a per-process value fixed at creation — so equality
//! distinguishes "the same process" from "a reused PID".
//!
//! The key is the RAW kernel value (Windows creation `FILETIME`, macOS `sysctl KERN_PROC`
//! (`kinfo_proc`) start µs, Linux the inode of the process's pidfd on pidfs, 6.9+, else the `/proc`
//! `starttime` jiffies), compared exactly. A Linux id holds one of the two kinds, and ids of
//! different kinds never compare equal. It is deliberately NOT a wall-clock time: deriving
//! wall-clock from boot time drifts under NTP and would silently break
//! `Eq`/`Hash`. The human-facing wall-clock lives in `created_at()`,
//! allowed to drift and never used for identity. Only on Windows is anything ordered (the tree
//! walk's PID-reuse guard): not by the key but by an `OrderKey`, the process sequence number.
//!
//! The key is not portable across a reboot on every platform — see [`ProcessIdRecord`]
//! for the persist/restore round trip and what it refuses.

pub(crate) mod probe;
pub(crate) mod stat_parse;

#[path = "identity/state.rs"]
mod state;
pub use state::{Existence, Liveness, Resolved};

#[path = "identity/persist.rs"]
mod persist;
pub use persist::{Platform, ProcessIdRecord, TokenKind, RECORD_VERSION};

#[path = "identity/tree.rs"]
mod tree;
pub use tree::Recursive;

#[cfg_attr(windows, path = "identity/windows.rs")]
#[cfg_attr(target_os = "linux", path = "identity/linux.rs")]
#[cfg_attr(target_os = "macos", path = "identity/macos.rs")]
mod backend;

#[cfg(all(windows, test))]
#[path = "identity/windows_fixture.rs"]
pub(crate) mod windows_fixture;

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
compile_error!("cosca::identity is implemented only for Windows, Linux, and macOS");

use crate::error::Error;

/// A process identifier as the OS knows it (matches `std::process::id`).
pub type RawPid = u32;

/// What makes a [`ProcessId`] one process and not a later holder of its pid: a raw, per-process
/// kernel value, opaque, compared exactly. Interpreted into a wall-clock time only by
/// `created_at`. Linux has two kinds, [`backend::Key`]; Windows and macOS one.
#[cfg(not(target_os = "linux"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Key(u64);

#[cfg(not(target_os = "linux"))]
impl Key {
    pub(crate) fn from_raw(v: u64) -> Key {
        Key(v)
    }

    fn raw(self) -> u64 {
        self.0
    }

    /// A key restored from a record's `token`. The kind is ignored: only Linux keys have one, and
    /// the record's platform has been checked first.
    fn restored(token: u64, _kind: Option<&TokenKind>) -> Key {
        Key(token)
    }

    /// The kind a record names for this key: none, off Linux.
    fn wire_kind(self) -> Option<TokenKind> {
        None
    }

    /// This backend's default kind, for tests that run on every platform.
    #[cfg(test)]
    pub(crate) fn for_test(v: u64) -> Key {
        Key(v)
    }

    /// The same kind with another value.
    #[cfg(test)]
    fn other_value(self) -> Key {
        Key(self.0.wrapping_add(1))
    }
}

#[cfg(target_os = "linux")]
pub(crate) use backend::Key;

/// Where a process falls in the order of process creation: comparable only with keys read on this
/// host this boot. The tree walk's PID-reuse guard orders by it where [`ORDER_AFTER_PARENT`], and
/// only Windows reads one: the `ProcessSequenceNumber`, a creation counter, so no two processes share
/// a key and a process always follows its creator. Not the identity.
///
/// Built only inside `identity`, by the Windows read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct OrderKey(u64);

impl OrderKey {
    #[cfg(test)]
    pub(crate) fn for_test(v: u64) -> OrderKey {
        OrderKey(v)
    }
}

/// Whether a process's order after its parent is what proves the parent, where elsewhere its own
/// `ppid`, read after the parent, is. True only on Windows, where the parent field is the creator
/// and never updated: a `ppid` can name a pid a later process holds now, and a second read of the
/// process shows nothing new. A process must then order strictly after its parent ([`keeps_order`]),
/// the backend reads an [`OrderKey`] only there, and [`ProcessId::parent`] does not read its process
/// again. False elsewhere: reparenting updates `ppid`, so the read under the
/// parent is the proof, and an order rule would drop a child whose in-tree tracer started after it
/// (XNU's `PT_ATTACH` makes the tracer the parent).
#[cfg(windows)]
pub(crate) const ORDER_AFTER_PARENT: bool = true;
#[cfg(not(windows))]
pub(crate) const ORDER_AFTER_PARENT: bool = false;

/// The PID-reuse keep-predicate where [`ORDER_AFTER_PARENT`] (the crate's core safety invariant, see
/// the tree walk's module docs): a process descends from `bound`'s owner only if its order key is
/// strictly after it. Keys are unique there, so the strict rule loses no genuine child. Callers go
/// through [`keeps`].
fn keeps_order(key: OrderKey, bound: OrderKey) -> bool {
    key > bound
}

/// The one keep rule, for [`ProcessId::of_ordered_with`]'s order bound and [`ProcessId::parent`]:
/// [`keeps_order`] over the optional keys of a read and of its bound: with no `bound` nothing
/// applies and the read is kept; under one, a read with no order key is not.
pub(crate) fn keeps(order: Option<OrderKey>, bound: Option<OrderKey>) -> bool {
    bound.is_none_or(|bound| order.is_some_and(|order| keeps_order(order, bound)))
}

/// The candidate's own parent number, as one ordered read found it: in the record or on the handle
/// that gave the candidate's id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParentRead {
    /// The read was not asked for the parent number.
    NotAsked,
    /// The parent number the read found.
    Is(RawPid),
    /// The read asked and could not find it.
    Unreadable,
}

impl ParentRead {
    /// What a read that found no process says of the parent number: it could not read it if it
    /// `asked`, else it was not asked.
    fn not_read(asked: bool) -> ParentRead {
        if asked {
            ParentRead::Unreadable
        } else {
            ParentRead::NotAsked
        }
    }
}

/// What a backend's one read of a process says: its key and its order key, which is `Some` exactly
/// where [`ORDER_AFTER_PARENT`], and the parent number found by the same read.
struct OrderedRead {
    read: Resolved<(Key, Option<OrderKey>)>,
    parent: ParentRead,
    cause: UnknownCause,
}

/// What an ordered read of a pid says: the identity and the order key it bounds its children by
/// (`Some` only where [`ORDER_AFTER_PARENT`]), or why there is none.
type Ordered = (Resolved<(ProcessId, Option<OrderKey>)>, UnknownCause);

/// What a read of a candidate under its parent says: `Ok(None)` for one that is gone (or no longer
/// its parent's child, or not ordered after the bound), `Err` for one that could not be read.
pub(crate) type Resolution = Result<Option<(ProcessId, Option<OrderKey>)>, Error>;

/// What `read`, the answer of an ordered read of `pid`, says: `Unknown` is the error of
/// [`unqueryable_read`], `label` (`pid` or `ppid`) naming the subject. The one mapping of the
/// shared read, for the tree walk and for [`ProcessId::parent`].
pub(crate) fn resolution_of<T>(
    label: &str,
    pid: RawPid,
    read: (Resolved<T>, UnknownCause),
) -> Result<Option<T>, Error> {
    match read {
        (Resolved::Found(read), _) => Ok(Some(read)),
        (Resolved::Gone, _) => Ok(None),
        (Resolved::Unknown, cause) => Err(unqueryable_read(label, pid, cause)),
    }
}

/// The error for a `subject` (`pid N` / `ppid N`) that exists but read `Unknown`: the `/proc`
/// view when that is why, else access.
pub(crate) fn unqueryable(subject: &str, cause: UnknownCause) -> Error {
    cause.into_error(subject).unwrap_or_else(|| Error::Unassessable {
        detail: format!("{subject} exists but could not be queried (access denied?)"),
        source: None,
    })
}

/// [`unqueryable`] for the ordered read of `pid` that left `Unknown` with `cause`: the subject is
/// `label pid`, or the parent whose proof failed when `cause` blames it, in which case a note says
/// which read was left unanswered: `pid`'s. This is the one place that words it.
pub(crate) fn unqueryable_read(label: &str, pid: RawPid, cause: UnknownCause) -> Error {
    match cause.blamed_parent() {
        Some(parent) => unqueryable(&format!("ppid {parent}"), cause).with_note(&format!("reading pid {pid}")),
        None => unqueryable(&format!("{label} {pid}"), cause),
    }
}

/// What [`OrderedRead::judged`] makes of a read before the parent is proved again.
enum Judged {
    /// The answer, whatever the proof of the parent says.
    Settled(Ordered),
    /// The read did not prove another parent: this is the answer if the parent is still held. A
    /// parent that is gone makes it `Gone`, and one that cannot be proved `Unknown` blaming the
    /// parent.
    IfParentHolds(Ordered),
}

impl Judged {
    /// The answer, given `proof` that the named parent still holds its pid: `Ok(())` if it does,
    /// else the answer the failed proof gives. A [`Judged::Settled`] answer never asks for it.
    fn proved(self, proof: impl FnOnce() -> Result<(), Ordered>) -> Ordered {
        match self {
            Judged::Settled(answer) => answer,
            Judged::IfParentHolds(answer) => match proof() {
                Ok(()) => answer,
                Err(verdict) => verdict,
            },
        }
    }
}

impl OrderedRead {
    /// A read that found no process: `read` is `Gone` or `Unknown` (it has no found value). There is
    /// no record to take a parent number from, so a read that `asked_parent` is told it could not
    /// read it ([`ParentRead::Unreadable`]), and one that did not ask says so.
    #[cfg(not(windows))]
    fn missing(read: Resolved<std::convert::Infallible>, cause: UnknownCause, asked_parent: bool) -> OrderedRead {
        OrderedRead {
            read: read.map(|never| match never {}),
            parent: ParentRead::not_read(asked_parent),
            cause,
        }
    }

    /// The read, as the answer about the process `expected` names (`None`: any): a key that is
    /// another's is `Gone`, with the parent number it found left for [`judged`](Self::judged).
    #[cfg(not(windows))]
    fn against(self, expected: Option<Key>) -> OrderedRead {
        match (&self.read, expected) {
            (Resolved::Found((key, _)), Some(expected)) if *key != expected => OrderedRead {
                read: Resolved::Gone,
                parent: self.parent,
                cause: UnknownCause::default(),
            },
            _ => self,
        }
    }

    /// The read with no parent named: the id and order key of `pid`.
    fn unclaimed(self, pid: RawPid) -> Ordered {
        (
            self.read.map(|(key, order)| (ProcessId { pid, key }, order)),
            self.cause,
        )
    }

    /// The read for `pid`, whose caller was told `parent` created it. A key not after `bound` (given
    /// only where [`ORDER_AFTER_PARENT`]), a found read with no order key under a bound, another
    /// parent's number, or a `Gone` read settles the answer; every other read waits on the proof of
    /// `parent` ([`Judged`]). The bound is checked first, so a candidate that cannot be the
    /// parent's child never asks for a proof that might fail.
    fn judged(self, pid: RawPid, parent: RawPid, bound: Option<OrderKey>) -> Judged {
        let OrderedRead {
            read,
            parent: claimed,
            cause,
        } = self;
        debug_assert!(
            claimed != ParentRead::NotAsked,
            "a parent was named, so its number must be asked for"
        );
        debug_assert!(
            bound.is_none() || ORDER_AFTER_PARENT,
            "a bound is handed out only where ORDER_AFTER_PARENT"
        );
        match (claimed, read) {
            (_, Resolved::Found((_, order))) if !keeps(order, bound) => {
                Judged::Settled((Resolved::Gone, UnknownCause::default()))
            }
            (ParentRead::Is(found), _) if found != parent => Judged::Settled((Resolved::Gone, UnknownCause::default())),
            (_, Resolved::Gone) => Judged::Settled((Resolved::Gone, cause)),
            (ParentRead::Is(_), Resolved::Found((key, order))) => {
                Judged::IfParentHolds((Resolved::Found((ProcessId { pid, key }, order)), cause))
            }
            // The candidate's own failure, which a held parent lets stand.
            (_, Resolved::Found(_) | Resolved::Unknown) => Judged::IfParentHolds((Resolved::Unknown, cause)),
        }
    }
}

/// The backend's one read of `pid`, asking for its parent number when `ask_parent`. `expected`: see
/// [`ProcessId::of_ordered_with`].
fn read_ordered(kernel: &dyn Kernel, pid: RawPid, expected: Option<Key>, ask_parent: bool) -> OrderedRead {
    #[cfg(all(test, target_os = "macos"))]
    seams::note_by_pid_read();
    #[cfg(target_os = "linux")]
    let read = backend::ordered_read(kernel, pid, expected, ask_parent);
    #[cfg(not(target_os = "linux"))]
    let read = {
        let _ = kernel;
        backend::ordered_read(pid, expected, ask_parent)
    };
    debug_assert!(
        match &read.read {
            Resolved::Found((_, order)) => order.is_some() == ORDER_AFTER_PARENT,
            _ => true,
        },
        "a backend reads an order key exactly where ORDER_AFTER_PARENT"
    );
    read
}

/// A process identity that stays unique across time: `(pid, key)`.
/// `Eq`/`Hash` are over the pair, so a recycled PID never compares equal to the
/// original process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessId {
    pid: RawPid,
    key: Key,
}

impl ProcessId {
    /// The raw OS process id. NOTE: a bare PID is not unique across time — use
    /// the whole `ProcessId` for identity, comparison, and map keys.
    pub fn pid(&self) -> RawPid {
        self.pid
    }

    /// The key, for tests that compare it with a stated one. Production code orders by
    /// [`OrderKey`] and never reads the key.
    #[cfg(test)]
    pub(crate) fn key(&self) -> Key {
        self.key
    }

    /// The same pid with another value of this id's own kind of key: what a later holder of the
    /// pid would have.
    #[cfg(test)]
    pub(crate) fn with_other_value(&self) -> ProcessId {
        ProcessId {
            pid: self.pid,
            key: self.key.other_value(),
        }
    }

    /// Resolve the live identity of `pid`. [`Resolved::Gone`] means the OS reports no such
    /// process; [`Resolved::Unknown`] means it refused the question (typically an
    /// unprivileged caller querying a service) — the process may well be running.
    pub fn of(pid: RawPid) -> Resolved<ProcessId> {
        Self::of_explained(pid).0
    }

    /// [`of`](Self::of), and why it was [`Resolved::Unknown`] when the read itself knows.
    pub(crate) fn of_explained(pid: RawPid) -> (Resolved<ProcessId>, UnknownCause) {
        Self::of_with(&HostKernel, pid)
    }

    /// [`of_explained`](Self::of_explained) through `kernel`: the one entry to a by-pid identity
    /// read, on every platform.
    pub(crate) fn of_with(kernel: &dyn Kernel, pid: RawPid) -> (Resolved<ProcessId>, UnknownCause) {
        #[cfg(all(test, target_os = "macos"))]
        seams::note_by_pid_read();
        #[cfg(target_os = "linux")]
        {
            let (read, cause) = backend::of(kernel, pid);
            (read.map(|key| ProcessId { pid, key }), cause)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = kernel;
            let (read, cause) = start_token_explained(pid);
            (read.map(|key| ProcessId { pid, key }), cause)
        }
    }

    /// `Err(Gone)` if another process now holds `self`'s pid, `Err(Unknown)` (blaming the parent) if
    /// that cannot be proved.
    fn still_held<T>(&self, kernel: &dyn Kernel) -> Result<(), (Resolved<T>, UnknownCause)> {
        match self.exists_with(kernel) {
            (Existence::Present, _) => Ok(()),
            (Existence::Gone, _) => Err((Resolved::Gone, UnknownCause::default())),
            (Existence::Unknown, cause) => Err((Resolved::Unknown, cause.of_parent(self.pid))),
        }
    }

    /// [`of_with`](Self::of_with), with the order key of the same read beside the id: the one entry
    /// that reads a pid under a parent, for the tree walk's candidates and for
    /// [`parent`](Self::parent)'s second read of its own process.
    ///
    /// `expected`: the key of the process the caller means, when it has one. A pid whose key is read
    /// and is another's is [`Resolved::Gone`], whatever else its read says; one whose key cannot be
    /// read is [`Resolved::Unknown`], as its holder may be the process meant.
    ///
    /// `parent`: the process the caller was told is this one's parent. Each backend's read carries
    /// the process's parent number from the record or handle that gives the id, and a process with
    /// another parent number now is [`Resolved::Gone`] whatever else the read said: the pid has
    /// changed hands, or the process was reparented. A number that is read does not yet name the
    /// parent, which may have been reaped and its number taken, so `parent` is then proved again: a
    /// number that no longer holds it is [`Resolved::Gone`] too, and one whose proof cannot be made
    /// is [`Resolved::Unknown`], blaming the parent. The candidate's own failure is blamed on it only
    /// while the parent is held ([`Judged`]).
    ///
    /// `order_bound`, only with a `parent` and only where [`ORDER_AFTER_PARENT`]: the order key the
    /// read must follow ([`keeps_order`]). A read that does not is [`Resolved::Gone`], settled
    /// before the parent is proved, so a proof that would fail never turns a process that cannot be
    /// the child into an error. The order key in the answer is the one the caller bounds the
    /// process's own children by: `None` elsewhere.
    pub(crate) fn of_ordered_with(
        kernel: &dyn Kernel,
        pid: RawPid,
        parent: Option<ProcessId>,
        expected: Option<Key>,
        order_bound: Option<OrderKey>,
    ) -> Ordered {
        debug_assert!(
            parent.is_some() || order_bound.is_none(),
            "an order bound is for a read under a named parent"
        );
        let read = read_ordered(kernel, pid, expected, parent.is_some());
        let Some(parent) = parent else {
            return read.unclaimed(pid);
        };
        read.judged(pid, parent.pid(), order_bound)
            .proved(|| parent.still_held(kernel))
    }

    /// The parent number and the order key (`Some` only where [`ORDER_AFTER_PARENT`]) of `self`'s own read, for
    /// [`parent`](Self::parent)'s first read, which names no parent yet and needs the number, which
    /// [`Ordered`] does not carry. The number is only a number: the parent it names may be another
    /// process by now, and where [`ORDER_AFTER_PARENT`] the caller reads that process and orders it
    /// against the key. `expected` is `self`'s key, as for [`of_ordered_with`](Self::of_ordered_with);
    /// [`Resolved::Unknown`] also when the read, or the number in it, cannot be had.
    pub(crate) fn parent_number_and_order_with(
        &self,
        kernel: &dyn Kernel,
    ) -> (Resolved<(RawPid, Option<OrderKey>)>, UnknownCause) {
        let OrderedRead { read, parent, cause } = read_ordered(kernel, self.pid, Some(self.key), true);
        debug_assert!(parent != ParentRead::NotAsked, "the parent number was asked for");
        match (read, parent) {
            (Resolved::Gone, _) => (Resolved::Gone, cause),
            (Resolved::Found((_, order)), ParentRead::Is(number)) => (Resolved::Found((number, order)), cause),
            // The read failed, or it found no parent number in the record or on the handle.
            _ => (Resolved::Unknown, cause),
        }
    }

    /// Where this process falls in the order of process creation (see [`OrderKey`]), for the
    /// anchor's bound on Windows ([`ORDER_AFTER_PARENT`]). [`Resolved::Gone`] and
    /// [`Resolved::Unknown`] mean no key could be read, and a pid that another process holds now is
    /// `Gone`; the [`UnknownCause`] says why when the read itself knows, as for
    /// [`of_with`](Self::of_with).
    #[cfg(windows)]
    pub(crate) fn order_key(&self) -> (Resolved<OrderKey>, UnknownCause) {
        backend::order_key(self.pid, self.key)
    }

    /// The proof that this process still holds its pid, for the anchor of a walk: [`Resolved::Found`]
    /// only if it did at the read, with the bound its children must follow (`Some` only where
    /// [`ORDER_AFTER_PARENT`]).
    /// On Windows the order key read is that proof, so the proof and the bound are one read: two
    /// could find a process that exits between them gone, and its children, which Windows does not
    /// reparent, unwalked. Elsewhere [`exists_with`](Self::exists_with) is the proof and there is no
    /// bound. A process gone there is `Gone`, and its children, reparented at its exit, no longer
    /// descend from it.
    pub(crate) fn anchor_bound_with(&self, kernel: &dyn Kernel) -> (Resolved<Option<OrderKey>>, UnknownCause) {
        #[cfg(windows)]
        {
            let _ = kernel;
            let (read, cause) = self.order_key();
            (read.map(Some), cause)
        }
        #[cfg(not(windows))]
        {
            match self.exists_with(kernel) {
                (Existence::Present, _) => (Resolved::Found(None), UnknownCause::default()),
                (Existence::Gone, cause) => (Resolved::Gone, cause),
                (Existence::Unknown, cause) => (Resolved::Unknown, cause),
            }
        }
    }

    /// Build a `ProcessId` from an already-known `(pid, start time)` pair, without a live read.
    /// The macOS group listing reads a member's start time in the very sysctl record it reads the
    /// pid from, and a second, separate read to re-derive it would itself race against the
    /// pid-reuse hazard this type exists to catch.
    #[cfg(target_os = "macos")]
    pub(crate) fn from_parts(pid: RawPid, token: u64) -> ProcessId {
        ProcessId {
            pid,
            key: Key::from_raw(token),
        }
    }

    /// A test identity with a stated key.
    #[cfg(test)]
    pub(crate) fn from_parts_for_test(pid: RawPid, key: Key) -> ProcessId {
        ProcessId { pid, key }
    }

    /// This process's own identity. Windows reads the current-process pseudo-handle, which
    /// performs no access check at all; macOS reads the caller's own entry by pid, and Linux the
    /// inode of the process's own pidfd (6.9+), or `/proc/self/stat` before it (no `openat2`, no
    /// `/proc` view needed), which no `hidepid` mount or sandbox policy hides from the task itself.
    /// Either way it is resolvable even for a process whose own DACL would deny a foreign by-pid
    /// open.
    ///
    /// # Panics
    /// If the process cannot read its own key: on Linux, if `pidfd_open` of itself fails (a
    /// refusal included) or, before 6.9, if `/proc/self/stat` cannot be read or has no parseable
    /// `starttime` (hard requirements of that backend); on Windows and macOS, if a self-directed
    /// `GetProcessTimes` / `proc_pidinfo` fails, which has no documented cause. Infallible by
    /// design — every caller, including `Process::current()`, relies on it (which returns the
    /// failure as an error on Linux instead).
    pub fn current() -> ProcessId {
        #[cfg(target_os = "linux")]
        {
            Self::try_current().expect(
                "a process must be able to read its own identity (Linux: pidfd_open of itself, and \
                 /proc/self/stat below 6.9, must work)",
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            let key = backend::current_token()
                .found()
                .expect("a process must be able to read its own identity");
            ProcessId {
                pid: std::process::id(),
                key,
            }
        }
    }

    /// [`current`](Self::current), with the error it would panic on. On Linux that is a
    /// `pidfd_open` of the process itself that fails, as an open of it would: `Unsupported` when
    /// refused. Elsewhere nothing fails.
    pub(crate) fn try_current() -> Result<ProcessId, crate::error::Error> {
        #[cfg(target_os = "linux")]
        {
            backend::current_key(&HostKernel).map(|key| ProcessId {
                pid: std::process::id(),
                key,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(Self::current())
        }
    }

    /// Whether a process with this exact identity is still *resolvable* (the
    /// zombie-inclusive sense, matching psutil's `is_running`). [`Existence::Present`] for a
    /// not-yet-reaped zombie on every platform: Linux (`/proc` persists), macOS (`sysctl
    /// KERN_PROC` resolves zombies), and Windows (during the post-exit handle window).
    /// [`Existence::Unknown`] when the OS refuses the query — never `Gone`. For "is it still
    /// running?", use [`ProcessId::is_alive`].
    pub fn exists(&self) -> Existence {
        self.exists_with(&HostKernel).0
    }

    /// [`exists`](Self::exists) through `kernel`, and why it was [`Existence::Unknown`] when the
    /// read itself knows; see [`of_with`](Self::of_with).
    pub(crate) fn exists_with(&self, kernel: &dyn Kernel) -> (Existence, UnknownCause) {
        #[cfg(target_os = "linux")]
        {
            backend::exists(kernel, self.pid, self.key)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = kernel;
            let (read, cause) = start_token_explained(self.pid);
            (self.existence_from(read), cause)
        }
    }

    /// What `read`, the key now at this pid, says about this process.
    #[cfg(not(target_os = "linux"))]
    fn existence_from(&self, read: Resolved<Key>) -> Existence {
        match read {
            Resolved::Found(t) if t == self.key => Existence::Present,
            Resolved::Found(_) | Resolved::Gone => Existence::Gone,
            Resolved::Unknown => Existence::Unknown,
        }
    }

    /// Whether the process is currently *running* (has not exited). Answers out of the OS's own
    /// exit bookkeeping — on Windows the handle's signaled state, on macOS process state, on Linux
    /// the process's pidfd (6.9+: a live process whose leader thread exited is alive, though
    /// `/proc` shows `Z`) or, before 6.9, its `/proc` state. A reused PID (different key) is never
    /// alive.
    /// [`Liveness::Unknown`] when the OS refuses the query, or answers ambiguously — never
    /// `Dead` on a process we could not assess.
    ///
    /// **On macOS the exit *edge* precedes that bookkeeping.** A death-watch
    /// ([`Process::wait`](crate::Process::wait)) returning, and a pipe or socket EOF on the dying
    /// process's own descriptors, both fire while the kernel is still tearing the process down —
    /// before it is marked a zombie, which is the state this reads. So `Alive` is briefly
    /// reachable for a process that has already exited; Linux and Windows signal only after their
    /// equivalent transition. Confirm a process is finished by reaping it, or by
    /// `waitid(WEXITED | WNOWAIT)` — never by asking this after an exit event.
    pub fn is_alive(&self) -> Liveness {
        self.is_alive_with(&HostKernel)
    }

    /// [`is_alive`](Self::is_alive) through `kernel`; see [`of_with`](Self::of_with).
    pub(crate) fn is_alive_with(&self, kernel: &dyn Kernel) -> Liveness {
        #[cfg(target_os = "linux")]
        {
            backend::is_running(kernel, self.pid, self.key)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = kernel;
            backend::is_running(self.pid, self.key)
        }
    }

    /// Best-effort wall-clock creation time. Lazy and allowed to drift (NTP);
    /// NEVER used for identity. `None` if the process is gone or unavailable. On Linux 6.9+ the
    /// time is read from `/proc` when asked, so a reaped process has none.
    pub fn created_at(&self) -> Option<std::time::SystemTime> {
        self.created_at_with(&HostKernel)
    }

    /// [`created_at`](Self::created_at) through `kernel`: on Linux a `pidfs` id reads the start
    /// time from `/proc`.
    pub(crate) fn created_at_with(&self, kernel: &dyn Kernel) -> Option<std::time::SystemTime> {
        #[cfg(target_os = "linux")]
        {
            backend::created_at(kernel, self.pid, self.key)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = kernel;
            backend::created_at(self.key)
        }
    }
}

#[cfg(windows)]
pub(crate) use backend::{
    close as windows_close, exit_look as windows_exit_look, granted_access as windows_granted_access,
    open_classified as windows_open_classified, open_dropping_refused as windows_open_dropping_refused,
    terminate_held as windows_terminate_held, Look, Opened, Termination,
};

#[cfg(all(windows, test))]
pub(crate) use backend::fault as windows_fault;
#[cfg(all(windows, test))]
pub(crate) use backend::TERMINATE_EXIT_CODE as WINDOWS_TERMINATE_EXIT_CODE;

#[cfg(target_os = "linux")]
pub(crate) use backend::pid_stat;

#[cfg(target_os = "linux")]
pub(crate) use backend::kernel::{HostKernel, Kernel};

#[cfg(target_os = "linux")]
pub(crate) use backend::prove::{prove, Proof};

#[cfg(all(target_os = "linux", test))]
pub(crate) use backend::kernel::PIDFD_THREAD;

#[cfg(not(target_os = "linux"))]
pub(crate) use no_reads::{HostKernel, Kernel};

/// The [`Kernel`] of the platforms whose reads no test answers yet.
#[cfg(not(target_os = "linux"))]
mod no_reads {
    /// What cosca asks the kernel about processes, so shared code takes one `&dyn Kernel` on every
    /// platform. No methods yet: one enters with its first caller in the macOS or Windows backend.
    pub(crate) trait Kernel: Sync {}

    /// The real kernel.
    pub(crate) struct HostKernel;

    impl Kernel for HostKernel {}
}

#[cfg(all(target_os = "linux", test))]
pub(crate) use backend::kernel::fake::FakeKernel;

#[cfg(all(target_os = "linux", test))]
pub(crate) use backend::proc_view::UNREADABLE_STATUS_REASON;

#[cfg(target_os = "linux")]
pub(crate) use backend::proc_view::{
    pidfd_pid_in, proc_view_with, utf8, PidfdTarget, ProcDir, ProcView, ViewUnreadable, DIVERGED_REASON,
};

/// Why a by-pid read answered `Unknown`, when the read itself knows: on Linux, the unusable
/// `/proc` view it went through or the failed pidfd call. Carried out of the failing read, so the
/// error describes that read and not a second look at a view that may have recovered.
#[derive(Debug, Default)]
pub(crate) struct UnknownCause {
    #[cfg(target_os = "linux")]
    view: Option<ViewUnreadable>,
    /// The failed `pidfd_open`, `fstatfs` or `fstat` that left the read `Unknown`.
    #[cfg(target_os = "linux")]
    errno: Option<rustix::io::Errno>,
    /// The parent whose proof left an ordered read `Unknown`, when that and not the read's own pid
    /// is why.
    parent: Option<RawPid>,
    /// The `NTSTATUS` of the refused process-sequence-number query that left the read `Unknown`.
    #[cfg(windows)]
    sequence_status: Option<windows::Win32::Foundation::NTSTATUS>,
    /// The `NTSTATUS` of the refused creator-pid query that left the read `Unknown`.
    #[cfg(windows)]
    creator_status: Option<windows::Win32::Foundation::NTSTATUS>,
}

impl UnknownCause {
    /// The pid an `Unknown` ordered read blames when it is not the pid read: the parent whose proof
    /// failed. `None` when the read's own pid is the subject.
    pub(crate) fn blamed_parent(&self) -> Option<RawPid> {
        self.parent
    }

    /// This cause, for a read that failed on proving `parent`.
    fn of_parent(mut self, parent: RawPid) -> UnknownCause {
        self.parent = Some(parent);
        self
    }

    /// This cause, for a read whose creator-pid query was refused with `status`.
    #[cfg(windows)]
    pub(crate) fn with_creator_status(mut self, status: windows::Win32::Foundation::NTSTATUS) -> UnknownCause {
        self.creator_status = Some(status);
        self
    }

    /// The cause of a read that a refused process-sequence-number query (`status`) left `Unknown`.
    #[cfg(windows)]
    pub(crate) fn of_sequence_status(status: windows::Win32::Foundation::NTSTATUS) -> UnknownCause {
        UnknownCause {
            sequence_status: Some(status),
            ..UnknownCause::default()
        }
    }

    /// The failed pidfd call, when one is why.
    #[cfg(target_os = "linux")]
    pub(crate) fn errno(&self) -> Option<rustix::io::Errno> {
        self.errno
    }

    /// The cause of a read through `/proc` that `view`, when it is `Some`, left `Unknown`.
    #[cfg(target_os = "linux")]
    pub(crate) fn of_view(view: Option<ViewUnreadable>) -> UnknownCause {
        UnknownCause {
            view,
            errno: None,
            parent: None,
        }
    }

    /// The cause of a read that a failed pidfd call (`errno`) left `Unknown`.
    #[cfg(target_os = "linux")]
    pub(crate) fn of_errno(errno: rustix::io::Errno) -> UnknownCause {
        UnknownCause {
            view: None,
            errno: Some(errno),
            parent: None,
        }
    }

    /// The error for `subject`'s `Unknown` read when the read knows why: `Error::Unsupported` naming
    /// the `openat2` requirement or a refused `pidfd_open`, or `Error::Unassessable` with the view's
    /// reason or the errno that failed; on Windows, `Error::Unassessable` naming the refused
    /// sequence-number query's `NTSTATUS`, else the refused creator-pid query's. `None` when nothing
    /// is known (or on macOS, which has no view and no pidfd): `hidepid`, a racing exit, an access
    /// denial.
    pub(crate) fn into_error(self, subject: &str) -> Option<crate::error::Error> {
        #[cfg(target_os = "linux")]
        {
            match (self.view, self.errno) {
                (Some(why), _) => Some(backend::view_error(subject, why)),
                (None, Some(errno)) => Some(backend::errno_error(subject, errno)),
                (None, None) => None,
            }
        }
        #[cfg(windows)]
        {
            let refused = self
                .sequence_status
                .map(|status| ("process sequence number", status))
                .or(self.creator_status.map(|status| ("creator process id", status)));
            refused.map(|(query, status)| crate::error::Error::Unassessable {
                detail: format!(
                    "{subject} exists but its {query} query failed: NTSTATUS {:#010x}",
                    status.0 as u32
                ),
                source: None,
            })
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            let _ = (self, subject);
            None
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn start_token_explained(pid: RawPid) -> (Resolved<Key>, UnknownCause) {
    (backend::start_token(pid), UnknownCause::default())
}

/// macOS test seams.
#[cfg(all(target_os = "macos", test))]
pub(crate) mod seams {
    use std::cell::Cell;

    thread_local! {
        static BY_PID_READS: Cell<usize> = const { Cell::new(0) };
    }

    pub(super) fn note_by_pid_read() {
        BY_PID_READS.with(|n| n.set(n.get() + 1));
    }

    /// How many by-pid identity reads ([`ProcessId::of`](super::ProcessId::of)) this thread has made.
    pub(crate) fn by_pid_reads() -> usize {
        BY_PID_READS.with(Cell::get)
    }
}

#[cfg(all(target_os = "linux", test))]
pub(crate) use backend::proc_view::openat2_refused_message;

#[cfg(target_os = "linux")]
impl ProcessId {
    /// The inode of the process's pidfd, when this id is of the `pidfs` kind: the proof of it is
    /// [`prove`].
    pub(crate) fn pidfs_ino(&self) -> Option<u64> {
        match self.key {
            Key::Pidfs(ino) => Some(ino),
            Key::Ticks(_) => None,
        }
    }

    /// [`of_with`](Self::of_with), and the process's own `stat` record (its `ppid`, `pgrp`, ...),
    /// read so that it belongs to the identity returned: a `stat` of a later holder of the pid is
    /// never paired with this id.
    pub(crate) fn of_stat_with(kernel: &dyn Kernel, pid: RawPid) -> (Resolved<(ProcessId, Vec<u8>)>, UnknownCause) {
        let (read, cause) = backend::of_stat(kernel, pid, None);
        (read.map(|(key, stat)| (ProcessId { pid, key }, stat)), cause)
    }

    /// [`exists`](Self::exists), reading through the `/proc` at `proc_dir` instead of
    /// re-resolving `/proc` by path. Only meaningful when that `/proc` is known to describe
    /// this pid's namespace.
    pub(crate) fn exists_in(&self, kernel: &dyn Kernel, proc_dir: &ProcDir) -> Existence {
        backend::exists_in(kernel, proc_dir, self.pid, self.key)
    }

    /// [`is_alive`](Self::is_alive), reading through the `/proc` at `proc_dir`; see
    /// [`exists_in`](Self::exists_in).
    pub(crate) fn is_alive_in(&self, kernel: &dyn Kernel, proc_dir: &ProcDir) -> Liveness {
        backend::is_running_in(kernel, proc_dir, self.pid, self.key)
    }

    /// Whether `kill(pid, 0)` answers `ESRCH`; independent of `/proc`.
    pub(crate) fn signal_says_no_such_process(&self, kernel: &dyn Kernel) -> bool {
        backend::signal_says_no_such_process(kernel, self.pid)
    }
}

/// The `kinfo_proc` ABI is defined once, here, behind the size tripwires in
/// `macos/kinfo.rs`. Containment's process-group listing reads it too.
#[cfg(target_os = "macos")]
pub(crate) use backend::kinfo;

/// A kernel, and a guard to hold while it is used, under which every by-pid identity read of `pid`
/// answers `Unknown`: an access refusal (`hidepid` on Linux, a sandboxed or cross-user read on
/// macOS) for a live pid.
///
/// Linux: the returned kernel states the answer, a `stat` row for `pid` answering `EACCES`, and the
/// guard holds nothing. That `stat` fails for every read through the kernel, a table scan's too.
/// macOS: the kernel is the host's and the guard hooks the reads of this thread; see the macOS
/// arm.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn unreadable(pid: RawPid) -> (impl Kernel, impl Sized) {
    (ticks_host(pid).on_read(&format!("{pid}/stat"), Err(libc::EACCES)), ())
}

/// A kernel over the host's that states a host before Linux 6.9 for live `pid` (see
/// [`FakeKernel::live_without_pidfs`]), its pidfd a stand-in that names no process: for a row about
/// the `/proc` path of a read, whatever kernel runs the suite. A row whose kill must pass the pidfd
/// proof gives `live_without_pidfs` the process's own pidfd instead.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn ticks_host(pid: RawPid) -> FakeKernel<'static> {
    let stand_in = std::os::fd::OwnedFd::from(std::fs::File::open("/dev/null").expect("/dev/null opens"));
    FakeKernel::over(&HostKernel).live_without_pidfs(pid, stand_in)
}

/// The identity of live `pid` on a host before Linux 6.9: its `starttime`. A forged `Ticks` id
/// would not be the process's own, so this reads it.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn ticks_id(pid: RawPid) -> ProcessId {
    ProcessId::of_with(&ticks_host(pid), pid)
        .0
        .found()
        .expect("a live pid has a starttime")
}

/// [`unreadable`] on macOS. The guard is what makes the reads refuse: `Kernel` has no macOS
/// methods yet, so the thread-local `force_unknown` hook answers in the kernel's place until it
/// drops.
#[cfg(all(test, target_os = "macos"))]
pub(crate) fn unreadable(pid: RawPid) -> (impl Kernel, impl Sized) {
    (HostKernel, backend::fault::force_unknown(pid))
}

#[cfg(all(target_os = "macos", test))]
pub(crate) use backend::UniqInfo;
/// The assert-free identity reads every `exit_only` check uses, and the purpose that names each.
#[cfg(target_os = "macos")]
pub(crate) use backend::{
    held_by, link, origin, own_unique_id, uniq_info, Held, Link, Origin, ReadPurpose, UniqRead, LAUNCHD,
};

/// The identity-read forcing seams.
#[cfg(all(target_os = "macos", test))]
pub(crate) use backend::{ppid_fault, uniq_fault, ReadErr};

/// `containment::enumerate::macos`'s parent-pid resolver, reused whole (primary
/// `proc_pidinfo` read, sysctl fallback, and the shared zero-ppid guard) — see
/// `identity::macos::ppid_of`'s doc for why it lives here instead of a second copy of either
/// the guard or `kinfo_proc`'s layout.
#[cfg(target_os = "macos")]
pub(crate) use backend::ppid_of as macos_ppid_of;

/// The macOS parent-pid read's test seams and its attempt type.
#[cfg(all(test, target_os = "macos"))]
pub(crate) use backend::{fault as macos_fault, PpidRead};

/// What an ALREADY-OPEN Windows handle says about an identity. The held handle pins the
/// kernel object, so this is pid-reuse-safe (unlike re-resolving by raw pid).
#[cfg(windows)]
#[derive(Debug)]
pub(crate) enum HandleIdentity {
    /// The handle's creation token matches — it IS this process.
    Same,
    /// The token differs — the pid was recycled; the original is gone.
    Different,
    /// `GetProcessTimes` failed, so nothing was established. Never treat as "gone". Carries
    /// the failure for the same reason `Opened::Denied` does: by the time a caller wants to
    /// report it, `GetLastError` has been overwritten.
    Unreadable(windows::core::Error),
}

#[cfg(windows)]
pub(crate) fn windows_handle_identity(handle: windows::Win32::Foundation::HANDLE, id: ProcessId) -> HandleIdentity {
    match backend::creation_token_result(handle) {
        Ok(t) if t == id.key => HandleIdentity::Same,
        Ok(_) => HandleIdentity::Different,
        Err(e) => HandleIdentity::Unreadable(e),
    }
}

/// Build a `ProcessId` from an already-open Windows handle + its pid, reusing the
/// creation-token read (no second `OpenProcess`). Forwards to the private backend so
/// the runas launch can derive identity from the owned handle of a possibly-elevated
/// child without re-opening it by pid.
#[cfg(windows)]
pub(crate) fn windows_identity_from_handle(
    handle: windows::Win32::Foundation::HANDLE,
    pid: RawPid,
) -> Option<ProcessId> {
    backend::windows_identity_from_handle(handle, pid)
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod identity_tests;
