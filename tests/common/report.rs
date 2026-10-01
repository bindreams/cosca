//! The grandchild pid report of the `spawn-grandchild*` testbin roots.
//!
//! A root started with [`GC_PID_ADDR_ENV`] connects to that address after spawning its grandchild
//! (waiting for the accept ack, like any control connection), writes the grandchild's pid as one
//! `<pid>\n` line, and then BLOCKS until the harness writes a second ack byte. The harness
//! captures the grandchild's [`ProcessId`] before writing that release. Until then the root is
//! alive and still the grandchild's parent, holding it unreaped (Unix) or by handle (Windows), so
//! the pid names the grandchild for certain and the identity taken here is the real one. The
//! tree helpers then watch that identity, never the bare pid, alongside the root's.

use std::cell::{Cell, RefCell};
use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::thread::LocalKey;

use cosca::identity::{Liveness, ProcessId, Resolved};

use super::accept::{
    accept_or_die, ack_now, died_before_connecting, died_before_reporting, wait_readable, Target, WatchEvent,
};

/// Env var telling a `spawn-grandchild*` testbin root where to report its grandchild's pid.
/// Unset, the root reports nothing, so other consumers of these modes see no extra connection.
pub const GC_PID_ADDR_ENV: &str = "COSCA_TEST_GC_PID_ADDR";

type RootHook = RefCell<Option<Box<dyn FnMut(u32)>>>;

thread_local! {
    static LAST_REPORTED: Cell<Option<u32>> = const { Cell::new(None) };
    static LAST_REPORTED_ID: Cell<Option<ProcessId>> = const { Cell::new(None) };
    static LAST_REPORTED_LIVENESS: Cell<Option<Liveness>> = const { Cell::new(None) };
    static LAST_REPORTED_CONTAINED: Cell<Option<bool>> = const { Cell::new(None) };
    #[cfg(feature = "tokio")]
    static LAST_ASYNC_ROOT: Cell<Option<ProcessId>> = const { Cell::new(None) };
    static ON_REPORT_ACCEPTED: RootHook = const { RefCell::new(None) };
    static ON_RELEASE: RootHook = const { RefCell::new(None) };
}

/// Has `hook` called on this thread, with the root's pid, each time a tree helper has accepted
/// and acked a root's report connection, before it reads the report. A root that exits there
/// without reporting can be let finish its exit before the helper looks. Removed when the guard
/// drops.
#[must_use = "the hook is removed as soon as the guard is dropped"]
pub fn on_report_accepted(hook: impl FnMut(u32) + 'static) -> RootHookGuard {
    install(&ON_REPORT_ACCEPTED, hook)
}

/// Has `hook` called on this thread, with the root's pid, each time a root has been released
/// ([`report_grandchild`] or its async sibling): after the release is written, before the helper's
/// next step. The root then runs on, so the hook can wait for what the root does next before the
/// helper looks at it. Removed when the guard drops.
#[must_use = "the hook is removed as soon as the guard is dropped"]
pub fn on_release(hook: impl FnMut(u32) + 'static) -> RootHookGuard {
    install(&ON_RELEASE, hook)
}

/// Blocks until the root `pid` has exited and can be reaped, leaving it unreaped: its zombie
/// edge on Unix (a death-watch fires earlier on macOS, see [`block_until_zombie`](super::block_until_zombie)),
/// its exit on Windows. The hook for [`on_report_accepted`] and [`on_release`] that makes the
/// helper's next look see an exited root.
pub fn until_reapable(pid: u32) {
    #[cfg(unix)]
    super::block_until_zombie(pid);
    #[cfg(windows)]
    super::accept::wait_for_exit(pid);
}

fn install(slot: &'static LocalKey<RootHook>, hook: impl FnMut(u32) + 'static) -> RootHookGuard {
    slot.with(|h| {
        let mut slot = h.borrow_mut();
        debug_assert!(slot.is_none(), "this root hook is already installed on this thread");
        *slot = Some(Box::new(hook));
    });
    RootHookGuard(slot)
}

/// Removes an [`on_report_accepted`] or [`on_release`] hook on drop.
pub struct RootHookGuard(&'static LocalKey<RootHook>);

impl Drop for RootHookGuard {
    fn drop(&mut self) {
        self.0.with(|h| *h.borrow_mut() = None);
    }
}

fn notify(slot: &'static LocalKey<RootHook>, root_pid: u32) {
    let taken = slot.with(|h| h.borrow_mut().take());
    if let Some(mut hook) = taken {
        hook(root_pid);
        slot.with(|h| *h.borrow_mut() = Some(hook));
    }
}

/// The pid of the grandchild most recently reported to this thread, if any. Lets a test that
/// expects a helper to panic assert which process the panic names.
pub fn last_reported_grandchild() -> Option<u32> {
    LAST_REPORTED.with(Cell::get)
}

/// The identity of the most recently reported grandchild, set only once it resolved; unlike the
/// pid, safe to wait on. `None` means identification did not complete (the helper panicked
/// earlier), so check the helper's panic message before treating `None` as a harness bug.
pub fn last_reported_grandchild_id() -> Option<ProcessId> {
    LAST_REPORTED_ID.with(Cell::get)
}

/// Blocks until the root of the async tree most recently spawned on this thread has exited. An
/// async `Child`'s drop only sends the kill, so a test whose helper panicked calls this before
/// returning: the root inherited the test's stdio and must be gone by then. Waits by identity.
#[cfg(feature = "tokio")]
pub fn wait_for_last_async_root() {
    let id = LAST_ASYNC_ROOT
        .with(Cell::get)
        .expect("an async tree helper recorded its root before panicking");
    cosca::Process::from_id(id)
        .wait()
        .expect("wait for the async tree's root");
}

fn record(pid: u32) {
    LAST_REPORTED.with(|c| c.set(Some(pid)));
    LAST_REPORTED_ID.with(|c| c.set(None));
    LAST_REPORTED_LIVENESS.with(|c| c.set(None));
    LAST_REPORTED_CONTAINED.with(|c| c.set(None));
}

fn record_id(id: ProcessId) {
    LAST_REPORTED_ID.with(|c| c.set(Some(id)));
    LAST_REPORTED_LIVENESS.with(|c| c.set(Some(id.is_alive())));
}

/// The liveness of the most recently reported grandchild at the moment it was identified, before
/// any unwind. A test that unwinds and then waits asserts `Some(Alive)` here, so the exit it waits
/// for cannot have preceded the teardown it is testing.
pub fn last_reported_grandchild_liveness() -> Option<Liveness> {
    LAST_REPORTED_LIVENESS.with(Cell::get)
}

/// Whether the most recently reported grandchild was, when identified and before any unwind, a
/// structural member of its root's containment (see [`is_contained_member`]). `None` means the
/// check did not run. A test that unwinds and then waits asserts `Some(true)`, so a containment
/// that silently does nothing fails at once instead of hanging the wait.
pub fn last_reported_grandchild_contained() -> Option<bool> {
    LAST_REPORTED_CONTAINED.with(Cell::get)
}

/// What a `Child` drop logs when it skips its tree kill because the root is already reaped (#382).
const DROP_SKIPPED_THE_KILL: &str = "Child::drop: the root is already reaped";

/// Whether a `Child` drop on this thread logged, since `mark`, that it skipped its tree kill
/// because the root was already reaped.
pub fn drop_skipped_its_kill(mark: usize) -> bool {
    super::contains_since_on_this_thread(mark, DROP_SKIPPED_THE_KILL)
}

/// Blocks until the grandchild most recently reported on this thread has exited, for a test whose
/// tree helper panicked and whose contained `Child` the unwind dropped: that drop's tree kill is
/// the only thing that ends the grandchild. `mark` is a [`log_mark`](super::log_mark) taken, after
/// [`install_log_capture`](super::install_log_capture), before the helper ran.
///
/// The grandchild must have been a live member of the containment when identified, and the drop
/// must not have skipped its kill, which it does once the root is reaped (#382). Each is asserted
/// before the wait, which would otherwise never return. On a skip the grandchild is killed by
/// identity first, so the failure leaves nothing running.
pub fn wait_for_the_dropped_trees_grandchild(mark: usize, message: &str) {
    let id = last_reported_grandchild_id()
        .unwrap_or_else(|| panic!("no grandchild identity; helper panicked with: {message:?}"));
    assert_eq!(
        last_reported_grandchild_contained(),
        Some(true),
        "the grandchild must be inside the root's containment when identified, or the drop does not kill it"
    );
    assert_eq!(
        last_reported_grandchild_liveness(),
        Some(Liveness::Alive),
        "the grandchild must be alive when identified, so its exit is the containment kill's"
    );
    if drop_skipped_its_kill(mark) {
        let killed = cosca::Process::from_id(id).kill();
        panic!(
            "the tree's drop skipped its kill because the root was already reaped, which leaves the grandchild \
             (pid {}) running; killed it by identity: {killed:?}",
            id.pid()
        );
    }
    cosca::Process::from_id(id)
        .wait()
        .expect("wait for the orphaned grandchild");
}

/// Whether `grandchild` is inside the containment `containment` of the still-held `root`.
/// `containment` is the root's own mechanism; `in_job` answers job membership (Windows only).
/// Uncontained and nested (`Delegated`) roots own no tree, so they never contain it.
fn is_contained_member(
    containment: cosca::Containment,
    root: u32,
    grandchild: u32,
    in_job: impl FnOnce(u32) -> bool,
) -> bool {
    use cosca::Containment as C;
    // Each platform's arms use a different subset of the inputs.
    let _ = (root, &in_job);
    match containment {
        C::None | C::Delegated => false,
        #[cfg(windows)]
        C::JobObject => in_job(grandchild),
        #[cfg(target_os = "linux")]
        C::CgroupV2 => {
            let leaf = |pid: &str| std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok();
            let (mine, roots, theirs) = (leaf("self"), leaf(&root.to_string()), leaf(&grandchild.to_string()));
            theirs.is_some() && theirs == roots && theirs != mine
        }
        #[cfg(unix)]
        C::ProcessGroup | C::Session => {
            // SAFETY: `getpgid` only reads the target's group id.
            unsafe { libc::getpgid(grandchild as libc::pid_t) == root as libc::pid_t }
        }
        #[cfg(unix)]
        C::FdMarker | C::TreeWalk => cosca::Process::from_pid(grandchild)
            .found()
            .and_then(|p| p.parent().expect("the grandchild's parent lookup failed"))
            .is_some_and(|parent| parent.id().pid() == root),
        _ => false,
    }
}

fn parse_pid(line: &str) -> u32 {
    line.trim()
        .parse()
        .unwrap_or_else(|e| panic!("grandchild pid report {line:?}: {e}"))
}

/// The identity of a reported grandchild, taken while its parent (the root) is held.
fn identify(pid: u32) -> ProcessId {
    record(pid);
    match ProcessId::of(pid) {
        Resolved::Found(id) => {
            record_id(id);
            id
        }
        // Unreaped (Unix) or handle-held (Windows) under the live root, so it still resolves;
        // gone means it was reaped, which only its death can explain.
        Resolved::Gone => died_before_connecting(pid),
        Resolved::Unknown => panic!("the OS refused to identify the reported grandchild pid {pid}"),
    }
}

/// Accepts the root's report connection, reads its pid line watching the root, captures the
/// grandchild's identity and releases the root. See the module doc.
pub fn report_grandchild(report: &TcpListener, root: &mut cosca::Child) -> ProcessId {
    let root_pid = root.pid();
    let mut stream = accept_or_die(report, root);
    notify(&ON_REPORT_ACCEPTED, root_pid);
    let mut line = Vec::new();
    let mut buf = [0u8; 64];
    while !line.contains(&b'\n') {
        // A root that dies here closes the socket too; watching the process is what does not
        // depend on that (a descendant could hold the socket open).
        match wait_readable(&stream, root_pid) {
            WatchEvent::Ready => {}
            WatchEvent::Died(pid) => died_before_reporting(pid, "the grandchild pid"),
        }
        let n = stream.read(&mut buf).expect("read the grandchild pid report");
        if n == 0 {
            died_before_reporting(root_pid, "the grandchild pid");
        }
        line.extend_from_slice(&buf[..n]);
    }
    let id = identify(parse_pid(std::str::from_utf8(&line).expect("the report is UTF-8")));
    let contained = is_contained_member(root.containment(), root_pid, id.pid(), |_pid| {
        #[cfg(windows)]
        return root.test_job_handle_contains(_pid);
        #[cfg(not(windows))]
        false
    });
    LAST_REPORTED_CONTAINED.with(|c| c.set(Some(contained)));
    release(stream);
    notify(&ON_RELEASE, root_pid);
    id
}

fn release(stream: TcpStream) {
    // The stream is written once and dropped; the root's next step is its main connection.
    drop(ack_now(stream));
}

/// Async sibling of [`report_grandchild`].
#[cfg(feature = "tokio")]
pub async fn report_grandchild_async(report: &::tokio::net::TcpListener, root: &mut cosca::tokio::Child) -> ProcessId {
    use ::tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    LAST_ASYNC_ROOT.with(|c| c.set(Some(root.id())));
    let root_pid = root.id().pid();
    let std_stream = super::accept::accept_or_die_async(report, root).await;
    notify(&ON_REPORT_ACCEPTED, root_pid);
    std_stream
        .set_nonblocking(true)
        .expect("set the report stream nonblocking");
    let mut stream = ::tokio::net::TcpStream::from_std(std_stream).expect("wrap the report stream for tokio");
    let mut line = String::new();
    let n = {
        let mut reader = BufReader::new(&mut stream);
        ::tokio::select! {
            biased;
            n = reader.read_line(&mut line) => n.expect("read the grandchild pid report"),
            status = root.wait() => match status {
                Ok(_) => died_before_reporting(root_pid, "the grandchild pid"),
                Err(e) => panic!("watching the root's exit while reading the grandchild pid report: {e}"),
            },
        }
    };
    if n == 0 {
        died_before_reporting(root_pid, "the grandchild pid");
    }
    let id = identify(parse_pid(&line));
    let contained = is_contained_member(root.containment(), root_pid, id.pid(), |_pid| {
        #[cfg(windows)]
        return root.test_job_handle_contains(_pid);
        #[cfg(not(windows))]
        false
    });
    LAST_REPORTED_CONTAINED.with(|c| c.set(Some(contained)));
    stream
        .write_all(&[super::accept::ack::ACK_BYTE])
        .await
        .unwrap_or_else(|e| panic!("writing the release to the grandchild pid report failed: {e}"));
    notify(&ON_RELEASE, root_pid);
    id
}
