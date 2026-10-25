//! What the tree paths send, for every mechanism that has a root, every way the root can be reaped
//! or its handle fail to vouch for it, and every tree entry point, sync and tokio. After a reap the
//! root's number may name another process, so nothing may go out by it: no `killpg`, no walk from
//! the root's pid, no signal by a bare pid. What names the tree exactly still runs: an fd marker's
//! holders, a cgroup's kill. A `TreeWalk` checks the root after its snapshot instead, and walks
//! nothing once the root is gone.
//!
//! The recorders replace `killpg` with a record and record every walk, holder signal, pidfd signal,
//! `cgroup.kill` write and bare-pid `SIGTERM`, so a mutant that sends by number reaches no process.
//! Each cell's tree is a root `sleep` and a `cat` in its group (in its leaf, holding its marker)
//! that ignores `SIGTERM` and outlives the root. Every cell is checked, and the whole matrix is
//! printed if any cell is wrong.
//!
//! Two sends by number are routed, and their cells expect them until the issue lands:
//! [`KILLPG_AFTER_OWN_REAP`] (a group after this handle's own reap, the pid naming nothing) and
//! [`CGROUP_TERM_BY_PID`] (a cgroup's `SIGTERM` to each member, reaped root or not).

use std::time::Duration;

use crate::identity::{ProcessId, Resolved};
#[cfg(target_os = "linux")]
use crate::test_groups::{cgroup, Group};

/// What a tree is contained by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mechanism {
    /// `Attached::ProcessGroup`: `ContainMode::Session`, with the fd marker suppressed on macOS.
    Group,
    #[cfg(target_os = "macos")]
    MarkerWithGroup,
    #[cfg(target_os = "macos")]
    MarkerWalk,
    /// `Attached::TreeWalk`: `ContainMode::TreeWalk`, with the fd marker suppressed on macOS.
    TreeWalk,
    #[cfg(target_os = "linux")]
    Cgroup,
}

impl Mechanism {
    fn has_group(self) -> bool {
        match self {
            Mechanism::Group => true,
            #[cfg(target_os = "macos")]
            Mechanism::MarkerWithGroup => true,
            #[cfg(target_os = "macos")]
            Mechanism::MarkerWalk => false,
            Mechanism::TreeWalk => false,
            #[cfg(target_os = "linux")]
            Mechanism::Cgroup => false,
        }
    }

    /// Whether the tree is reached by a walk from the root's pid.
    fn walks(self) -> bool {
        self.is_marker() || self == Mechanism::TreeWalk
    }

    fn is_marker(self) -> bool {
        #[cfg(target_os = "macos")]
        if matches!(self, Mechanism::MarkerWithGroup | Mechanism::MarkerWalk) {
            return true;
        }
        false
    }

    fn is_cgroup(self) -> bool {
        #[cfg(target_os = "linux")]
        if self == Mechanism::Cgroup {
            return true;
        }
        false
    }

    fn mode(self) -> crate::ContainMode {
        match self {
            Mechanism::Group => crate::ContainMode::Session,
            #[cfg(target_os = "macos")]
            Mechanism::MarkerWithGroup => crate::ContainMode::Session,
            #[cfg(target_os = "macos")]
            Mechanism::MarkerWalk => crate::ContainMode::TreeWalk,
            Mechanism::TreeWalk => crate::ContainMode::TreeWalk,
            #[cfg(target_os = "linux")]
            Mechanism::Cgroup => crate::ContainMode::Strongest,
        }
    }

    fn containment(self) -> crate::Containment {
        match self {
            Mechanism::Group => crate::Containment::Session,
            #[cfg(target_os = "macos")]
            Mechanism::MarkerWithGroup | Mechanism::MarkerWalk => crate::Containment::FdMarker,
            Mechanism::TreeWalk => crate::Containment::TreeWalk,
            #[cfg(target_os = "linux")]
            Mechanism::Cgroup => crate::Containment::CgroupV2,
        }
    }

    /// The tree's command: [`TREE`] under this mechanism, with every stdio piped.
    fn configure(self, cmd: &mut crate::Command) {
        cmd.args(["sh", "-c", TREE]);
        cmd.contain_with(self.mode());
        #[cfg(target_os = "macos")]
        if matches!(self, Mechanism::Group | Mechanism::TreeWalk) {
            cmd.suppress_fd_marker();
        }
        cmd.stdin(crate::Stdio::pipe_in()).expect("stdin pipe");
        cmd.stdout(crate::Stdio::pipe_out()).expect("stdout pipe");
        cmd.stderr(crate::Stdio::pipe_out()).expect("stderr pipe");
    }
}

/// A root `sleep` and a `cat` it forked, in its group, that ignores `SIGTERM` (an ignored signal stays
/// ignored across `exec`) and reads the root's stdin through fd 3, as `sh` points a background job's
/// stdin at `/dev/null` otherwise. The `cat` prints its pid once it ignores `SIGTERM`. Both hold the
/// stderr pipe's write end, so stderr reaches EOF once both are gone. Closing stdin ends the `cat`.
const TREE: &str = r#"exec 3<&0
sh -c 'trap "" TERM; echo $$; exec cat >/dev/null' <&3 3<&- &
exec 3<&-
exec sleep 300"#;

/// How the root was reaped before the entry point ran, and what its pid reads as then.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reap {
    None,
    /// Not reaped, but the root's own handle cannot answer (`RootState::Unknown`), so its pid may
    /// name another process. On Linux its pidfd still names it exactly.
    Unanswered,
    /// macOS: not reaped, but launchd holds the root (`RootState::Unpinned`) and may reap it at any
    /// time.
    #[cfg(target_os = "macos")]
    Unpinned,
    OwnFree,
    OwnReused,
    /// This handle reaped the root, and its pid cannot be read (`Resolved::Unknown`).
    OwnUnknown,
    ForeignFree,
    ForeignReused,
    /// [`ForeignFree`](Reap::ForeignFree), seen by a `try_wait` first: it answers `ECHILD`, and a
    /// tokio handle forgets its backend as reaped elsewhere.
    ForeignSeen,
}

impl Reap {
    const ALL: &[Reap] = &[
        Reap::None,
        Reap::Unanswered,
        #[cfg(target_os = "macos")]
        Reap::Unpinned,
        Reap::OwnFree,
        Reap::OwnReused,
        Reap::OwnUnknown,
        Reap::ForeignFree,
        Reap::ForeignReused,
        Reap::ForeignSeen,
    ];

    fn own(self) -> bool {
        matches!(self, Reap::OwnFree | Reap::OwnReused | Reap::OwnUnknown)
    }

    /// Whether the root is reaped when the entry point runs.
    fn reaped(self) -> bool {
        match self {
            Reap::None | Reap::Unanswered => false,
            #[cfg(target_os = "macos")]
            Reap::Unpinned => false,
            _ => true,
        }
    }

    /// Whether the cell exists for `mechanism`. On Linux the handle's answer is read only by a
    /// mechanism that reaches its tree through the root's number and does not check the root itself;
    /// macOS reads it for every mechanism.
    fn applies_to(self, mechanism: Mechanism) -> bool {
        #[cfg(target_os = "linux")]
        if self == Reap::Unanswered {
            return !mechanism.is_cgroup() && mechanism != Mechanism::TreeWalk;
        }
        let _ = mechanism;
        true
    }

    /// What every read of the root's pid answers after the reap: nothing, another process, or no
    /// answer.
    fn read(self, root: ProcessId) -> Option<Resolved<ProcessId>> {
        match self {
            Reap::None | Reap::Unanswered => None,
            #[cfg(target_os = "macos")]
            Reap::Unpinned => None,
            Reap::OwnFree | Reap::ForeignFree | Reap::ForeignSeen => Some(Resolved::Gone),
            Reap::OwnUnknown => Some(Resolved::Unknown),
            Reap::OwnReused | Reap::ForeignReused => Some(Resolved::Found(ProcessId::from_parts_for_test(
                root.pid(),
                root.start_token_raw() + 1,
            ))),
        }
    }
}

impl Reap {
    /// Arms what makes the root read as this reap, until the guard drops. On macOS every look at the
    /// root answers the same, so a graceful shutdown's sweep reads what its signal read.
    fn force(self, id: ProcessId) -> Option<Box<dyn std::any::Any>> {
        #[cfg(target_os = "linux")]
        if self == Reap::Unanswered {
            let failed = Err(std::io::Error::other("forced peek failure"));
            return Some(Box::new(crate::wait::exit_only::seams::force_peek_once(failed)));
        }
        #[cfg(target_os = "macos")]
        {
            use crate::wait::exit_only::seams::force_every_peek;
            use crate::wait::exit_only::{Foreign, Peek};
            match self {
                Reap::Unanswered => {
                    return Some(Box::new(force_every_peek(|| {
                        Err(std::io::Error::other("forced peek failure"))
                    })));
                }
                Reap::Unpinned => {
                    return Some(Box::new(force_every_peek(|| Ok(Peek::Foreign(Foreign::Orphaned)))));
                }
                _ => {}
            }
        }
        self.read(id)
            .map(|read| Box::new(crate::child::fault::force_root_reads(read)) as Box<dyn std::any::Any>)
    }

    /// Checks that the failed peek was the one look at the root the entry point took (Linux).
    fn assert_forced_used(self) {
        #[cfg(target_os = "linux")]
        if self == Reap::Unanswered {
            crate::wait::exit_only::seams::assert_peeks_exhausted();
        }
    }

    /// Whether the root is unreaped, but its handle cannot vouch for it.
    fn untrusted(self) -> bool {
        !self.reaped() && self != Reap::None
    }

    fn unpinned(self) -> bool {
        #[cfg(target_os = "macos")]
        if self == Reap::Unpinned {
            return true;
        }
        false
    }

    /// Whether the force must be lifted before the cell's cleanup kills and reaps the root: a macOS
    /// root forced untrusted would refuse both.
    fn lift_before_cleanup(self) -> bool {
        cfg!(target_os = "macos") && self.untrusted()
    }
}

/// The tree entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    /// `kill_tree`.
    Kill,
    /// `terminate_tree`.
    Terminate,
    /// `graceful_shutdown_tree`, with no grace.
    GracefulShutdown,
}

impl Op {
    const ALL: [Op; 3] = [Op::Kill, Op::Terminate, Op::GracefulShutdown];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Api {
    Sync,
    #[cfg(feature = "tokio")]
    Tokio,
}

impl Api {
    #[cfg(not(feature = "tokio"))]
    const ALL: &[Api] = &[Api::Sync];
    #[cfg(feature = "tokio")]
    const ALL: &[Api] = &[Api::Sync, Api::Tokio];
}

/// What one cell sent, through the recording seams.
#[derive(Debug, Default)]
struct Sent {
    // By number.
    killpg: bool,
    walk: bool,
    /// A signal to a bare pid: macOS's identity-checked kill of the root, or a cgroup member's
    /// `SIGTERM`.
    by_pid: bool,
    // Exact.
    /// The signals the `cat`, a marker holder, got through the holders channel.
    holder: Vec<nix::sys::signal::Signal>,
    /// The signals the root, also a marker holder, got through the holders channel.
    root_holder: Vec<nix::sys::signal::Signal>,
    pidfd: bool,
    cgroup_kill: bool,
}

/// What a cell must send through one channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Want {
    Yes,
    No,
    Any,
    /// Sent today, and wrongly: the issue that removes it.
    Routed(&'static str),
}

impl Want {
    fn holds(self, sent: bool) -> bool {
        match self {
            Want::Yes | Want::Routed(_) => sent,
            Want::No => !sent,
            Want::Any => true,
        }
    }
}

struct Expected {
    killpg: Want,
    walk: Want,
    by_pid: Want,
    /// `None`: not checked.
    holder: Option<&'static [nix::sys::signal::Signal]>,
    /// `None`: not checked.
    root_holder: Option<&'static [nix::sys::signal::Signal]>,
    pidfd: Want,
    cgroup_kill: Want,
}

/// The killpg after this handle's own reap, while the pid names nothing: the group may still have
/// members, but once none survives another process may take the number first.
const KILLPG_AFTER_OWN_REAP: Want = Want::Routed("bindreams/cosca#382");
/// A cgroup's `SIGTERM` goes to each member by the pid `cgroup.procs` lists.
const CGROUP_TERM_BY_PID: Want = Want::Routed("bindreams/cosca#106");

fn expected(mechanism: Mechanism, reap: Reap, op: Op) -> Expected {
    use nix::sys::signal::Signal::{SIGKILL, SIGTERM};
    let reaped = reap.reaped();
    let killpg = match (mechanism.has_group(), reap) {
        (false, _) => Want::No,
        (true, Reap::None) => Want::Yes,
        (true, Reap::OwnFree) => KILLPG_AFTER_OWN_REAP,
        (true, _) => Want::No,
    };
    let walk = if mechanism.walks() && reap == Reap::None {
        Want::Yes
    } else {
        Want::No
    };
    let by_pid = if mechanism.is_cgroup() && op != Op::Kill {
        CGROUP_TERM_BY_PID
    } else if reaped || reap != Reap::None {
        Want::No
    } else {
        Want::Any
    };
    let holder: Option<&'static [nix::sys::signal::Signal]> = match (mechanism.is_marker(), reap == Reap::None) {
        (true, false) => Some(match op {
            Op::Kill => &[SIGKILL],
            Op::Terminate => &[SIGTERM],
            Op::GracefulShutdown => &[SIGTERM, SIGKILL],
        }),
        // The walk reaches the `cat` first.
        (true, true) => None,
        (false, _) => Some(&[]),
    };
    // A macOS root the handle cannot vouch for: launchd's zombie is left alone, and an unanswered
    // root is signalled with the other holders. A graceful shutdown's `SIGTERM` may end it before
    // the sweep looks for holders.
    let root_holder: Option<&'static [nix::sys::signal::Signal]> = if !(cfg!(target_os = "macos") && reap.untrusted()) {
        None
    } else if !mechanism.is_marker() || reap.unpinned() {
        Some(&[])
    } else {
        match op {
            Op::Kill => Some(&[SIGKILL]),
            Op::Terminate => Some(&[SIGTERM]),
            Op::GracefulShutdown => None,
        }
    };
    // The handle backstop, through the pidfd; after a reap it has nothing to reach. A root whose
    // handle cannot answer is signalled through it by every entry point: it names the root exactly.
    let pidfd = match (cfg!(target_os = "linux"), reaped, op) {
        (false, _, _) => Want::No,
        (true, true, _) => Want::Any,
        (true, false, _) if reap != Reap::None => Want::Yes,
        (true, false, Op::Terminate) => Want::No,
        (true, false, _) => Want::Yes,
    };
    let cgroup_kill = if mechanism.is_cgroup() && op != Op::Terminate {
        Want::Yes
    } else {
        Want::No
    };
    Expected {
        killpg,
        walk,
        by_pid,
        holder,
        root_holder,
        pidfd,
        cgroup_kill,
    }
}

/// The checks `sent` fails against `want`, by channel.
fn mismatches(want: &Expected, sent: &Sent) -> Vec<String> {
    let mut wrong = Vec::new();
    let mut check = |name: &str, want: Want, sent: bool| {
        if !want.holds(sent) {
            wrong.push(format!("{name}: want {want:?}, sent {sent}"));
        }
    };
    check("killpg", want.killpg, sent.killpg);
    check("walk", want.walk, sent.walk);
    check("by-pid", want.by_pid, sent.by_pid);
    check("pidfd", want.pidfd, sent.pidfd);
    check("cgroup.kill", want.cgroup_kill, sent.cgroup_kill);
    if let Some(holder) = want.holder {
        if sent.holder != holder {
            wrong.push(format!("holder: want {holder:?}, sent {:?}", sent.holder));
        }
    }
    if let Some(root) = want.root_holder {
        if sent.root_holder != root {
            wrong.push(format!("root holder: want {root:?}, sent {:?}", sent.root_holder));
        }
    }
    wrong
}

/// The recorders for one cell, on this thread.
struct Recorders {
    groups: crate::containment::unix::fault::KillGroupRecorder,
    terms: crate::containment::unix::fault::TermGroupRecorder,
    walks: crate::containment::treewalk::fault::WalkRecorder,
    sends: crate::send_log::Capture,
    #[cfg(target_os = "macos")]
    holders: crate::containment::fdmarker::fault::HolderKillRecorder,
}

impl Recorders {
    fn start() -> Recorders {
        #[cfg(target_os = "linux")]
        {
            crate::containment::cgroup::fault::record_leaf_steps();
            crate::containment::cgroup::fault::take_terminated_by_pid();
        }
        Recorders {
            groups: crate::containment::unix::fault::record_kill_group(),
            terms: crate::containment::unix::fault::record_term_group(),
            walks: crate::containment::treewalk::fault::record_walks(),
            sends: crate::send_log::Capture::start(),
            #[cfg(target_os = "macos")]
            holders: crate::containment::fdmarker::fault::record_holder_kills(),
        }
    }

    /// What was sent so far. `root` and `cat` are the tree's pids.
    #[cfg_attr(
        not(target_os = "macos"),
        allow(unused_variables, reason = "only macOS has marker holders")
    )]
    fn sent(&self, root: u32, cat: u32) -> Sent {
        use crate::send_log::Via;
        let entries = self.sends.entries();
        #[cfg(target_os = "linux")]
        let (cgroup_kill, terminated) = (
            crate::containment::cgroup::fault::take_leaf_steps()
                .iter()
                .any(|step| step == "kill"),
            !crate::containment::cgroup::fault::take_terminated_by_pid().is_empty(),
        );
        #[cfg(not(target_os = "linux"))]
        let (cgroup_kill, terminated) = (false, false);
        Sent {
            killpg: !self.groups.killed().is_empty() || !self.terms.termed().is_empty(),
            walk: !self.walks.walked().is_empty(),
            by_pid: terminated || entries.iter().any(|(_, _, via)| *via == Via::Pid),
            #[cfg(target_os = "macos")]
            holder: self.holders.signals_to(cat),
            #[cfg(not(target_os = "macos"))]
            holder: Vec::new(),
            #[cfg(target_os = "macos")]
            root_holder: self.holders.signals_to(root),
            #[cfg(not(target_os = "macos"))]
            root_holder: Vec::new(),
            pidfd: entries.iter().any(|(pid, _, via)| *pid == root && *via == Via::Pidfd),
            cgroup_kill,
        }
    }
}

/// Checks a `try_wait` after a foreign reap answered `ECHILD`.
#[track_caller]
fn assert_echild<T: std::fmt::Debug>(waited: Result<T, crate::error::Error>) {
    assert!(
        matches!(&waited, Err(crate::error::Error::Io(e)) if e.raw_os_error() == Some(libc::ECHILD)),
        "a try_wait after a foreign reap: {waited:?}"
    );
}

/// Reads the `cat`'s pid, the line it prints once it ignores `SIGTERM`.
fn cat_pid(line: &str) -> u32 {
    line.trim().parse().expect("the cat's pid")
}

/// Runs one sync cell and returns what it sent.
fn run_sync(mechanism: Mechanism, reap: Reap, op: Op) -> Sent {
    use std::io::{BufRead as _, Read as _};
    let mut cmd = crate::Command::new();
    mechanism.configure(&mut cmd);
    let mut child = cmd.spawn().expect("spawn");
    assert_eq!(child.containment(), mechanism.containment(), "{mechanism:?}");
    let mut line = String::new();
    std::io::BufReader::new(child.stdout().expect("stdout pipe"))
        .read_line(&mut line)
        .expect("read the cat's pid");
    let cat = cat_pid(&line);
    let stdin = child.stdin().expect("stdin pipe");
    let mut stderr = child.stderr().expect("stderr pipe");
    let root = child.id().pid();
    if reap.reaped() {
        child.kill().expect("kill the root");
        if reap.own() {
            child.wait().expect("this handle reaps the root");
        } else {
            crate::test_child::reaped_elsewhere::reap_behind(root);
            if reap == Reap::ForeignSeen {
                assert_echild(child.try_wait());
            }
        }
    }
    let mut forced = reap.force(child.id());

    let recorders = Recorders::start();
    // The cell checks what was sent, not what the call answered.
    _ = match op {
        Op::Kill => child.kill_tree(),
        Op::Terminate => child.terminate_tree(),
        Op::GracefulShutdown => child.graceful_shutdown_tree(Duration::ZERO).map(drop),
    };
    reap.assert_forced_used();
    let sent = recorders.sent(root, cat);
    if reap.lift_before_cleanup() {
        drop(forced.take());
    }

    // The tree is gone before the drop, which runs under the recorders: it sends no killpg.
    if !reap.reaped() {
        child.kill().expect("kill the root");
        child.wait().expect("reap the root");
    }
    drop(stdin);
    let mut rest = Vec::new();
    stderr
        .read_to_end(&mut rest)
        .expect("the root and the cat are gone, closing stderr");
    if mechanism.is_cgroup() {
        child.wait_tree().expect("the leaf drains");
    }
    drop(child);
    drop(forced);
    drop(recorders);
    sent
}

/// Runs one tokio cell and returns what it sent.
#[cfg(feature = "tokio")]
async fn run_tokio(mechanism: Mechanism, reap: Reap, op: Op) -> Sent {
    use ::tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _};
    let mut cmd = crate::tokio::Command::new();
    mechanism.configure(cmd.as_sync_mut());
    let mut child = cmd.spawn().expect("spawn");
    assert_eq!(child.containment(), mechanism.containment(), "{mechanism:?}");
    let mut line = String::new();
    ::tokio::io::BufReader::new(child.stdout().expect("stdout pipe"))
        .read_line(&mut line)
        .await
        .expect("read the cat's pid");
    let cat = cat_pid(&line);
    let stdin = child.stdin().expect("stdin pipe");
    let mut stderr = child.stderr().expect("stderr pipe");
    let root = child.id().pid();
    if reap.reaped() {
        child.kill().expect("kill the root");
        if reap.own() {
            child.wait().await.expect("this handle reaps the root");
        } else {
            crate::test_child::reaped_elsewhere::reap_behind(root);
            if reap == Reap::ForeignSeen {
                assert_echild(child.try_wait());
            }
        }
    }
    let mut forced = reap.force(child.id());

    let recorders = Recorders::start();
    // The cell checks what was sent, not what the call answered.
    _ = match op {
        Op::Kill => child.kill_tree(),
        Op::Terminate => child.terminate_tree(),
        Op::GracefulShutdown => child.graceful_shutdown_tree(Duration::ZERO).await.map(drop),
    };
    reap.assert_forced_used();
    let sent = recorders.sent(root, cat);
    if reap.lift_before_cleanup() {
        drop(forced.take());
    }

    if !reap.reaped() {
        child.kill().expect("kill the root");
        child.wait().await.expect("reap the root");
    }
    drop(stdin);
    let mut rest = Vec::new();
    stderr
        .read_to_end(&mut rest)
        .await
        .expect("the root and the cat are gone, closing stderr");
    // An async drop does not wait for the leaf to drain: it would leave the leaf behind.
    if mechanism.is_cgroup() {
        child.wait_tree().await.expect("the leaf drains");
    }
    drop(child);
    drop(forced);
    drop(recorders);
    sent
}

/// Runs every cell of `mechanisms` and fails, printing the whole matrix, if any cell is wrong.
fn check_matrix(mechanisms: &[Mechanism]) {
    #[cfg(feature = "tokio")]
    let runtime = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build a current-thread runtime: the recorders are thread-local");
    let mut rows = Vec::new();
    let mut failed = 0;
    for &mechanism in mechanisms {
        for &reap in Reap::ALL.iter().filter(|reap| reap.applies_to(mechanism)) {
            for op in Op::ALL {
                for &api in Api::ALL {
                    let sent = match api {
                        Api::Sync => run_sync(mechanism, reap, op),
                        #[cfg(feature = "tokio")]
                        Api::Tokio => runtime.block_on(run_tokio(mechanism, reap, op)),
                    };
                    let want = expected(mechanism, reap, op);
                    let wrong = mismatches(&want, &sent);
                    let routed: Vec<_> = [want.killpg, want.by_pid]
                        .into_iter()
                        .filter_map(|w| match w {
                            Want::Routed(issue) => Some(issue),
                            _ => None,
                        })
                        .collect();
                    let verdict = if wrong.is_empty() {
                        "ok".to_owned()
                    } else {
                        failed += 1;
                        format!("WRONG: {}", wrong.join("; "))
                    };
                    let routed = if routed.is_empty() {
                        String::new()
                    } else {
                        format!(" (routed: {})", routed.join(", "))
                    };
                    rows.push(format!(
                        "{mechanism:?} | {reap:?} | {op:?} | {api:?} | {sent:?} | {verdict}{routed}"
                    ));
                }
            }
        }
    }
    assert_eq!(
        failed,
        0,
        "{failed} of {} cells are wrong:\n{}",
        rows.len(),
        rows.join("\n")
    );
}

/// The process group, the tree walk, and on macOS both fd markers.
///
/// Mutants: `root_number` answers `Trusted` for any of a foreign reap, an own reap whose pid is
/// reused, (macOS, an fd marker) an own reap whose pid names nothing, or (macOS) a root that is
/// `Unpinned` or `Unknown`; a tokio backend forgotten as reaped elsewhere counted as its own reap;
/// the holders sweep skipped after a reap or for an untrusted root; an
/// `Unpinned` root signalled as a holder; `treewalk::hard_kill` or `treewalk::terminate` walks
/// without `anchor_present`.
#[skuld::test]
fn tree_paths_send_nothing_by_the_root_number_after_a_reap() {
    check_matrix(&[
        Mechanism::Group,
        Mechanism::TreeWalk,
        #[cfg(target_os = "macos")]
        Mechanism::MarkerWithGroup,
        #[cfg(target_os = "macos")]
        Mechanism::MarkerWalk,
    ]);
}

/// A cgroup names no pid, so its kill still runs after any reap.
///
/// Mutant: the cgroup's kill skipped after a reap.
#[cfg(target_os = "linux")]
#[skuld::test]
fn cgroup_tree_paths_still_kill_through_the_cgroup_after_a_reap(#[fixture(cgroup)] _group: &Group) {
    check_matrix(&[Mechanism::Cgroup]);
}
