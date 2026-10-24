//! What the tree paths send, for every mechanism that has a root, every way the root can be reaped,
//! and every tree entry point, sync and tokio. After a reap the root's number may name another
//! process, so nothing may go out by it: no `killpg`, no walk from the root's pid, no signal by a
//! bare pid. What names the tree exactly still runs: an fd marker's holders, a cgroup's kill.
//!
//! The recorders replace `killpg` with a record and record every walk, holder signal, pidfd signal,
//! `cgroup.kill` write and bare-pid `SIGTERM`, so a mutant that sends by number reaches no process.
//! Each cell's tree is a root `sleep` and a `cat` in its group (in its leaf, holding its marker)
//! that ignores `SIGTERM` and outlives the root. Every cell is checked, and the whole matrix is
//! printed if any cell is wrong.

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
            #[cfg(target_os = "linux")]
            Mechanism::Cgroup => false,
        }
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
            #[cfg(target_os = "linux")]
            Mechanism::Cgroup => crate::ContainMode::Strongest,
        }
    }

    fn containment(self) -> crate::Containment {
        match self {
            Mechanism::Group => crate::Containment::Session,
            #[cfg(target_os = "macos")]
            Mechanism::MarkerWithGroup | Mechanism::MarkerWalk => crate::Containment::FdMarker,
            #[cfg(target_os = "linux")]
            Mechanism::Cgroup => crate::Containment::CgroupV2,
        }
    }

    /// The tree's command: [`TREE`] under this mechanism, with every stdio piped.
    fn configure(self, cmd: &mut crate::Command) {
        cmd.args(["sh", "-c", TREE]);
        cmd.contain_with(self.mode());
        #[cfg(target_os = "macos")]
        if self == Mechanism::Group {
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
    OwnFree,
    OwnReused,
    ForeignFree,
    ForeignReused,
}

impl Reap {
    const ALL: [Reap; 5] = [
        Reap::None,
        Reap::OwnFree,
        Reap::OwnReused,
        Reap::ForeignFree,
        Reap::ForeignReused,
    ];

    fn own(self) -> bool {
        matches!(self, Reap::OwnFree | Reap::OwnReused)
    }

    /// What every read of the root's pid answers after the reap: nothing, or another process.
    fn read(self, root: ProcessId) -> Option<Resolved<ProcessId>> {
        match self {
            Reap::None => None,
            Reap::OwnFree | Reap::ForeignFree => Some(Resolved::Gone),
            Reap::OwnReused | Reap::ForeignReused => Some(Resolved::Found(ProcessId::from_parts_for_test(
                root.pid(),
                root.start_token_raw() + 1,
            ))),
        }
    }
}

/// The tree entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    KillTree,
    TerminateTree,
    GracefulShutdownTree,
}

impl Op {
    const ALL: [Op; 3] = [Op::KillTree, Op::TerminateTree, Op::GracefulShutdownTree];
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
    pidfd: Want,
    cgroup_kill: Want,
}

/// The killpg after this handle's own reap, while the pid names nothing: the group may still have
/// members, but once none survives another process may take the number first.
const KILLPG_AFTER_OWN_REAP: Want = Want::Routed("bindreams/cosca#382, plan A P14");
/// A cgroup's `SIGTERM` goes to each member by the pid `cgroup.procs` lists.
const CGROUP_TERM_BY_PID: Want = Want::Routed("bindreams/cosca#106");

fn expected(mechanism: Mechanism, reap: Reap, op: Op) -> Expected {
    use nix::sys::signal::Signal::{SIGKILL, SIGTERM};
    let reaped = reap != Reap::None;
    let killpg = match (mechanism.has_group(), reap) {
        (false, _) => Want::No,
        (true, Reap::None) => Want::Yes,
        (true, Reap::OwnFree) => KILLPG_AFTER_OWN_REAP,
        (true, _) => Want::No,
    };
    let walk = if mechanism.is_marker() && !reaped {
        Want::Yes
    } else {
        Want::No
    };
    let by_pid = if mechanism.is_cgroup() && op != Op::KillTree {
        CGROUP_TERM_BY_PID
    } else if reaped {
        Want::No
    } else {
        Want::Any
    };
    let holder: Option<&'static [nix::sys::signal::Signal]> = match (mechanism.is_marker(), reaped) {
        (true, true) => Some(match op {
            Op::KillTree => &[SIGKILL],
            Op::TerminateTree => &[SIGTERM],
            Op::GracefulShutdownTree => &[SIGTERM, SIGKILL],
        }),
        // The walk reaches the `cat` first.
        (true, false) => None,
        (false, _) => Some(&[]),
    };
    // The handle backstop, through the pidfd; after a reap it has nothing to reach.
    let pidfd = match (cfg!(target_os = "linux"), reaped, op) {
        (false, _, _) => Want::No,
        (true, true, _) => Want::Any,
        (true, false, Op::TerminateTree) => Want::No,
        (true, false, _) => Want::Yes,
    };
    let cgroup_kill = if mechanism.is_cgroup() && op != Op::TerminateTree {
        Want::Yes
    } else {
        Want::No
    };
    Expected {
        killpg,
        walk,
        by_pid,
        holder,
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
            pidfd: entries.iter().any(|(pid, _, via)| *pid == root && *via == Via::Pidfd),
            cgroup_kill,
        }
    }
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
    if reap != Reap::None {
        child.kill().expect("kill the root");
        if reap.own() {
            child.wait().expect("this handle reaps the root");
        } else {
            crate::test_child::reaped_elsewhere::reap_behind(root);
        }
    }
    let forced = reap.read(child.id()).map(crate::child::fault::force_root_reads);

    let recorders = Recorders::start();
    let _ = match op {
        Op::KillTree => child.kill_tree(),
        Op::TerminateTree => child.terminate_tree(),
        Op::GracefulShutdownTree => child.graceful_shutdown_tree(Duration::ZERO).map(drop),
    };
    let sent = recorders.sent(root, cat);

    // The tree is gone before the drop, which runs under the recorders: it sends no killpg.
    if reap == Reap::None {
        let _ = child.kill();
        let _ = child.wait();
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
    if reap != Reap::None {
        child.kill().expect("kill the root");
        if reap.own() {
            child.wait().await.expect("this handle reaps the root");
        } else {
            crate::test_child::reaped_elsewhere::reap_behind(root);
        }
    }
    let forced = reap.read(child.id()).map(crate::child::fault::force_root_reads);

    let recorders = Recorders::start();
    let _ = match op {
        Op::KillTree => child.kill_tree(),
        Op::TerminateTree => child.terminate_tree(),
        Op::GracefulShutdownTree => child.graceful_shutdown_tree(Duration::ZERO).await.map(drop),
    };
    let sent = recorders.sent(root, cat);

    if reap == Reap::None {
        let _ = child.kill();
        let _ = child.wait().await;
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
        for reap in Reap::ALL {
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

/// The process group, and on macOS both fd markers.
///
/// Mutants: `root_number` answers `Trusted` for any of a foreign reap, an own reap whose pid is
/// reused, or (macOS, an fd marker) an own reap whose pid names nothing; the holders sweep skipped
/// after a reap.
#[skuld::test]
fn tree_paths_send_nothing_by_the_root_number_after_a_reap() {
    check_matrix(&[
        Mechanism::Group,
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
