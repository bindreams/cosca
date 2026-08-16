//! macOS inherited-fd marker containment, end to end. Death is proven by control-socket EOF
//! and life by a control-socket round trip — never by sleeping or polling.
#![cfg(target_os = "macos")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};

#[path = "common/mod.rs"]
mod common;
use common::testbin;

/// `Holder.clexec` is `pub(crate)`, unreachable from this crate; the ONLY observable production
/// effect of `holders()`'s CLOEXEC AND-fold is this warning, so that is what this test asserts on.
const WOULD_LOSE_MARKER_LOG_NEEDLE: &str = "will lose the marker at its next";

/// One tree member's control channel: its pid, and the socket that proves it alive or dead.
struct Member {
    pid: u32,
    sock: TcpStream,
}

impl Member {
    /// Alive, proven positively: a byte in, the same byte back. A dead member EOFs instead.
    fn assert_alive(&mut self, who: &str) {
        self.sock.write_all(b"x").expect("write to the control socket");
        let mut b = [0u8; 1];
        let n = self.sock.read(&mut b).expect("read the control socket");
        assert_eq!(n, 1, "{who} (pid {}) must still be alive and echoing", self.pid);
        assert_eq!(&b, b"x", "{who} echoed {b:?} instead of the byte sent");
    }

    /// Dead, proven by a write failure OR a read failure/EOF on a socket the test still holds.
    /// Write first, exactly like `assert_alive` (`control-echo-pid` only speaks when spoken to,
    /// so a bare read would block forever against a still-alive peer). A dead peer can surface
    /// EITHER way depending on which side of the TCP teardown the kernel processes first: the
    /// probe write can fail immediately (EPIPE/ECONNRESET, if the FIN was already queued), OR
    /// it can succeed and the FOLLOWING read then sees the connection reset (BSD `soreceive`
    /// checks `so_error` before end-of-file, so a dead peer's `read` can return `ECONNRESET`
    /// rather than `Ok(0)`) or plain EOF (`Ok(0)`, if the FIN direction won the race instead).
    /// All three are proof of death; only "the read returns an actual echoed byte" is proof of
    /// life, and that alone panics.
    fn assert_dead(&mut self, who: &str) {
        if self.sock.write_all(b"x").is_err() {
            return; // the peer already closed its end: dead, as expected
        }
        let mut b = [0u8; 1];
        match self.sock.read(&mut b) {
            Ok(0) => {} // EOF: dead, as expected
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
                ) =>
            {
                // The kernel resolved the race the other way (RST before FIN): also dead.
            }
            Ok(n) => panic!("{who} (pid {}) must be dead; it echoed {n} byte(s) instead", self.pid),
            Err(e) => panic!("{who} (pid {}): unexpected control-socket error: {e}", self.pid),
        }
    }
}

/// Spawn the orphan-escapee tree contained. Returns the root child plus the root's and the
/// orphaned grandchild's members, demuxed by tag. Each member publishes `<tag><pid>\n`.
fn spawn_orphan_tree(mode: cosca::ContainMode) -> (cosca::Child, Member, Member) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let child = cosca::Command::new()
        .executable(testbin())
        .args(["cosca_testbin", "spawn-orphan-escapee", &addr])
        .contain_with(mode)
        .spawn()
        .expect("spawn the orphan tree");

    let mut root = None;
    let mut grand = None;
    for _ in 0..2 {
        let (s, _) = listener.accept().expect("accept");
        let mut line = String::new();
        BufReader::new(s.try_clone().expect("clone"))
            .read_line(&mut line)
            .expect("read tag+pid");
        let (tag, pid) = line.trim().split_at(1);
        let m = Member {
            pid: pid.parse().expect("member pid"),
            sock: s,
        };
        match tag {
            "R" => root = Some(m),
            "G" => grand = Some(m),
            other => panic!("unexpected tree tag {other:?}"),
        }
    }
    (child, root.expect("root tag"), grand.expect("grandchild tag"))
}

/// The orphan is provably outside both legacy channels: launchd is its parent, so the ppid
/// walk cannot reach it, and its pgid differs from the root's, so `killpg` misses it.
fn assert_escaped(root_pid: u32, grand_pid: u32) {
    let out = common::output_locked(std::process::Command::new("/bin/ps").args([
        "-o",
        "ppid=,pgid=",
        "-p",
        &grand_pid.to_string(),
    ]))
    .expect("ps the orphan");
    let text = String::from_utf8_lossy(&out.stdout);
    let mut it = text.split_whitespace();
    let ppid: u32 = it.next().expect("ppid").parse().expect("ppid number");
    let pgid: u32 = it.next().expect("pgid").parse().expect("pgid number");
    assert_eq!(ppid, 1, "precondition: the orphan must be reparented to launchd");
    assert_ne!(
        pgid, root_pid,
        "precondition: the orphan must have left the root's process group"
    );
}

/// Cleanup that is never an assertion: SIGKILL anything the test deliberately left running.
fn reap(pids: &[u32]) {
    for pid in pids {
        let _ = common::status_locked(std::process::Command::new("/bin/kill").args(["-9", &pid.to_string()]));
    }
}

#[test]
fn a_contained_macos_root_reports_the_fd_marker_mechanism() {
    let (child, _root, _grand) = spawn_orphan_tree(cosca::ContainMode::Strongest);
    assert_eq!(
        child.containment(),
        cosca::Containment::FdMarker,
        "a contained macOS root must report the strongest channel it achieved"
    );
    child.kill_tree().expect("kill_tree");
}

/// `killpg` misses the orphan (different pgid) and the ppid walk misses it (ppid 1). The
/// marker sweep finds it, and `kill_tree` kills it — proven by EOF on the grandchild's
/// socket, which the test holds open across the teardown.
#[test]
fn kill_tree_reaches_a_setsid_double_forked_reparented_orphan() {
    let (child, _root, mut grand) = spawn_orphan_tree(cosca::ContainMode::Strongest);
    assert_escaped(child.id().pid(), grand.pid);
    child.kill_tree().expect("kill_tree");
    grand.assert_dead("the reparented setsid orphan");
}

#[test]
fn terminate_tree_reaches_the_reparented_orphan() {
    let (child, _root, mut grand) = spawn_orphan_tree(cosca::ContainMode::Strongest);
    assert_escaped(child.id().pid(), grand.pid);
    child.terminate_tree().expect("terminate_tree");
    grand.assert_dead("the reparented setsid orphan under SIGTERM");
    child.kill_tree().expect("kill_tree cleanup");
}

/// `ContainMode::TreeWalk` creates no process group, so the marker is the ONLY channel that
/// can reach this orphan. Without the marker this test fails outright.
#[test]
fn treewalk_mode_reaches_the_orphan_through_the_marker_alone() {
    let (child, _root, mut grand) = spawn_orphan_tree(cosca::ContainMode::TreeWalk);
    assert_escaped(child.id().pid(), grand.pid);
    child.kill_tree().expect("kill_tree");
    grand.assert_dead("the orphan, with no process-group channel available");
}

/// `detach()` drops the marker's read end; that must kill nothing.
#[test]
fn detach_leaves_a_marked_tree_running() {
    let (child, mut root, mut grand) = spawn_orphan_tree(cosca::ContainMode::Strongest);
    let (root_pid, grand_pid) = (root.pid, grand.pid);
    child.detach();
    root.assert_alive("the detached root");
    grand.assert_alive("the detached orphan");
    reap(&[root_pid, grand_pid]);
}

/// Dropping a contained `Child` sweeps the tree, orphan included.
#[test]
fn dropping_a_marked_child_kills_the_reparented_orphan() {
    let (child, _root, mut grand) = spawn_orphan_tree(cosca::ContainMode::Strongest);
    assert_escaped(child.id().pid(), grand.pid);
    drop(child);
    grand.assert_dead("the reparented orphan, on Child::drop");
}

/// The async spawn path (`src/tokio/spawn.rs`) is a hand-maintained mirror of the sync path's
/// Task 5 marker restructuring (widen `spawn_lock` around `prepare()..drop(tcmd)`) — every
/// OTHER test in this file spawns exclusively through `cosca::Command`, so nothing else would
/// ever exercise it. This proves the SAME orphan-reaching property through
/// `cosca::tokio::Command`, not merely "does a marker get installed": a transcription slip in
/// the mirror (e.g. `drop(tcmd)` moved to after the guard is released, reopening the
/// fork-bystander window on the async path alone) would still pass a narrower "marker exists"
/// check, since the marker would still be created — only the ability to actually REACH and
/// kill the reparented orphan depends on the restructuring being right.
#[cfg(feature = "tokio")]
fn spawn_orphan_tree_async(mode: cosca::ContainMode) -> (cosca::tokio::Child, Member, Member) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(testbin())
        .args(["cosca_testbin", "spawn-orphan-escapee", &addr])
        .contain_with(mode);
    let child = cmd.spawn().expect("spawn the orphan tree (tokio)");

    let mut root = None;
    let mut grand = None;
    for _ in 0..2 {
        let (s, _) = listener.accept().expect("accept");
        let mut line = String::new();
        BufReader::new(s.try_clone().expect("clone"))
            .read_line(&mut line)
            .expect("read tag+pid");
        let (tag, pid) = line.trim().split_at(1);
        let m = Member {
            pid: pid.parse().expect("member pid"),
            sock: s,
        };
        match tag {
            "R" => root = Some(m),
            "G" => grand = Some(m),
            other => panic!("unexpected tree tag {other:?}"),
        }
    }
    (child, root.expect("root tag"), grand.expect("grandchild tag"))
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn kill_tree_reaches_a_setsid_double_forked_reparented_orphan_via_tokio_spawn() {
    let (mut child, _root, mut grand) = spawn_orphan_tree_async(cosca::ContainMode::Strongest);
    assert_escaped(child.id().pid(), grand.pid);
    child.kill_tree().expect("kill_tree");
    grand.assert_dead("the reparented setsid orphan (tokio spawn path)");
}

/// Proves the marker survives a REAL `cosca::Command::fd()` mapping through the ACTUAL
/// production wiring (`child_ends.keys()` in `src/child/spawn.rs`, feeding `prepare`'s
/// `reserved` argument) — not `super::install()` called directly with a hand-typed reserved
/// slice (`fdmarker_tests.rs`'s `install_places_the_marker_above_every_reserved_child_fd`,
/// which never spawns) nor a hand-built `command_fds::FdMapping` bypassing `cosca::Command`
/// entirely (`a_child_with_a_colliding_fd_mapping_still_holds_the_marker`). Neither of those
/// exercises the collection logic this test targets, so a future bug there (an fd mapping
/// added after `prepare()` is called, or a merge-slot fd omitted from the `reserved` vec) would
/// not be caught by either.
///
/// The marker's actual placed fd number is not observable from an external integration test
/// (`prepare`/`install` are crate-private), so this cannot assert "the marker landed above fd
/// N" directly. Instead it reserves a WIDE, contiguous range (64..=90, comfortably straddling
/// `HIGH_FLOOR`) with real `.fd()` mappings, so `child_ends.keys()` — the real production
/// source of `prepare`'s `reserved` argument — must correctly report EVERY one of them for the
/// marker to land clear of all of them, whichever exact number it picks. The orphan-reaching
/// proof (not merely `child.containment()`) is the actual property under test: if the
/// collection silently dropped an entry and the marker landed on it, the child's descriptor at
/// that number would be the caller's `Stdio::null()`, not the marker, and the orphan — whose
/// only channel under `ContainMode::TreeWalk` is the marker — would survive `kill_tree()`.
#[test]
fn kill_tree_reaches_the_orphan_through_a_real_wide_fd_mapping() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let mut cmd = cosca::Command::new();
    cmd.executable(testbin())
        .args(["cosca_testbin", "spawn-orphan-escapee", &addr])
        .contain_with(cosca::ContainMode::TreeWalk);
    for slot in 64..=90 {
        cmd.fd(slot, cosca::Stdio::null()).expect("map a real child fd");
    }
    let child = cmd
        .spawn()
        .expect("spawn the orphan tree with a wide reserved-fd range");

    let mut root = None;
    let mut grand = None;
    for _ in 0..2 {
        let (s, _) = listener.accept().expect("accept");
        let mut line = String::new();
        BufReader::new(s.try_clone().expect("clone"))
            .read_line(&mut line)
            .expect("read tag+pid");
        let (tag, pid) = line.trim().split_at(1);
        let m = Member {
            pid: pid.parse().expect("member pid"),
            sock: s,
        };
        match tag {
            "R" => root = Some(m),
            "G" => grand = Some(m),
            other => panic!("unexpected tree tag {other:?}"),
        }
    }
    let (_root, mut grand) = (root.expect("root tag"), grand.expect("grandchild tag"));

    assert_escaped(child.id().pid(), grand.pid);
    child.kill_tree().expect("kill_tree");
    grand.assert_dead("the orphan, reachable only via a marker that must have survived a real, wide caller fd mapping");
}

/// `holders()` reports a holder as CLOEXEC only when EVERY matching descriptor is (#59): a
/// regression to first-fd-wins would misreport a holder that also keeps a non-CLOEXEC copy. The
/// testbin dups a second, CLOEXEC copy of its inherited marker fd, which the correct AND-fold
/// must not let outvote the still-open, non-CLOEXEC original.
///
/// The testbin is TOLD the marker's fd number over the control socket (`Child::test_fdmarker_fd`
/// — this crate's own bookkeeping from installing the marker), not left to infer it from ambient
/// process state. An earlier version had the testbin scan its own open fds for "the one nobody
/// else explains"; that passed locally but was flaky on a GitHub-hosted macOS runner, which
/// hands the process extra inherited descriptors the scan could not tell apart from the marker.
#[test]
fn holders_and_folds_cloexec_across_a_holder_with_a_mixed_copy() {
    common::install_log_capture();
    let mark = common::log_mark();

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();
    let child = cosca::Command::new()
        .executable(testbin())
        .args(["cosca_testbin", "control-block-mixed-cloexec-marker", &addr, "R"])
        .contain()
        .spawn()
        .expect("spawn the mixed-cloexec holder");
    let marker_fd = child
        .test_fdmarker_fd()
        .expect("Strongest containment on macOS must install an fd marker");

    let (mut sock, _) = listener.accept().expect("accept");
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("read tag");
    writeln!(sock, "{marker_fd}").expect("send the marker fd to the testbin child");

    child.kill_tree().expect("kill_tree");
    assert!(
        !common::contains_since(mark, WOULD_LOSE_MARKER_LOG_NEEDLE),
        "a holder that still keeps a non-CLOEXEC copy of the marker must not be reported as \
         about to lose it — the AND-fold must have regressed to first-fd-wins"
    );
}
