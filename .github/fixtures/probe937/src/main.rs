//! Issue #937 probe: does Toolhelp list a process that has exited while its handle is held?
//!
//! Per trial: spawn, make it exit (kill or by itself), `wait()` (the handle stays held), then take
//! Toolhelp snapshots until the pid is absent, counting them. A process still listed after
//! `HELD_BOUND` snapshots is reported as "stuck while held"; its handle is then dropped and
//! snapshots continue until the pid is absent (counted again).
//!
//! The run ends in a panic carrying the whole table, so CI shows it as the job's failure.

use std::process::{Child, Command, Stdio};

use windows::Win32::Foundation::ERROR_NO_MORE_FILES;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

/// Snapshots a held, exited process may be listed in before it is called stuck. Measurement bound.
const HELD_BOUND: u32 = 2000;
/// Snapshots after the handle is dropped before the probe gives up. Measurement bound.
const DROPPED_BOUND: u32 = 2000;
const TRIALS: u32 = 200;

#[derive(Clone, Copy)]
struct Listing {
    threads: u32,
    ppid: u32,
}

fn listed(pid: u32) -> Option<Listing> {
    // SAFETY: an owned snapshot handle, closed before return.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).expect("snapshot");
        let mut entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let end = windows::core::HRESULT::from_win32(ERROR_NO_MORE_FILES.0);
        let mut found = None;
        let mut step = Process32FirstW(snap, &mut entry);
        loop {
            match step {
                Ok(()) => {
                    if entry.th32ProcessID == pid {
                        found = Some(Listing {
                            threads: entry.cntThreads,
                            ppid: entry.th32ParentProcessID,
                        });
                    }
                }
                Err(e) if e.code() == end => break,
                Err(e) => panic!("process walk: {e}"),
            }
            step = Process32NextW(snap, &mut entry);
        }
        _ = windows::Win32::Foundation::CloseHandle(snap);
        found
    }
}

#[derive(Default)]
struct Tally {
    name: &'static str,
    /// Trials listed at the first snapshot after the wait.
    listed_first: u32,
    /// Trials absent at the first snapshot.
    absent_first: u32,
    /// For trials listed first and then absent while held: the snapshot count it took.
    gone_held_after: Vec<u32>,
    /// Trials still listed after HELD_BOUND snapshots with the handle held.
    stuck_held: u32,
    /// Of the stuck: snapshots after the handle was dropped until absent (u32::MAX = never).
    gone_dropped_after: Vec<u32>,
    /// Listing of the first listed trial: (threads, ppid is this process).
    sample: Option<(u32, bool)>,
}

fn trial(tally: &mut Tally, mut child: Child, kill: bool) {
    let pid = child.id();
    if kill {
        child.kill().expect("kill");
    }
    child.wait().expect("wait");
    // The handle is held by `child` from here on.
    let mut attempts = 0u32;
    let mut first = true;
    let stuck = loop {
        attempts += 1;
        match listed(pid) {
            None => break false,
            Some(l) => {
                if first {
                    tally.listed_first += 1;
                    if tally.sample.is_none() {
                        tally.sample = Some((l.threads, l.ppid == std::process::id()));
                    }
                }
                first = false;
                if attempts >= HELD_BOUND {
                    break true;
                }
            }
        }
    };
    if first {
        tally.absent_first += 1;
    } else if !stuck {
        tally.gone_held_after.push(attempts);
    }
    if stuck {
        tally.stuck_held += 1;
        drop(child);
        let mut after = 0u32;
        let gone = loop {
            after += 1;
            if listed(pid).is_none() {
                break true;
            }
            if after >= DROPPED_BOUND {
                break false;
            }
        };
        tally.gone_dropped_after.push(if gone { after } else { u32::MAX });
    }
}

fn findstr() -> Child {
    // The failing test's blocker: `held_std_blocker(piped stdout)`.
    Command::new("findstr")
        .arg("x")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn findstr")
}

fn cmd_with_ping() -> Child {
    // The treewalk row's root (a `cmd.exe` holding a `ping`), with a shorter ping.
    Command::new("cmd.exe")
        .args(["/c", "ping.exe", "-n", "4", "127.0.0.1"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn cmd")
}

fn cmd_exit() -> Child {
    Command::new("cmd.exe")
        .args(["/c", "exit", "0"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn cmd exit")
}

fn text(program: &str, args: &[&str]) -> String {
    match Command::new(program).args(args).output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).trim().replace('\r', "").replace('\n', " | "),
        Err(e) => format!("<{e}>"),
    }
}

fn describe(t: &Tally) -> String {
    let mut hist = std::collections::BTreeMap::new();
    for a in &t.gone_held_after {
        *hist.entry(*a).or_insert(0u32) += 1;
    }
    format!(
        "{name}: trials={TRIALS} listed_at_first_snapshot={lf} absent_at_first_snapshot={af} \
         absent_after_n_snapshots_while_held(n:count)={hist:?} stuck_while_held(>={HELD_BOUND})={sh} \
         after_drop_snapshots_until_absent={dd:?} first_listed_sample(cntThreads,ppid_is_us)={s:?}",
        name = t.name,
        lf = t.listed_first,
        af = t.absent_first,
        sh = t.stuck_held,
        dd = t.gone_dropped_after,
        s = t.sample,
    )
}

fn main() {
    let key = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let mut report = vec![format!(
        "arch={} ver=[{}] UBR=[{}] DisplayVersion=[{}]",
        std::env::consts::ARCH,
        text("cmd.exe", &["/c", "ver"]),
        text("reg", &["query", key, "/v", "UBR"]),
        text("reg", &["query", key, "/v", "DisplayVersion"]),
    )];
    type Spawn = fn() -> Child;
    let variants: [(&'static str, Spawn, bool); 4] = [
        ("findstr_killed (tree_tests shape)", findstr, true),
        ("cmd_with_ping_killed (treewalk_tests shape)", cmd_with_ping, true),
        ("cmd_exits_by_itself", cmd_exit, false),
        ("findstr_killed_again", findstr, true),
    ];
    for (name, spawn, kill) in variants {
        let mut tally = Tally {
            name,
            ..Default::default()
        };
        for _ in 0..TRIALS {
            trial(&mut tally, spawn(), kill);
        }
        let line = describe(&tally);
        println!("{line}");
        report.push(line);
    }
    panic!("probe937 report:\n{}", report.join("\n"));
}
