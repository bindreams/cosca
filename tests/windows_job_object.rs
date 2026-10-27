//! The public `cosca::Job` primitive, end to end: a caller that spawns its own process via a raw
//! `CreateProcessW` (never going through `cosca::Command`) follows the mandatory
//! suspend/assign/resume sequence from `cosca::Job`'s own docs, and the kernel guarantee that
//! buys must actually hold — every descendant, including a grandchild the root spawns AFTER
//! being resumed, is genuinely reachable through the job.
//!
//! Both required behaviors need a real, provably-alive descendant tree, not merely "hasn't been
//! reaped yet": `control-block`'s EOF-on-death is proof of death, never proof of life. Both
//! members here run the testbin's `control-echo-pid` round-trip (via `spawn-grandchild-echo`):
//! alive = a real write/read round trip. Death is proven by the exit event in
//! `kill_tree_reaps_every_descendant` and `dropping_a_live_job_reaps_every_descendant`, because a
//! job kill only starts termination.

#[cfg(windows)]
use std::io::{BufRead, BufReader};
#[cfg(windows)]
use std::net::TcpListener;
#[cfg(windows)]
use std::os::windows::io::{BorrowedHandle, RawHandle};

#[cfg(windows)]
#[path = "common/mod.rs"]
mod common;

#[cfg(windows)]
use windows::core::PWSTR;
#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
#[cfg(windows)]
use windows::Win32::System::Threading::{
    CreateProcessW, ResumeThread, TerminateProcess, WaitForSingleObject, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    PROCESS_INFORMATION, STARTUPINFOW,
};

#[cfg(windows)]
/// A process created `CREATE_SUSPENDED` via a raw `CreateProcessW` call — never through
/// `cosca::Command` — so the test genuinely exercises the caller sequence `cosca::Job`'s docs
/// describe: create suspended, assign, only then resume.
struct Suspended {
    process: HANDLE,
    thread: HANDLE,
    pid: u32,
}

#[cfg(windows)]
impl Suspended {
    /// Spawn `exe` with `args` (argv[1..]), suspended. The command line is built with
    /// `cosca::quote::windows::join_wide` rather than hand-rolled quoting.
    fn spawn(exe: &str, args: &[&str], extra_env: &[(&str, &str)]) -> Suspended {
        let wide_args: Vec<Vec<u16>> = std::iter::once(exe)
            .chain(args.iter().copied())
            .map(|a| a.encode_utf16().collect())
            .collect();
        let refs: Vec<&[u16]> = wide_args.iter().map(Vec::as_slice).collect();
        let mut cmdline = cosca::quote::windows::join_wide(&refs);
        cmdline.push(0); // CreateProcessW requires a NUL-terminated, writable buffer.

        let si = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();
        // Our environment plus the accept-handshake opt-in and `extra_env`, as a UTF-16 block.
        let overrides = [(common::ACK_ENV, "1")].into_iter().chain(extra_env.iter().copied());
        let env =
            common::windows_env::env_block(std::env::vars_os().chain(overrides.map(|(k, v)| (k.into(), v.into()))));
        // Serialized against the crate's own inheritable-handle window, exactly like
        // `tests/windows_console_identity.rs`'s `probe_raw` — a raw spawn that bypasses
        // `cosca::Command` entirely still needs to be ordered against it.
        let created = {
            let _guard = cosca::test_spawn_lock();
            // SAFETY: `cmdline` is a NUL-terminated, writable UTF-16 buffer; `si`/`pi` are
            // valid, correctly-sized in/out params; no handles are inherited.
            unsafe {
                CreateProcessW(
                    None,
                    Some(PWSTR(cmdline.as_mut_ptr())),
                    None,
                    None,
                    false,
                    CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                    Some(env.as_ptr().cast()),
                    None,
                    &si,
                    &mut pi,
                )
            }
        };
        created.expect("CreateProcessW(CREATE_SUSPENDED)");
        Suspended {
            process: pi.hProcess,
            thread: pi.hThread,
            pid: pi.dwProcessId,
        }
    }

    /// Borrow the process handle for [`cosca::Job::assign`]. The borrow does not outlive this
    /// call; `Suspended` keeps owning (and eventually closing) the real handle.
    fn borrow_process(&self) -> BorrowedHandle<'_> {
        let raw: RawHandle = self.process.0;
        // SAFETY: `self.process` is a live handle owned by `self`, which outlives this borrow.
        unsafe { BorrowedHandle::borrow_raw(raw) }
    }

    /// Resume the (single) initial thread. Must only be called after the process has been
    /// assigned to a job — see `cosca::Job`'s mandatory sequence.
    fn resume(&mut self) {
        // SAFETY: `self.thread` is the live, still-suspended main thread from `CreateProcessW`.
        let prev = unsafe { ResumeThread(self.thread) };
        assert_eq!(
            prev, 1,
            "pid {}: a CREATE_SUSPENDED process's main thread must resume from exactly one suspend",
            self.pid
        );
    }
}

#[cfg(windows)]
impl common::Target for Suspended {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn has_exited(&mut self) -> bool {
        // SAFETY: `self.process` is a live handle owned by `self`, which keeps the pid stable.
        unsafe { WaitForSingleObject(self.process, 0) == WAIT_OBJECT_0 }
    }
}

#[cfg(windows)]
impl Drop for Suspended {
    fn drop(&mut self) {
        // Best-effort cleanup: whether the tree is contained, disarmed, or already dead by the
        // time a test ends, nothing should be left running past it. `TerminateProcess` on an
        // already-exited process is a harmless failure.
        // SAFETY: `self.process`/`self.thread` are live, owned handles.
        unsafe {
            let _ = TerminateProcess(self.process, 1);
            let _ = CloseHandle(self.thread);
            let _ = CloseHandle(self.process);
        }
    }
}

#[cfg(windows)]
/// Spawn the testbin's `spawn-grandchild-echo` tree, contained: create the root suspended,
/// assign it to a fresh `cosca::Job`, resume it, then demux both members' `<tag><pid>\n`
/// handshakes by tag. The grandchild is spawned by the ROOT after resume — proving the job
/// reaches a descendant this test process never itself created or assigned.
fn spawn_contained_tree() -> (Suspended, cosca::Job, common::Member, common::Member) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr").to_string();

    let (report, report_addr) = common::bind_report();
    let mut root = Suspended::spawn(
        env!("CARGO_BIN_EXE_cosca_testbin"),
        &["spawn-grandchild-echo", &addr],
        &[
            (common::GC_PID_ADDR_ENV, &report_addr),
            (common::RELEASED_EXIT_ENV, &common::RELEASED_EXIT_CODE.to_string()),
        ],
    );
    // Step 1 (spawn suspended) already happened above. Step 2: assign, while still frozen.
    let job = cosca::Job::assign(root.borrow_process()).expect("Job::assign");
    // Step 3: only now resume.
    root.resume();
    let watched = common::report_grandchild_of(report, &mut root);

    // Both members' `<tag><pid>\n` handshakes, in arrival order; the root is watched throughout
    // and the grandchild until it has connected.
    let mut handshakes: Vec<(String, u32)> = Vec::new();
    let socks = common::accept_tree_also(&listener, &mut root, watched, |s| {
        let mut line = String::new();
        BufReader::new(s.try_clone().expect("clone"))
            .read_line(&mut line)
            .expect("read tag+pid");
        let (tag, pid) = line.trim().split_at(1);
        handshakes.push((tag.to_string(), pid.parse().expect("member pid")));
        tag == "G"
    });
    let mut root_member = None;
    let mut grand_member = None;
    for ((tag, pid), sock) in handshakes.into_iter().zip(socks) {
        // Both members are alive and blocked on their sockets, which this test holds; see
        // `common::Member` for why a pid captured earlier cannot be trusted at teardown.
        let m = common::Member::new(sock, pid);
        match tag.as_str() {
            "R" => root_member = Some(m),
            "G" => grand_member = Some(m),
            other => panic!("unexpected tree tag {other:?}"),
        }
    }
    (
        root,
        job,
        root_member.expect("root tag"),
        grand_member.expect("grandchild tag"),
    )
}

#[cfg(windows)]
/// The contract this whole primitive exists for: a caller that spawns its own process
/// (suspend/assign/resume, never `cosca::Command`) still gets the full kernel guarantee —
/// `kill_tree()` reaps every descendant, including one the root spawned after being resumed.
#[skuld::test]
fn kill_tree_reaps_every_descendant() {
    let (_root, job, mut root_member, mut grand_member) = spawn_contained_tree();
    root_member.assert_alive("the root, before teardown");
    grand_member.assert_alive("the grandchild, before teardown");

    job.kill_tree().expect("kill_tree");

    // `TerminateJobObject` only starts termination, so the proof is each member's exit event and
    // kill exit code, with its socket released so a missing kill ends the wait too.
    common::assert_members_killed(vec![
        (root_member, "the root, after kill_tree"),
        (grand_member, "the grandchild, after kill_tree"),
    ]);
}

#[cfg(windows)]
/// The other half of the contract: `disarm()` is "session ended normally, leave background
/// processes alone" — dropping (or having already dropped) the `Job` afterward must not kill
/// anything, for the whole tree, not just the root.
#[skuld::test]
fn disarm_leaves_every_descendant_running() {
    let (root, job, mut root_member, mut grand_member) = spawn_contained_tree();
    root_member.assert_alive("the root, before disarm");
    grand_member.assert_alive("the grandchild, before disarm");

    job.disarm();
    drop(job);

    root_member.assert_alive("the root, after disarm + drop(Job)");
    grand_member.assert_alive("the grandchild, after disarm + drop(Job)");

    // Cleanup: `Suspended::drop` only reaches the root; the grandchild survives it, because a
    // disarmed job is by design no longer this test's tool for reaching it. Dropping a
    // `common::Member` terminates it through its own pinned handle.
    root_member.sock.shutdown(std::net::Shutdown::Both).ok();
    grand_member.sock.shutdown(std::net::Shutdown::Both).ok();
    drop(root);
}

#[cfg(windows)]
/// Dropping a live `Job` reaps the tree, exactly as `kill_tree` does.
///
/// This is the path a caller reaches by doing nothing, and it is the one the `#[must_use]` on
/// `assign` warns about — so it needs coverage of its own rather than being inferred from
/// `kill_tree`'s. The distinction matters: `kill_tree` terminates explicitly, whereas this
/// relies on `KILL_ON_JOB_CLOSE` firing when the last handle closes.
#[skuld::test]
fn dropping_a_live_job_reaps_every_descendant() {
    let (root, job, mut root_member, mut grand_member) = spawn_contained_tree();
    root_member.assert_alive("the root, before drop");
    grand_member.assert_alive("the grandchild, before drop");

    // Closing the last job handle only STARTS termination, and its exit code is only required not to
    // be a release or crash code.
    //
    // Soundness rests on `CloseHandle` of the last job handle terminating every member before it
    // returns (Job Objects docs: it "terminates all associated processes and then destroys the job
    // object"), so no member can read the release. If that failed the test would fail on correct
    // code, never pass on broken code.
    drop(job);

    common::assert_members_not_released(vec![
        (root_member, "the root, after dropping the Job"),
        (grand_member, "the grandchild, after dropping the Job"),
    ]);
    drop(root);
}

#[cfg(windows)]
/// The block keeps names Windows keeps apart (`straße`/`STRASSE`, two different malformed names)
/// and merges names differing only in case, the later spelling winning. Its entries come out in
/// ascending ordinal-ignore-case order, as `CreateProcessW` requires.
#[skuld::test]
fn env_block_keys_names_by_ordinal_per_unit_case_folding() {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    let lone = |unit: u16| OsString::from_wide(&[u16::from(b'M'), unit]);
    let block = common::windows_env::env_block([
        ("straße".into(), "1".into()),
        ("STRASSE".into(), "2".into()),
        (lone(0xD800), "3".into()),
        (lone(0xD801), "4".into()),
        ("Path".into(), "5".into()),
        ("PATH".into(), "6".into()),
    ]);
    let entries: Vec<String> = block
        .split(|&u| u == 0)
        .filter(|e| !e.is_empty())
        .map(String::from_utf16_lossy)
        .collect();
    assert_eq!(entries.len(), 5, "distinct names must stay distinct: {entries:?}");
    assert!(entries.contains(&"straße=1".to_string()), "{entries:?}");
    assert!(entries.contains(&"STRASSE=2".to_string()), "{entries:?}");
    assert!(
        entries.contains(&"PATH=6".to_string()) && !entries.iter().any(|e| e == "Path=5"),
        "{entries:?}"
    );
    assert!(block.ends_with(&[0, 0]), "the block ends with a double NUL");
    let names: Vec<&[u16]> = block
        .split(|&u| u == 0)
        .filter(|e| !e.is_empty())
        .map(|e| &e[..e.iter().position(|&u| u == u16::from(b'=')).expect("NAME=value")])
        .collect();
    // The oracle is `CompareStringOrdinal` itself, not the helper's own ordering.
    for pair in names.windows(2) {
        // SAFETY: both slices are valid UTF-16 buffers that outlive the call; the API only reads them.
        let order = unsafe { windows::Win32::Globalization::CompareStringOrdinal(pair[0], pair[1], true) };
        assert_eq!(
            order,
            windows::Win32::Globalization::CSTR_LESS_THAN,
            "entries must be strictly ascending: {:?} then {:?}",
            String::from_utf16_lossy(pair[0]),
            String::from_utf16_lossy(pair[1])
        );
    }
    // The two malformed names are told apart by the raw units, which a lossy decode cannot show.
    let raw: Vec<&[u16]> = block.split(|&u| u == 0).collect();
    for unit in [0xD800u16, 0xD801] {
        assert!(
            raw.iter()
                .any(|e| e.first() == Some(&u16::from(b'M')) && e.get(1) == Some(&unit)),
            "{unit:#x}"
        );
    }
}

#[cfg(windows)]
/// An empty environment is still a valid block: two NULs, the first ending the absent first entry.
#[skuld::test]
fn env_block_of_nothing_is_a_double_nul() {
    assert_eq!(common::windows_env::env_block([]), [0, 0]);
}

#[path = "../src/test_harness.rs"]
mod test_harness;

fn main() {
    #[cfg(windows)]
    common::install_log_capture();
    let mut runner = skuld::TestRunner::new();
    runner.libtest_names();
    runner.require_known_labels();
    runner.run()
}
