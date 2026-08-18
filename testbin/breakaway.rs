//! The `report-breakaway <report-addr> <shape> <vehicle>` mode: build one job-object shape,
//! assign THIS process to it, spawn a child through one of three vehicles, and report where the
//! child landed.
//!
//! It lives in a short-lived helper because assigning a process to a job is irreversible — the
//! test binary cannot do it and keep running its other tests.
//!
//! The `limits` field is the helper's OWN reading of the job it built, taken through
//! `QueryInformationJobObject`. It is not cosca's verdict: this binary compiles as its own crate,
//! so the library's `pub(crate)` probe is not visible to it. That independence is the point — a
//! shape that was not built the way the test names it fails loudly instead of measuring something
//! else.

use std::io::{Read, Write};
use std::mem::size_of;
use std::net::{TcpListener, TcpStream};

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JobObjectBasicLimitInformation,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    JOBOBJECT_BASIC_LIMIT_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT,
    JOB_OBJECT_LIMIT_BREAKAWAY_OK, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, CREATE_BREAKAWAY_FROM_JOB, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// A job with `limits`, with THIS process assigned to it. `None` when either step failed, which
/// the caller reports as its own token rather than proceeding to measure a job it did not build.
///
/// The breakaway limits are **extended**-limit flags: setting them through
/// `JobObjectBasicLimitInformation` returns `ERROR_INVALID_PARAMETER`, at runtime and not at
/// compile time. The read side is asymmetric on purpose — the query class returns the basic
/// structure, the setter needs the extended one.
fn job_with_self(limits: JOB_OBJECT_LIMIT) -> Option<HANDLE> {
    // SAFETY: standard Win32; `info` is fully initialised (zeroed by default()), and the handle
    // stays owned by this short-lived process.
    unsafe {
        let job = CreateJobObjectW(None, windows::core::PCWSTR::null()).ok()?;
        if limits.0 != 0 {
            let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            info.BasicLimitInformation.LimitFlags = limits;
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                std::ptr::addr_of!(info).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
            .ok()?;
        }
        AssignProcessToJobObject(job, GetCurrentProcess()).ok()?;
        Some(job)
    }
}

/// This process's current (innermost) job limits, as a whitespace-free token.
fn own_limits_token() -> &'static str {
    let mut info = JOBOBJECT_BASIC_LIMIT_INFORMATION::default();
    // SAFETY: standard Win32; `info` is a valid, correctly-sized out-param. `None` asks about the
    // calling process's own job.
    let ok = unsafe {
        QueryInformationJobObject(
            None,
            JobObjectBasicLimitInformation,
            std::ptr::addr_of_mut!(info).cast(),
            size_of::<JOBOBJECT_BASIC_LIMIT_INFORMATION>() as u32,
            None,
        )
    };
    if ok.is_err() {
        return "query-failed";
    }
    let breakaway = info.LimitFlags & JOB_OBJECT_LIMIT_BREAKAWAY_OK != JOB_OBJECT_LIMIT(0);
    let silent = info.LimitFlags & JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK != JOB_OBJECT_LIMIT(0);
    match (breakaway, silent) {
        (true, true) => "both",
        (true, false) => "breakaway-ok",
        (false, true) => "silent-breakaway-ok",
        (false, false) => "none",
    }
}

/// Is `handle` in `job`? `None` when the query failed.
fn in_job(handle: HANDLE, job: Option<HANDLE>) -> Option<bool> {
    let mut result = windows::core::BOOL(0);
    // SAFETY: standard Win32; `handle` pins a live process, `result` is a valid out-param.
    unsafe { IsProcessInJob(handle, job, &mut result) }.ok()?;
    Some(result.as_bool())
}

fn tri(v: Option<bool>) -> &'static str {
    match v {
        Some(true) => "1",
        Some(false) => "0",
        None => "?",
    }
}

/// The child every vehicle spawns: `control-block`, which tags its socket and then blocks. The
/// tag read is the real edge proving the child started — a "successful" spawn into an image that
/// never ran would otherwise look identical.
struct Spawned {
    outcome: String,
    /// Kept alive across the measurement so the pid cannot be recycled, and so the child is torn
    /// down when this helper exits.
    _child: Option<ChildHandle>,
    /// The child's control socket, held open so the child stays blocked on its read.
    _ctrl: Option<TcpStream>,
    pid: Option<u32>,
}

/// Both variants exist to be HELD: keeping the value alive is what keeps the child's pid from
/// being recycled while it is measured, and what tears the child down when this helper exits.
enum ChildHandle {
    Raw(std::process::Child),
    Cosca(#[allow(dead_code)] cosca::Child),
}

impl Drop for ChildHandle {
    fn drop(&mut self) {
        if let ChildHandle::Raw(c) = self {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// Encode a spawn outcome as ONE whitespace-free token.
fn raw_outcome(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(code) => format!("Io-{code}"),
        None => "Io-unknown".to_string(),
    }
}

fn cosca_outcome(e: &cosca::error::Error) -> String {
    match e {
        cosca::error::Error::Containment { .. } => "Containment".to_string(),
        cosca::error::Error::Io(io) => raw_outcome(io),
        cosca::error::Error::Unsupported { .. } => "Unsupported".to_string(),
        other => format!("Other-{}", other.to_string().replace(char::is_whitespace, "_")),
    }
}

fn spawn_child(vehicle: &str, request: bool, listener: &TcpListener, addr: &str) -> Spawned {
    let exe = std::env::current_exe().expect("current_exe");
    let (outcome, child, pid) = match vehicle {
        "raw" => {
            use std::os::windows::process::CommandExt;
            let mut cmd = std::process::Command::new(&exe);
            cmd.args(["control-block", addr, "C"]).creation_flags(if request {
                CREATE_BREAKAWAY_FROM_JOB.0
            } else {
                0
            });
            match cmd.spawn() {
                Ok(c) => {
                    let pid = c.id();
                    ("Ok".to_string(), Some(ChildHandle::Raw(c)), Some(pid))
                }
                Err(e) => (raw_outcome(&e), None, None),
            }
        }
        "argv" | "exec" => {
            let mut cmd = cosca::Command::new();
            if vehicle == "exec" {
                cmd.executable(&exe).args(["cosca_testbin", "control-block", addr, "C"]);
            } else {
                cmd.args([exe.to_string_lossy().as_ref(), "control-block", addr, "C"]);
            }
            if request {
                cmd.breakaway_from_job();
            }
            match cmd.spawn() {
                Ok(c) => {
                    let pid = c.id().pid();
                    ("Ok".to_string(), Some(ChildHandle::Cosca(c)), Some(pid))
                }
                Err(e) => (cosca_outcome(&e), None, None),
            }
        }
        other => panic!("unknown breakaway vehicle {other:?}"),
    };
    // The real edge: the child connected and tagged, so it is running and its job membership is
    // settled. No timer anywhere.
    let ctrl = child.as_ref().map(|_| {
        let (mut sock, _) = listener.accept().expect("accept the child's control socket");
        let mut tag = [0u8; 1];
        sock.read_exact(&mut tag).expect("read the child's tag");
        assert_eq!(&tag, b"C", "wrong child tag");
        sock
    });
    Spawned {
        outcome,
        _child: child,
        _ctrl: ctrl,
        pid,
    }
}

/// Connect to `report_addr` FIRST, so a panic below reaches the test as socket EOF rather than a
/// hang, then report and block until the test closes the socket.
pub fn run(report_addr: &str, shape: &str, vehicle: &str) {
    let mut sock: TcpStream = std::net::TcpStream::connect(report_addr).expect("connect report socket");

    let request = !shape.ends_with("no-request");
    let (outer, inner) = match shape {
        "permit" | "permit-no-request" => (None, job_with_self(JOB_OBJECT_LIMIT_BREAKAWAY_OK)),
        "forbid" => (None, job_with_self(JOB_OBJECT_LIMIT(0))),
        "silent" | "silent-no-request" => (None, job_with_self(JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK)),
        "nested" => {
            // A: forbids breakaway. B: permits it, and becomes a CHILD job of A because this
            // process is already in A when it is assigned. A child that breaks away from B must
            // then stop at A.
            let a = job_with_self(JOB_OBJECT_LIMIT(0));
            let b = if a.is_some() {
                job_with_self(JOB_OBJECT_LIMIT_BREAKAWAY_OK)
            } else {
                None
            };
            (a, b)
        }
        other => panic!("unknown breakaway shape {other:?}"),
    };

    // A failed build is its own token, never swallowed: otherwise the helper would measure a
    // limit-less job while the test believed it built a permitting one.
    let limits = if inner.is_none() {
        "set-failed"
    } else {
        own_limits_token()
    };

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the child's control listener");
    let child_addr = listener.local_addr().unwrap().to_string();
    let spawned = if inner.is_some() {
        spawn_child(vehicle, request, &listener, &child_addr)
    } else {
        Spawned {
            outcome: "not-attempted".to_string(),
            _child: None,
            _ctrl: None,
            pid: None,
        }
    };

    // Windows cannot recycle a pid while a handle to the process is open, and the live child
    // value above holds one, so this handle cannot answer about an unrelated process.
    let child_handle = spawned.pid.and_then(|pid| {
        // SAFETY: standard Win32; the live child value pins `pid`.
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()
    });
    let (in_inner, in_outer, in_any) = match child_handle {
        Some(h) => (in_job(h, inner), in_job(h, outer), in_job(h, None)),
        None => (None, None, None),
    };
    // `outer` is only meaningful for the nested shape; every other shape reports `?`.
    let in_outer = if outer.is_some() { in_outer } else { None };

    let line = format!(
        "limits={limits} spawn={} in_inner={} in_outer={} in_any={}\n",
        spawned.outcome,
        tri(in_inner),
        tri(in_outer),
        tri(in_any),
    );
    sock.write_all(line.as_bytes()).expect("write report");
    sock.flush().expect("flush report");

    let mut buf = [0u8; 1];
    let _ = sock.read(&mut buf);
}
