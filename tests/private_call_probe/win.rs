//! W1-W9: `NtQueryInformationProcess` classes 92, 64 and 0, `NtTerminateProcess`, Toolhelp, and
//! `SystemBootEnvironmentInformation`.

use std::ffi::c_void;
use std::io::{BufRead, BufReader, Read};
use std::os::windows::io::AsRawHandle;
use std::process::{Child, Command, Stdio};

use windows::core::{w, PWSTR};
use windows::Wdk::System::SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS};
use windows::Wdk::System::SystemServices::RtlGetVersion;
use windows::Wdk::System::Threading::{NtQueryInformationProcess, NtTerminateProcess, PROCESSINFOCLASS};
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HANDLE_FLAGS, HLOCAL, NTSTATUS};
use windows::Win32::Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT};
use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows::Win32::Security::{
    CreateRestrictedToken, GetLengthSid, GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation,
    SetTokenInformation, TokenElevation, TokenIntegrityLevel, DISABLE_MAX_PRIVILEGE, PSID, SID_AND_ATTRIBUTES,
    TOKEN_ACCESS_MASK, TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_MANDATORY_LABEL,
    TOKEN_QUERY,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::SystemInformation::OSVERSIONINFOW;
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, GetCurrentProcess, OpenProcess, OpenProcessToken, TerminateProcess, WaitForSingleObject,
    CREATE_NO_WINDOW, PROCESS_ACCESS_RIGHTS, PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, STARTF_USESTDHANDLES, STARTUPINFOW,
};
use windows::Win32::System::Threading::INFINITE;

use super::KillOnDrop;

const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_PROCESS_IS_TERMINATING: u32 = 0xC000_010A;

const CLASS_BASIC: i32 = 0;
const CLASS_TELEMETRY: i32 = 64;
const CLASS_SEQUENCE: i32 = 92;
const SYSTEM_BOOT_ENVIRONMENT_INFORMATION: i32 = 90;

/// Owns a handle.
struct Owned(HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: the handle is owned by this value.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// Opens `pid`; the error is the HRESULT of the failure.
fn open(pid: u32, access: PROCESS_ACCESS_RIGHTS) -> Result<Owned, u32> {
    // SAFETY: plain call.
    unsafe { OpenProcess(access, false, pid) }.map(Owned).map_err(|e| e.code().0 as u32)
}

/// `(NTSTATUS, ReturnLength)`.
fn nt_query(h: HANDLE, class: i32, buf: *mut c_void, len: u32) -> (u32, u32) {
    let mut ret = 0u32;
    // SAFETY: the caller passes a buffer of `len` bytes.
    let st = unsafe { NtQueryInformationProcess(h, PROCESSINFOCLASS(class), buf, len, &mut ret) };
    (st.0 as u32, ret)
}

/// Class 92: `(status, return length, value)`.
fn sequence(h: HANDLE) -> (u32, u32, u64) {
    let mut v = 0u64;
    let (st, ret) = nt_query(h, CLASS_SEQUENCE, (&mut v as *mut u64).cast(), 8);
    (st, ret, v)
}

fn hex_bytes(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn rd<T: Copy>(buf: &[u8], off: usize) -> T {
    assert!(off + std::mem::size_of::<T>() <= buf.len());
    // SAFETY: bounds checked above.
    unsafe { std::ptr::read_unaligned(buf.as_ptr().add(off).cast::<T>()) }
}

/// The phnt `PROCESS_TELEMETRY_ID_INFORMATION` header: 96 bytes.
const TELEMETRY_HEADER: usize = 96;

struct Telemetry {
    header_size: u32,
    process_id: u32,
    start_key: u64,
    create_time: u64,
    sequence: u64,
    boot_id: u32,
}

/// Class 64 on `h`, printing status and `ReturnLength` for a header-sized buffer and then for one
/// of exactly `ReturnLength`. `None` when neither call succeeded.
fn class64(id: &str, tag: &str, h: HANDLE) -> Option<Telemetry> {
    let mut small = vec![0u64; TELEMETRY_HEADER / 8];
    let (s1, r1) = nt_query(h, CLASS_TELEMETRY, small.as_mut_ptr().cast(), TELEMETRY_HEADER as u32);
    d0!(id, "{tag}.c64.header_sized status={s1:#010x} return_length={r1}");
    let mut bytes: Option<Vec<u8>> = None;
    if s1 == 0 {
        // SAFETY: `small` is initialised and 96 bytes long.
        bytes = Some(unsafe { std::slice::from_raw_parts(small.as_ptr().cast::<u8>(), TELEMETRY_HEADER) }.to_vec());
    }
    if r1 != 0 {
        let mut exact = vec![0u64; (r1 as usize).div_ceil(8).max(TELEMETRY_HEADER / 8)];
        let (s2, r2) = nt_query(h, CLASS_TELEMETRY, exact.as_mut_ptr().cast(), r1);
        d0!(id, "{tag}.c64.exact_return_length status={s2:#010x} return_length={r2} buffer={r1}");
        if s2 == 0 {
            let n = (r2 as usize).min(exact.len() * 8);
            // SAFETY: `exact` is initialised and at least `n` bytes long.
            bytes = Some(unsafe { std::slice::from_raw_parts(exact.as_ptr().cast::<u8>(), n) }.to_vec());
        }
    }
    let b = bytes?;
    d0!(id, "{tag}.c64.raw_header={}", hex_bytes(&b[..TELEMETRY_HEADER.min(b.len())]));
    let t = Telemetry {
        header_size: rd(&b, 0),
        process_id: rd(&b, 4),
        start_key: rd(&b, 8),
        create_time: rd(&b, 16),
        sequence: rd(&b, 40),
        boot_id: rd(&b, 60),
    };
    d0!(
        id,
        "{tag}.c64.HeaderSize={} ProcessId={} ProcessSequenceNumber={} BootId={} ProcessStartKey={:#018x} \
         start_key_low48_is_seq={} start_key_high16_is_boot_id={} CreateTime={}",
        t.header_size,
        t.process_id,
        t.sequence,
        t.boot_id,
        t.start_key,
        t.start_key & 0x0000_ffff_ffff_ffff == t.sequence,
        (t.start_key >> 48) as u32 == t.boot_id,
        t.create_time
    );
    Some(t)
}

// Toolhelp -----

/// `(pid, parent pid, exe name)` of every process in a fresh snapshot.
fn toolhelp() -> Vec<(u32, u32, String)> {
    let mut out = Vec::new();
    // SAFETY: standard snapshot iteration; `e.dwSize` is set.
    unsafe {
        let snap = Owned(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).expect("snapshot"));
        let mut e = PROCESSENTRY32W { dwSize: size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
        let mut more = Process32FirstW(snap.0, &mut e).is_ok();
        while more {
            let len = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(e.szExeFile.len());
            out.push((e.th32ProcessID, e.th32ParentProcessID, String::from_utf16_lossy(&e.szExeFile[..len])));
            more = Process32NextW(snap.0, &mut e).is_ok();
        }
    }
    out
}

fn pid_of(name: &str) -> Option<u32> {
    toolhelp().into_iter().find(|(_, _, n)| n.eq_ignore_ascii_case(name)).map(|(p, _, _)| p)
}

// Fixtures -----

fn quiet(mut c: Command) -> Command {
    c.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    c
}

/// A child that lives until killed: this test binary in the `sleeper` role.
fn spawn_sleeper() -> KillOnDrop {
    let mut c = Command::new(std::env::current_exe().expect("exe"));
    c.args(["--exact", "win::d0_role_sleeper", "--nocapture"]).env("D0_ROLE", "sleeper");
    KillOnDrop(quiet(c).spawn().expect("spawn sleeper"))
}

/// A child that has exited or is about to: `cmd /c exit 0`.
fn spawn_quick() -> Child {
    let mut c = Command::new("cmd");
    c.args(["/c", "exit", "0"]);
    quiet(c).spawn().expect("spawn cmd")
}

#[test]
fn d0_role_sleeper() {
    if std::env::var("D0_ROLE").as_deref() != Ok("sleeper") {
        return;
    }
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

/// Spawns a sleeper grandchild, prints its pid and exits without waiting for it.
#[test]
fn d0_role_spawner() {
    if std::env::var("D0_ROLE").as_deref() != Ok("spawner") {
        return;
    }
    let mut c = Command::new(std::env::current_exe().expect("exe"));
    c.args(["--exact", "win::d0_role_sleeper", "--nocapture"]).env("D0_ROLE", "sleeper");
    let g = quiet(c).spawn().expect("spawn grandchild");
    println!("D0-GC {}", g.id());
}

// Environment -----

pub fn print_os_build() {
    let mut info = OSVERSIONINFOW { dwOSVersionInfoSize: size_of::<OSVERSIONINFOW>() as u32, ..Default::default() };
    // SAFETY: `info` is a live out-parameter with its size set.
    let st = unsafe { RtlGetVersion(&mut info) };
    d0!(
        "ENV",
        "rtl_get_version status={:#010x} version={}.{}.{}",
        st.0 as u32,
        info.dwMajorVersion,
        info.dwMinorVersion,
        info.dwBuildNumber
    );
    let (elevated, rid) = describe_own_token();
    d0!("ENV", "token_elevated={elevated} integrity_rid={rid:#x}");
}

/// `(elevated, integrity RID)` of this process's token.
fn describe_own_token() -> (bool, u32) {
    // SAFETY: standard token queries into correctly sized buffers.
    unsafe {
        let mut tok = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok).expect("OpenProcessToken");
        let tok = Owned(tok);
        let mut elev = [0u32; 1];
        let mut ret = 0u32;
        GetTokenInformation(tok.0, TokenElevation, Some(elev.as_mut_ptr().cast()), 4, &mut ret).expect("elevation");
        let mut buf = vec![0u64; 16];
        GetTokenInformation(tok.0, TokenIntegrityLevel, Some(buf.as_mut_ptr().cast()), 128, &mut ret).expect("integrity");
        let label = &*(buf.as_ptr().cast::<TOKEN_MANDATORY_LABEL>());
        let sid: PSID = label.Label.Sid;
        let n = *GetSidSubAuthorityCount(sid) as u32;
        (elev[0] != 0, *GetSidSubAuthority(sid, n - 1))
    }
}

/// Opens `pid` with `PROCESS_QUERY_LIMITED_INFORMATION` only and runs classes 92 and 64.
fn probe_target(id: &str, tag: &str, pid: u32) {
    match open(pid, PROCESS_QUERY_LIMITED_INFORMATION) {
        Err(hr) => d0!(id, "{tag}.pid={pid} open=denied_or_failed hresult={hr:#010x}"),
        Ok(h) => {
            d0!(id, "{tag}.pid={pid} open=ok");
            let (st, ret, v) = sequence(h.0);
            d0!(id, "{tag}.c92 status={st:#010x} return_length={ret} value={v}");
            class64(id, tag, h.0);
        }
    }
}

/// W9: `SystemBootEnvironmentInformation`. Returns the GUID string when the call succeeded.
fn boot_environment(id: &str, tag: &str) -> Option<String> {
    let mut buf = vec![0u64; 8];
    let mut ret = 0u32;
    // SAFETY: a 64-byte buffer, of which 32 are offered.
    let st = unsafe {
        NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS(SYSTEM_BOOT_ENVIRONMENT_INFORMATION), buf.as_mut_ptr().cast(), 32, &mut ret)
    };
    d0!(id, "{tag}.boot_env status={:#010x} return_length={ret}", st.0 as u32);
    if st.0 != 0 {
        return None;
    }
    // SAFETY: `buf` is initialised.
    let b = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), 64) };
    let (d1, d2, d3): (u32, u16, u16) = (rd(b, 0), rd(b, 4), rd(b, 6));
    let guid = format!(
        "{d1:08x}-{d2:04x}-{d3:04x}-{}-{}",
        hex_bytes(&b[8..10]),
        hex_bytes(&b[10..16])
    );
    let firmware: u32 = rd(b, 16);
    d0!(id, "{tag}.boot_env.BootIdentifier={guid} FirmwareType={firmware}");
    Some(guid)
}

// W1..W3 -----

/// W1 and W3.
#[test]
fn d0_w1_w3_sequence_number() {
    let mut child = spawn_sleeper();
    let pid = child.0.id();
    let h = open(pid, PROCESS_QUERY_LIMITED_INFORMATION).expect("open with QUERY_LIMITED");
    let (st, ret, v1) = sequence(h.0);
    d0!("W1", "c92 status={st:#010x} return_length={ret} value={v1}");
    assert_eq!((st, ret), (0, 8));
    assert_ne!(v1, 0);

    child.0.kill().expect("kill");
    child.0.wait().expect("wait");
    let (st, ret, v2) = sequence(h.0);
    d0!("W3", "c92_after_exit status={st:#010x} return_length={ret} value={v2} same_value={}", v1 == v2);
    assert_eq!((st, ret, v2), (0, 8, v1));
}

/// W2.
#[test]
fn d0_w2_sequence_order() {
    let mut prev = 0u64;
    let (mut first, mut last, mut increasing) = (0u64, 0u64, true);
    for i in 0..50 {
        let mut c = spawn_quick();
        let h = open(c.id(), PROCESS_QUERY_LIMITED_INFORMATION).expect("open");
        let (st, _, v) = sequence(h.0);
        assert_eq!(st, 0, "c92 status {st:#x}");
        if i == 0 {
            first = v;
        }
        increasing &= v > prev;
        prev = v;
        last = v;
        c.wait().expect("wait");
    }
    d0!("W2", "spawns50.first={first} last={last} strictly_increasing={increasing}");
    assert!(increasing);
}

// W4 -----

#[test]
fn d0_w4_telemetry() {
    let child = spawn_sleeper();
    let h = open(child.0.id(), PROCESS_QUERY_LIMITED_INFORMATION).expect("open");
    let (_, _, seq92) = sequence(h.0);
    let t = class64("W4", "child", h.0).expect("class 64 on the child");
    d0!("W4", "child.c64_sequence_equals_c92={}", t.sequence == seq92);
    assert_eq!(t.sequence, seq92);
    assert_eq!(t.process_id, child.0.id());

    // SAFETY: the pseudo-handle needs no close.
    let me = unsafe { GetCurrentProcess() };
    let (_, _, seq_me) = sequence(me);
    let tm = class64("W4", "self", me).expect("class 64 on self");
    d0!("W4", "self.c64_sequence_equals_c92={} c92={seq_me}", tm.sequence == seq_me);
}

// W5 -----

#[test]
fn d0_w5_system_processes() {
    let (elevated, rid) = describe_own_token();
    d0!("W5", "caller.elevated={elevated} integrity_rid={rid:#x}");
    probe_target("W5", "system4", 4);
    match pid_of("csrss.exe") {
        Some(p) => probe_target("W5", "csrss", p),
        None => d0!("W5", "csrss.not_found"),
    }
}

// W5b + W9 (child) -----

/// The low-integrity child of W5b: opens and queries the probe and pid 4.
#[test]
fn d0_role_w5b_child() {
    if std::env::var("D0_ROLE").as_deref() != Ok("w5b_child") {
        return;
    }
    let target: u32 = std::env::var("D0_W5B_TARGET").expect("target").parse().expect("pid");
    let (elevated, rid) = describe_own_token();
    d0!("W5b", "child.elevated={elevated} integrity_rid={rid:#x}");
    probe_target("W5b", "parent_probe", target);
    probe_target("W5b", "system4", 4);
    match pid_of("csrss.exe") {
        Some(p) => probe_target("W5b", "csrss", p),
        None => d0!("W5b", "csrss.not_found"),
    }
    // SAFETY: the pseudo-handle needs no close.
    let me = unsafe { GetCurrentProcess() };
    let (st, ret, v) = sequence(me);
    d0!("W5b", "self.c92 status={st:#010x} return_length={ret} value={v}");
    boot_environment("W9", "low_integrity_child");
    d0!("W5b", "done");
}

/// Re-executes this test under a restricted, low-integrity copy of its own token.
#[test]
fn d0_w5b_low_integrity() {
    // SAFETY: token plumbing over handles owned here; buffers outlive each call.
    let output = unsafe {
        let mut tok = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ACCESS_MASK(TOKEN_DUPLICATE.0 | TOKEN_QUERY.0 | TOKEN_ASSIGN_PRIMARY.0 | TOKEN_ADJUST_DEFAULT.0),
            &mut tok,
        )
        .expect("OpenProcessToken");
        let tok = Owned(tok);
        let mut restricted = HANDLE::default();
        CreateRestrictedToken(tok.0, DISABLE_MAX_PRIVILEGE, None, None, None, &mut restricted)
            .expect("CreateRestrictedToken");
        let restricted = Owned(restricted);

        let mut sid = PSID::default();
        ConvertStringSidToSidW(w!("S-1-16-4096"), &mut sid).expect("low integrity SID");
        let label = TOKEN_MANDATORY_LABEL { Label: SID_AND_ATTRIBUTES { Sid: sid, Attributes: 0x20 } };
        let len = size_of::<TOKEN_MANDATORY_LABEL>() as u32 + GetLengthSid(sid);
        SetTokenInformation(restricted.0, TokenIntegrityLevel, (&label as *const TOKEN_MANDATORY_LABEL).cast(), len)
            .expect("SetTokenInformation(TokenIntegrityLevel)");
        let _ = LocalFree(Some(HLOCAL(sid.0)));

        let (reader, writer) = std::io::pipe().expect("pipe");
        SetHandleInformation(HANDLE(writer.as_raw_handle()), HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(HANDLE_FLAG_INHERIT.0))
            .expect("make the write end inheritable");

        std::env::set_var("D0_ROLE", "w5b_child");
        std::env::set_var("D0_W5B_TARGET", std::process::id().to_string());
        let exe = std::env::current_exe().expect("exe");
        let exe_w: Vec<u16> = exe.as_os_str().encode_wide_nul();
        let mut cmd: Vec<u16> = format!("\"{}\" --exact win::d0_role_w5b_child --nocapture", exe.display())
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let out = HANDLE(writer.as_raw_handle());
        let si = STARTUPINFOW {
            cb: size_of::<STARTUPINFOW>() as u32,
            dwFlags: STARTF_USESTDHANDLES,
            hStdInput: HANDLE::default(),
            hStdOutput: out,
            hStdError: out,
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();
        CreateProcessAsUserW(
            Some(restricted.0),
            windows::core::PCWSTR(exe_w.as_ptr()),
            Some(PWSTR(cmd.as_mut_ptr())),
            None,
            None,
            true,
            CREATE_NO_WINDOW,
            None,
            windows::core::PCWSTR::null(),
            &si,
            &mut pi,
        )
        .expect("CreateProcessAsUserW");
        let proc_h = Owned(pi.hProcess);
        let _thread = Owned(pi.hThread);
        drop(writer);
        let mut text = String::new();
        BufReader::new(reader).read_to_string(&mut text).expect("read child output");
        WaitForSingleObject(proc_h.0, INFINITE);
        text
    };
    let mut saw_done = false;
    for line in output.lines() {
        if line.starts_with("D0 ") {
            println!("{line}");
            saw_done |= line.starts_with("D0 W5b done");
        } else {
            println!("D0-child-noise {line}");
        }
    }
    assert!(saw_done, "the low-integrity child did not finish");
}

trait EncodeWideNul {
    fn encode_wide_nul(&self) -> Vec<u16>;
}

impl EncodeWideNul for std::ffi::OsStr {
    fn encode_wide_nul(&self) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        self.encode_wide().chain(Some(0)).collect()
    }
}

// W6 -----

#[test]
fn d0_w6_toolhelp_after_exit() {
    let mut c = spawn_sleeper();
    let pid = c.0.id();
    let listed = |pid| toolhelp().iter().any(|(p, _, _)| *p == pid);
    d0!("W6", "live.in_snapshot={}", listed(pid));
    c.0.kill().expect("kill");
    c.0.wait().expect("wait"); // std keeps the process handle open until `c` drops
    d0!("W6", "exited_handle_held.in_snapshot={}", listed(pid));
}

// W7 -----

fn nt_terminate(h: HANDLE) -> u32 {
    // SAFETY: plain call on a handle owned by the caller.
    unsafe { NtTerminateProcess(Some(h), NTSTATUS(1)) }.0 as u32
}

#[test]
fn d0_w7_nt_terminate() {
    // Live, with PROCESS_TERMINATE: success, then a second call.
    let mut live = spawn_sleeper();
    let h = open(live.0.id(), PROCESS_TERMINATE).expect("open PROCESS_TERMINATE");
    let first = nt_terminate(h.0);
    let second = nt_terminate(h.0);
    live.0.wait().expect("wait");
    d0!("W7", "live.first={first:#010x} live.second={second:#010x}");

    // After a natural exit, handle held.
    let mut quick = spawn_quick();
    quick.wait().expect("wait");
    let h = open(quick.id(), PROCESS_TERMINATE).expect("open PROCESS_TERMINATE on an exited child");
    let after_exit = nt_terminate(h.0);
    d0!("W7", "exited.with_terminate_right={after_exit:#010x}");

    // Without the right: QUERY_LIMITED | SYNCHRONIZE, on the exited child and on a live one.
    let weak = PROCESS_ACCESS_RIGHTS(PROCESS_QUERY_LIMITED_INFORMATION.0 | PROCESS_SYNCHRONIZE.0);
    let h = open(quick.id(), weak).expect("open weak on an exited child");
    let weak_exited = nt_terminate(h.0);
    let mut live2 = spawn_sleeper();
    let h2 = open(live2.0.id(), weak).expect("open weak on a live child");
    let weak_live = nt_terminate(h2.0);
    live2.0.kill().expect("kill");
    live2.0.wait().expect("wait");
    d0!("W7", "exited.without_terminate_right={weak_exited:#010x} live.without_terminate_right={weak_live:#010x}");

    assert_eq!(first, 0);
    assert_eq!(second, STATUS_PROCESS_IS_TERMINATING);
    assert_eq!(after_exit, STATUS_PROCESS_IS_TERMINATING);
    assert_eq!(weak_exited, STATUS_ACCESS_DENIED);
    assert_eq!(weak_live, STATUS_ACCESS_DENIED);
}

// W8 -----

#[repr(C)]
#[derive(Default)]
struct BasicInfo {
    exit_status: i32,
    peb: usize,
    affinity: usize,
    base_priority: i32,
    unique_pid: usize,
    inherited_from: usize,
}

fn basic_ppid(pid: u32) -> (u32, u64) {
    let h = open(pid, PROCESS_QUERY_LIMITED_INFORMATION).expect("open");
    let mut b = BasicInfo::default();
    let (st, _) = nt_query(h.0, CLASS_BASIC, (&mut b as *mut BasicInfo).cast(), size_of::<BasicInfo>() as u32);
    (st, b.inherited_from as u64)
}

fn toolhelp_ppid(pid: u32) -> Option<u32> {
    toolhelp().into_iter().find(|(p, _, _)| *p == pid).map(|(_, pp, _)| pp)
}

#[test]
fn d0_w8_basic_ppid() {
    let child = spawn_sleeper();
    let (st, ppid) = basic_ppid(child.0.id());
    let th = toolhelp_ppid(child.0.id());
    d0!(
        "W8",
        "child.c0 status={st:#010x} inherited_from={ppid} toolhelp_ppid={th:?} probe_pid={}",
        std::process::id()
    );
    assert_eq!(st, 0);
    assert_eq!(ppid, std::process::id() as u64);
    assert_eq!(th, Some(std::process::id()));

    // A grandchild whose parent has exited.
    let mut c = Command::new(std::env::current_exe().expect("exe"));
    c.args(["--exact", "win::d0_role_spawner", "--nocapture"]).env("D0_ROLE", "spawner");
    c.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    let mut spawner = c.spawn().expect("spawn spawner");
    let spawner_pid = spawner.id();
    let mut gc = None;
    for line in BufReader::new(spawner.stdout.take().unwrap()).lines() {
        if let Some(p) = line.expect("line").strip_prefix("D0-GC ") {
            gc = Some(p.trim().parse::<u32>().expect("pid"));
        }
    }
    spawner.wait().expect("wait spawner");
    let gc = gc.expect("grandchild pid");
    let (st, ppid) = basic_ppid(gc);
    let th = toolhelp_ppid(gc);
    d0!(
        "W8",
        "orphan.c0 status={st:#010x} inherited_from={ppid} toolhelp_ppid={th:?} spawner_pid={spawner_pid} spawner_in_snapshot={}",
        toolhelp().iter().any(|(p, _, _)| *p == spawner_pid)
    );
    // Clean up the grandchild.
    let h = open(gc, PROCESS_ACCESS_RIGHTS(PROCESS_TERMINATE.0 | PROCESS_SYNCHRONIZE.0)).expect("open grandchild");
    // SAFETY: plain calls on an owned handle.
    unsafe {
        let _ = TerminateProcess(h.0, 1);
        WaitForSingleObject(h.0, INFINITE);
    }
    assert_eq!(st, 0);
    assert_eq!(ppid, spawner_pid as u64);
    assert_eq!(th, Some(spawner_pid));
}

// W9 -----

#[test]
fn d0_w9_boot_environment() {
    let a = boot_environment("W9", "first_read").expect("call succeeds");
    let b = boot_environment("W9", "second_read").expect("call succeeds");
    d0!("W9", "stable_within_process={}", a == b);
    assert_eq!(a, b);
    // SAFETY: the pseudo-handle needs no close.
    let me = unsafe { GetCurrentProcess() };
    if let Some(t) = class64("W9", "self", me) {
        d0!("W9", "class64_BootId={}", t.boot_id);
    }
}
