//! The `spawn-with-null-std` and `report-std-handles` modes: what a grandchild receives when this
//! process's std handles are null, as a GUI or service process's are.
//!
//! `spawn-with-null-std <backend> <nulled> <dir>` sets the std handles named by `<nulled>` (`all`,
//! or names joined by `+`, e.g. `stdin+stderr`; prefixed `invalid:` to set `INVALID_HANDLE_VALUE`
//! instead, which is what a parent with no std handles hands down) to null, spawns `report-std-handles` once per
//! route, restores the handles, and prints one `<route>=<report>` line per route. `<backend>` is
//! `sync` or `tokio`. A route whose spawn fails prints `err=<error>`. Each grandchild also reports
//! whether it inherited `<dir>\stray.txt`, an inheritable handle given to no `Command`, and how many
//! handles it holds that name the NUL device. A spawn that leaves an inheritable handle open in
//! this process is a route failure: `err=inheritable handles left open: [...]`.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use windows::Win32::Foundation::{SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT};
use windows::Win32::Storage::FileSystem::{
    GetFileType, GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED, FILE_TYPE_CHAR, FILE_TYPE_DISK, FILE_TYPE_PIPE,
};
use windows::Win32::System::Console::{
    SetStdHandle, STD_ERROR_HANDLE, STD_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::System::Threading::{GetCurrentProcess, GetStartupInfoW, STARTF_USESTDHANDLES, STARTUPINFOW};

#[link(name = "kernel32", kind = "raw-dylib")]
extern "system" {
    /// `GetStdHandle` unwrapped: the `windows` crate turns a null handle into an error.
    #[link_name = "GetStdHandle"]
    fn raw_std_handle(id: STD_HANDLE) -> HANDLE;
}

#[link(name = "ntdll", kind = "raw-dylib")]
extern "system" {
    /// `process` is a process handle; `info` is `len` bytes for `class`, and `ret_len` receives the
    /// size the class needs.
    fn NtQueryInformationProcess(
        process: HANDLE,
        class: u32,
        info: *mut std::ffi::c_void,
        len: u32,
        ret_len: *mut u32,
    ) -> i32;

    /// `class` 4 is `FileFsDeviceInformation`: a [`DeviceInfo`]. `io_status` is an
    /// `IO_STATUS_BLOCK`: two pointer-sized words.
    fn NtQueryVolumeInformationFile(
        handle: HANDLE,
        io_status: *mut [usize; 2],
        info: *mut DeviceInfo,
        len: u32,
        class: u32,
    ) -> i32;
}

/// `FILE_FS_DEVICE_INFORMATION`.
#[repr(C)]
#[derive(Default)]
struct DeviceInfo {
    device_type: u32,
    characteristics: u32,
}

/// `FILE_DEVICE_NULL`: the device type of `\Device\Null`.
const FILE_DEVICE_NULL: u32 = 0x15;

/// This process's std handle `id`, null included.
fn std_handle(id: STD_HANDLE) -> HANDLE {
    unsafe { raw_std_handle(id) }
}

const STD: [(&str, STD_HANDLE); 3] = [
    ("stdin", STD_INPUT_HANDLE),
    ("stdout", STD_OUTPUT_HANDLE),
    ("stderr", STD_ERROR_HANDLE),
];

/// `std`: `std::process::Command`. `argv`: cosca's std route. The rest are cosca's raw backend:
/// `exe` (`executable()`), `fd3` (fd 3 is the null device), `exe_merge` (stderr merged into
/// stdout), `listed` (fd 3 is the stray file: a handle that is listed, so it must be inherited) and
/// `merge3` (fd 3 is merged from stdout, so it is null when stdout is) and `merge_live` (every std
/// slot whose handle in this process is live is merged from the first nulled slot, so all three of
/// the child's std ends are null while this process still holds a live handle). Three routes
/// configure real child ends, whatever this process's own handles are: `pipe_out` (stdout is a
/// pipe), `null_io` (stdin and stdout are the null device) and `pipe_fd3` (stdout is a pipe, fd 3
/// the null device).
const ROUTES: [&str; 11] = [
    "std",
    "argv",
    "exe",
    "fd3",
    "exe_merge",
    "listed",
    "merge3",
    "merge_live",
    "pipe_out",
    "null_io",
    "pipe_fd3",
];

const STRAY: &str = "stray.txt";

/// `report-std-handles <report> <stray>`: writes to `<report>` one line,
/// `usestdhandles=<bool>,stdin=<kind>,stdout=<kind>,stderr=<kind>,fd3=<open|closed>,stray=<state>,nul=<n>`.
/// A kind is `null`, `char`, `pipe`, `disk`, `invalid` or `unknown(err=<code>)`. `<stray>` is a hex
/// handle value, or `fd:<n>` for the handle behind CRT fd `n`; `stray` is `true` if it names a file
/// called `stray.txt` in this process, `false` if it is not (a handle to) a disk file here, else `error(<code>)`.
/// `nul` is the number of handles this process holds that name the NUL device, `\Device\Null`.
pub fn report(path: &str, stray: &str) {
    let mut si = STARTUPINFOW::default();
    unsafe { GetStartupInfoW(&mut si) };
    let mut fields = vec![format!("usestdhandles={}", si.dwFlags.0 & STARTF_USESTDHANDLES.0 != 0)];
    for (name, id) in STD {
        let h = std_handle(id);
        let kind = if h.0.is_null() {
            "null".to_owned()
        } else if h.0 as isize == -1 {
            "invalid".to_owned()
        } else {
            match unsafe { GetFileType(h) } {
                FILE_TYPE_CHAR => "char".to_owned(),
                FILE_TYPE_PIPE => "pipe".to_owned(),
                FILE_TYPE_DISK => "disk".to_owned(),
                _ => format!(
                    "unknown(err={})",
                    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
                ),
            }
        };
        fields.push(format!("{name}={kind}"));
    }
    fields.push(format!(
        "fd3={}",
        if crt_handle(3).is_some() { "open" } else { "closed" }
    ));
    let stray = match stray.strip_prefix("fd:") {
        Some(fd) => crt_handle(fd.parse().expect("a CRT fd")).unwrap_or(HANDLE(-1isize as *mut _)),
        None => HANDLE(usize::from_str_radix(stray, 16).expect("a hex handle value") as *mut _),
    };
    fields.push(format!("stray={}", probe_stray(stray)));
    fields.push(format!("nul={}", count_nul_handles()));
    std::fs::write(path, fields.join(",")).expect("write the report");
}

/// `class` 51 of `NtQueryInformationProcess`, `ProcessHandleInformation`: a
/// [`HandleSnapshotHeader`] followed by that many [`HandleTableEntry`].
const PROCESS_HANDLE_INFORMATION: u32 = 51;

/// `STATUS_INFO_LENGTH_MISMATCH`: the buffer is too small; the call reports the size it needs.
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;

/// `OBJ_INHERIT`: the kernel's bit for `HANDLE_FLAG_INHERIT` in a handle table entry.
const OBJ_INHERIT: u32 = 0x2;

/// `PROCESS_HANDLE_SNAPSHOT_INFORMATION`, without its trailing array.
#[repr(C)]
struct HandleSnapshotHeader {
    number_of_handles: usize,
    reserved: usize,
}

/// `PROCESS_HANDLE_TABLE_ENTRY_INFO`.
#[repr(C)]
struct HandleTableEntry {
    handle_value: usize,
    handle_count: usize,
    pointer_count: usize,
    granted_access: u32,
    object_type_index: u32,
    handle_attributes: u32,
    reserved: u32,
}

/// Calls `visit` with every handle this process holds and its `OBJ_*` attributes, from one
/// snapshot the kernel takes in a single call. Other threads may close a handle in the snapshot, or
/// reuse its value, before `visit` runs, so a caller that queries the handle must say why that
/// cannot change its answer. The attributes are the snapshot's own and need no query.
fn walk_handles(mut visit: impl FnMut(HANDLE, u32)) {
    // `u64` words keep the buffer aligned for both structs.
    let mut words = vec![0u64; (size_of::<HandleSnapshotHeader>() + 64 * size_of::<HandleTableEntry>()) / 8];
    loop {
        let mut needed = 0u32;
        // SAFETY: the pseudo-handle is always valid; the buffer and `needed` are live and of the
        // sizes passed.
        let status = unsafe {
            NtQueryInformationProcess(
                GetCurrentProcess(),
                PROCESS_HANDLE_INFORMATION,
                words.as_mut_ptr().cast(),
                (words.len() * 8) as u32,
                &mut needed,
            )
        };
        if status == STATUS_INFO_LENGTH_MISMATCH {
            // The process may have opened more handles since: ask again at the size it reported.
            let len = (needed as usize).div_ceil(8).max(words.len() * 2);
            words.resize(len, 0);
            continue;
        }
        assert!(
            status >= 0,
            "NtQueryInformationProcess(ProcessHandleInformation): {status:#x}"
        );
        break;
    }
    let base = words.as_ptr().cast::<u8>();
    // SAFETY: a successful call filled the buffer with a header and `number_of_handles` entries.
    let count = unsafe { (*base.cast::<HandleSnapshotHeader>()).number_of_handles };
    debug_assert!(
        size_of::<HandleSnapshotHeader>() + count * size_of::<HandleTableEntry>() <= words.len() * 8,
        "the snapshot's entries fit the buffer"
    );
    // SAFETY: as above; the entries follow the header, whose size is a multiple of their alignment.
    let entries = unsafe {
        std::slice::from_raw_parts(
            base.add(size_of::<HandleSnapshotHeader>()).cast::<HandleTableEntry>(),
            count,
        )
    };
    for entry in entries {
        visit(HANDLE(entry.handle_value as *mut _), entry.handle_attributes);
    }
}

/// How many handles this process holds that name `\Device\Null`. It asks each handle for its
/// device type, as `GetFileType` does, never for its name: a name query on a synchronous pipe blocks
/// while any process has a read pending on the same file object, as a CI runner has on a pipe
/// handle this process inherits.
///
/// A snapshot handle that is closed before it is asked is skipped (`device_type` is `None`). One
/// whose value is reused is asked about its new object, which counts only if that is a NUL device.
/// Every NUL handle this process holds is inherited or made by cosca on the thread that calls
/// this, and no other thread opens `\Device\Null`, so a reused value cannot add one. A NUL handle
/// held throughout is counted once: the snapshot lists each value once.
fn count_nul_handles() -> usize {
    let mut nul = 0;
    walk_handles(|h, _| {
        if device_type(h) == Some(FILE_DEVICE_NULL) {
            nul += 1;
        }
    });
    nul
}

/// The values of the handles this process holds with `HANDLE_FLAG_INHERIT` set. The flag comes
/// from the snapshot, so no handle is queried and a reused value cannot misreport it.
fn inheritable_handles() -> BTreeSet<usize> {
    let mut found = BTreeSet::new();
    walk_handles(|h, attributes| {
        if attributes & OBJ_INHERIT != 0 {
            found.insert(h.0 as usize);
        }
    });
    found
}

/// The device type of the file `h` names, or `None` if `h` is not a file.
fn device_type(h: HANDLE) -> Option<u32> {
    let (mut io_status, mut info) = ([0usize; 2], DeviceInfo::default());
    // SAFETY: `io_status` and `info` are live out-parameters of the sizes passed.
    let status =
        unsafe { NtQueryVolumeInformationFile(h, &mut io_status, &mut info, size_of::<DeviceInfo>() as u32, 4) };
    (status >= 0).then_some(info.device_type)
}

/// The handle behind CRT fd `fd`, or `None` if the fd is not open.
fn crt_handle(fd: i32) -> Option<HANDLE> {
    extern "C" fn ignore(_: *const u16, _: *const u16, _: *const u16, _: u32, _: usize) {}
    #[link(name = "ucrt")]
    extern "C" {
        fn _set_invalid_parameter_handler(
            handler: Option<extern "C" fn(*const u16, *const u16, *const u16, u32, usize)>,
        ) -> usize;
    }
    // An unopened fd makes the CRT call the invalid-parameter handler, which kills the process by
    // default. `get_osfhandle` then returns -1.
    unsafe { _set_invalid_parameter_handler(Some(ignore)) };
    let h = unsafe { libc::get_osfhandle(fd) };
    (h != -1 && h != -2).then_some(HANDLE(h as *mut _))
}

/// Whether `h` names `stray.txt` in this process. A value that is not a handle here, or that is
/// another kind of object this process made at the same value, is not the stray: `false`. A disk
/// file that the probe cannot name is reported as `error(<code>)`, so a broken probe cannot read as
/// "not inherited". Only a disk file is asked for its name, for the reason in [`count_nul_handles`].
fn probe_stray(h: HANDLE) -> String {
    // SAFETY: a handle value this process does not hold is an error, not UB.
    if unsafe { GetFileType(h) } != FILE_TYPE_DISK {
        return "false".to_owned();
    }
    let mut buf = vec![0u16; 1024];
    // SAFETY: `buf` is a live buffer of its length.
    let n = unsafe { GetFinalPathNameByHandleW(h, &mut buf, FILE_NAME_NORMALIZED) } as usize;
    if n == 0 {
        let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        return format!("error({code})");
    }
    assert!(
        n < buf.len(),
        "the stray handle's path needs {n} units, the buffer has {}",
        buf.len()
    );
    String::from_utf16_lossy(&buf[..n]).ends_with(STRAY).to_string()
}

pub fn spawn(backend: &str, nulled: &str, dir: &str) {
    let (nulled, set_to) = match nulled.strip_prefix("invalid:") {
        Some(rest) => (rest, HANDLE(-1isize as *mut _)),
        None => (nulled, HANDLE::default()),
    };
    let ids: Vec<(&str, STD_HANDLE)> = if nulled == "all" {
        STD.to_vec()
    } else {
        nulled
            .split('+')
            .map(|name| *STD.iter().find(|(n, _)| *n == name).expect("a std handle name"))
            .collect()
    };
    let stray = std::fs::File::create(Path::new(dir).join(STRAY)).expect("create the stray file");
    // SAFETY: the handle is owned by `stray`, alive for the call.
    unsafe {
        SetHandleInformation(
            HANDLE(stray.as_raw_handle()),
            HANDLE_FLAG_INHERIT.0,
            HANDLE_FLAG_INHERIT,
        )
    }
    .expect("mark the stray handle inheritable");
    let stray_hex = format!("{:x}", stray.as_raw_handle() as usize);
    let saved: Vec<usize> = ids.iter().map(|&(_, id)| std_handle(id).0 as usize).collect();
    // A panic below would print to a null stderr and be lost: restore the handles first.
    let default_hook = std::panic::take_hook();
    let (hook_ids, hook_saved) = (ids.clone(), saved.clone());
    std::panic::set_hook(Box::new(move |info| {
        restore_std(&hook_ids, &hook_saved);
        default_hook(info);
    }));
    for &(_, id) in &ids {
        // SAFETY: sets this process's own std handle; restored below.
        unsafe { SetStdHandle(id, set_to) }.expect("SetStdHandle");
    }
    let merges = live_merges(&ids);
    let lines: Vec<String> = ROUTES
        .iter()
        .map(|route| {
            let report = Path::new(dir).join(format!("{route}.txt"));
            match run_leaving_no_handle(backend, route, &report, &stray_hex, &stray, &merges) {
                Ok(()) => format!(
                    "{route}={}",
                    std::fs::read_to_string(&report).expect("the grandchild's report")
                ),
                Err(e) => format!("{route}=err={e}"),
            }
        })
        .collect();
    drop(std::panic::take_hook());
    restore_std(&ids, &saved);
    for line in lines {
        println!("{line}");
    }
}

/// `(live slot, first nulled slot)` for every std slot not in `ids`: the merges that null the
/// child's end of a slot this process holds a live handle for. Empty when `ids` is all three.
fn live_merges(ids: &[(&str, STD_HANDLE)]) -> Vec<(cosca::Fd, cosca::Fd)> {
    let fd = |id: STD_HANDLE| match id {
        STD_INPUT_HANDLE => cosca::Fd::STDIN,
        STD_OUTPUT_HANDLE => cosca::Fd::STDOUT,
        _ => cosca::Fd::STDERR,
    };
    let first_nulled = fd(ids[0].1);
    STD.iter()
        .filter(|(_, id)| !ids.iter().any(|(_, n)| n == id))
        .map(|&(_, id)| (fd(id), first_nulled))
        .collect()
}

/// Sets each of `ids` to the matching handle value in `saved`.
fn restore_std(ids: &[(&str, STD_HANDLE)], saved: &[usize]) {
    for (&(_, id), &h) in ids.iter().zip(saved) {
        // SAFETY: sets this process's own std handle back to a value it held.
        unsafe { SetStdHandle(id, HANDLE(h as *mut _)) }.expect("restore the std handle");
    }
}

/// [`run`], then check that the spawn left no inheritable handle open in this process: one left
/// open would reach any other spawner here that passes `bInheritHandles` TRUE with no list. A route
/// whose child ends are all null (`merge_live`, or `exe_merge` with stdin and stdout nulled)
/// lists a NUL filler handle of cosca's own, and this is the check on its close.
fn run_leaving_no_handle(
    backend: &str,
    route: &str,
    report: &Path,
    stray_hex: &str,
    stray: &std::fs::File,
    merges: &[(cosca::Fd, cosca::Fd)],
) -> Result<(), String> {
    let before = inheritable_handles();
    run(backend, route, report, stray_hex, stray, merges)?;
    let left: Vec<_> = inheritable_handles().difference(&before).copied().collect();
    if left.is_empty() {
        Ok(())
    } else {
        Err(format!("inheritable handles left open: {left:x?}"))
    }
}

/// Run `report-std-handles <report> <stray>` through `route` and wait for it.
fn run(
    backend: &str,
    route: &str,
    report: &Path,
    stray_hex: &str,
    stray: &std::fs::File,
    merges: &[(cosca::Fd, cosca::Fd)],
) -> Result<(), String> {
    let exe = std::env::current_exe().expect("current_exe");
    if route == "std" {
        #[allow(
            clippy::disallowed_methods,
            reason = "this process runs no other spawn concurrently, so std's inheritable window races nothing"
        )]
        let status = std::process::Command::new(&exe)
            .arg("report-std-handles")
            .arg(report)
            .arg(stray_hex)
            .status();
        return match status {
            Ok(s) if s.success() => Ok(()),
            Ok(s) => Err(format!("exit-{s}")),
            Err(e) => Err(e.to_string()),
        };
    }
    let argv: [OsString; 4] = [
        "cosca_testbin".into(),
        "report-std-handles".into(),
        report.as_os_str().to_owned(),
        // `listed` hands the child the stray file at fd 3, a dup with another handle value.
        if route == "listed" { "fd:3" } else { stray_hex }.into(),
    ];
    match backend {
        "sync" => {
            let mut cmd = cosca::Command::new();
            configure_sync(&mut cmd, route, &exe, &argv, stray, merges)?;
            // Not `status()`, which resets stdout and stderr to inherit and would undo a merge.
            let child = cmd.spawn().map_err(|e| e.to_string())?;
            match child.wait() {
                Ok(s) if s.success() => Ok(()),
                Ok(s) => Err(format!("exit-{s:?}")),
                Err(e) => Err(e.to_string()),
            }
        }
        #[cfg(feature = "tokio")]
        "tokio" => {
            let mut cmd = cosca::tokio::Command::new();
            configure_tokio(&mut cmd, route, &exe, &argv, stray, merges)?;
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build a tokio runtime");
            rt.block_on(async {
                let mut child = cmd.spawn().map_err(|e| e.to_string())?;
                match child.wait().await {
                    Ok(s) if s.success() => Ok(()),
                    Ok(s) => Err(format!("exit-{s:?}")),
                    Err(e) => Err(e.to_string()),
                }
            })
        }
        other => panic!("unknown backend {other:?}"),
    }
}

fn configure_sync(
    cmd: &mut cosca::Command,
    route: &str,
    exe: &Path,
    argv: &[OsString],
    stray: &std::fs::File,
    merges: &[(cosca::Fd, cosca::Fd)],
) -> Result<(), String> {
    match route {
        "exe" | "exe_merge" | "listed" | "merge3" | "merge_live" | "pipe_out" | "null_io" | "pipe_fd3" => {
            cmd.executable(exe).args(argv);
        }
        "argv" => {
            cmd.arg(exe).args(&argv[1..]);
        }
        "fd3" => {
            cmd.arg(exe).args(&argv[1..]);
            cmd.fd(3, cosca::Stdio::null()).map_err(|e| e.to_string())?;
        }
        other => panic!("unknown route {other:?}"),
    }
    match route {
        "listed" => {
            let dup = stray.try_clone().map_err(|e| e.to_string())?;
            cmd.fd(3, cosca::Stdio::from_file(dup)).map_err(|e| e.to_string())?;
        }
        "merge3" => {
            cmd.fd(3, cosca::Stdio::merge(cosca::Fd::STDOUT))
                .map_err(|e| e.to_string())?;
        }
        _ => {}
    }
    if route == "exe_merge" {
        cmd.stderr(cosca::Stdio::merge(cosca::Fd::STDOUT))
            .map_err(|e| e.to_string())?;
    }
    if route == "merge_live" {
        for &(slot, from) in merges {
            cmd.fd(slot, cosca::Stdio::merge(from)).map_err(|e| e.to_string())?;
        }
    }
    if route == "null_io" {
        cmd.stdin(cosca::Stdio::null()).map_err(|e| e.to_string())?;
        cmd.stdout(cosca::Stdio::null()).map_err(|e| e.to_string())?;
    }
    if route == "pipe_out" || route == "pipe_fd3" {
        cmd.stdout(cosca::Stdio::pipe()).map_err(|e| e.to_string())?;
    }
    if route == "pipe_fd3" {
        cmd.fd(3, cosca::Stdio::null()).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(feature = "tokio")]
/// [`configure_sync`] for the tokio `Command`.
fn configure_tokio(
    cmd: &mut cosca::tokio::Command,
    route: &str,
    exe: &Path,
    argv: &[OsString],
    stray: &std::fs::File,
    merges: &[(cosca::Fd, cosca::Fd)],
) -> Result<(), String> {
    match route {
        "exe" | "exe_merge" | "listed" | "merge3" | "merge_live" | "pipe_out" | "null_io" | "pipe_fd3" => {
            cmd.executable(exe).args(argv);
        }
        "argv" => {
            cmd.arg(exe).args(&argv[1..]);
        }
        "fd3" => {
            cmd.arg(exe).args(&argv[1..]);
            cmd.fd(3, cosca::Stdio::null()).map_err(|e| e.to_string())?;
        }
        other => panic!("unknown route {other:?}"),
    }
    match route {
        "listed" => {
            let dup = stray.try_clone().map_err(|e| e.to_string())?;
            cmd.fd(3, cosca::Stdio::from_file(dup)).map_err(|e| e.to_string())?;
        }
        "merge3" => {
            cmd.fd(3, cosca::Stdio::merge(cosca::Fd::STDOUT))
                .map_err(|e| e.to_string())?;
        }
        _ => {}
    }
    if route == "exe_merge" {
        cmd.stderr(cosca::Stdio::merge(cosca::Fd::STDOUT))
            .map_err(|e| e.to_string())?;
    }
    if route == "merge_live" {
        for &(slot, from) in merges {
            cmd.fd(slot, cosca::Stdio::merge(from)).map_err(|e| e.to_string())?;
        }
    }
    if route == "null_io" {
        cmd.stdin(cosca::Stdio::null()).map_err(|e| e.to_string())?;
        cmd.stdout(cosca::Stdio::null()).map_err(|e| e.to_string())?;
    }
    if route == "pipe_out" || route == "pipe_fd3" {
        cmd.stdout(cosca::Stdio::pipe()).map_err(|e| e.to_string())?;
    }
    if route == "pipe_fd3" {
        cmd.fd(3, cosca::Stdio::null()).map_err(|e| e.to_string())?;
    }
    Ok(())
}
