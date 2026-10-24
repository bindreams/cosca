//! The `spawn-with-null-std` and `report-std-handles` modes: what a grandchild receives when this
//! process's std handles are null, as a GUI or service process's are.
//!
//! `spawn-with-null-std <backend> <nulled> <dir>` sets this process's std handles to null (`all`
//! three, or `stdin` alone), spawns `report-std-handles` once per route, restores the handles, and
//! prints one `<route>=<report>` line per route. `<backend>` is `sync` or `tokio`. Routes: `std`
//! (`std::process::Command`), `argv` (cosca, argv only: its std route) and three on cosca's raw
//! backend: `exe` (`executable()`), `fd3` (argv with fd 3 mapped) and `exe_merge` (`executable()`
//! with stderr merged into stdout). A route whose
//! spawn fails prints `err=<error>`. Each grandchild also reports whether it inherited
//! `<dir>\stray.txt`, an inheritable handle given to no `Command`.

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
use windows::Win32::System::Threading::{GetStartupInfoW, STARTF_USESTDHANDLES, STARTUPINFOW};

#[link(name = "kernel32", kind = "raw-dylib")]
extern "system" {
    /// `GetStdHandle` unwrapped: the `windows` crate turns a null handle into an error.
    #[link_name = "GetStdHandle"]
    fn raw_std_handle(id: STD_HANDLE) -> HANDLE;
}

/// This process's std handle `id`, null included.
fn std_handle(id: STD_HANDLE) -> HANDLE {
    // SAFETY: no preconditions.
    unsafe { raw_std_handle(id) }
}

const STD: [(&str, STD_HANDLE); 3] = [
    ("stdin", STD_INPUT_HANDLE),
    ("stdout", STD_OUTPUT_HANDLE),
    ("stderr", STD_ERROR_HANDLE),
];

const ROUTES: [&str; 5] = ["std", "argv", "exe", "fd3", "exe_merge"];

const STRAY: &str = "stray.txt";

/// `report-std-handles <report> <stray>`: writes to `<report>` one line,
/// `usestdhandles=<bool>,stdin=<kind>,stdout=<kind>,stderr=<kind>,stray=<bool>`. A kind is `null`,
/// `char`, `pipe`, `disk`, `invalid` or `unknown(err=<code>)`; `stray` is whether the hex handle
/// value `<stray>` names a file called `stray.txt` in this process.
pub fn report(path: &str, stray: &str) {
    let mut si = STARTUPINFOW::default();
    // SAFETY: `si` is a live out-parameter.
    unsafe { GetStartupInfoW(&mut si) };
    let mut fields = vec![format!("usestdhandles={}", si.dwFlags.0 & STARTF_USESTDHANDLES.0 != 0)];
    for (name, id) in STD {
        let h = std_handle(id);
        let kind = if h.0.is_null() {
            "null".to_owned()
        } else if h.0 as isize == -1 {
            "invalid".to_owned()
        } else {
            // SAFETY: `h` is this process's own std handle.
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
    let stray = HANDLE(usize::from_str_radix(stray, 16).expect("a hex handle value") as *mut _);
    let mut buf = vec![0u16; 1024];
    // SAFETY: `buf` is a live buffer of its length; a handle value this process does not hold is an
    // error, not UB.
    let n = unsafe { GetFinalPathNameByHandleW(stray, &mut buf, FILE_NAME_NORMALIZED) } as usize;
    let inherited = n > 0 && n <= buf.len() && String::from_utf16_lossy(&buf[..n]).ends_with(STRAY);
    fields.push(format!("stray={inherited}"));
    std::fs::write(path, fields.join(",")).expect("write the report");
}

/// `spawn-with-null-std <backend> <nulled> <dir>`.
pub fn spawn(backend: &str, nulled: &str, dir: &str) {
    let ids: &[(&str, STD_HANDLE)] = match nulled {
        "all" => &STD,
        "stdin" => &STD[..1],
        other => panic!("unknown handle set {other:?}"),
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
    let saved: Vec<HANDLE> = ids.iter().map(|&(_, id)| std_handle(id)).collect();
    for &(_, id) in ids {
        // SAFETY: sets this process's own std handle; restored below.
        unsafe { SetStdHandle(id, HANDLE::default()) }.expect("SetStdHandle(NULL)");
    }
    let lines: Vec<String> = ROUTES
        .iter()
        .map(|route| {
            let report = Path::new(dir).join(format!("{route}.txt"));
            match run(backend, route, &report, &stray_hex) {
                Ok(()) => format!(
                    "{route}={}",
                    std::fs::read_to_string(&report).expect("the grandchild's report")
                ),
                Err(e) => format!("{route}=err={e}"),
            }
        })
        .collect();
    for (&(_, id), h) in ids.iter().zip(saved) {
        // SAFETY: restores the handle saved above.
        unsafe { SetStdHandle(id, h) }.expect("restore the std handle");
    }
    for line in lines {
        println!("{line}");
    }
}

/// Run `report-std-handles <report> <stray>` through `route` and wait for it.
fn run(backend: &str, route: &str, report: &Path, stray: &str) -> Result<(), String> {
    let exe = std::env::current_exe().expect("current_exe");
    if route == "std" {
        #[allow(
            clippy::disallowed_methods,
            reason = "this process runs no other spawn concurrently, so std's inheritable window races nothing"
        )]
        let status = std::process::Command::new(&exe)
            .arg("report-std-handles")
            .arg(report)
            .arg(stray)
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
        stray.into(),
    ];
    match backend {
        "sync" => {
            let mut cmd = cosca::Command::new();
            configure_sync(&mut cmd, route, &exe, &argv)?;
            match cmd.status() {
                Ok(s) if s.success() => Ok(()),
                Ok(s) => Err(format!("exit-{s:?}")),
                Err(e) => Err(e.to_string()),
            }
        }
        #[cfg(feature = "tokio")]
        "tokio" => {
            let mut cmd = cosca::tokio::Command::new();
            configure_tokio(&mut cmd, route, &exe, &argv)?;
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

fn configure_sync(cmd: &mut cosca::Command, route: &str, exe: &Path, argv: &[OsString]) -> Result<(), String> {
    match route {
        "exe" | "exe_merge" => {
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
    if route == "exe_merge" {
        cmd.stderr(cosca::Stdio::merge(cosca::Fd::STDOUT))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(feature = "tokio")]
fn configure_tokio(cmd: &mut cosca::tokio::Command, route: &str, exe: &Path, argv: &[OsString]) -> Result<(), String> {
    match route {
        "exe" | "exe_merge" => {
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
    if route == "exe_merge" {
        cmd.stderr(cosca::Stdio::merge(cosca::Fd::STDOUT))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}
