//! Windows `ShellExecuteEx(runas)` probe: which image an elevated launch loads when an App Paths
//! key names another, with and without `SEE_MASK_CLASSNAME`.
//!
//! cosca's elevated path launches through `ShellExecuteEx`, whose lookup consults App Paths
//! before the file (Wine `shlexec.c` `SHELL_FindExecutable`), so a registration could swap the
//! image for anything, a batch file included. `SEE_MASK_CLASSNAME` sends shell32 straight to the
//! class's verb command instead (`SHELL_execute_class`). This measures both on a real runner.
//!
//! Dispatch-only: it ELEVATES, so it runs only when the `windows-probes` workflow is dispatched
//! with `elevating=true`, on a runner whose process is already elevated (GitHub's Windows runners
//! are), so `runas` raises no prompt. It launches only copies of `cosca_testbin_image` — never a
//! batch file — and registers one volatile App Paths key in HKLM and then in HKCU, each deleted by
//! a guard. Creating a volatile key also creates any missing parent volatile, and that parent is
//! left behind; it goes at the next reboot, with the ephemeral runner.
#![cfg(windows)]

use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE};
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegGetValueW, RegSetValueExW, HKEY, HKEY_CURRENT_USER,
    HKEY_LOCAL_MACHINE, KEY_WRITE, REG_CREATED_NEW_KEY, REG_CREATE_KEY_DISPOSITION, REG_OPEN_CREATE_OPTIONS,
    REG_OPTION_VOLATILE, REG_SZ, RRF_RT_REG_DWORD,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, WaitForSingleObject, INFINITE,
};
use windows::Win32::UI::Shell::{
    ShellExecuteExW, SEE_MASK_CLASSNAME, SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS,
    SHELLEXECUTEINFOW,
};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

/// `ERROR_FILE_NOT_FOUND` as the HRESULT `ShellExecuteExW` fails with (measured).
const FILE_NOT_FOUND: i32 = 0x8007_0002_u32 as i32;
/// `ERROR_NO_ASSOCIATION` as an HRESULT: the class has no command for the verb (measured).
const NO_ASSOCIATION: i32 = 0x8007_0483_u32 as i32;

const APP: &str = "cosca_probe_a.exe";
const KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\App Paths\cosca_probe_a.exe";

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain([0]).collect()
}

/// An App Paths key for [`APP`], deleted on drop. Created only if absent, so a key this probe did
/// not make is never touched.
struct AppPathKey(HKEY, Vec<u16>);

impl AppPathKey {
    fn register(hive: HKEY, options: REG_OPEN_CREATE_OPTIONS, target: &Path) -> Result<Self, String> {
        let name = wide(OsStr::new(KEY));
        let mut hkey = HKEY::default();
        let mut disposition = REG_CREATE_KEY_DISPOSITION::default();
        // SAFETY: `name` is NUL-terminated and outlives the call; the out-pointers are live locals.
        let rc = unsafe {
            RegCreateKeyExW(
                hive,
                PCWSTR(name.as_ptr()),
                None,
                PCWSTR::null(),
                options,
                KEY_WRITE,
                None,
                &mut hkey,
                Some(&mut disposition),
            )
        };
        if rc != ERROR_SUCCESS {
            return Err(format!("RegCreateKeyExW({KEY}) failed: {rc:?}"));
        }
        if disposition != REG_CREATED_NEW_KEY {
            // SAFETY: `hkey` was opened above.
            let _ = unsafe { RegCloseKey(hkey) };
            return Err(format!(
                "{KEY} already existed; refusing to overwrite a key this probe did not make"
            ));
        }
        let guard = AppPathKey(hive, name);
        let value: Vec<u8> = wide(target.as_os_str()).iter().flat_map(|u| u.to_le_bytes()).collect();
        // SAFETY: `hkey` is open for writing; `value` is a NUL-terminated UTF-16 string as bytes.
        let set = unsafe { RegSetValueExW(hkey, PCWSTR::null(), None, REG_SZ, Some(&value)) };
        // SAFETY: `hkey` was opened above and is closed once.
        let _ = unsafe { RegCloseKey(hkey) };
        if set != ERROR_SUCCESS {
            return Err(format!("RegSetValueExW failed: {set:?}"));
        }
        Ok(guard)
    }
}

impl Drop for AppPathKey {
    fn drop(&mut self) {
        // SAFETY: the name is NUL-terminated and owned by `self`.
        let rc = unsafe { RegDeleteKeyW(self.0, PCWSTR(self.1.as_ptr())) };
        if rc != ERROR_SUCCESS {
            println!("CLEANUP: RegDeleteKeyW({KEY}) failed: {rc:?}");
        }
    }
}

fn is_elevated() -> Result<bool, String> {
    let mut token = HANDLE::default();
    // SAFETY: the pseudo-handle needs no closing; `token` is closed below.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .map_err(|e| format!("OpenProcessToken: {e}"))?;
    let mut elevation = TOKEN_ELEVATION::default();
    let mut len = 0u32;
    // SAFETY: `elevation` is a live TOKEN_ELEVATION of the size passed.
    let got = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    };
    // SAFETY: `token` was opened above.
    let _ = unsafe { CloseHandle(token) };
    got.map_err(|e| format!("GetTokenInformation: {e}"))?;
    Ok(elevation.TokenIsElevated != 0)
}

fn uac_policy(name: &str) -> String {
    let key = wide(OsStr::new(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"));
    let value = wide(OsStr::new(name));
    let mut data = 0u32;
    let mut size = 4u32;
    // SAFETY: both names are NUL-terminated; `data` is a live u32 of the size passed.
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(key.as_ptr()),
            PCWSTR(value.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some((&mut data as *mut u32).cast()),
            Some(&mut size),
        )
    };
    if rc == ERROR_SUCCESS {
        data.to_string()
    } else {
        format!("unreadable ({rc:?})")
    }
}

/// What a payload run reported: the image it was loaded from.
#[derive(Debug)]
struct Report {
    image: String,
}

/// Why a launch produced no report.
#[derive(Debug)]
enum Failure {
    /// `ShellExecuteExW` failed with this HRESULT.
    Shell(i32),
    Other(#[expect(dead_code, reason = "read through `Debug`, in failure messages")] String),
}

/// Launch `file` in `dir` through `ShellExecuteExW(verb)`, optionally as `class`, from a
/// single-threaded COM apartment as cosca's own launch does, and return what the payload reported.
fn launch(verb: &str, file: &OsStr, dir: &Path, class: Option<&str>, report: &Path) -> Result<Report, Failure> {
    let _ = std::fs::remove_file(report);
    // SAFETY: paired with the `CoUninitialize` below on this thread.
    let com = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) };
    if com.is_err() {
        return Err(Failure::Other(format!("CoInitializeEx: {com:?}")));
    }
    let launched = launch_in_apartment(verb, file, dir, class, report);
    // SAFETY: balances the successful `CoInitializeEx` above.
    unsafe { CoUninitialize() };
    launched
}

fn launch_in_apartment(
    verb: &str,
    file: &OsStr,
    dir: &Path,
    class: Option<&str>,
    report: &Path,
) -> Result<Report, Failure> {
    let verb = wide(OsStr::new(verb));
    let file_w = wide(file);
    let params = wide(OsStr::new(&format!("--report-to \"{}\"", report.display())));
    let dir_w = wide(dir.as_os_str());
    let class_w = class.map(|c| wide(OsStr::new(c)));
    let mut sei = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOASYNC | SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(file_w.as_ptr()),
        lpParameters: PCWSTR(params.as_ptr()),
        lpDirectory: PCWSTR(dir_w.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    if let Some(class_w) = &class_w {
        sei.fMask |= SEE_MASK_CLASSNAME;
        sei.lpClass = PCWSTR(class_w.as_ptr());
    }
    // SAFETY: every string field points at a NUL-terminated buffer that outlives the call.
    unsafe { ShellExecuteExW(&mut sei) }.map_err(|e| Failure::Shell(e.code().0))?;
    if sei.hProcess.is_invalid() {
        return Err(Failure::Other(
            "ShellExecuteExW succeeded without a process handle".into(),
        ));
    }
    // The child is `cosca_testbin_image`, which exits on its own once it has written the report.
    // SAFETY: `hProcess` is a live process handle owned here, closed once below.
    let _ = unsafe { WaitForSingleObject(sei.hProcess, INFINITE) };
    let mut code = 0u32;
    // SAFETY: as above.
    let _ = unsafe { GetExitCodeProcess(sei.hProcess, &mut code) };
    // SAFETY: as above.
    let _ = unsafe { CloseHandle(sei.hProcess) };
    let body = std::fs::read_to_string(report).map_err(|e| Failure::Other(format!("exit {code}, no report: {e}")))?;
    let line = |prefix: &str| body.lines().find_map(|l| l.strip_prefix(prefix).map(str::to_string));
    match line("image=") {
        Some(image) => Ok(Report { image }),
        _ => Err(Failure::Other(format!("exit {code}, incomplete report: {body:?}"))),
    }
}

fn mark_passed() {
    let Some(dir) = std::env::var_os("COSCA_CANARY_MARKERS") else {
        return;
    };
    let name = std::thread::current()
        .name()
        .expect("libtest names each test's thread")
        .replace("::", ".");
    std::fs::write(Path::new(&dir).join(name), b"").expect("write the canary marker");
}

/// Whether `image` is `want`, by file name: every payload copy has a name of its own, and the
/// image path comes back long (`runneradmin`) where the temp path may be 8.3 (`RUNNER~1`).
fn same_file(image: &str, want: &Path) -> bool {
    let want = want
        .file_name()
        .expect("a payload path has a file name")
        .to_string_lossy();
    Path::new(image)
        .file_name()
        .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case(&want))
}

/// The scratch layout both tests use: `a\cosca_probe_a.exe`, `b\cosca_probe_b.exe`,
/// `a\cosca_probe_c.com`, `onpath\cosca_probe_p.exe` (copies of the payload) and an empty dir.
struct Layout {
    root: tempfile::TempDir,
    dir_a: PathBuf,
    dir_empty: PathBuf,
    dir_path: PathBuf,
    b: PathBuf,
    c: PathBuf,
    report: PathBuf,
}

fn layout() -> Layout {
    match is_elevated() {
        Ok(true) => {}
        Ok(false) => panic!(
            "the measurement could not be taken: this process is not elevated, so runas would \
             prompt (EnableLUA={}, ConsentPromptBehaviorAdmin={})",
            uac_policy("EnableLUA"),
            uac_policy("ConsentPromptBehaviorAdmin")
        ),
        Err(e) => panic!("the measurement could not be taken: {e}"),
    }
    println!(
        "elevated; EnableLUA={}, ConsentPromptBehaviorAdmin={}",
        uac_policy("EnableLUA"),
        uac_policy("ConsentPromptBehaviorAdmin")
    );
    let root = tempfile::tempdir().expect("tempdir");
    let dir = |name: &str| -> PathBuf {
        let d = root.path().join(name);
        std::fs::create_dir(&d).expect("mkdir");
        d
    };
    let (dir_a, dir_b, dir_empty, dir_path) = (dir("a"), dir("b"), dir("empty"), dir("onpath"));
    let source = env!("CARGO_BIN_EXE_cosca_testbin_image");
    let b = dir_b.join("cosca_probe_b.exe");
    let c = dir_a.join("cosca_probe_c.com");
    for copy in [&dir_a.join(APP), &b, &c, &dir_path.join("cosca_probe_p.exe")] {
        std::fs::copy(source, copy).expect("copy the payload");
    }
    let report = root.path().join("report.txt");
    Layout {
        root,
        dir_a,
        dir_empty,
        dir_path,
        b,
        c,
        report,
    }
}

fn run(l: &Layout, label: &str, verb: &str, file: &OsStr, dir: &Path, class: Option<&str>) -> Result<Report, Failure> {
    let got = launch(verb, file, dir, class, &l.report);
    println!(
        "{label}: verb={verb} file={file:?} dir={} class={class:?} -> {got:?}",
        dir.display()
    );
    got
}

fn ends_with(got: &Result<Report, Failure>, path: &Path) -> bool {
    got.as_ref().is_ok_and(|r| same_file(&r.image, path))
}

fn failed_with(got: &Result<Report, Failure>, hresult: i32) -> bool {
    matches!(got, Err(Failure::Shell(code)) if *code == hresult)
}

/// Canary: with `SEE_MASK_CLASSNAME` and `lpClass = "exefile"`, `runas` runs a FULL path — an
/// `.exe`, and a `.com` too — and finds nothing by a bare name, in `lpDirectory` or on `PATH`,
/// where the same launch without the class finds both. `comfile` has no `runas` verb.
#[test]
#[ignore = "elevating probe: dispatch windows-probes with elevating=true"]
fn classname_runas_needs_a_full_path() {
    let l = layout();
    let mut failures: Vec<String> = Vec::new();
    let mut check = |ok: bool, what: &str, got: &Result<Report, Failure>| {
        if !ok {
            failures.push(format!("{what}: {got:?}"));
        }
    };
    let app = OsStr::new(APP);
    let a = l.dir_a.join(APP);
    let got = run(&l, "no class, bare, in lpDirectory", "runas", app, &l.dir_a, None);
    check(
        ends_with(&got, &a),
        "without a class, a bare name is found in lpDirectory",
        &got,
    );
    let got = run(
        &l,
        "exefile, bare, in lpDirectory",
        "runas",
        app,
        &l.dir_a,
        Some("exefile"),
    );
    check(
        failed_with(&got, FILE_NOT_FOUND),
        "with exefile, a bare name is not found in lpDirectory",
        &got,
    );
    let got = run(
        &l,
        "exefile, full path",
        "runas",
        a.as_os_str(),
        &l.dir_empty,
        Some("exefile"),
    );
    check(ends_with(&got, &a), "with exefile, a full .exe path runs", &got);
    let got = run(
        &l,
        "exefile, .com by full path",
        "runas",
        l.c.as_os_str(),
        &l.dir_empty,
        Some("exefile"),
    );
    check(ends_with(&got, &l.c), "with exefile, a full .com path runs", &got);
    let got = run(
        &l,
        "comfile, .com by full path",
        "runas",
        l.c.as_os_str(),
        &l.dir_empty,
        Some("comfile"),
    );
    check(failed_with(&got, NO_ASSOCIATION), "comfile has no runas verb", &got);

    let old_path = std::env::var_os("PATH").unwrap_or_default();
    let mut new_path = OsString::from(l.dir_path.as_os_str());
    new_path.push(";");
    new_path.push(&old_path);
    std::env::set_var("PATH", &new_path);
    let p_name = OsStr::new("cosca_probe_p.exe");
    let p = l.dir_path.join("cosca_probe_p.exe");
    let without = run(&l, "no class, on PATH", "runas", p_name, &l.dir_empty, None);
    let with = run(&l, "exefile, on PATH", "runas", p_name, &l.dir_empty, Some("exefile"));
    std::env::set_var("PATH", &old_path);
    check(
        ends_with(&without, &p),
        "without a class, a bare name is found on PATH",
        &without,
    );
    check(
        failed_with(&with, FILE_NOT_FOUND),
        "with exefile, a bare name is not found on PATH",
        &with,
    );

    drop(l.root);
    assert!(failures.is_empty(), "{}", failures.join("; "));
    mark_passed();
}

/// Canary: `ShellExecuteExW` consults an HKLM App Paths registration for a bare name, for `runas`
/// and `open` alike, and loads the registered image — but not when launched as `exefile`. An HKCU
/// registration is not consulted at all; that is printed, not asserted.
#[test]
#[ignore = "elevating probe: dispatch windows-probes with elevating=true"]
fn exefile_skips_the_app_paths_lookup() {
    let l = layout();
    let app = OsStr::new(APP);
    let mut failures: Vec<String> = Vec::new();
    for (label, hive, options) in [
        ("HKLM", HKEY_LOCAL_MACHINE, REG_OPTION_VOLATILE),
        ("HKCU", HKEY_CURRENT_USER, REG_OPTION_VOLATILE),
    ] {
        let key = AppPathKey::register(hive, options, &l.b)
            .unwrap_or_else(|e| panic!("the measurement could not be taken: {label}: {e}"));
        println!("--- {label}: {KEY} -> {}", l.b.display());
        for verb in ["runas", "open"] {
            let plain = run(&l, label, verb, app, &l.dir_empty, None);
            let redirected = ends_with(&plain, &l.b);
            println!("  => {label} {verb} redirected to b: {redirected}");
            if label == "HKLM" && !redirected {
                failures.push(format!("{label} {verb} without a class should load b: {plain:?}"));
            }
            let classed = run(&l, label, verb, app, &l.dir_empty, Some("exefile"));
            if !failed_with(&classed, FILE_NOT_FOUND) {
                failures.push(format!("{label} {verb} as exefile should find nothing: {classed:?}"));
            }
        }
        drop(key);
    }
    drop(l.root);
    assert!(failures.is_empty(), "{}", failures.join("; "));
    mark_passed();
}
