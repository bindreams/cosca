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
//! batch file — and registers one volatile HKCU key, which a guard deletes.
#![cfg(windows)]

use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegGetValueW, RegSetValueExW, HKEY, HKEY_CURRENT_USER,
    HKEY_LOCAL_MACHINE, KEY_WRITE, REG_CREATED_NEW_KEY, REG_CREATE_KEY_DISPOSITION, REG_OPTION_VOLATILE, REG_SZ,
    RRF_RT_REG_DWORD,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, WaitForSingleObject, INFINITE,
};
use windows::Win32::UI::Shell::{
    ShellExecuteExW, SEE_MASK_CLASSNAME, SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS,
    SHELLEXECUTEINFOW,
};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

const APP: &str = "cosca_probe_a.exe";
const KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\App Paths\cosca_probe_a.exe";

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain([0]).collect()
}

/// The HKCU App Paths key for [`APP`], deleted on drop. Created VOLATILE and only if absent, so a
/// key this probe did not make is never touched.
struct AppPathKey(Vec<u16>);

impl AppPathKey {
    fn register(target: &Path) -> Result<Self, String> {
        let name = wide(OsStr::new(KEY));
        let mut hkey = HKEY::default();
        let mut disposition = REG_CREATE_KEY_DISPOSITION::default();
        // SAFETY: `name` is NUL-terminated and outlives the call; the out-pointers are live locals.
        let rc = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(name.as_ptr()),
                None,
                PCWSTR::null(),
                REG_OPTION_VOLATILE,
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
                "HKCU\\{KEY} already existed; refusing to overwrite a key this probe did not make"
            ));
        }
        let guard = AppPathKey(name);
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
        let rc = unsafe { RegDeleteKeyW(HKEY_CURRENT_USER, PCWSTR(self.0.as_ptr())) };
        if rc != ERROR_SUCCESS {
            println!("CLEANUP: RegDeleteKeyW(HKCU\\{KEY}) failed: {rc:?}");
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

/// Elevate `file` in `dir` through `ShellExecuteExW(runas)`, optionally as `class`, and return the
/// `image=` line the payload wrote, or why there is none.
fn launch(file: &OsStr, dir: &Path, class: Option<&str>, report: &Path) -> Result<String, String> {
    let _ = std::fs::remove_file(report);
    let verb = wide(OsStr::new("runas"));
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
    unsafe { ShellExecuteExW(&mut sei) }.map_err(|e| format!("ShellExecuteExW failed: {e}"))?;
    if sei.hProcess.is_invalid() {
        return Err("ShellExecuteExW succeeded without a process handle".into());
    }
    // The child is `cosca_testbin_image`, which exits on its own once it has written the report.
    // SAFETY: `hProcess` is a live process handle owned here, closed once below.
    let _ = unsafe { WaitForSingleObject(sei.hProcess, INFINITE) };
    let mut code = 0u32;
    // SAFETY: as above.
    let _ = unsafe { GetExitCodeProcess(sei.hProcess, &mut code) };
    // SAFETY: as above.
    let _ = unsafe { CloseHandle(sei.hProcess) };
    let body = std::fs::read_to_string(report).map_err(|e| format!("exit {code}, no report: {e}"))?;
    body.lines()
        .find_map(|l| l.strip_prefix("image=").map(str::to_string))
        .ok_or_else(|| format!("exit {code}, report without image=: {body:?}"))
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

fn same_file(image: &str, want: &Path) -> bool {
    image.eq_ignore_ascii_case(&want.display().to_string())
}

/// Canary: without `SEE_MASK_CLASSNAME`, `runas` on a bare name App Paths knows loads the
/// REGISTERED image; with `SEE_MASK_CLASSNAME` and `lpClass = "exefile"`, it loads the file the
/// name finds in `lpDirectory`, and a name found nowhere is not redirected to the registered image.
/// Also prints, without asserting, how `.com` and a `PATH` search behave under each.
#[test]
#[ignore = "elevating probe: dispatch windows-probes with elevating=true"]
fn classname_launch_skips_app_paths() {
    let mut failures: Vec<String> = Vec::new();
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
    let a = dir_a.join(APP);
    let b = dir_b.join("cosca_probe_b.exe");
    let c = dir_a.join("cosca_probe_c.com");
    let p = dir_path.join("cosca_probe_p.exe");
    for copy in [&a, &b, &c, &p] {
        std::fs::copy(source, copy).expect("copy the payload");
    }
    let report = root.path().join("report.txt");
    let _key = AppPathKey::register(&b).unwrap_or_else(|e| panic!("the measurement could not be taken: {e}"));
    println!("registered HKCU\\{KEY} -> {}", b.display());

    let app = OsStr::new(APP);
    let run = |label: &str, file: &OsStr, dir: &Path, class: Option<&str>| {
        let got = launch(file, dir, class, &report);
        println!(
            "{label}: file={file:?} dir={} class={class:?} -> {got:?}",
            dir.display()
        );
        got
    };

    // The lookup is live: a name found nowhere else loads the registered image.
    let appaths_only = run("no class, not in lpDirectory", app, &dir_empty, None);
    if !appaths_only.as_deref().is_ok_and(|i| same_file(i, &b)) {
        failures.push(format!("without CLASSNAME, App Paths should load b: {appaths_only:?}"));
    }
    run("no class, in lpDirectory", app, &dir_a, None).ok();

    let class_found = run("exefile, in lpDirectory", app, &dir_a, Some("exefile"));
    if !class_found.as_deref().is_ok_and(|i| same_file(i, &a)) {
        failures.push(format!(
            "with CLASSNAME, the file in lpDirectory should load: {class_found:?}"
        ));
    }
    let class_nowhere = run("exefile, not in lpDirectory", app, &dir_empty, Some("exefile"));
    if class_nowhere.as_deref().is_ok_and(|i| same_file(i, &b)) {
        failures.push("with CLASSNAME, App Paths still redirected to b".into());
    }

    // Printed only.
    run("comfile, .com by full path", c.as_os_str(), &dir_empty, Some("comfile")).ok();
    run("exefile, .com by full path", c.as_os_str(), &dir_empty, Some("exefile")).ok();
    let old_path = std::env::var_os("PATH").unwrap_or_default();
    let mut new_path = OsString::from(dir_path.as_os_str());
    new_path.push(";");
    new_path.push(&old_path);
    std::env::set_var("PATH", &new_path);
    let p_name = OsStr::new("cosca_probe_p.exe");
    run("no class, on PATH", p_name, &dir_empty, None).ok();
    run("exefile, on PATH", p_name, &dir_empty, Some("exefile")).ok();
    std::env::set_var("PATH", &old_path);

    assert!(failures.is_empty(), "{}", failures.join("; "));
    mark_passed();
}
