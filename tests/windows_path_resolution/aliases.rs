//! M19: app execution aliases (`AppExecLink` reparse points in `%LOCALAPPDATA%\Microsoft\WindowsApps`)
//! and links to them: what `metadata`, `symlink_metadata`, the reparse tag and `GetFileAttributesW`
//! say, and whether `CreateProcessW` launches each by full path.
//!
//! It writes in its temp directory, and in one directory of its own under
//! `%LOCALAPPDATA%\Microsoft` (the junction row needs a sibling of `WindowsApps`). A `tempfile`
//! directory with a unique name, it is removed explicitly once its row is recorded, and the removal
//! must succeed; a panic before then leaves it to `Drop`.
//! Only `winget` is launched (with `--version`): another alias may open a store page or a REPL.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, DuplicateTokenEx, GetTokenInformation, SecurityImpersonation, TokenElevation,
    TokenImpersonation, TokenPrivileges, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_DUPLICATE,
    TOKEN_ELEVATION, TOKEN_IMPERSONATE, TOKEN_QUERY,
};
use windows::Win32::Storage::FileSystem::{
    FindClose, FindFirstFileW, GetFileAttributesW, FILE_ATTRIBUTE_REPARSE_POINT, INVALID_FILE_ATTRIBUTES,
    WIN32_FIND_DATAW,
};
use windows::Win32::System::Threading::{
    CreateProcessW, GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, SetThreadToken, WaitForSingleObject,
    CREATE_NO_WINDOW, INFINITE, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
};

use crate::common::windows_reparse::{app_exec_link_data, set_reparse, IO_REPARSE_TAG_APPEXECLINK};
use crate::measure::canonical;
use crate::provenance::survey_platform;
use crate::test_groups::{path_probes, Group};

const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
const IO_REPARSE_TAG_LX_SYMLINK: u32 = 0xA000_001D;

#[skuld::test]
fn m19_app_execution_aliases(#[fixture(path_probes)] _group: &Group) {
    survey_platform();
    let root = tempfile::tempdir().expect("tempdir");
    let t = canonical(root.path());
    println!("M19 elevated={}", elevated());

    let apps = PathBuf::from(std::env::var_os("LOCALAPPDATA").expect("LOCALAPPDATA"))
        .join("Microsoft")
        .join("WindowsApps");
    let mut names: Vec<String> = Vec::new();
    match std::fs::read_dir(&apps) {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(e) => {
                        let name = e.file_name().to_string_lossy().into_owned();
                        if name.to_ascii_lowercase().ends_with(".exe") {
                            names.push(name);
                        }
                    }
                    Err(e) => println!("M19 windows_apps_entry=err({e})"),
                }
            }
        }
        Err(e) => println!("M19 windows_apps=err({e})"),
    }
    names.sort();
    println!(
        "M19 aliases={}",
        if names.is_empty() {
            "none".to_owned()
        } else {
            names.join(",")
        }
    );

    self_made_alias(&t);

    let Some(name) = names
        .iter()
        .find(|n| n.eq_ignore_ascii_case("winget.exe"))
        .or(names.first())
    else {
        println!("M19 alias_rows=none: the runner has no alias to link to");
        return;
    };
    let alias = apps.join(name);
    let launch = name.eq_ignore_ascii_case("winget.exe").then_some("--version");
    println!("M19 alias={name}");
    println!("M19 alias {}", facts(&alias, launch));
    link_rows(&t, &apps, name, &alias, launch);
}

/// Whether this process can make its own alias with every privilege disabled, and what it is
/// then. Its target is a copy of `cosca_testbin_image`; its package is made up.
fn self_made_alias(t: &Path) {
    let target = t.join("own-target.exe");
    std::fs::copy(env!("CARGO_BIN_EXE_cosca_testbin_image"), &target).expect("copy the image");
    let alias = t.join("own-alias.exe");
    std::fs::write(&alias, b"").expect("create the alias file");
    let data = app_exec_link_data(target.as_os_str());
    let mut created = without_privileges(|| set_reparse(&alias, IO_REPARSE_TAG_APPEXECLINK, &data));
    println!("M19 own_alias_unprivileged_create={}", outcome(&created));
    if created.is_err() {
        created = set_reparse(&alias, IO_REPARSE_TAG_APPEXECLINK, &data);
        println!("M19 own_alias_privileged_create={}", outcome(&created));
    }
    if created.is_ok() {
        println!("M19 own_alias {}", facts(&alias, Some("")));
    }
}

/// The link rows, each `M19 <row> create=<outcome> <facts>`.
fn link_rows(t: &Path, apps: &Path, name: &str, alias: &Path, launch: Option<&str>) {
    let row = |label: &str, created: Result<(), String>, path: &Path| {
        let facts = if created.is_ok() {
            facts(path, launch)
        } else {
            String::new()
        };
        println!("M19 {label} create={} {facts}", outcome(&created));
    };
    let links = t.join("links");
    std::fs::create_dir(&links).expect("create links");

    let l = links.join(format!("abs-{name}"));
    row(
        "file_symlink_abs",
        io(std::os::windows::fs::symlink_file(alias, &l)),
        &l,
    );

    let l = links.join(format!("rel-{name}"));
    let created = relative_to(&links, alias).and_then(|rel| io(std::os::windows::fs::symlink_file(rel, &l)));
    row("file_symlink_rel", created, &l);

    let l = links.join(format!("junction-{name}"));
    row("junction_to_alias", junction(&l, alias), &l);

    let l = links.join(format!("dirlink-{name}"));
    row(
        "dir_symlink_to_alias",
        io(std::os::windows::fs::symlink_dir(alias, &l)),
        &l,
    );

    let l = links.join(format!("lx-{name}"));
    let target = alias.to_string_lossy().replace('\\', "/");
    let mut data = 2u32.to_le_bytes().to_vec();
    data.extend_from_slice(target.as_bytes());
    let created = io(std::fs::write(&l, b"")).and_then(|()| set_reparse(&l, IO_REPARSE_TAG_LX_SYMLINK, &data));
    row("lx_symlink", created, &l);

    row("alias_as_component", Ok(()), &alias.join("git.exe"));

    let d = t.join("dirlink");
    row(
        "dir_symlink_to_apps",
        io(std::os::windows::fs::symlink_dir(apps, &d)),
        &d.join(name),
    );

    // `..` past the volume root: a run longer than the link's depth, then the alias's own path.
    let a = t.join("a");
    std::fs::create_dir(&a).expect("create <t>\\a");
    let l = a.join(name);
    let created = same_drive(&a, alias).and_then(|()| {
        // Below the prefix and the root.
        let depth = a.components().count() - 2;
        let rest = alias.to_string_lossy();
        let rest = rest.get(3..).expect("a drive-absolute alias path");
        io(std::os::windows::fs::symlink_file(
            format!(r"{}{rest}", r"..\".repeat(depth + 2)),
            &l,
        ))
    });
    row("rel_past_root", created, &l);

    // A relative link, `..\WindowsApps\<name>`, read through a junction to its directory.
    let sibling = tempfile::Builder::new()
        .prefix("cosca-m19-")
        .tempdir_in(apps.parent().expect("WindowsApps has a parent"))
        .expect("create the sibling of WindowsApps");
    let l = sibling.path().join(name);
    let created = io(std::os::windows::fs::symlink_file(
        format!(r"..\WindowsApps\{name}"),
        &l,
    ));
    let j = t.join("j");
    let created = created.and_then(|()| junction(&j, sibling.path()));
    row("rel_in_junction", created, &j.join(name));
    sibling.close().expect("remove the sibling of WindowsApps");

    // The link found by std's search through a verbatim `PATH` entry.
    let v = t.join("vlinks");
    std::fs::create_dir(&v).expect("create vlinks");
    let created = io(std::os::windows::fs::symlink_file(alias, v.join(name)));
    let mut entry = std::ffi::OsString::from(r"\\?\");
    entry.push(&v);
    let mut verbatim = PathBuf::from(&entry);
    verbatim.push(name);
    row("verbatim_path_entry", created.clone(), &verbatim);
    if created.is_ok() {
        let stem = name.strip_suffix(".exe").unwrap_or(name);
        let found = match launch {
            Some(arg) => {
                let mut cmd = std::process::Command::new(stem);
                cmd.arg(arg).env("PATH", &entry);
                match crate::common::output_locked(&mut cmd) {
                    Ok(out) => format!("ok,exit={:?}", out.status.code()),
                    Err(e) => io_outcome(&e),
                }
            }
            None => "not-attempted".to_owned(),
        };
        println!("M19 verbatim_path_entry_std_search={found}");
    }
}

/// What std and Win32 say about `path`, and the launch by full path when `args` is given.
fn facts(path: &Path, args: Option<&str>) -> String {
    use std::os::windows::fs::FileTypeExt;
    let metadata = match std::fs::metadata(path) {
        Ok(m) => format!("ok,is_file={}", m.is_file()),
        Err(e) => io_outcome(&e),
    };
    let symlink = match std::fs::symlink_metadata(path) {
        Ok(m) => {
            let ft = m.file_type();
            if ft.is_symlink_file() {
                "symlink_file"
            } else if ft.is_symlink_dir() {
                "symlink_dir"
            } else if ft.is_dir() {
                "dir"
            } else {
                "file"
            }
            .to_owned()
        }
        Err(e) => io_outcome(&e),
    };
    let wide = wide_of(path.as_os_str());
    // SAFETY: `wide` is NUL-terminated and outlives the call.
    let attrs = unsafe { GetFileAttributesW(PCWSTR(wide.as_ptr())) };
    let attrs = if attrs == INVALID_FILE_ATTRIBUTES {
        io_outcome(&std::io::Error::last_os_error())
    } else {
        format!("{attrs:#x}")
    };
    let launch = args.map_or_else(|| "not-attempted".to_owned(), |args| launch(path, args));
    format!(
        "metadata={metadata} symlink_metadata={symlink} tag={} attrs={attrs} launch={launch}",
        reparse_tag(path)
    )
}

/// The reparse tag `FindFirstFileW` reports, `none` for a file that is no reparse point.
fn reparse_tag(path: &Path) -> String {
    let wide = wide_of(path.as_os_str());
    let mut data = WIN32_FIND_DATAW::default();
    // SAFETY: `wide` is NUL-terminated; `data` is a live out-parameter.
    match unsafe { FindFirstFileW(PCWSTR(wide.as_ptr()), &mut data) } {
        Ok(find) => {
            // SAFETY: `find` was just returned and is closed once.
            let _ = unsafe { FindClose(find) };
            if data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
                format!("{:#010x}", data.dwReserved0)
            } else {
                "none".to_owned()
            }
        }
        Err(e) => format!("err={}", e.code().0 & 0xFFFF),
    }
}

/// `CreateProcessW` with `path` as `lpApplicationName` and null std handles: `ok,exit=<code>` or
/// `err=<code>`. The wait is unbounded: the only programs launched (`winget --version` and this
/// test's own image) exit on their own.
fn launch(path: &Path, args: &str) -> String {
    let app = wide_of(path.as_os_str());
    let mut line = wide_of(OsStr::new(&format!("\"{}\" {args}", path.display())));
    let si = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTF_USESTDHANDLES,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();
    // SAFETY: `app` and `line` are NUL-terminated and outlive the call; `line` is writable; `si`
    // and `pi` are live.
    let created = unsafe {
        CreateProcessW(
            PCWSTR(app.as_ptr()),
            Some(PWSTR(line.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_NO_WINDOW,
            None,
            None,
            &si,
            &mut pi,
        )
    };
    if let Err(e) = created {
        return format!("err={}", e.code().0 & 0xFFFF);
    }
    let mut code = 0u32;
    // SAFETY: `pi`'s handles are live and owned here, each closed once.
    unsafe {
        WaitForSingleObject(pi.hProcess, INFINITE);
        let got = GetExitCodeProcess(pi.hProcess, &mut code);
        let _ = CloseHandle(pi.hThread);
        let _ = CloseHandle(pi.hProcess);
        if let Err(e) = got {
            return format!("ok,exit=unknown({e})");
        }
    }
    format!("ok,exit={code}")
}

/// A junction (mount point) at `link`, a new directory, to `target`, set by `FSCTL_SET_REPARSE_POINT`
/// so that a file target is allowed.
fn junction(link: &Path, target: &Path) -> Result<(), String> {
    io(std::fs::create_dir(link))?;
    let mut substitute = OsStr::new(r"\??\").to_os_string();
    substitute.push(target);
    let sub: Vec<u16> = substitute.encode_wide().collect();
    let print: Vec<u16> = target.as_os_str().encode_wide().collect();
    let (sub_bytes, print_bytes) = (sub.len() as u16 * 2, print.len() as u16 * 2);
    let mut data = Vec::new();
    for field in [0, sub_bytes, sub_bytes + 2, print_bytes] {
        data.extend_from_slice(&field.to_le_bytes());
    }
    for unit in sub.iter().chain(&[0]).chain(&print).chain(&[0]) {
        data.extend_from_slice(&unit.to_le_bytes());
    }
    set_reparse(link, IO_REPARSE_TAG_MOUNT_POINT, &data)
}

/// Runs `f` on a thread of its own, impersonating this process's token with every privilege
/// disabled. A token left with an enabled privilege fails the test: the row would not measure the
/// unprivileged case.
fn without_privileges<T: Send>(f: impl FnOnce() -> T + Send) -> T {
    std::thread::scope(|s| {
        s.spawn(|| {
            let mut token = HANDLE::default();
            // SAFETY: the pseudo-handle needs no close; `token` is a live out-parameter.
            unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE, &mut token) }.expect("OpenProcessToken");
            let mut dup = HANDLE::default();
            // SAFETY: `token` is live with TOKEN_DUPLICATE; `dup` is a live out-parameter.
            let duplicated = unsafe {
                DuplicateTokenEx(
                    token,
                    TOKEN_ADJUST_PRIVILEGES | TOKEN_IMPERSONATE | TOKEN_QUERY,
                    None,
                    SecurityImpersonation,
                    TokenImpersonation,
                    &mut dup,
                )
            };
            // SAFETY: `token` is owned here and closed once.
            let _ = unsafe { CloseHandle(token) };
            duplicated.expect("DuplicateTokenEx");
            // SAFETY: `dup` is this thread's own fresh token.
            unsafe { AdjustTokenPrivileges(dup, true, None, 0, None, None) }.expect("AdjustTokenPrivileges");
            assert_eq!(enabled_privileges(dup), 0, "precondition: every privilege is disabled");
            // SAFETY: `dup` is an impersonation token of this process's own identity.
            unsafe { SetThreadToken(None, Some(dup)) }.expect("SetThreadToken");
            let result = f();
            // SAFETY: reverts this thread to no impersonation, the counterpart of the call above.
            unsafe { SetThreadToken(None, None) }.expect("revert the impersonation");
            // SAFETY: `dup` is owned here and closed once.
            let _ = unsafe { CloseHandle(dup) };
            result
        })
        .join()
        .expect("the unprivileged thread")
    })
}

/// How many of `token`'s privileges are enabled.
fn enabled_privileges(token: HANDLE) -> usize {
    let mut len = 0u32;
    // SAFETY: a size query; `len` is a live out-parameter.
    let _ = unsafe { GetTokenInformation(token, TokenPrivileges, None, 0, &mut len) };
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buf` is a live, 8-aligned allocation of at least `len` bytes.
    unsafe { GetTokenInformation(token, TokenPrivileges, Some(buf.as_mut_ptr().cast()), len, &mut len) }
        .expect("GetTokenInformation(TokenPrivileges)");
    let bytes: &[u8] = bytemuck_bytes(&buf);
    let count = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    // TOKEN_PRIVILEGES: a u32 count, then 12-byte LUID_AND_ATTRIBUTES (LUID, then attributes).
    (0..count)
        .filter(|i| {
            let at = 4 + i * 12 + size_of::<LUID>();
            let attributes = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
            attributes & SE_PRIVILEGE_ENABLED.0 != 0
        })
        .count()
}

fn bytemuck_bytes(words: &[u64]) -> &[u8] {
    // SAFETY: any initialised `u64` slice is a valid byte slice of eight times its length.
    unsafe { std::slice::from_raw_parts(words.as_ptr().cast(), words.len() * 8) }
}

/// Whether this process's token is elevated.
fn elevated() -> bool {
    let mut token = HANDLE::default();
    // SAFETY: the pseudo-handle needs no close; `token` is a live out-parameter.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.expect("OpenProcessToken");
    let mut elevation = TOKEN_ELEVATION::default();
    let mut len = 0u32;
    // SAFETY: `elevation` is a live out-parameter of the size passed.
    let got = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some(std::ptr::addr_of_mut!(elevation).cast()),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    };
    // SAFETY: `token` is owned here and closed once.
    let _ = unsafe { CloseHandle(token) };
    got.expect("GetTokenInformation(TokenElevation)");
    elevation.TokenIsElevated != 0
}

/// `target` relative to the directory `from`: `..` up to the volume root, then `target` below it.
fn relative_to(from: &Path, target: &Path) -> Result<PathBuf, String> {
    same_drive(from, target)?;
    let t = target.to_string_lossy();
    // Below the prefix and the root.
    let depth = from.components().count() - 2;
    Ok(PathBuf::from(format!(r"{}{}", r"..\".repeat(depth), &t[3..])))
}

/// `Ok` when both drive-absolute paths are on one drive; no `..` run reaches across drives.
fn same_drive(from: &Path, target: &Path) -> Result<(), String> {
    let (f, t) = (from.to_string_lossy(), target.to_string_lossy());
    if f[..2].eq_ignore_ascii_case(&t[..2]) {
        Ok(())
    } else {
        Err(format!("impossible: {from:?} and {target:?} are on different drives"))
    }
}

fn wide_of(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain([0]).collect()
}

fn io(r: std::io::Result<()>) -> Result<(), String> {
    r.map_err(|e| io_outcome(&e))
}

fn io_outcome(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(code) => format!("err={code}"),
        None => format!("err({:?})", e.kind()),
    }
}

fn outcome(r: &Result<(), String>) -> String {
    match r {
        Ok(()) => "ok".to_owned(),
        Err(why) => why.clone(),
    }
}
