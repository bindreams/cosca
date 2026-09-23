//! Canaries that spawn the payload: which file loads, and whether std substitutes `cmd.exe`.

use crate::dots_and_spaces::WEIRD_NAMES;
use crate::harness::Disagreements;
use crate::provenance::announce_platform;
use crate::pure::verbatim_spelling;
use crate::winapi::{outcome, wide};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0};
use windows::Win32::Storage::FileSystem::{FileIdInfo, GetFileInformationByHandleEx, FILE_ID_INFO};
use windows::Win32::System::Threading::{
    CreateProcessW, GetExitCodeProcess, QueryFullProcessImageNameW, WaitForSingleObject, CREATE_NO_WINDOW,
    CREATE_SUSPENDED, INFINITE, PROCESS_INFORMATION, PROCESS_NAME_WIN32, STARTF_USESTDHANDLES, STARTUPINFOW,
};

/// Canary: an image under a verbatim dots-and-spaces name LOADS through `std::process`, and the
/// file that loads is the one under that name.
///
/// This measures Rust's `std::process` as well as Windows. For a `\\?\C:\…` program shorter than
/// `MAX_PATH`, std runs `GetFullPathNameW` on the part after the prefix and drops the prefix only
/// if that comes back unchanged. For these names it does not (the final component is stripped, see
/// `dots_and_spaces::a_final_dots_and_spaces_component_is_stripped_even_verbatim`), so std keeps
/// the verbatim string and hands it to `CreateProcessW`. The loaded image being the planted file
/// witnesses that: the stripped string names a directory. That std's `.bat`/`.cmd` test also reads
/// the literal verbatim string (`is_verbatim` → `has_bat_extension` on the program) is read from
/// rust-src, not witnessed here; witnessing it would need a batch-shaped name.
///
/// So refusing these names would refuse a loadable executable. Raw `CreateProcessW` and both plain
/// spellings are printed alongside.
///
/// The payload, `cosca_testbin_image`, only reports its image and exits 0. Its `image=` line is
/// `QueryFullProcessImageNameW`; the canary opens that path verbatim and compares file identity
/// with the planted copy, so a spawn that ran any other file fails. Its `module=` line, the name
/// the loader recorded, is printed only.
#[test]
#[ignore = "platform canary: needs a Windows runner"]
fn a_verbatim_dots_and_spaces_file_exists_and_loads() {
    let mut failures: Vec<String> = announce_platform().err().into_iter().collect();
    let mut facts = Disagreements::about("Windows and Rust's std::process");
    let root = tempfile::tempdir().expect("tempdir");
    let root = root.path().to_str().expect("temp path is not UTF-8").to_string();
    let source = env!("CARGO_BIN_EXE_cosca_testbin_image");
    println!("temp root: {root:?}\nsource image: {source:?}");
    let mut spawnable = 0usize;

    for (i, &(name, note, creatable)) in WEIRD_NAMES.iter().enumerate() {
        let case_dir = format!(r"{root}\case{i}");
        if let Err(e) = std::fs::create_dir(&case_dir) {
            failures.push(format!("could not create the case directory {case_dir:?}: {e}"));
            continue;
        }
        let verbatim = format!(r"\\?\{case_dir}\{name}");
        let plain = format!(r"{case_dir}\{name}");
        println!("--- {verbatim:?}  ({note})");
        // Whether the name can hold an image is itself a fact, checked either way, so a platform
        // change here is reported as one and never reaches the planted-count guard below.
        // `dots_and_spaces::only_dot_and_dotdot_are_refused_as_verbatim_file_names` owns which
        // names those are.
        let copied = std::fs::copy(source, &verbatim);
        facts.check(
            copied.is_ok() == creatable,
            &format!(
                "an image {} be copied to verbatim {name:?}",
                if creatable { "can" } else { "cannot" }
            ),
            outcome(&copied),
        );
        if let Err(e) = &copied {
            println!(
                "  copy: FAILED: {e} (raw_os_error={:?}) — nothing to spawn",
                e.raw_os_error()
            );
            continue;
        }
        if !creatable {
            println!("  copy: succeeded where it should not — not spawned");
            if let Err(e) = std::fs::remove_file(&verbatim) {
                println!("  CLEANUP: {verbatim:?} could not be removed: {e}");
            }
            continue;
        }
        spawnable += 1;
        let planted = match file_identity(&verbatim) {
            Ok(id) => id,
            Err(why) => {
                failures.push(why);
                continue;
            }
        };
        println!("  planted file identity: {planted:?}");
        for (tag, program) in [("verbatim", &verbatim), ("plain", &plain)] {
            let out = format!(r"\\?\{case_dir}\out_{tag}.txt");
            match create_process(program, &out) {
                Ok((code, captured)) => {
                    println!("  CreateProcessW as {tag} {program:?}: ran, exit={code}, child said {captured:?}")
                }
                Err(why) => println!("  CreateProcessW as {tag} {program:?}: {why}"),
            }
            // std::process is the route cosca actually takes, and it resolves the program itself
            // before calling CreateProcessW — so it can disagree with the line above.
            let ran = std::process::Command::new(program).output();
            match &ran {
                Ok(o) => println!(
                    "  std::process as {tag} {program:?}: ran, {:?}, child said {:?}",
                    o.status,
                    String::from_utf8_lossy(&o.stdout)
                ),
                Err(e) => println!(
                    "  std::process as {tag} {program:?}: FAILED: {e} (raw_os_error={:?})",
                    e.raw_os_error()
                ),
            }
            if tag != "verbatim" {
                continue;
            }
            let output = match ran {
                Ok(o) if o.status.success() => o,
                other => {
                    facts.check(
                        false,
                        &format!("std::process runs the image at verbatim {name:?}"),
                        other.map_or_else(|e| e.to_string(), |o| format!("{:?}", o.status)),
                    );
                    continue;
                }
            };
            let stdout = String::from_utf8_lossy(&output.stdout);
            let Some(image) = stdout.lines().find_map(|l| l.strip_prefix("image=")) else {
                failures.push(format!("the payload at {verbatim:?} exited 0 without an image= line"));
                continue;
            };
            // An image path that cannot be opened is a broken probe, not a changed platform.
            let loaded = match file_identity(&verbatim_spelling(image)) {
                Ok(id) => id,
                Err(why) => {
                    failures.push(format!("the reported image {image:?}: {why}"));
                    continue;
                }
            };
            println!("  image={image:?} opened verbatim has identity {loaded:?}");
            facts.check(
                loaded == planted,
                &format!("std::process on verbatim {name:?} loads that file, not another"),
                format_args!("image={image:?} with identity {loaded:?}, planted {planted:?}"),
            );
        }
        if let Err(e) = std::fs::remove_file(&verbatim) {
            println!("  CLEANUP: {verbatim:?} could not be removed: {e}");
        }
    }
    println!("names that could hold an image: {spawnable} of {}", WEIRD_NAMES.len());
    assert!(
        failures.is_empty(),
        "the measurement could not be taken: {}",
        failures.join("; ")
    );
    // A creatable name that could not hold an image is a changed platform, reported here first.
    facts.assert_none();
    // Otherwise every creatable name was spawned; without this a run that planted nothing would
    // measure nothing and pass.
    let expected = WEIRD_NAMES.iter().filter(|&&(_, _, creatable)| creatable).count();
    assert!(
        expected > 0 && spawnable == expected,
        "the measurement could not be taken: images were planted under {spawnable} names, not the \
         {expected} that can hold one"
    );
}

/// The volume serial number and 128-bit file ID of `path`: the file's identity, whatever the
/// spelling. `GetFileInformationByHandle`'s 64-bit index is not unique on ReFS; `FileIdInfo` is.
pub(crate) fn file_identity(path: &str) -> Result<(u64, [u8; 16]), String> {
    use std::os::windows::io::AsRawHandle;
    let file = std::fs::File::open(path).map_err(|e| format!("could not open {path:?}: {e}"))?;
    let mut info = FILE_ID_INFO::default();
    // SAFETY: the handle is owned by `file`, alive for the call; `info` is a live out-parameter of
    // exactly the size passed, the one `FileIdInfo` requires.
    unsafe {
        GetFileInformationByHandleEx(
            HANDLE(file.as_raw_handle()),
            FileIdInfo,
            std::ptr::addr_of_mut!(info).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    }
    .map_err(|e| format!("GetFileInformationByHandleEx({path:?}, FileIdInfo) failed: {e}"))?;
    Ok((info.VolumeSerialNumber, info.FileId.Identifier))
}

/// Canary: `std::process` hands a verbatim `x.bat.` or `x.bat ` (one trailing space) to
/// `CreateProcessW` as given, while it runs a verbatim `x.bat` through `cmd.exe`.
///
/// This measures Rust's `std::process`, whose toolchain floats like the runner image. For a
/// verbatim program std tests `.bat`/`.cmd` on the literal string when `GetFullPathNameW` would
/// rewrite it, and `x.bat.`/`x.bat ` do not end in `.bat`. Were std to test the rewritten
/// `…\x.bat` instead, it would substitute `cmd.exe`. The verbatim `x.bat` row is the control: it
/// survives `GetFullPathNameW` unchanged, so std drops the prefix and does substitute `cmd.exe`,
/// which shows that this probe sees a substitution when one happens.
///
/// **Nothing executes.** Each spawn is created suspended, its image is read from the new process
/// with `QueryFullProcessImageNameW` and compared by file identity with the planted payload, and
/// the process is terminated before its first instruction runs. So `cmd.exe`, when std picks it,
/// never runs.
#[test]
#[ignore = "platform canary: needs a Windows runner"]
fn std_runs_a_verbatim_trailing_dot_or_space_batch_name_itself() {
    let mut failures: Vec<String> = announce_platform().err().into_iter().collect();
    let mut facts = Disagreements::about("Rust's std::process");
    let root = tempfile::tempdir().expect("tempdir");
    let root = root.path().to_str().expect("temp path is not UTF-8").to_string();
    let source = env!("CARGO_BIN_EXE_cosca_testbin_image");
    println!("temp root: {root:?}\nsource image: {source:?}");

    // (name, whether std should run the planted file itself)
    for (i, (name, runs_itself)) in [("x.bat.", true), ("x.bat ", true), ("x.bat", false)]
        .into_iter()
        .enumerate()
    {
        let case_dir = format!(r"{root}\case{i}");
        if let Err(e) = std::fs::create_dir(&case_dir) {
            failures.push(format!("could not create the case directory {case_dir:?}: {e}"));
            continue;
        }
        let verbatim = format!(r"\\?\{case_dir}\{name}");
        println!("--- {verbatim:?}");
        if let Err(e) = std::fs::copy(source, &verbatim) {
            failures.push(format!("could not plant the payload at {verbatim:?}: {e}"));
            continue;
        }
        let planted = file_identity(&verbatim);
        let image = suspended_image(&verbatim);
        println!("  planted identity {planted:?}; std::process created {image:?}");
        match (planted, image) {
            (Ok(planted), Ok(image)) => match file_identity(&verbatim_spelling(&image)) {
                Ok(loaded) if runs_itself => facts.check(
                    loaded == planted,
                    &format!("std::process runs verbatim {name:?} itself, not through cmd.exe"),
                    format_args!("image {image:?}"),
                ),
                Ok(loaded) => facts.check(
                    loaded != planted && image.to_ascii_lowercase().ends_with(r"\cmd.exe"),
                    &format!("std::process runs verbatim {name:?} through cmd.exe (the control)"),
                    format_args!("image {image:?}"),
                ),
                Err(why) => failures.push(format!("the created image {image:?}: {why}")),
            },
            (planted, image) => failures.extend(planted.err().into_iter().chain(image.err())),
        }
        if let Err(e) = std::fs::remove_file(&verbatim) {
            println!("  CLEANUP: {verbatim:?} could not be removed: {e}");
        }
    }
    assert!(
        failures.is_empty(),
        "the measurement could not be taken: {}",
        failures.join("; ")
    );
    facts.assert_none();
}

/// Spawn `program` through `std::process` SUSPENDED, read the image the new process was created
/// from, and terminate it before it runs. `Err` if any step fails.
pub(crate) fn suspended_image(program: &str) -> Result<String, String> {
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use std::process::Stdio;

    let mut child = std::process::Command::new(program)
        .creation_flags(CREATE_SUSPENDED.0 | CREATE_NO_WINDOW.0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("std::process could not spawn {program:?}: {e}"))?;
    let mut buf = vec![0u16; 32 * 1024];
    let mut len = buf.len() as u32;
    // SAFETY: the process handle is owned by `child` and alive; `buf` is a live allocation of
    // `len` units, which the call writes at most that many of.
    let queried = unsafe {
        QueryFullProcessImageNameW(
            HANDLE(child.as_raw_handle()),
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
    };
    // Terminate and reap whatever happened above: the process must never be resumed.
    let killed = child.kill();
    let reaped = child.wait();
    queried.map_err(|e| format!("QueryFullProcessImageNameW on the child of {program:?} failed: {e}"))?;
    killed.map_err(|e| format!("could not terminate the suspended child of {program:?}: {e}"))?;
    reaped.map_err(|e| format!("could not reap the child of {program:?}: {e}"))?;
    Ok(String::from_utf16_lossy(&buf[..len as usize]))
}

/// `CreateProcessW(lpApplicationName = program)` with no arguments, stdout captured to `out_path`.
/// `Err` is a spawn that did not happen, rendered with its Win32 error.
pub(crate) fn create_process(program: &str, out_path: &str) -> Result<(u32, String), String> {
    use std::os::windows::io::AsRawHandle;

    let file = std::fs::File::create(out_path).map_err(|e| format!("could not open the capture file: {e}"))?;
    let handle = HANDLE(file.as_raw_handle());
    // SAFETY: `handle` is a live handle owned by `file` for the whole call.
    unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT) }
        .map_err(|e| format!("could not make the capture handle inheritable: {e}"))?;

    let program_w = wide(program);
    let mut cmdline_w = wide(&format!("\"{program}\""));
    let si = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTF_USESTDHANDLES,
        hStdOutput: handle,
        hStdError: handle,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();
    // SAFETY: both wide buffers are nul-terminated and outlive the call; `cmdline_w` is writable,
    // as CreateProcessW requires; `si` and `pi` are live and correctly sized.
    let spawned = unsafe {
        CreateProcessW(
            PCWSTR(program_w.as_ptr()),
            Some(PWSTR(cmdline_w.as_mut_ptr())),
            None,
            None,
            true,
            CREATE_NO_WINDOW,
            None,
            None,
            &si,
            &mut pi,
        )
    };
    if let Err(e) = spawned {
        return Err(format!("did not spawn: {e} (HRESULT {:#010x})", e.code().0));
    }

    // SAFETY: `pi.hProcess` is the live handle CreateProcessW just handed us. INFINITE is not a
    // chosen timeout — the child is `cosca_testbin_image`, which exits on its own.
    let waited = unsafe { WaitForSingleObject(pi.hProcess, INFINITE) };
    // Captured before anything else can overwrite the thread's last error.
    let wait_error = std::io::Error::last_os_error();
    let mut code = 0u32;
    let got_code = if waited == WAIT_OBJECT_0 {
        // SAFETY: the process has exited and `code` is a live out-parameter.
        unsafe { GetExitCodeProcess(pi.hProcess, &mut code) }.map_err(|e| format!("GetExitCodeProcess failed: {e}"))
    } else {
        // Anything else leaves the child possibly running and the capture incomplete.
        Err(format!(
            "WaitForSingleObject returned {:#x}, not WAIT_OBJECT_0: {wait_error}",
            waited.0
        ))
    };
    // SAFETY: both handles are owned by us and not used again.
    unsafe {
        let _ = CloseHandle(pi.hThread);
        let _ = CloseHandle(pi.hProcess);
    }
    got_code?;

    drop(file);
    let captured = std::fs::read_to_string(out_path).map_err(|e| format!("could not read the capture file: {e}"))?;
    Ok((code, captured))
}
