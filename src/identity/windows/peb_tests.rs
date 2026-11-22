//! The start-up read against real processes, the only check that the private PEB layout holds on the build
//! the tests run on. Each child has written its first line, so its start-up is over; the in-loader state is
//! read in `child::suspended_tests`.

use std::io::Read as _;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::JobObjects::IsProcessInJob;
use windows::Win32::System::Threading::CREATE_SUSPENDED;

use super::{read_peb, start_state, PebField, StartupRead};
use crate::test_child::ctrl_break::{
    kill_release_reap, spawn_consoleless_root, spawn_member, Handler, FREE_CONSOLE_ENV,
};
use crate::ContainMode;

fn process_of(child: &crate::Child) -> HANDLE {
    HANDLE(child.process_handle())
}

/// A child that has a console of its own (`no_window`) has, after its first line, finished starting with
/// a console handle that is a real one: positive, and not the `4` that is positive and attaches nothing.
///
/// Mutants: the console handle is read from another offset of the block (a pointer, a flag word, not a
/// handle); the bit test is inverted (the finished child reads `Initializing`); `Ldr` is read from another
/// offset (the word is null, so `NotBegun`).
#[skuld::test]
fn a_child_with_a_console_reads_finished_with_a_real_console_handle() {
    let (child, sock, _) = spawn_member(Handler::Ignore, None, ContainMode::Strongest, |cmd| _ = cmd.no_window());

    let state = start_state(process_of(&child)).expect("read a running child");

    assert!(
        matches!(state, StartupRead::Finished { console_handle } if console_handle > 4),
        "finished, with a real console's handle: {state:?}"
    );
    kill_release_reap(&child, sock, false);
}

/// A `DETACHED_PROCESS` child has, after its first line, finished starting with console handle `0`.
///
/// Mutants: the console handle is read from another offset; the parameters pointer is read at another
/// offset of the PEB (the `Ldr` word: a pointer that is not the block, so the handle read is not `0`); the
/// bit test is inverted (the finished child reads `Initializing`).
#[skuld::test]
fn a_detached_child_reads_finished_with_no_console() {
    let (child, sock, _) = spawn_member(Handler::Ignore, None, ContainMode::Strongest, |cmd| _ = cmd.detached());

    let state = start_state(process_of(&child)).expect("read a running child");

    assert_eq!(state, StartupRead::Finished { console_handle: 0 });
    kill_release_reap(&child, sock, false);
}

/// A GUI-subsystem child (the suite's `cosca_testbin_gui`, which opens no window and never attaches to a
/// console) reads, after its handshake, as finished starting with console handle `0`.
///
/// Mutants: the console handle is read from another offset; the bit test is inverted (the finished child
/// reads `Initializing`); `Ldr` is read from another offset (`NotBegun`).
#[skuld::test]
fn a_gui_subsystem_child_reads_finished_with_no_console() {
    let (child, sock) = spawn_consoleless_root();

    let state = start_state(process_of(&child)).expect("read a running child");

    assert_eq!(state, StartupRead::Finished { console_handle: 0 });
    kill_release_reap(&child, sock, false);
}

/// A child that called `FreeConsole` (it reports so on its socket after the call) reads finished with
/// console handle `0`, though it started with a console.
///
/// Mutant: the console handle is read from another offset (not `0`).
#[skuld::test]
fn a_child_that_freed_its_console_reads_finished_with_no_console() {
    let (child, mut sock, _) = spawn_member(Handler::Ignore, None, ContainMode::Strongest, |cmd| {
        cmd.no_window().env(FREE_CONSOLE_ENV, "1");
    });
    let mut freed = [0u8; 1];
    sock.read_exact(&mut freed)
        .expect("the child reports that it freed its console");
    assert_eq!(&freed, b"F");

    let state = start_state(process_of(&child)).expect("read a running child");

    assert_eq!(state, StartupRead::Finished { console_handle: 0 });
    kill_release_reap(&child, sock, false);
}

/// The word read at the listed offset of the PEB is `CrossProcessFlags`: its bit 0, `ProcessInJob`, is set
/// for a child in a Job Object, which a contained child is, and agrees with the OS's own answer.
///
/// Mutant: the flags are read from a neighbouring field (a pointer's half, which is not `1` here).
#[skuld::test]
fn the_cross_process_flags_word_is_the_one_the_listing_places_at_the_offset() {
    let (child, sock, _) = spawn_member(Handler::Ignore, None, ContainMode::Strongest, |cmd| _ = cmd.no_window());
    let process = process_of(&child);
    let mut in_job = windows::core::BOOL(0);
    // SAFETY: the handle is live; `in_job` is the buffer the call writes.
    unsafe { IsProcessInJob(process, None, &mut in_job) }.expect("ask the OS whether the child is in a job");

    let flags = read_peb(process, PebField::CrossProcessFlags).expect("read a running child");

    assert!(in_job.as_bool(), "a contained child is in a Job Object");
    assert_eq!(flags & 1 == 1, in_job.as_bool(), "bit 0 is ProcessInJob: {flags:#x}");
    kill_release_reap(&child, sock, false);
}

/// Which children `check_native` lets through, over the facts `IsWow64Process2` gives: the build, the host
/// and the child's WOW64 machine.
///
/// Mutants: the host's machine is not compared with the build's (either build); a WOW64 child is let
/// through (either build); a build for neither architecture is let through.
#[skuld::test]
fn only_a_child_native_to_a_measured_host_and_build_passes_check_native() {
    use windows::Win32::System::SystemInformation::{
        IMAGE_FILE_MACHINE_AMD64 as X64, IMAGE_FILE_MACHINE_ARM64 as ARM64, IMAGE_FILE_MACHINE_I386 as X86,
        IMAGE_FILE_MACHINE_UNKNOWN as NONE,
    };

    // (build, host, child's WOW64 machine, ok or the text the refusal holds)
    let rows: [(_, _, _, Result<(), &str>); 8] = [
        (X64, X64, NONE, Ok(())),
        (
            X64,
            X64,
            X86,
            Err("not native to the host (it runs under WOW64 as machine 0x14c)"),
        ),
        (
            X64,
            ARM64,
            NONE,
            Err("the host's native machine (0xaa64) is not this build's (0x8664)"),
        ),
        (ARM64, ARM64, NONE, Ok(())),
        (ARM64, ARM64, X86, Err("not native to the host (it runs under WOW64")),
        (
            ARM64,
            ARM64,
            X64,
            Err("not native to the host (it runs under WOW64 as machine 0x8664)"),
        ),
        (
            ARM64,
            X64,
            NONE,
            Err("the host's native machine (0x8664) is not this build's (0xaa64)"),
        ),
        (X86, X86, NONE, Err("this build of cosca is for neither x64 nor ARM64")),
    ];
    for (build, host, wow64, expected) in rows {
        let got = super::check_native(build, host, wow64);
        let case = format!("build {:#x}, host {:#x}, wow64 {:#x}", build.0, host.0, wow64.0);
        match (got, expected) {
            (Ok(()), Ok(())) => {}
            (Err(err), Err(text)) => {
                assert_eq!(err.kind(), std::io::ErrorKind::Unsupported, "{case}: {err}");
                assert!(err.to_string().contains(text), "{case}: {err}");
            }
            (got, expected) => panic!("{case}: got {got:?}, expected {expected:?}"),
        }
    }
}

/// Which process machines `check_machine` lets through on an ARM64 build: ARM64, and no other (an x64
/// program emulated on an ARM64 host, which `IsWow64Process2` does not show).
///
/// Mutants: an x64 machine is let through; every machine is let through.
#[skuld::test]
fn only_an_arm64_process_machine_passes_check_machine() {
    use windows::Win32::System::SystemInformation::{
        IMAGE_FILE_MACHINE_AMD64 as X64, IMAGE_FILE_MACHINE_ARM64 as ARM64, IMAGE_FILE_MACHINE_I386 as X86,
    };

    super::check_machine(ARM64).expect("a native ARM64 process");
    for (machine, text) in [
        (
            X64,
            "not native to the host (it is an emulated process of machine 0x8664)",
        ),
        (
            X86,
            "not native to the host (it is an emulated process of machine 0x14c)",
        ),
    ] {
        let err = super::check_machine(machine).expect_err("an emulated process is refused");
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported, "{machine:?}: {err}");
        assert!(err.to_string().contains(text), "{machine:?}: {err}");
    }
}

/// The child is the system's 32-bit `cmd.exe`, created suspended.
///
/// Mutant: the read goes on for a WOW64 image (it returns a state).
#[skuld::test]
fn a_32_bit_child_is_not_read() {
    let system = std::env::var_os("SystemRoot").expect("SystemRoot names the Windows directory");
    let image = std::path::Path::new(&system).join("SysWOW64").join("cmd.exe");
    assert!(image.is_file(), "the 32-bit image {image:?} must exist to be read");
    let mut cmd = std::process::Command::new(&image);
    cmd.args(["/d", "/c", "more >nul"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let child =
        crate::test_child::StdChild::spawn_with(&mut cmd, CREATE_SUSPENDED.0, crate::test_child::Console::Hidden);

    let err = start_state(HANDLE(crate::test_frozen::raw(&child))).expect_err("a 32-bit child is not read");

    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported, "{err:?}");
    assert!(err.to_string().contains("not native to the host"), "{err}");
}

/// A native child's handle without `PROCESS_VM_READ` is the error, naming the failed read: the machine check
/// passes, and the first read of the child's memory is refused with access denied.
///
/// Mutant: a refused read reads as `NotBegun`.
#[skuld::test]
fn a_handle_that_cannot_read_the_childs_memory_is_an_error_naming_the_failed_read() {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    let (child, sock, _) = spawn_member(Handler::Ignore, None, ContainMode::Strongest, |cmd| _ = cmd.no_window());
    // SAFETY: a plain open by pid of a child this test holds, closed below.
    let limited = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, child.pid()) }
        .expect("open the child without the right to read its memory");
    let err = start_state(limited).expect_err("the memory of the child is not readable through this handle");
    // SAFETY: the handle was opened above and is used no more.
    unsafe { CloseHandle(limited) }.expect("close the handle");

    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    assert!(
        err.to_string().contains("ReadProcessMemory(the PEB's loader pointer)"),
        "{err}"
    );
    kill_release_reap(&child, sock, false);
}

/// The word read at the listed offset of the PEB as `ProcessParameters` points at the parameters block: the
/// block's `Length` field (the second `ULONG`) is at least the size the `windows` crate gives the struct.
///
/// Mutant: the pointer is read from a neighbouring field (the loader data's pointer: its second `ULONG` is
/// `1`).
#[skuld::test]
fn the_parameters_word_is_the_one_the_listing_places_at_the_offset() {
    let (child, sock, _) = spawn_member(Handler::Ignore, None, ContainMode::Strongest, |cmd| _ = cmd.no_window());
    let process = process_of(&child);

    let block = read_peb(process, PebField::ProcessParameters).expect("read a running child");

    let mut head = [0u8; 8];
    super::read_exact(process, block, &mut head, "the block's lengths").expect("read the block");
    let length = u32::from_ne_bytes(head[4..].try_into().unwrap()) as usize;
    assert!(
        length >= std::mem::size_of::<windows::Win32::System::Threading::RTL_USER_PROCESS_PARAMETERS>(),
        "the block's Length: {length:#x}"
    );
    kill_release_reap(&child, sock, false);
}
