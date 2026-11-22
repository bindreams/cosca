//! Holds its own start-up until stdin closes, so a test can read the process mid-loader. A TLS callback (run
//! by the loader before `main`) writes one byte to stdout, then reads stdin to its end; `main` prints
//! `started` and parks. A `[[bin]]` cannot be `cfg`-ed out, so off Windows only `main` compiles.

#[cfg(windows)]
mod held {
    use std::ffi::c_void;

    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
    use windows::Win32::System::Console::{GetStdHandle, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};

    const DLL_PROCESS_ATTACH: u32 = 1;

    const IN_START_UP: u8 = b'T';

    unsafe extern "system" fn hold_at_start(_module: *mut c_void, reason: u32, _reserved: *mut c_void) {
        if reason != DLL_PROCESS_ATTACH {
            return;
        }
        // SAFETY: the handles are the process's own standard handles, which the parent made.
        let (stdin, stdout): (HANDLE, HANDLE) = unsafe {
            (
                GetStdHandle(STD_INPUT_HANDLE).expect("stdin"),
                GetStdHandle(STD_OUTPUT_HANDLE).expect("stdout"),
            )
        };
        let mut written = 0u32;
        // SAFETY: a one-byte buffer and a count the call writes.
        unsafe { WriteFile(stdout, Some(&[IN_START_UP]), Some(&mut written), None) }.expect("write the byte");
        let mut buf = [0u8; 64];
        let mut read = 0u32;
        // SAFETY: a buffer and a count the call writes.
        while unsafe { ReadFile(stdin, Some(&mut buf), Some(&mut read), None) }.is_ok() && read != 0 {}
    }

    #[link_section = ".CRT$XLB"]
    #[used]
    static HOLD_AT_START: unsafe extern "system" fn(*mut c_void, u32, *mut c_void) = hold_at_start;
}

fn main() {
    println!("started");
    loop {
        std::thread::park();
    }
}
