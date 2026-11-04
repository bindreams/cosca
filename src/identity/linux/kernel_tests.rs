use rustix::io::Errno;

use super::{HostKernel, Kernel};

#[skuld::test]
fn host_kernel_reads_a_file_under_the_proc_it_opens() {
    let dir = HostKernel.open_proc().expect("/proc opens");
    let stat = HostKernel.read(&dir, "self/stat").expect("self/stat reads");
    let text = String::from_utf8(stat).expect("stat is UTF-8");
    assert!(
        text.starts_with(&format!("{} ", std::process::id())),
        "self/stat names this process: {text:?}"
    );
}

#[skuld::test]
fn host_signal_probe_is_ok_for_this_process_and_esrch_for_i32_max() {
    assert_eq!(HostKernel.signal_probe(std::process::id()), Ok(()));
    assert_eq!(HostKernel.signal_probe(i32::MAX as u32), Err(Errno::SRCH));
}
