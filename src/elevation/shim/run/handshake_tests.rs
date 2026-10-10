use rustix::io::Errno;

use super::proc_probe_failure;

#[skuld::test]
fn only_a_missing_proc_says_proc_must_be_mounted() {
    let path = "/proc/thread-self/fd/5";
    let missing = proc_probe_failure(path, Errno::NOENT);
    assert!(missing.starts_with("/proc must be mounted"), "{missing}");
    for errno in [Errno::ACCESS, Errno::NOTDIR, Errno::LOOP, Errno::IO] {
        let other = proc_probe_failure(path, errno);
        assert!(!other.contains("must be mounted"), "{errno}: {other}");
        assert!(other.contains(path) && other.contains(&errno.to_string()), "{other}");
    }
}
