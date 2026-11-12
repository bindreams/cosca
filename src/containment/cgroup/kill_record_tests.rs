use super::KillRecord;

/// An error whose own text is one layer and whose cause is another.
#[derive(Debug)]
struct Layered(std::io::Error);

impl std::fmt::Display for Layered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the write failed")
    }
}

impl std::error::Error for Layered {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Mutant: the record keeps the top layer's `Display` alone.
#[skuld::test]
fn a_failed_write_is_answered_with_its_whole_chain() {
    let cause = std::io::Error::from_raw_os_error(libc::EIO);
    let cause_text = cause.to_string();
    let failed = std::io::Error::other(Layered(cause));
    let record = KillRecord::default();

    record.record(Err(&failed));

    let said = record.answer().expect("a write was made").expect_err("it failed");
    assert!(said.contains("the write failed"), "{said}");
    assert!(said.contains(&cause_text), "{said}");
    assert_eq!(record.failure().as_deref(), Some(said.as_str()));
}
