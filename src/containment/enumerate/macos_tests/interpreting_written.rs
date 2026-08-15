//! Interpreting the kernel's return value: `interpret_written`.

use super::super::interpret_written;

/// Pins `interpret_written`'s `<= 0` failure guard (see its doc) with synthetic values,
/// since a real EFAULT is not easily provoked from safe Rust.
#[test]
fn a_zero_return_is_an_error_not_an_empty_list() {
    interpret_written(0).expect_err("0 means failure, not zero pids");
}

#[test]
fn a_negative_return_is_an_error() {
    interpret_written(-1).expect_err("a negative return is also a failure");
}

#[test]
fn a_positive_return_is_the_written_count() {
    assert_eq!(interpret_written(5).expect("5 is a valid count"), 5);
}
