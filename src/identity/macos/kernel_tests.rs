//! The blanket `Kernel` impls: a borrow, a `Box` or an `Arc` of a kernel is one.

use super::fake::FakeKernel;
use super::Kernel;
use crate::identity::{UniqInfo, UniqRead};

fn unique(unique_id: u64) -> UniqRead {
    UniqRead::Found(UniqInfo {
        unique_id,
        id_version: 1,
    })
}

/// A kernel handed over as a borrow, a `Box` or an `Arc` answers as the one it points to.
#[skuld::test]
fn a_pointer_to_a_kernel_is_a_kernel() {
    const PID: u32 = 4242;
    fn unique_of(kernel: impl Kernel) -> UniqRead {
        kernel.unique_info(PID)
    }
    let table = || FakeKernel::new().on_unique_info(PID, unique(5));

    let borrowed = table();
    assert_eq!(unique_of(&borrowed), unique(5));
    assert_eq!(unique_of(Box::new(table())), unique(5));
    assert_eq!(unique_of(std::sync::Arc::new(table())), unique(5));
}
