//! Moves cosca's `#[test]`/`#[tokio::test]` spellings onto `#[skuld::test]` by byte-range
//! splices (so formatting and comments survive), and proves two revisions equal under a
//! canonical form that keeps each test's runtime.

pub mod attr;
pub mod modtree;
pub mod rewrite;
pub mod roots;
pub mod shapes;
pub mod targets;
pub mod verify;

#[cfg(test)]
mod modtree_tests;
#[cfg(test)]
mod rewrite_tests;
#[cfg(test)]
mod targets_tests;
#[cfg(test)]
mod test_util;
#[cfg(test)]
mod verify_tests;
