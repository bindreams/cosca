//! Test groups: one declaration each (`docs/principles.md` §10). The rules, the macro and the rows are
//! in `test_group_rules.rs`, which integration roots include as well.

#[path = "test_group_rules.rs"]
mod rules;
pub(crate) use rules::*;
