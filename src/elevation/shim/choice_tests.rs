use super::ShimChoice;

#[skuld::test]
fn the_default_choice_is_direct() {
    assert_eq!(ShimChoice::default(), ShimChoice::Direct);
}
