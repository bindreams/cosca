use super::Secret;

#[test]
fn secret_debug_is_redacted() {
    let s = Secret::new("hunter2");
    let dbg = format!("{s:?}");
    assert!(!dbg.contains("hunter2"), "Secret Debug must not leak the value: {dbg}");
    assert!(dbg.contains("Secret"), "{dbg}");
}

#[test]
fn secret_exposes_bytes_for_the_effect_layer() {
    let s = Secret::new("pw");
    assert_eq!(s.expose(), b"pw");
}
