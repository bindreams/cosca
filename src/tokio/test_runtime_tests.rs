use ::tokio::time::{advance, Duration, Instant};

#[test]
fn paused_runtime_is_paused_with_io_and_time() {
    let runtime = super::paused();
    runtime.block_on(async {
        let before = Instant::now();
        advance(Duration::from_secs(3600)).await;
        assert_eq!(Instant::now() - before, Duration::from_secs(3600));
        ::tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("the IO driver is enabled");
    });
}

#[test]
fn assert_current_thread_accepts_a_current_thread_runtime() {
    super::paused().block_on(async { super::assert_current_thread() });
}
