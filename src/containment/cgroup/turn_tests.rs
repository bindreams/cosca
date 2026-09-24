use super::WatchTurns;

/// Turns are handed on first come, first served: a waiter already queued gets the turn before
/// anyone asking after it, however soon after the release they ask.
#[test]
fn a_queued_waiter_gets_the_turn_before_a_later_taker() {
    let turns = std::sync::Arc::new(WatchTurns::new(None));
    let held = turns.take_until(None).expect("the first turn is free");

    let (queued_tx, queued_rx) = std::sync::mpsc::channel();
    let (took_tx, took_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let waiter_turns = turns.clone();
    let waiter = std::thread::spawn(move || {
        super::super::fault::set_turn_queued_notifier(queued_tx);
        let turn = waiter_turns.take_until(None).expect("an unbounded wait gets its turn");
        took_tx.send(()).expect("report the turn");
        release_rx.recv().expect("wait to release");
        drop(turn);
    });
    queued_rx.recv().expect("the waiter queues");

    drop(held);
    // Asked after the release, with no time to wait: the queued waiter comes first.
    assert!(
        turns.take_until(Some(Some(std::time::Instant::now()))).is_none(),
        "a later taker must not overtake a queued waiter"
    );
    took_rx.recv().expect("the queued waiter gets the turn");
    release_tx.send(()).expect("let the waiter release");
    waiter.join().expect("the waiter");
    assert!(turns.take_until(None).is_some(), "the turn is free again");
}

/// A queued waiter that gives up leaves no gap: the next in line still gets the turn.
#[test]
fn a_waiter_that_gives_up_while_queued_leaves_no_gap() {
    let turns = std::sync::Arc::new(WatchTurns::new(None));
    let held = turns.take_until(None).expect("the first turn is free");
    // Queues, then gives up at once.
    assert!(turns.take_until(Some(Some(std::time::Instant::now()))).is_none());
    drop(held);
    assert!(
        turns.take_until(Some(Some(std::time::Instant::now()))).is_some(),
        "with the only earlier waiter gone, the turn is free"
    );
}
