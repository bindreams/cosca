//! The spawn's policy ([`SpawnPolicy`]) reaches the teardowns of the child it made: the wait for a
//! root the child's own teardown killed, and the failed spawn's, and what a handed-back
//! [`Unreaped`](crate::Unreaped) does when dropped. Every `Child` and every teardown elsewhere in the
//! suite carries [`SpawnPolicy::SYNC`], which warns of nothing, so only a row here sees the policy
//! dropped on the way. The Linux-only teardowns (a front's look, the cgroup-only reap, the held
//! child's) have their rows beside the lanes that reach them.

use std::time::Duration;

use super::teardown::{fire_on_block, slow_warns_during};
use crate::child::owned::unreaped::DropKind;
use crate::child::spawn::policy::SpawnPolicy;
use crate::os_process::fake::{FakeProcess, ReapAnswer};
use crate::test_child::held_uncontained_blocker;

/// Warns past a threshold that has already passed, and waits as the sync spawn does.
const WARNING: SpawnPolicy = SpawnPolicy {
    teardown_warn_after: Some(Duration::ZERO),
    unreaped_drop: DropKind::Wait,
};

/// A live blocker whose reaps answer `Running` twice, so its teardown's wait is still running when
/// it starts and blocks once, then are the real child's. The kill is the real one. The write end of
/// its stdin comes with it.
fn slow_to_be_reaped(policy: SpawnPolicy) -> (crate::Child, FakeProcess, crate::PipeWriter) {
    let (mut child, stdin) = held_uncontained_blocker(true);
    child.policy = policy;
    let fake = child
        .proc
        .script_over(|f| f.reaps([ReapAnswer::Running, ReapAnswer::Running]));
    (child, fake, stdin)
}

/// A child dropped under a policy that warns waits for the root its kill ended past the policy's
/// threshold: it warns once. (Unix `drop_unix`'s root `tear_down`, Windows `tear_down`'s.)
///
/// Mutants: `Child::tear_down` hands the root's teardown no threshold on Unix, or on Windows.
#[skuld::test]
fn a_dropped_childs_wait_warns_past_its_spawns_threshold() {
    let (child, fake, _stdin) = slow_to_be_reaped(WARNING);
    let _fire = fire_on_block(&fake);

    let warns = slow_warns_during(|| drop(child));

    assert_eq!(warns, 1);
}

/// The failed spawn's teardown of a child it holds exists on Linux and Windows.
#[cfg(any(target_os = "linux", windows))]
mod failed_spawn {
    use super::{slow_to_be_reaped, WARNING};
    use crate::child::owned::owned_tests::teardown::{fire_on_block, slow_warns_during};
    use crate::child::owned::teardown::{Disposition, Past};
    use crate::child::owned::unreaped::DropKind;
    use crate::child::owned::OwnedChild;
    use crate::child::spawn::held_teardown::tear_down_failed_spawn;
    use crate::child::spawn::policy::SpawnPolicy;
    use crate::child::spawn::Diagnosis;
    use crate::error::ChildFate;
    use crate::os_process::fake::ReapAnswer;
    use crate::signal::{Sent, Sig};
    use crate::test_child::held_uncontained_blocker;

    /// A failed spawn's teardown of the child it holds warns past its policy's threshold, once.
    ///
    /// Mutant: `tear_down_failed_spawn` hands the teardown no threshold.
    #[skuld::test]
    fn a_failed_spawns_wait_warns_past_its_policys_threshold() {
        let (mut child, fake, _stdin) = slow_to_be_reaped(SpawnPolicy::SYNC);
        let _fire = fire_on_block(&fake);
        child.kill_on_drop = false;
        let owned: OwnedChild = child.proc.take().expect("the child holds its root");
        let mut fate = None;

        let warns = slow_warns_during(|| {
            let (reaped, handed_back) = tear_down_failed_spawn(
                owned,
                None,
                Past::Clean,
                Disposition::Leave,
                WARNING,
                &mut Diagnosis::default(),
            );
            assert!(handed_back.is_none(), "a reaped child is not handed back");
            fate = Some(reaped);
        });

        assert_eq!(fate, Some(ChildFate::Reaped));
        assert_eq!(warns, 1);
    }

    /// The `Unreaped` a failed spawn hands back does what the spawn's policy says when dropped: under
    /// `LetGo` one more kill, and no wait.
    ///
    /// Mutant: `say_failed_spawn` hands `Unreaped::new` the sync drop kind.
    #[skuld::test]
    fn the_unreaped_a_failed_spawn_hands_back_does_what_its_policy_says_on_drop() {
        let (mut child, stdin) = held_uncontained_blocker(true);
        // The kill is scripted: the child runs until `stdin` closes, below.
        let fake = child.proc.script_over(|f| {
            f.signals([Ok(Sent::Delivered), Ok(Sent::Delivered)])
                .reaps([ReapAnswer::Err(std::io::ErrorKind::Other)])
        });
        child.kill_on_drop = false;
        let owned: OwnedChild = child.proc.take().expect("the child holds its root");

        let (_, handed_back) = tear_down_failed_spawn(
            owned,
            None,
            Past::WaitMayFail,
            Disposition::HandBack,
            SpawnPolicy {
                teardown_warn_after: None,
                unreaped_drop: DropKind::LetGo,
            },
            &mut Diagnosis::default(),
        );
        let handed_back = handed_back.expect("a child whose wait failed is handed back");
        assert_eq!(fake.signal_calls(), [Sig::Kill], "the teardown's own kill");
        // So that a drop that waits ends with the child, not never.
        drop(stdin);

        drop(handed_back);

        assert_eq!(fake.signal_calls(), [Sig::Kill, Sig::Kill], "the drop's kill");
    }
}
