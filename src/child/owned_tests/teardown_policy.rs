//! The spawn's policy ([`SpawnPolicy`]) reaches the teardowns of the child it made: the wait for a
//! root the child's own teardown killed, and the failed spawn's, and what a handed-back
//! [`Unreaped`](crate::Unreaped) does when dropped. Every `Child` and every teardown elsewhere in the
//! suite carries [`SpawnPolicy::SYNC`], which warns of nothing, so only a row here sees the policy
//! dropped on the way. The Linux-only teardowns (a front's look, the cgroup-only reap, the held
//! child's) have their rows beside the lanes that reach them.

use super::teardown::{fire_on_block, slow_warns_during};
use crate::child::spawn::policy::SpawnPolicy;
use crate::os_process::fake::{FakeProcess, ReapAnswer};
use crate::test_child::held_uncontained_blocker;

/// The reaps of a child whose teardown's wait is still running when it starts and blocks once:
/// `Running` twice, then the real child's. The kill is the real one.
fn slow_to_be_reaped(fake: FakeProcess) -> FakeProcess {
    fake.reaps([ReapAnswer::Running, ReapAnswer::Running])
}

/// A child dropped under a policy that warns waits for the root its kill ended past the policy's
/// threshold: it warns once. (Unix `drop_unix`'s root `tear_down`, Windows `tear_down`'s.)
///
/// Mutants: `Child::tear_down` hands the root's teardown no threshold on Unix, or on Windows.
#[skuld::test]
fn a_dropped_childs_wait_warns_past_its_spawns_threshold() {
    let (mut child, _stdin) = held_uncontained_blocker(true);
    child.policy = SpawnPolicy::WARNS_AT_ONCE;
    let fake = child.proc.script_over(slow_to_be_reaped);
    let _fire = fire_on_block(&fake);

    let warns = slow_warns_during(|| drop(child));

    assert_eq!(warns, 1);
}

/// The failed spawn's teardown of a child it holds exists on Linux and Windows.
#[cfg(any(target_os = "linux", windows))]
mod failed_spawn {
    use super::slow_to_be_reaped;
    use crate::child::owned::owned_tests::teardown::{fire_on_block, held_owned_blocker, slow_warns_during};
    use crate::child::owned::teardown::{Disposition, Past};
    use crate::child::owned::unreaped::DropKind;
    use crate::child::spawn::held_teardown::tear_down_failed_spawn;
    use crate::child::spawn::policy::SpawnPolicy;
    use crate::child::spawn::Diagnosis;
    use crate::error::ChildFate;
    use crate::os_process::fake::ReapAnswer;
    use crate::signal::{Sent, Sig};

    /// A failed spawn's teardown of the child it holds warns past its policy's threshold, once.
    ///
    /// Mutant: `tear_down_failed_spawn` hands the teardown no threshold.
    #[skuld::test]
    fn a_failed_spawns_wait_warns_past_its_policys_threshold() {
        let mut fake = None;
        let (owned, _stdin) = held_owned_blocker(|f| {
            fake = Some(f.clone());
            slow_to_be_reaped(f)
        });
        let _fire = fire_on_block(&fake.expect("the script ran"));
        let mut fate = None;

        let warns = slow_warns_during(|| {
            let (reaped, handed_back) = tear_down_failed_spawn(
                owned,
                None,
                Past::Clean,
                Disposition::Leave,
                SpawnPolicy::WARNS_AT_ONCE,
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
        let mut fake = None;
        // The kill is scripted: the child runs until `stdin` closes, below.
        let (owned, stdin) = held_owned_blocker(|f| {
            fake = Some(f.clone());
            f.signals([Ok(Sent::Delivered), Ok(Sent::Delivered)])
                .reaps([ReapAnswer::Err(std::io::ErrorKind::Other)])
        });
        let fake = fake.expect("the script ran");

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
