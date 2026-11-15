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
    use crate::child::owned::teardown::{Disposition, Past, RootKill};
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
            let torn = tear_down_failed_spawn(
                owned,
                None,
                Past::Clean,
                Disposition::Leave,
                SpawnPolicy::WARNS_AT_ONCE,
                &mut Diagnosis::default(),
            );
            assert!(torn.unreaped.is_none(), "a reaped child is not handed back");
            fate = Some(torn.fate);
        });

        assert_eq!(fate, Some(ChildFate::Reaped));
        assert_eq!(warns, 1);
    }

    /// A hook that waits for the killed root itself, warning past the threshold, leaves the wait
    /// after it no threshold: the failed spawn warns of that root once, not once per wait.
    ///
    /// Mutant: the wait after the hook carries the policy's threshold too: two warns.
    #[skuld::test]
    fn a_hook_that_waited_with_the_threshold_leaves_the_settle_none() {
        use crate::child::spawn::held_teardown::tear_down_failed_spawn_between;

        let mut fake = None;
        // One reap that is not ready: the wait blocks on it once, and the block's hook fires it.
        let (owned, _stdin) = held_owned_blocker(|f| {
            fake = Some(f.clone());
            f.reaps([ReapAnswer::Running])
        });
        let _fire = fire_on_block(&fake.expect("the script ran"));
        let mut fate = None;

        let warns = slow_warns_during(|| {
            let torn = tear_down_failed_spawn_between(
                owned,
                None,
                Past::WaitMayFail,
                Disposition::HandBack,
                SpawnPolicy::WARNS_AT_ONCE,
                &mut Diagnosis::default(),
                |owned, kill, _| {
                    assert_eq!(kill, RootKill::Sent, "the kill was sent");
                    crate::child::spawn::warn_still_waiting(owned.pid(), std::time::Duration::ZERO);
                    true
                },
            );
            fate = Some(torn.fate);
        });

        assert_eq!(fate, Some(ChildFate::Reaped));
        assert_eq!(warns, 1);
    }

    /// A root this handle had already reaped is sent nothing (`Gone`), and the hook is told so, as it
    /// is told of a kill that was sent and of one that was refused: no wait is left pending, and the
    /// kill was not refused.
    ///
    /// Mutant: the hook is told the kill was sent, or refused, whenever no wait is pending.
    #[skuld::test]
    fn the_hook_is_told_a_root_already_reaped_was_sent_nothing() {
        use crate::child::spawn::held_teardown::tear_down_failed_spawn_between;

        let (owned, stdin) = held_owned_blocker(|f| f);
        drop(stdin);
        owned.wait(None).expect("the released blocker exits");
        let mut seen = None;
        let _torn = tear_down_failed_spawn_between(
            owned,
            None,
            Past::WaitMayFail,
            Disposition::HandBack,
            SpawnPolicy::SYNC,
            &mut Diagnosis::default(),
            |owned, kill, _| {
                seen = Some((kill, owned.exit_seen()));
                false
            },
        );
        assert_eq!(
            seen,
            Some((RootKill::Reaped, true)),
            "nothing was sent: the root was reaped already"
        );
    }

    /// What a caller of `tear_down_failed_spawn_between` sees when its hook runs: the root's kill was
    /// sent and the root is not reaped yet ([`RootKill::Sent`]), so it can act on a root that is a
    /// zombie still, and the teardown goes on to reap it after the hook. A refused kill leaves
    /// nothing to wait for ([`RootKill::Refused`]): the hook then runs after the one look, with the
    /// root still running.
    ///
    /// Mutants: the hook runs after the reap, or never; it runs before the kill; a refused kill is
    /// said to leave a wait pending.
    #[skuld::test]
    fn the_hook_between_the_kill_and_the_wait_runs_between_them() {
        use super::super::teardown::held_owned_blocker as held;
        use crate::child::spawn::held_teardown::tear_down_failed_spawn_between;

        let run = |script: fn(crate::os_process::fake::FakeProcess) -> crate::os_process::fake::FakeProcess| {
            let (owned, stdin) = held(script);
            let mut seen = None;
            let torn = tear_down_failed_spawn_between(
                owned,
                None,
                Past::WaitMayFail,
                Disposition::HandBack,
                SpawnPolicy::SYNC,
                &mut Diagnosis::default(),
                |owned, kill, _| {
                    seen = Some((kill, owned.exit_seen()));
                    false
                },
            );
            (seen, torn, stdin)
        };

        // The kill is the real one: the blocker dies of it, and the teardown reaps it after the hook.
        let (seen, torn, stdin) = run(|f| f);
        drop(stdin);
        assert_eq!(
            seen,
            Some((RootKill::Sent, false)),
            "the hook ran with the wait pending"
        );
        assert_eq!(torn.fate, ChildFate::Reaped);

        // A refused kill: one look, nothing pending; the blocker still runs, and the test ends it. A
        // Windows handle is never refused (`KillRefusal::Never`), so only Linux's can say this.
        #[cfg(target_os = "linux")]
        {
            let (seen, torn, stdin) =
                run(|f| f.signals([Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))]));
            assert_eq!(
                seen,
                Some((RootKill::Refused, false)),
                "the hook ran with no wait pending"
            );
            assert!(torn.unreaped.is_some(), "a running child is handed back");
            drop(stdin);
            torn.unreaped
                .expect("handed back")
                .wait()
                .expect("the released blocker exits");
        }
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

        let torn = tear_down_failed_spawn(
            owned,
            None,
            Past::WaitMayFail,
            Disposition::HandBack,
            SpawnPolicy::LET_GO,
            &mut Diagnosis::default(),
        );
        let handed_back = torn.unreaped.expect("a child whose wait failed is handed back");
        assert_eq!(fake.signal_calls(), [Sig::Kill], "the teardown's own kill");
        // So that a drop that waits ends with the child, not never.
        drop(stdin);

        drop(handed_back);

        assert_eq!(fake.signal_calls(), [Sig::Kill, Sig::Kill], "the drop's kill");
    }
}
