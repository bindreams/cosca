//! The rule that selects windows and the fold of what the posts came to, as tables: no window is listed or
//! posted to here. What the OS says of real windows is in `wm_close_real_tests.rs` (the `WM_CLOSE` group).

use std::io;

use super::{after_failed_post, answer, asked, fold, Class, Fold, Listed, Missed, Unasked, Unposted, Why, Window};
use crate::child::graceful::shutdown::{run_ready, BlockingDriver};
use crate::containment::fake::FakeContains;
use crate::containment::{Containment, SendAnswer};
use crate::error::{first_os_code, said, Error};
use crate::os_process::fake::{Answer, FakeProcess};
use crate::stop::{StopTarget, TreeCall};
use crate::test_child::over_fake::child_with;
use crate::Child;

const PID: u32 = 7;

/// A visible window of `PID` with no owner and an ordinary class: the one a stop asks.
fn plain(hwnd: isize) -> Listed {
    Listed {
        hwnd,
        pid: PID,
        visible: true,
        has_owner: false,
        class: Class::Other("Notepad".to_owned()),
    }
}

fn asked_handles(listing: &[Listed], pid: u32) -> Vec<isize> {
    asked(listing, pid).iter().map(|asked| asked.window.hwnd).collect()
}

// The rule -----

/// A visible, unowned window of an ordinary class is asked. Mutant: the rule asks nothing.
#[skuld::test]
fn a_visible_unowned_window_of_an_ordinary_class_is_asked() {
    assert_eq!(asked_handles(&[plain(1)], PID), [1]);
}

/// A tool window has no field of its own in a record: it is a visible unowned window of an ordinary class,
/// and is asked with the others, in the listing's order. Mutant: the rule asks only the first window.
#[skuld::test]
fn every_window_that_qualifies_is_asked_in_the_listings_order() {
    assert_eq!(asked_handles(&[plain(3), plain(1), plain(2)], PID), [3, 1, 2]);
}

/// Mutant: hidden windows are asked.
#[skuld::test]
fn a_hidden_window_is_not_asked() {
    let hidden = Listed {
        visible: false,
        ..plain(1)
    };
    assert_eq!(asked_handles(&[hidden, plain(2)], PID), [2]);
}

/// Mutant: owned windows are asked (an input-method helper window is owned).
#[skuld::test]
fn an_owned_window_is_not_asked() {
    let owned = Listed {
        has_owner: true,
        ..plain(1)
    };
    assert_eq!(asked_handles(&[owned, plain(2)], PID), [2]);
}

/// Mutant: a console class is asked, or only one of the two is refused.
#[skuld::test]
fn a_console_window_is_not_asked_whichever_class_names_it() {
    for class in ["ConsoleWindowClass", "PseudoConsoleWindow"] {
        let console = Listed {
            class: Class::of(class),
            ..plain(1)
        };
        assert_eq!(console.class, Class::Console, "{class}");
        assert_eq!(asked_handles(&[console, plain(2)], PID), [2], "{class}");
    }
}

/// Windows compares class names without regard to case. Mutant: the comparison is exact.
#[skuld::test]
fn a_console_class_is_told_without_regard_to_case() {
    assert_eq!(Class::of("consolewindowclass"), Class::Console);
    assert_eq!(Class::of("PSEUDOCONSOLEWINDOW"), Class::Console);
}

/// A name that only contains a console class is an ordinary class. Mutant: the match is a substring.
#[skuld::test]
fn a_class_that_merely_contains_a_console_class_is_ordinary() {
    assert_eq!(
        Class::of("MyConsoleWindowClassHost"),
        Class::Other("MyConsoleWindowClassHost".to_owned())
    );
}

/// A window whose class could not be read is not asked: the class is what keeps a post from becoming
/// `CTRL_CLOSE_EVENT`. Mutant: an unread class is treated as ordinary.
#[skuld::test]
fn a_window_whose_class_was_not_read_is_not_asked() {
    let unread = Listed {
        class: Class::Unread,
        ..plain(1)
    };
    assert_eq!(asked_handles(&[unread, plain(2)], PID), [2]);
}

/// Mutant: the pid is not compared, so another process's windows are asked.
#[skuld::test]
fn another_processs_window_is_not_asked() {
    let other = Listed {
        pid: PID + 1,
        ..plain(1)
    };
    assert_eq!(asked_handles(&[other.clone(), plain(2)], PID), [2]);
    assert_eq!(asked_handles(&[other, plain(2)], PID + 1), [1]);
}

/// Every condition has to hold. Mutant: the rule is an `or` of them.
#[skuld::test]
fn a_window_that_fails_any_one_condition_is_not_asked() {
    let none_qualifies = [
        Listed {
            visible: false,
            has_owner: true,
            ..plain(1)
        },
        Listed {
            has_owner: true,
            class: Class::Console,
            ..plain(2)
        },
        Listed {
            visible: false,
            class: Class::Unread,
            ..plain(3)
        },
    ];
    assert!(asked(&none_qualifies, PID).is_empty());
}

// The fold -----

/// What asking a process came to, for each window and for a process that was not asked.
type Came = Result<Window, Unasked>;

fn posted() -> Came {
    Ok(Window::Posted)
}

fn gone() -> Came {
    Ok(Window::Gone)
}

fn refused(pid: u32) -> Came {
    Ok(Window::Unposted(Unposted {
        pid,
        class: "Notepad".to_owned(),
        why: Why::Refused,
    }))
}

fn failed(pid: u32, code: i32) -> Came {
    Ok(Window::Unposted(Unposted {
        pid,
        class: "Notepad".to_owned(),
        why: Why::Failed(io::Error::from_raw_os_error(code)),
    }))
}

/// A process whose windows were not asked, for the cause with the OS code `code`.
fn unasked(code: i32) -> Came {
    Err(Unasked {
        cause: Error::Io(io::Error::from_raw_os_error(code)),
    })
}

/// What the open of the process `pid` says when it cannot be done.
fn unopened(pid: u32) -> Error {
    Error::Unassessable {
        detail: format!("pid {pid} could not be opened"),
        source: None,
    }
}

/// The pids of the windows among `missed`.
fn pids(missed: &[Missed]) -> Vec<u32> {
    missed
        .iter()
        .filter_map(|missed| missed.as_ref().ok())
        .map(|window| window.pid)
        .collect()
}

/// Row 1. Mutant: a send with a post is not `Sent`.
#[skuld::test]
fn a_post_is_a_send_that_went_out() {
    let Fold::Sent(missed) = fold(vec![posted()]) else {
        panic!("a post is a send")
    };
    assert!(missed.is_empty());
}

/// Row 1 over the overlaps: a post beside a refusal and a failure is `Sent`, and the others are kept to be
/// warned of, in order. Mutant: a refusal or a failure beside a post fails the send.
#[skuld::test]
fn a_post_beside_a_refusal_and_a_failure_is_a_send_that_warns_of_them() {
    let Fold::Sent(missed) = fold(vec![refused(1), posted(), failed(2, 1234), gone()]) else {
        panic!("a post is a send")
    };
    assert_eq!(pids(&missed), [1, 2]);
}

/// Row 2 over its overlap with row 3: no post, a refusal and a failure: the failure, the first of them.
/// Mutant: the refusal wins, or the later failure does.
#[skuld::test]
fn with_no_post_a_failure_outranks_a_refusal_and_the_first_failure_is_the_answer() {
    let Fold::Failed { first, others } = fold(vec![refused(1), failed(2, 1234), failed(3, 5678)]) else {
        panic!("a failure with no post fails the send")
    };
    assert_eq!(first_os_code(&first), Some(1234));
    assert_eq!(pids(&others), [1, 3], "the other misses are kept, in order");
}

/// A process whose windows were not asked is a failure of its own kind: with no post it is the answer, in
/// the order the processes were asked, and beside a post it is warned of. Mutant: it is dropped, or counted
/// as a refusal.
#[skuld::test]
fn a_process_whose_windows_were_not_asked_is_a_failure() {
    let Fold::Failed { first, .. } = fold(vec![refused(1), unasked(1234), failed(3, 5678)]) else {
        panic!("an unasked process with no post fails the send")
    };
    assert_eq!(first_os_code(&first), Some(1234));

    let Fold::Sent(missed) = fold(vec![unasked(1234), posted()]) else {
        panic!("a post is a send")
    };
    assert!(
        matches!(&missed[..], [Err(Unasked { cause })] if first_os_code(cause) == Some(1234)),
        "{missed:?}"
    );
}

/// Row 3. Mutant: a refusal with no post and no failure is not remembered, so the fold is `NothingAsked`.
#[skuld::test]
fn with_no_post_and_no_failure_a_refusal_is_the_answer_and_the_first_is_named() {
    let Fold::Refused { first, others } = fold(vec![gone(), refused(4), refused(5)]) else {
        panic!("every window refused")
    };
    assert_eq!(first.pid, 4);
    assert_eq!(others.iter().map(|refusal| refusal.pid).collect::<Vec<_>>(), [5]);
}

/// Row 4: no window asked, and every window asked gone. Mutant: a gone window is a failure or a refusal.
#[skuld::test]
fn nothing_asked_or_everything_gone_is_nothing_asked() {
    assert!(matches!(fold(Vec::new()), Fold::NothingAsked));
    assert!(matches!(fold(vec![gone(), gone()]), Fold::NothingAsked));
}

/// A tree target folds the windows of every member together: members that were posted to, gone, refused and
/// failed give one answer, and a member that only refused does not fail the send another member made.
/// Mutant: the fold decides per member, and a refusing member fails the send.
#[skuld::test]
fn a_tree_of_members_that_differ_is_one_fold_over_all_their_windows() {
    // Member 10: posted. Member 11: gone. Member 12: refused. Member 13: failed.
    let windows = vec![posted(), gone(), refused(12), failed(13, 1234)];
    let Fold::Sent(missed) = fold(windows) else {
        panic!("a member's post is the tree's")
    };
    assert_eq!(pids(&missed), [12, 13]);

    // No member was posted to: the failure of one outranks the refusal of another.
    let Fold::Failed { first, others } = fold(vec![gone(), refused(12), failed(13, 1234)]) else {
        panic!("a failure outranks a refusal")
    };
    assert_eq!(first_os_code(&first), Some(1234));
    assert_eq!(pids(&others), [12]);
}

// The answer -----

/// Row 1 as the answer. Mutant: a send that went out is recorded as not sent.
#[skuld::test]
fn a_send_that_went_out_is_sent_ok() {
    assert!(matches!(
        answer(Fold::Sent(vec![Ok(Unposted {
            pid: 1,
            class: "Notepad".to_owned(),
            why: Why::Refused
        })])),
        Some(SendAnswer::Sent(Ok(())))
    ));
}

/// What a failed post of a window of class "Notepad" of pid 7 says of itself, with the OS code 1234.
fn failed_post() -> io::Error {
    let Window::Unposted(Unposted {
        why: Why::Failed(cause),
        ..
    }) = after_failed_post(7, "Notepad", io::Error::from_raw_os_error(1234))
    else {
        panic!("a post that failed with another code is a failure")
    };
    cause
}

/// The post failures a window can have: a stale handle is a window that is gone, a refusal is its own row,
/// and any other code is a failure.
///
/// Mutant: the stale handle is a failure, or the refusal is one.
#[skuld::test]
fn a_failed_post_is_gone_refused_or_a_failure_by_its_code() {
    use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INVALID_WINDOW_HANDLE};

    let after = |code: u32| after_failed_post(7, "Notepad", io::Error::from_raw_os_error(code as i32));
    assert!(matches!(after(ERROR_INVALID_WINDOW_HANDLE.0), Window::Gone));
    assert!(matches!(
        after(ERROR_ACCESS_DENIED.0),
        Window::Unposted(Unposted { why: Why::Refused, .. })
    ));
    assert!(matches!(
        after(1234),
        Window::Unposted(Unposted {
            why: Why::Failed(_),
            ..
        })
    ));
}

/// The cause of a failed post says what happened to that window, with the OS code kept as its source, and
/// not that nothing was sent: that is the answer's to say, once. Mutant: "nothing was sent" in the cause.
#[skuld::test]
fn the_cause_of_a_failed_post_says_only_what_happened_to_the_window() {
    let cause = failed_post();
    assert_eq!(
        said(&cause),
        format!(
            "WM_CLOSE could not be posted to a window of class \"Notepad\" of pid 7: {}",
            io::Error::from_raw_os_error(1234)
        )
    );
    assert_eq!(crate::error::first_os_code(&cause), Some(1234));
}

/// Row 2 as the answer: `Error::Io` that says "nothing was sent" once, above the failure's own cause, which
/// is kept whole (its OS code too). Mutant: the cause is replaced, the words are missing or said twice, or
/// the answer is `Sent`.
#[skuld::test]
fn a_failure_is_an_io_error_that_says_nothing_was_sent_once_above_its_cause() {
    let Some(SendAnswer::NotSent(answered, _)) = answer(Fold::Failed {
        first: Error::Io(failed_post()),
        others: Vec::new(),
    }) else {
        panic!("a failure sends nothing")
    };
    let Error::Io(_) = &answered else {
        panic!("a failure is an Io error: {answered:?}")
    };
    assert_eq!(
        said(&answered),
        format!("an I/O operation failed: nothing was sent: {}", said(&failed_post()))
    );
    assert_eq!(crate::error::first_os_code(&answered), Some(1234));

    let Some(SendAnswer::NotSent(not_asked, _)) = answer(Fold::Failed {
        first: unopened(7),
        others: Vec::new(),
    }) else {
        panic!("a failure sends nothing")
    };
    let Error::Io(_) = &not_asked else {
        panic!("a process that was not asked is an Io failure: {not_asked:?}")
    };
    assert_eq!(
        said(&not_asked),
        format!("an I/O operation failed: nothing was sent: {}", said(&unopened(7)))
    );
}

/// A send that went out warns of each window or process that was not posted to or asked, with the cause as
/// it happened to that window or process and not "nothing was sent", which is not true of a send that went out.
///
/// Mutant: the cause says "nothing was sent", or a warn is dropped.
#[skuld::test]
fn a_send_that_went_out_warns_of_what_it_missed_in_the_causes_words() {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();

    let sent = answer(Fold::Sent(vec![
        Ok(Unposted {
            pid: 4,
            class: "Notepad".to_owned(),
            why: Why::Refused,
        }),
        Ok(Unposted {
            pid: 7,
            class: "Notepad".to_owned(),
            why: Why::Failed(failed_post()),
        }),
        Err(Unasked { cause: unopened(9) }),
    ]));

    assert!(matches!(sent, Some(SendAnswer::Sent(Ok(())))));
    let warns = crate::log_capture::warns_since(mark, "");
    assert_eq!(
        warns,
        [
            "WM_CLOSE was refused by a window of class \"Notepad\" of pid 4 (error 5), while another window was sent it"
                .to_owned(),
            format!(
                "WM_CLOSE was sent to another window, but not to every window asked: {}",
                said(&failed_post())
            ),
            format!(
                "WM_CLOSE was sent to another window, but not to every window asked: {}",
                said(&unopened(9))
            ),
        ]
    );
}

/// An answer that is not a send warns of every other miss, so only the first failure or refusal is the
/// answer and none vanishes: a failure and the refusal and failure beside it, or refusals alone.
///
/// Mutant: the other misses are not warned of.
#[skuld::test]
fn an_answer_that_sent_nothing_warns_of_every_other_miss() {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let Some(SendAnswer::NotSent(_, _)) = answer(fold(vec![refused(4), failed(7, 1234), unasked(5678)])) else {
        panic!("a failure sends nothing")
    };
    let warns = crate::log_capture::warns_since(mark, "");
    assert_eq!(
        warns,
        [
            "WM_CLOSE was refused by a window of class \"Notepad\" of pid 4 (error 5)".to_owned(),
            format!(
                "WM_CLOSE was not sent to every window asked: {}",
                said(&Error::Io(io::Error::from_raw_os_error(5678)))
            ),
        ]
    );

    let mark = crate::log_capture::mark();
    let Some(SendAnswer::NotSent(_, _)) = answer(fold(vec![refused(4), refused(5)])) else {
        panic!("every window refused")
    };
    assert_eq!(
        crate::log_capture::warns_since(mark, ""),
        ["WM_CLOSE was refused by a window of class \"Notepad\" of pid 5 (error 5)".to_owned()]
    );
}

/// Row 3 as the answer: `Unsupported` whose source is the `io::Error` with code 5, naming `Child::kill`, with
/// nothing sent. Mutant: no source, another code, or an answer that names no way out.
#[skuld::test]
fn a_refusal_is_unsupported_with_access_denied_as_its_source() {
    let Fold::Refused { first, others } = fold(vec![refused(4)]) else {
        panic!("a refusal")
    };
    let Some(SendAnswer::NotSent(refusal, _)) = answer(Fold::Refused { first, others }) else {
        panic!("a refusal sends nothing")
    };
    let Error::Unsupported { detail, source, .. } = &refusal else {
        panic!("{refusal:?}")
    };
    assert!(detail.contains("Child::kill"), "{detail}");
    assert!(detail.contains("pid 4"), "{detail}");
    assert_eq!(crate::error::first_os_code(&refusal), Some(5), "{refusal:?}");
    assert!(source.is_some(), "{refusal:?}");
}

/// Row 4 is left to the caller, which looks at the root. Mutant: the answer decides it as `Sent`.
#[skuld::test]
fn nothing_asked_is_left_to_the_caller() {
    assert!(answer(Fold::NothingAsked).is_none());
}

/// The refusal for no visible window names what it covers and `Child::kill`, for a root and for a tree.
/// Mutant: the text drops the hidden-window or the notification-area limit, or the way out.
#[skuld::test]
fn no_visible_window_says_what_it_covers_and_names_kill() {
    for tree in [false, true] {
        let error = super::no_visible_window(tree);
        let Error::Unsupported { detail, source, .. } = &error else {
            panic!("{error:?}")
        };
        for fragment in [
            "visible top-level window",
            "this desktop",
            "keeps its window hidden",
            "notification area",
            "has not shown its window yet",
            "another desktop or in another session",
            "console program",
            "Child::kill",
        ] {
            assert!(detail.contains(fragment), "{fragment:?} is missing from {detail}");
        }
        assert_eq!(detail.contains("no member of the contained tree"), tree, "{detail}");
        assert!(source.is_none());
    }
}

// The send over a fake-contained child -----
//
// No window is listed or posted to: each case is answered before the desktop is read.

/// How the send of a child over a fake root answers, for a tree target (`tree`) or a root target.
fn sent_over(child: &Child, tree: bool) -> SendAnswer {
    let target = if tree {
        StopTarget::tree(child, TreeCall::SignalOnly)
    } else {
        StopTarget::from(child)
    };
    run_ready(super::outcome(&BlockingDriver(child), &target))
}

/// A child over a root that has exited or runs, whose tree is `fake`.
fn child_over_a_fake_tree(root_exited: bool, fake: FakeContains) -> Child {
    let root = FakeProcess::new([if root_exited { Answer::Exited } else { Answer::Running }]);
    child_with(&root, fake)
}

fn fake_tree() -> FakeContains {
    FakeContains::new(Containment::JobObject, false).0
}

/// The detail of an `Unsupported` or `Unassessable` answer.
fn detail_of(error: &Error) -> &str {
    match error {
        Error::Unsupported { detail, .. } | Error::Unassessable { detail, .. } => detail,
        other => panic!("{other:?}"),
    }
}

/// A child with no identity is refused for a root and for a tree target, naming `Child::kill`, before any
/// member is listed or window read.
///
/// Mutant: the send goes on with the child's pid (it would read the desktop, so this test cannot run it).
#[skuld::test]
fn a_child_with_no_identity_is_refused_naming_kill() {
    for tree in [false, true] {
        let mut child = child_over_a_fake_tree(false, fake_tree());
        child.id = None;
        let SendAnswer::NotSent(error, _) = sent_over(&child, tree) else {
            panic!("a child with no identity sends nothing")
        };
        assert!(matches!(error, Error::Unsupported { .. }), "{error:?}");
        let detail = detail_of(&error);
        assert!(detail.contains("no identity"), "{detail}");
        assert!(detail.contains("Child::kill"), "{detail}");
    }
}

/// What `terminate` (a root target) or `terminate_tree` (a tree target) answers of `send_wm_close` over `child`:
/// the send's answer, concluded into the target's record, read as the calls read it. A root target with an
/// identity lists the desktop: only the cases answered before that are run here.
fn wm_close_call(child: &Child, tree: bool) -> Result<(), crate::stop::StopError> {
    let target = if tree {
        StopTarget::tree(child, TreeCall::SignalOnly)
    } else {
        StopTarget::from(child)
    };
    let acted = run_ready(super::send(&BlockingDriver(child), &target));
    target.into_stop_result(acted)
}

/// The outcome a failed `terminate` and `terminate_tree` report of a `send_wm_close` that sent nothing, for
/// every case that is answered before a window is listed: a child with no identity (a root and a tree
/// target), and a tree that names no member (a tree target only: a root target always lists the desktop),
/// over a root that runs (no visible window) and over one that had exited. Each is `NotSent`, through the
/// tree's real route (an empty job).
///
/// Mutants: the send's end is not recorded (the failed call reads `Unknown`); an exited root's answer is
/// recorded as a send.
#[skuld::test]
fn a_wm_close_that_sent_nothing_is_not_sent_for_a_root_and_for_a_tree() {
    use crate::stop::SendOutcome::NotSent;

    let over_a_job = |root_exited: bool, identity: bool| {
        let mut child = child_over_a_fake_tree(root_exited, fake_tree());
        child.tree = crate::containment::Tree::contained(crate::containment::Mechanism::Job(
            crate::containment::windows::JobHandle::create_empty_for_test(),
        ));
        if !identity {
            child.id = None;
        }
        child
    };
    for tree in [false, true] {
        let err = wm_close_call(&over_a_job(false, false), tree).expect_err("no identity, nothing sent");
        assert_eq!(err.outcome(), NotSent, "tree: {tree}, no identity: {err:?}");
    }
    for (what, root_exited) in [("no visible window", false), ("an exited root", true)] {
        let err = wm_close_call(&over_a_job(root_exited, true), true).expect_err("no member asked, nothing sent");
        assert_eq!(err.outcome(), NotSent, "{what}: {err:?}");
    }
}

/// A listing the mechanism could not make is the send's answer as it is: nothing was sent, and it is not the
/// no-window refusal. Mutant: the listing error is taken for a tree with no member (the no-window refusal).
#[skuld::test]
fn a_listing_that_could_not_be_made_is_the_answer() {
    let child = child_over_a_fake_tree(false, fake_tree().unable_to_list("the fake could not list"));
    let SendAnswer::NotSent(error, _) = sent_over(&child, true) else {
        panic!("a failed listing sends nothing")
    };
    assert_eq!(detail_of(&error), "the fake could not list");
}

/// A tree that names no member asks no window, and the answer is the look at the root: a root that has exited
/// is `RootExited`, naming that no window of a member that outlived it was asked; a running one is the
/// refusal for a tree with no visible window. No desktop listing is made for it.
///
/// Mutants: the exited root is answered as the no-window refusal, or the running one as `RootExited`; a
/// listing is made for the empty list (it would read the desktop, so this test cannot run it).
#[skuld::test]
fn a_tree_that_names_no_member_is_answered_by_the_look_at_the_root() {
    let exited = child_over_a_fake_tree(true, fake_tree());
    let SendAnswer::RootExited(error) = sent_over(&exited, true) else {
        panic!("a root that exited with no member asked")
    };
    let detail = detail_of(&error);
    assert!(detail.contains("had exited when cosca looked"), "{detail}");
    assert!(
        detail.contains("no window of a member of its tree that outlived it was asked"),
        "{detail}"
    );

    let running = child_over_a_fake_tree(false, fake_tree());
    let SendAnswer::NotSent(error, _) = sent_over(&running, true) else {
        panic!("a running root with no member shows no window")
    };
    assert!(
        detail_of(&error).contains("no member of the contained tree shows"),
        "{error:?}"
    );
}

/// A tree whose every member the mechanism could not name is the `Io` failure naming the first of them, with
/// nothing sent, and the others are warned of. Not the no-window answer, which would say what no member
/// shows, and not `RootExited` for an exited root.
///
/// Mutants: the unnamed members are dropped (the answer is the no-window refusal or `RootExited`); only the
/// first is warned of, or none.
#[skuld::test]
fn a_tree_whose_members_could_not_all_be_named_is_a_failure_that_names_the_first() {
    crate::log_capture::install();
    for root_exited in [false, true] {
        let mark = crate::log_capture::mark();
        let fake = fake_tree()
            .unable_to_name("pid 31 could not be named")
            .unable_to_name("pid 32 could not be named");
        let child = child_over_a_fake_tree(root_exited, fake);

        let SendAnswer::NotSent(error, _) = sent_over(&child, true) else {
            panic!("no member could be named, and nothing was sent")
        };

        let Error::Io(_) = &error else {
            panic!("an Io failure: {error:?}")
        };
        assert_eq!(
            said(&error),
            format!(
                "an I/O operation failed: nothing was sent: {}",
                said(&Error::Unassessable {
                    detail: "pid 31 could not be named".into(),
                    source: None
                })
            )
        );
        assert_eq!(
            crate::log_capture::warns_since(mark, ""),
            [format!(
                "WM_CLOSE was not sent to every window asked: {}",
                said(&Error::Unassessable {
                    detail: "pid 32 could not be named".into(),
                    source: None
                })
            )]
        );
    }
}

/// A process whose pid names another process now is not the process asked: the open by identity finds
/// nothing, and that is no failure and no window. (The listing holds a window of that pid, so the open is
/// reached.)
///
/// Mutant: the open that finds nothing is taken for a process that could not be opened (a failure).
#[skuld::test]
fn a_process_whose_pid_names_another_process_has_no_window_to_ask() {
    use crate::identity::{HostKernel, Key, ProcessId};

    let another = ProcessId::from_parts_for_test(std::process::id(), Key::for_test(1));
    let listing = [Listed {
        pid: another.pid(),
        ..plain(1)
    }];

    assert!(super::ask(&listing, &HostKernel, another).is_empty());
}

/// A process with no listed window to ask is not opened: a live process whose open is refused (the DACL
/// fixture, which is also why this runs in a process of its own) is no failure of the send, and no window is
/// asked of it. Needs the DACL fixture, which creates a Job Object: CI only.
///
/// Mutant: the process is opened before the rule selects its windows (the refused open is an `Unasked`).
#[skuld::test]
fn a_process_with_no_listed_window_is_not_opened() {
    use crate::identity::{windows_fixture, HostKernel};

    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(a_process_with_no_listed_window_is_not_opened),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let refused = windows_fixture::spawn_unkillable(&done);
    let id = crate::identity::windows_identity_from_handle_result(&HostKernel, refused.handle(), refused.pid())
        .expect("the owned handle always yields an identity");
    assert!(
        crate::os_process::open_with(&HostKernel, id).is_err(),
        "precondition: the open of this process is refused"
    );

    let hidden = Listed {
        visible: false,
        pid: id.pid(),
        ..plain(1)
    };
    assert!(super::ask(&[], &HostKernel, id).is_empty(), "no window listed");
    assert!(super::ask(&[hidden], &HostKernel, id).is_empty(), "no window selected");
}
