#![expect(
    clippy::indexing_slicing,
    clippy::panic,
    reason = "Fixture indexing must fail when an expected record or property is missing. Unexpected fixture variants and deliberate callback panics must fail or exercise the recorded unwind path."
)]
#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "The concurrency contract checks original errors, completion order, and context retained after scope exit"
)]

use super::*;
use crate::hooks::{
    RequestHookContext, current_request_hook_context, with_request_hook_context_value,
};
use crate::store::{EphemeralStore, StatelessSchema};
use crate::{AuthConfig, AuthContext, AuthRequest, FieldMap, FieldValue, HttpMethod};
use futures_util::future::BoxFuture;
use std::sync::Arc;
use tokio::sync::{Notify, mpsc};
use tracing::{Dispatch, instrument::WithSubscriber, subscriber::NoSubscriber};

type Work = BoxFuture<'static, AuthResult<usize>>;

#[derive(Clone, Copy, Debug)]
enum Join {
    All,
    Pair,
}

async fn combine(kind: Join, [left, right]: [Work; 2]) -> AuthResult<Vec<usize>> {
    match kind {
        Join::All => all("retained contract", [left, right]).await,
        Join::Pair => pair("retained contract", left, right)
            .await
            .map(|(left, right)| vec![left, right]),
    }
}

fn check_context(
    expected: &Arc<AuthContext<StatelessSchema>>,
    marker: &FieldValue,
) -> AuthResult<()> {
    let active = expected
        .current_request_context()
        .ok_or_else(|| AuthError::internal("Concurrent peer lost its auth instance"))?;
    assert!(Arc::ptr_eq(&active, expected));
    assert_eq!(active.base_url(), "http://retained.test");
    let request = current_request_hook_context()
        .ok_or_else(|| AuthError::internal("Concurrent peer lost its endpoint context"))?;
    assert_eq!(request.path.as_deref(), Some("/organization/list-members"));
    assert_eq!(request.operation_id.as_deref(), Some("listMembers"));
    assert_eq!(
        request.headers.get("x-contract").map(String::as_str),
        Some("retained-peer")
    );
    assert!(request.body.strict_equals(marker));
    Ok(())
}

fn work(
    index: usize,
    gate: Arc<Notify>,
    events: mpsc::UnboundedSender<(usize, &'static str)>,
    context: Arc<AuthContext<StatelessSchema>>,
    marker: FieldValue,
    dispatcher: Dispatch,
    error: Option<String>,
) -> Work {
    Box::pin(async move {
        check_context(&context, &marker)?;
        assert!(uses_dispatcher(&dispatcher));
        events
            .send((index, "start"))
            .map_err(|_| AuthError::internal("Contract receiver closed"))?;
        gate.notified().await;
        check_context(&context, &marker)?;
        assert!(uses_dispatcher(&dispatcher));
        events
            .send((index, "complete"))
            .map_err(|_| AuthError::internal("Contract receiver closed"))?;
        match error {
            Some(error) => Err(AuthError::Internal(error)),
            None => Ok(index),
        }
    })
}

async fn event(
    receiver: &mut mpsc::UnboundedReceiver<(usize, &'static str)>,
) -> (usize, &'static str) {
    tokio::time::timeout(std::time::Duration::from_secs(5), receiver.recv())
        .await
        .expect("Concurrent peer must advance after its gate opens")
        .expect("Concurrent peer must report its context-preserving progress")
}

fn uses_dispatcher(expected: &Dispatch) -> bool {
    let subscriber = expected
        .downcast_ref::<NoSubscriber>()
        .expect("Contract dispatcher owns its subscriber");
    tracing::dispatcher::get_default(|current| {
        current
            .downcast_ref::<NoSubscriber>()
            .is_some_and(|current| std::ptr::eq(current, subscriber))
    })
}

#[tokio::test]
async fn all_and_pair_preserve_original_first_error_and_finish_started_peers_with_context()
-> AuthResult<()> {
    for kind in [Join::All, Join::Pair] {
        for first in [0, 1] {
            for late_error in [false, true] {
                let config = AuthConfig {
                    base_url: crate::request_runtime::BaseUrl::Static(
                        "http://retained.test".into(),
                    ),
                    ..Default::default()
                };
                let config = Arc::new(config);
                let context = Arc::new(
                    AuthContext::<StatelessSchema>::new(
                        config.clone(),
                        Arc::new(EphemeralStore::new(config)),
                    )
                    .expect("fixture context initializes"),
                );
                let marker: FieldValue =
                    FieldMap::from_iter([("original".into(), true.into())]).into();
                let mut request = RequestHookContext::from_request(&AuthRequest::new(
                    HttpMethod::Get,
                    "/organization/list-members",
                ))?;
                request.operation_id = Some("listMembers".into());
                let _ = request
                    .headers
                    .insert("x-contract".into(), "retained-peer".into());
                request.body = marker.clone();
                let dispatcher = Dispatch::new(NoSubscriber::default());
                let gates = [Arc::new(Notify::new()), Arc::new(Notify::new())];
                let (events, mut receiver) = mpsc::unbounded_channel();
                let original = format!("original-{first}");
                let original_buffer = original.as_ptr() as usize;
                let errors = if first == 0 {
                    [
                        Some(original),
                        late_error.then(|| "late-peer-error".to_owned()),
                    ]
                } else {
                    [
                        late_error.then(|| "late-peer-error".to_owned()),
                        Some(original),
                    ]
                };
                let mut futures = errors.into_iter().enumerate().map(|(index, error)| {
                    work(
                        index,
                        gates[index].clone(),
                        events.clone(),
                        context.clone(),
                        marker.clone(),
                        dispatcher.clone(),
                        error,
                    )
                });
                let peers = [
                    futures.next().expect("Left peer"),
                    futures.next().expect("Right peer"),
                ];
                let scoped = super::super::scope::run(
                    context.clone(),
                    with_request_hook_context_value(request, combine(kind, peers)),
                );
                let task = tokio::spawn(scoped.with_subscriber(dispatcher.clone()));
                assert_eq!(event(&mut receiver).await, (0, "start"), "{kind:?}");
                assert_eq!(event(&mut receiver).await, (1, "start"), "{kind:?}");
                gates[first].notify_one();
                assert_eq!(event(&mut receiver).await, (first, "complete"));
                let result = tokio::time::timeout(std::time::Duration::from_secs(5), task)
                    .await
                    .expect("First error must return before the other peer's gate opens")
                    .expect("Concurrent supervisor must not panic");
                match result.expect_err("One peer has rejected") {
                    AuthError::Internal(message) => {
                        assert_eq!(message, format!("original-{first}"));
                        assert_eq!(message.as_ptr() as usize, original_buffer);
                    }
                    error => panic!("Original runtime error was replaced: {error}"),
                }
                assert!(context.current_request_context().is_none());
                assert!(current_request_hook_context().is_none());
                assert!(!uses_dispatcher(&dispatcher));
                gates[1 - first].notify_one();
                assert_eq!(event(&mut receiver).await, (1 - first, "complete"));
                assert!(!uses_dispatcher(&dispatcher));
            }
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_and_pair_wait_for_each_initial_poll_before_returning_a_synchronous_error()
-> AuthResult<()> {
    for kind in [Join::All, Join::Pair] {
        let config = AuthConfig {
            base_url: crate::request_runtime::BaseUrl::Static("http://retained.test".into()),
            ..Default::default()
        };
        let config = Arc::new(config);
        let context = Arc::new(
            AuthContext::<StatelessSchema>::new(
                config.clone(),
                Arc::new(EphemeralStore::new(config)),
            )
            .expect("fixture context initializes"),
        );
        let marker: FieldValue = FieldMap::from_iter([("original".into(), true.into())]).into();
        let mut request = RequestHookContext::from_request(&AuthRequest::new(
            HttpMethod::Get,
            "/organization/list-members",
        ))?;
        request.operation_id = Some("listMembers".into());
        let _ = request
            .headers
            .insert("x-contract".into(), "retained-peer".into());
        request.body = marker.clone();

        let original = "synchronous-original".to_owned();
        let original_buffer = original.as_ptr() as usize;
        let left_context = context.clone();
        let left_marker = marker.clone();
        let left: Work = Box::pin(async move {
            check_context(&left_context, &left_marker)?;
            Err(AuthError::Internal(original))
        });
        let (release_prefix, prefix) = std::sync::mpsc::channel();
        let (events, mut receiver) = mpsc::unbounded_channel();
        let release_async = Arc::new(Notify::new());
        let right_gate = release_async.clone();
        let right_context = context.clone();
        let right_marker = marker.clone();
        let right: Work = Box::pin(async move {
            check_context(&right_context, &right_marker)?;
            events
                .send((1, "start"))
                .map_err(|_| AuthError::internal("Contract receiver closed"))?;
            // Hold the first poll open so the caller can inspect the startup barrier.
            prefix
                .recv()
                .map_err(|_| AuthError::internal("Contract prefix gate closed"))?;
            right_gate.notified().await;
            check_context(&right_context, &right_marker)?;
            events
                .send((1, "complete"))
                .map_err(|_| AuthError::internal("Contract receiver closed"))?;
            Ok(1)
        });
        let mut pending = Box::pin(super::super::scope::run(
            context.clone(),
            with_request_hook_context_value(request, combine(kind, [left, right])),
        ));
        let first_poll = futures_util::poll!(pending.as_mut());
        let entered = event(&mut receiver).await;
        let before_prefix_release = match first_poll {
            std::task::Poll::Pending => futures_util::poll!(pending.as_mut()),
            ready => ready,
        };
        let released = release_prefix.send(());
        assert_eq!(entered, (1, "start"), "{kind:?}");
        released.expect("Right peer must remain inside its first poll");
        assert!(
            before_prefix_release.is_pending(),
            "{kind:?} returned the left error before the right peer completed its first poll"
        );

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), pending)
            .await
            .expect("Original error must return before the right peer's async gate opens");
        match result.expect_err("Left peer rejected synchronously") {
            AuthError::Internal(message) => {
                assert_eq!(message, "synchronous-original");
                assert_eq!(message.as_ptr() as usize, original_buffer);
            }
            error => panic!("Original runtime error was replaced: {error}"),
        }
        assert!(context.current_request_context().is_none());
        assert!(current_request_hook_context().is_none());
        release_async.notify_one();
        assert_eq!(event(&mut receiver).await, (1, "complete"), "{kind:?}");
    }
    Ok(())
}

#[tokio::test]
async fn all_and_pair_keep_result_order_when_peers_complete_in_reverse_order() -> AuthResult<()> {
    for kind in [Join::All, Join::Pair] {
        let first_release = Arc::new(Notify::new());
        let later = first_release.clone();
        let (complete, mut receiver) = mpsc::unbounded_channel();
        let first: Work = Box::pin(async move {
            later.notified().await;
            Ok(10)
        });
        let second: Work = Box::pin(async move {
            complete
                .send(())
                .map_err(|_| AuthError::internal("Contract receiver closed"))?;
            Ok(20)
        });
        let task = tokio::spawn(combine(kind, [first, second]));
        tokio::time::timeout(std::time::Duration::from_secs(5), receiver.recv())
            .await
            .expect("Second peer must complete while the first peer waits")
            .expect("Second peer must report completion");
        assert!(!task.is_finished());
        first_release.notify_one();
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("Both successful peers must resolve")
            .expect("Concurrent supervisor must not panic")?;
        assert_eq!(result, [10, 20]);
    }
    Ok(())
}

#[tokio::test]
async fn all_and_pair_resume_the_original_panic_payload() {
    for kind in [Join::All, Join::Pair] {
        let original = Arc::new("original peer panic".to_owned());
        let payload = original.clone();
        let first: Work = Box::pin(async move { std::panic::panic_any(payload) });
        let second: Work = Box::pin(async { Ok(1) });
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::spawn(combine(kind, [first, second])),
        )
        .await
        .expect("Peer panic must wake the caller");
        let error = result.expect_err("Supervisor must propagate the peer panic");
        assert!(error.is_panic());
        let payload = error
            .into_panic()
            .downcast::<Arc<String>>()
            .expect("Supervisor must preserve the original panic payload type");
        assert!(Arc::ptr_eq(&payload, &original));
    }
}
