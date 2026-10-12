#![expect(
    clippy::panic_in_result_fn,
    reason = "The boundary tests assert original error identity, conversion counts, and hook ownership."
)]

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use crate::{
    AuthConfig, AuthContext, AuthError, AuthRequest, AuthResult, FieldMap, FieldValue, HttpMethod,
    observability::{LogArgument, LogLevel, LogSink, LoggerConfig},
    store::{EphemeralStore, StatelessSchema},
};

struct ThrowingSink {
    calls: AtomicUsize,
    cause: FieldValue,
}

impl LogSink for ThrowingSink {
    fn log(&self, _: LogLevel, _: LogArgument<'_>, _: &[LogArgument<'_>]) -> AuthResult<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(AuthError::from_thrown(self.cause.clone()))
    }
}

fn context(sink: Arc<ThrowingSink>) -> AuthResult<AuthContext<StatelessSchema>> {
    let config = Arc::new(AuthConfig {
        logger: LoggerConfig {
            log: Some(sink),
            ..Default::default()
        }
        .into(),
        ..Default::default()
    });
    AuthContext::new(config.clone(), Arc::new(EphemeralStore::new(config)))
}

#[tokio::test]
async fn logger_failure_escapes_typed_error_conversion_once() -> AuthResult<()> {
    for source in [
        AuthError::internal("original conversion failure"),
        AuthError::PasswordHash("original hash failure".into()),
        AuthError::internal("original conversion failure").into_shared(),
        AuthError::PasswordHash("original hash failure".into()).into_shared(),
    ] {
        let sink = Arc::new(ThrowingSink {
            calls: AtomicUsize::new(0),
            cause: FieldMap::from([("token".into(), FieldMap::new().into())]).into(),
        });
        let error = context(sink.clone())?
            .with_endpoint_context(|_| async move { source.to_auth_response() })
            .await
            .err()
            .ok_or_else(|| AuthError::internal("The logger failure must escape conversion"))?;
        assert!(
            error
                .raw_value()
                .is_some_and(|raw| raw.strict_equals(&sink.cause))
        );
        assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
    }
    Ok(())
}

#[tokio::test]
async fn shared_header_capture_keeps_the_original_conversion_failure_boundary() -> AuthResult<()> {
    for source in [
        AuthError::internal("original conversion failure"),
        AuthError::PasswordHash("original hash failure".into()),
        AuthError::internal("original conversion failure").into_shared(),
        AuthError::PasswordHash("original hash failure".into()).into_shared(),
    ] {
        let sink = Arc::new(ThrowingSink {
            calls: AtomicUsize::new(0),
            cause: FieldMap::from([("token".into(), FieldMap::new().into())]).into(),
        });
        let error = context(sink.clone())?
            .with_endpoint_context(|_| async move {
                source.capture_native_headers(FieldMap::new().into())
            })
            .await;
        assert!(
            error
                .raw_value()
                .is_some_and(|raw| raw.strict_equals(&sink.cause))
        );
        assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
    }
    Ok(())
}

#[test]
fn matcher_logger_failure_precedes_marker_and_sanitized_error() -> AuthResult<()> {
    let sink = Arc::new(ThrowingSink {
        calls: AtomicUsize::new(0),
        cause: FieldMap::from([("logger".into(), true.into())]).into(),
    });
    let context = context(sink.clone())?;
    let request = AuthRequest::new(HttpMethod::Get, "/matcher");
    let error = crate::hooks::run_before_hook_matcher::<()>(
        &context.config,
        Some(&request),
        "before",
        || Err(AuthError::internal("matcher source")),
    )
    .err()
    .ok_or_else(|| AuthError::internal("The logger failure must escape the matcher"))?;
    assert!(
        error
            .raw_value()
            .is_some_and(|raw| raw.strict_equals(&sink.cause))
    );
    assert!(matches!(
        request.take_hook_error_stage(),
        crate::types::HookErrorStage::Unhandled
    ));
    assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[cfg(feature = "axum")]
#[tokio::test]
async fn axum_terminal_conversion_does_not_reenter_the_logger_or_replacement() -> AuthResult<()> {
    let source_calls = Arc::new(AtomicUsize::new(0));
    let replacement_calls = Arc::new(AtomicUsize::new(0));
    let observed = replacement_calls.clone();
    let replacement: FieldValue = FieldMap::from([(
        "toJSON".into(),
        crate::FieldFunction::contextual(move |_, _| {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok("replacement must remain unread".into())
        })
        .into(),
    )])
    .into();
    let sink = Arc::new(ThrowingSink {
        calls: AtomicUsize::new(0),
        cause: replacement.clone(),
    });
    let observed = source_calls.clone();
    let value = FieldMap::from([(
        "toJSON".into(),
        crate::FieldFunction::contextual(move |_, _| {
            observed.fetch_add(1, Ordering::SeqCst);
            Err(AuthError::from_thrown(replacement.clone()))
        })
        .into(),
    )]);
    let response = context(sink.clone())?
        .with_endpoint_context(|_| async move {
            super::finish_axum_response(Ok(crate::AuthResponse::json_value(None, value.into())))
        })
        .await;
    assert_eq!(
        response.status(),
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    assert_eq!(body.as_ref(), b"Internal server error");
    assert_eq!(source_calls.load(Ordering::SeqCst), 1);
    assert_eq!(replacement_calls.load(Ordering::SeqCst), 0);
    assert_eq!(sink.calls.load(Ordering::SeqCst), 0);
    Ok(())
}
