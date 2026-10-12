#![expect(
    clippy::panic_in_result_fn,
    reason = "Anonymous rejection regressions compare complete response, callback, and storage results."
)]

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use better_auth_core::{
    AuthError, AuthPlugin, AuthRequest, AuthResult, FieldDate, FieldFunction, FieldMap,
    FieldObject, FieldValue, HttpMethod,
    config::{FieldTransforms, UserFieldConfig, UserFieldTransform},
    store::{EphemeralStore, StatelessSchema},
};

use super::{EmailVerificationCallbacks, EmailVerificationPlugin};

const EMAIL: &str = "anonymous@native-email.test";
const TYPED_ERROR: &str = "Anonymous verification callback failed";

fn rejection(value: Option<FieldValue>) -> AuthError {
    value.map_or_else(|| AuthError::internal(TYPED_ERROR), AuthError::from_thrown)
}

// The anonymous source catch uses `if (error)` after its timing floor.
#[tokio::test]
async fn anonymous_verification_only_rethrows_truthy_caught_failures() -> AuthResult<()> {
    for fail_at_method in [true, false] {
        for (name, thrown, swallowed) in [
            ("undefined", Some(FieldValue::Undefined), true),
            ("null", Some(FieldValue::Null), true),
            ("false", Some(false.into()), true),
            ("zero", Some(0.0.into()), true),
            ("negative-zero", Some((-0.0).into()), true),
            ("nan", Some(f64::NAN.into()), true),
            ("empty-string", Some("".into()), true),
            ("number", Some(1.0.into()), false),
            (
                "object",
                Some(FieldMap::from([("failure".into(), "original".into())]).into()),
                false,
            ),
            ("typed", None, false),
        ] {
            let method_calls = Arc::new(AtomicUsize::new(0));
            let method_count = method_calls.clone();
            let method_error = thrown.clone();
            let email = FieldValue::from(FieldMap::from([
                ("marker".into(), "native-email".into()),
                (
                    "toLowerCase".into(),
                    FieldFunction::contextual(move |receiver, arguments| {
                        assert!(arguments.is_empty());
                        assert_eq!(receiver.model_property("marker")?, "native-email".into());
                        let _ = method_count.fetch_add(1, Ordering::SeqCst);
                        if fail_at_method {
                            Err(rejection(method_error.clone()))
                        } else {
                            Ok(EMAIL.into())
                        }
                    })
                    .into(),
                ),
            ]));
            let fields = FieldMap::from([
                ("id".into(), "owner".into()),
                ("name".into(), "Owner".into()),
                ("email".into(), EMAIL.into()),
                ("emailVerified".into(), false.into()),
                ("image".into(), FieldValue::Null),
                (
                    "createdAt".into(),
                    FieldDate::from_milliseconds(2_000_000_000_000.0).into(),
                ),
                (
                    "updatedAt".into(),
                    FieldDate::from_milliseconds(2_000_000_000_000.0).into(),
                ),
            ]);
            let stored = FieldObject::from(fields.clone());
            let mut expected_user = fields.clone();
            let _ = expected_user.insert("email".into(), email.clone());
            let expected_user = FieldValue::from(expected_user);
            let delivery_calls = Arc::new(AtomicUsize::new(0));
            let delivery_count = delivery_calls.clone();
            let delivery_error = thrown.clone();
            let plugin = EmailVerificationPlugin::new().callbacks(EmailVerificationCallbacks::<
                StatelessSchema,
            >::send(
                move |message, endpoint| {
                    let _ = delivery_count.fetch_add(1, Ordering::SeqCst);
                    assert!(endpoint.session.is_none());
                    assert_eq!(message.user, expected_user);
                    let claims = super::token::decode_email_verification_token(
                        endpoint.auth.config.signing_secret(),
                        &message.token,
                    )?;
                    assert_eq!(claims.email, EMAIL);
                    assert!(claims.update_to.is_none());
                    assert!(claims.request_type.is_none());
                    assert_eq!(
                        message.url,
                        format!(
                            "{}/verify-email?token={}&callbackURL=%2F",
                            endpoint.auth.base_url(),
                            message.token
                        )
                    );
                    Err(rejection(delivery_error.clone()))
                },
            ));
            let mut config = crate::plugins::test_helpers::create_test_config();
            let _ = config.user.fields_mut().insert(
                "email".into(),
                UserFieldConfig {
                    transform: Some(FieldTransforms {
                        input: None,
                        output: Some(UserFieldTransform::new(move |_| Ok(email.clone()))),
                    }),
                    ..Default::default()
                },
            );
            let config = Arc::new(config);
            let store = EphemeralStore::from_storage_objects(
                config.clone(),
                [
                    ("user".into(), vec![stored.clone()]),
                    ("session".into(), Vec::new()),
                    ("account".into(), Vec::new()),
                    ("verification".into(), Vec::new()),
                ],
            )?;
            let ctx = crate::plugins::test_helpers::initialize_test_context(
                config,
                Arc::new(store),
                &[&plugin],
            )
            .await?;
            let mut request = AuthRequest::new(HttpMethod::Post, "/send-verification-email");
            let _ = request
                .headers
                .insert("content-type".into(), "application/json".into());
            request.body = Some(serde_json::to_vec(&serde_json::json!({"email":EMAIL}))?);
            let started = std::time::Instant::now();
            let result = plugin.on_request(&request, &ctx).await;
            assert!(
                started.elapsed() >= std::time::Duration::from_millis(500),
                "{name}"
            );
            assert_eq!(method_calls.load(Ordering::SeqCst), 1, "{name}");
            assert_eq!(
                delivery_calls.load(Ordering::SeqCst),
                usize::from(!fail_at_method),
                "{name}"
            );
            assert_eq!(stored.snapshot_fields()?, fields, "{name}");
            assert!(request.new_session()?.is_none());
            assert!(request.native_session_snapshot()?.is_none());
            if swallowed {
                let Some(response) = result? else {
                    panic!("Verification route must return a response for {name}");
                };
                assert_eq!(response.status, 200, "{name}");
                assert_eq!(
                    response.body.json()?,
                    Some(serde_json::json!({"status":true})),
                    "{name}"
                );
            } else {
                let Err(error) = result else {
                    panic!("Verification route must propagate {name}");
                };
                if let Some(thrown) = thrown {
                    assert!(
                        error
                            .raw_value()
                            .is_some_and(|value| value.strict_equals(&thrown)),
                        "{name}"
                    );
                } else {
                    assert!(
                        matches!(error, AuthError::Internal(message) if message == TYPED_ERROR)
                    );
                }
            }
        }
    }
    Ok(())
}
