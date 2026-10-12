#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Native token callers must retain complete delivery payloads and original failures."
)]

use super::*;
use better_auth_core::{
    CreateUser, FieldFunction, FieldMap, FieldValue, HttpMethod, SchemaValue,
    store::{EphemeralStore, StatelessSchema},
};
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};

#[tokio::test]
async fn verification_callers_retain_native_email_method_results() -> AuthResult<()> {
    for caller in ["signup", "signin", "oauth"] {
        for fail in [false, true] {
            let calls = Arc::new(AtomicUsize::new(0));
            let called = calls.clone();
            let original = FieldValue::from(FieldMap::from([("failure".into(), caller.into())]));
            let thrown = original.clone();
            let email = FieldValue::from(FieldMap::from([
                ("marker".into(), "native-email".into()),
                (
                    "toLowerCase".into(),
                    FieldFunction::contextual(move |receiver, arguments| {
                        assert!(arguments.is_empty());
                        assert_eq!(receiver.model_property("marker")?, "native-email".into());
                        called.fetch_add(1, Ordering::SeqCst);
                        if fail {
                            Err(AuthError::from_thrown(thrown.clone()))
                        } else {
                            Ok("SELECTED@NATIVE-EMAIL.TEST".into())
                        }
                    })
                    .into(),
                ),
            ]));
            let messages = Arc::new(Mutex::new(Vec::new()));
            let delivered = messages.clone();
            let options = EmailVerificationConfig {
                send_on_sign_in: true,
                send_on_sign_up: Some(true),
                ..Default::default()
            };
            let plugin = EmailVerificationPlugin::with_config(options.clone());
            let registered = EmailVerificationPlugin::with_config(options).callbacks(
                EmailVerificationCallbacks::<StatelessSchema>::send(move |message, _| {
                    delivered.lock().unwrap().push(message.clone());
                    Ok(None)
                }),
            );
            let config = Arc::new(crate::plugins::test_helpers::create_test_config());
            let ctx = crate::plugins::test_helpers::initialize_test_context(
                config.clone(),
                Arc::new(EphemeralStore::new(config)),
                &[&registered],
            )
            .await?;
            let stored = ctx
                .database
                .create_user(CreateUser::new().with_email("owner@native-email.test"))
                .await?;
            let mut user = stored.clone();
            user.email = SchemaValue::from_field(email.clone());
            let request = AuthRequest::new(HttpMethod::Post, "/native-token-caller");
            let endpoint = crate::plugins::endpoint_context::EndpointContext::new(
                Some(&request),
                FieldValue::Null,
                &ctx,
            );
            let result = match caller {
                "signup" => {
                    plugin
                        .send_verification_on_sign_up(&user, true, None, &endpoint)
                        .await
                }
                "signin" => plugin.send_verification_on_sign_in(&user, None, &ctx).await,
                _ => {
                    plugin
                        .send_verification_on_oauth_sign_in(
                            Some(&user),
                            true,
                            true,
                            "/",
                            &request,
                            &ctx,
                        )
                        .await
                }
            };
            assert_eq!(calls.load(Ordering::SeqCst), 1, "{caller}");
            assert_eq!(
                ctx.database
                    .get_user_by_id_value(&stored.id.field_value())
                    .await?,
                Some(stored)
            );
            assert!(request.new_session()?.is_none());
            let messages = messages.lock().unwrap();
            if fail {
                assert!(messages.is_empty());
                if caller == "oauth" {
                    result?;
                } else {
                    assert!(
                        result
                            .unwrap_err()
                            .raw_value()
                            .unwrap()
                            .strict_equals(&original)
                    );
                }
            } else {
                result?;
                assert_eq!(messages.len(), 1);
                assert!(
                    messages[0]
                        .user
                        .model_property("email")?
                        .strict_equals(&email)
                );
                let claims = token::decode_email_verification_token(
                    ctx.config.signing_secret(),
                    &messages[0].token,
                )?;
                assert_eq!(claims.email, "SELECTED@NATIVE-EMAIL.TEST");
                assert!(claims.update_to.is_none());
            }
        }
    }
    Ok(())
}
