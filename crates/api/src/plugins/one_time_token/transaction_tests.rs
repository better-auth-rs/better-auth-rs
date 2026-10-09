#![expect(
    clippy::panic_in_result_fn,
    reason = "The transaction regression asserts visibility and rollback while setup errors propagate"
)]

use super::{OneTimeTokenCallbacks, OneTimeTokenPlugin};
use crate::plugins::{
    endpoint_context::EndpointContext,
    test_helpers::{create_test_config, initialize_test_context},
};
use better_auth_core::{
    AuthError, AuthResult, CreateSession, CreateUser, CreateVerification, FieldMap, FieldValue,
    SchemaValue,
    session::NativeSessionData,
    store::{EphemeralStore, StatelessSchema, transaction},
};
use chrono::{Duration, Utc};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

const MARKER: &str = "ott-transaction-marker";
const CALLBACK_RECORD: &str = "ott-transaction-callback";
const TOKEN: &str = "transactional-token";
const PROOF: &str = "one-time-token:transactional-token";

fn verification(identifier: &str, value: &SchemaValue<String>) -> CreateVerification {
    CreateVerification {
        identifier: identifier.to_owned().into(),
        value: value.clone(),
        expires_at: (Utc::now() + Duration::minutes(5)).into(),
        ..Default::default()
    }
}

#[tokio::test]
async fn typed_generator_and_proof_share_commit_and_rollback() -> AuthResult<()> {
    for commit in [false, true] {
        let calls = Arc::new(AtomicUsize::new(0));
        let generated = calls.clone();
        let callbacks =
            OneTimeTokenCallbacks::<StatelessSchema>::generate(move |data, endpoint| {
                let generated = generated.clone();
                Box::pin(async move {
                    tokio::task::yield_now().await;
                    let tx = endpoint.transaction.ok_or_else(|| {
                        AuthError::internal("The generator did not receive the active transaction")
                    })?;
                    let marker = tx
                        .get_verification_including_expired(MARKER)
                        .await?
                        .ok_or_else(|| AuthError::internal("The transaction marker is missing"))?;
                    assert_eq!(marker.value, data.session.token);
                    assert!(
                        endpoint
                            .auth
                            .database
                            .get_verification_including_expired(MARKER)
                            .await?
                            .is_none()
                    );
                    let _ = tx
                        .create_verification(verification(CALLBACK_RECORD, &data.session.token))
                        .await?;
                    let _ = generated.fetch_add(1, Ordering::SeqCst);
                    Ok(TOKEN.to_owned())
                })
            });
        let config = Arc::new(create_test_config());
        let mut ctx =
            initialize_test_context(config.clone(), Arc::new(EphemeralStore::new(config)), &[])
                .await?;
        ctx.extensions.insert(Arc::new(callbacks));
        let ctx = Arc::new(ctx);
        let user = ctx
            .database
            .create_user(CreateUser::new().with_email("owner@ott-transaction.test"))
            .await?;
        let session = ctx
            .database
            .create_session(CreateSession {
                user_id: user.id.clone(),
                expires_at: (Utc::now() + Duration::hours(1)).into(),
                inherited_fields: Default::default(),
                additional_fields: Default::default(),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await?;
        let expected_token = session.token.clone();
        let data = NativeSessionData {
            session,
            user: FieldMap::from(user).into(),
        };
        let legacy_calls = Arc::new(AtomicUsize::new(0));
        let legacy = legacy_calls.clone();
        let plugin = OneTimeTokenPlugin::new().generate_token(Arc::new(move |_| {
            let _ = legacy.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err(AuthError::internal("The legacy generator must not run")) })
        }));
        let during = ctx.clone();
        let result = transaction(ctx.database.as_ref(), move |tx| {
            Box::pin(async move {
                let _ = tx
                    .create_verification(verification(MARKER, &data.session.token))
                    .await?;
                let mut endpoint =
                    EndpointContext::native(None, None, FieldValue::Undefined, during.as_ref());
                endpoint.transaction = Some(tx);
                let selected_token = data.session.token.clone();
                let token = plugin.generate_in_endpoint(data, &endpoint).await?;
                assert_eq!(token, TOKEN);
                for identifier in [MARKER, CALLBACK_RECORD, PROOF] {
                    let row = tx
                        .get_verification_including_expired(identifier)
                        .await?
                        .ok_or_else(|| {
                            AuthError::internal(format!(
                                "Transaction record is missing: {identifier}"
                            ))
                        })?;
                    assert_eq!(row.value, selected_token, "{identifier}");
                    assert!(
                        during
                            .database
                            .get_verification_including_expired(identifier)
                            .await?
                            .is_none(),
                        "{identifier} became visible before commit"
                    );
                }
                if commit {
                    Ok(token)
                } else {
                    Err(AuthError::bad_request("Rollback the generated token"))
                }
            })
        })
        .await;
        if commit {
            assert_eq!(result?, TOKEN);
        } else {
            assert!(matches!(
                result,
                Err(AuthError::BadRequest(message)) if message == "Rollback the generated token"
            ));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(legacy_calls.load(Ordering::SeqCst), 0);
        for identifier in [MARKER, CALLBACK_RECORD, PROOF] {
            let row = ctx
                .database
                .get_verification_including_expired(identifier)
                .await?;
            assert_eq!(row.is_some(), commit, "{identifier}");
            if let Some(row) = row {
                assert_eq!(row.value, expected_token, "{identifier}");
            }
        }
    }
    Ok(())
}
