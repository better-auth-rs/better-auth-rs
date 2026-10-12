#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract. Fixture indexing must fail when an expected record or property is missing. Assertions report exact contract mismatches while Result propagates fixture errors."
)]

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use better_auth_core::{
    AuthError, AuthRequest, AuthResponse, AuthResult, CreateSession, CreateUser, FieldMap,
    FieldValue, HttpMethod,
    session::NativeSessionData,
    store::{EphemeralStore, MemoryCacheAdapter, SecondaryStorage, secondary::SecondaryStore},
};
use chrono::{Duration, Utc};
use serde_json::Value;

use super::AnonymousPlugin;
use crate::plugins::test_helpers::{create_test_config, initialize_test_context};

#[tokio::test]
async fn anonymous_signin_uses_the_injected_native_session_before_database_state() -> AuthResult<()>
{
    use crate::plugins::test_helpers::native_session::{NativeSessionHook, dispatch_http_plugin};
    use better_auth_core::{
        AuthPlugin,
        store::{StatelessSchema, schema::EntityRole},
    };

    let plugin = AnonymousPlugin::new();
    let config = Arc::new(create_test_config());
    let store = Arc::new(EphemeralStore::new(config.clone()));
    let mut context = initialize_test_context(config, store.clone(), &[&plugin]).await?;
    let hook =
        NativeSessionHook::install(&mut context, AuthPlugin::<StatelessSchema>::routes(&plugin));
    let user = context
        .database
        .create_user(CreateUser {
            id: Some("existing-owner".into()),
            email: Some("existing@anonymous.test".into()),
            is_anonymous: Some(false),
            ..Default::default()
        })
        .await?;
    let session = context
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
    let mut native = FieldMap::from(user);
    let _ = native.insert("isAnonymous".into(), "anonymous native value".into());
    let native: FieldValue = native.into();
    let request = hook.request(
        &context,
        &session,
        native.clone(),
        HttpMethod::Post,
        "/sign-in/anonymous",
        serde_json::json!({}),
    )?;
    let response = dispatch_http_plugin(&request, &context, &plugin)
        .await?
        .ok_or_else(|| AuthError::internal("Anonymous sign-in did not return a response"))?;
    assert_eq!(response.status, 400);
    assert!(!response.is_api_error()?);
    assert!(!response.headers.contains_key("set-cookie"));
    assert_eq!(
        serde_json::from_slice::<Value>(&response.body.bytes()?)?,
        serde_json::json!({
            "code":"ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY",
            "message":"Anonymous users cannot sign in again anonymously"
        })
    );
    let snapshot = request
        .native_session_snapshot()?
        .ok_or_else(|| AuthError::internal("Anonymous sign-in discarded its native session"))?;
    assert!(snapshot.user_value()?.strict_equals(&native));
    assert_eq!(snapshot.session_view()?, session);
    assert!(request.new_session()?.is_none());
    let users = store.storage_rows(EntityRole::User)?;
    assert_eq!(users.len(), 1);
    assert_eq!(
        users.first().and_then(|user| user.get("isAnonymous")),
        Some(&false.into())
    );
    assert_eq!(store.storage_rows(EntityRole::Session)?.len(), 1);
    assert!(!request.take_response_headers()?.contains_key("set-cookie"));
    Ok(())
}

#[tokio::test]
async fn anonymous_link_uses_native_truthiness_and_normalizes_the_callback_identity()
-> AuthResult<()> {
    let cases = [
        (FieldValue::Bool(true), true),
        ("anonymous".into(), true),
        (1.0.into(), true),
        (Vec::<FieldValue>::new().into(), true),
        (FieldValue::Bool(false), false),
        (0.0.into(), false),
        (FieldValue::Null, false),
        (FieldValue::Undefined, false),
    ];
    for (new_anonymous, retains_previous) in cases {
        let links = Arc::new(Mutex::new(Vec::new()));
        let captured = links.clone();
        let plugin = AnonymousPlugin::new().on_link_account(move |link| {
            captured.lock().unwrap().push(link);
            async { Ok(()) }
        });
        let config = Arc::new(create_test_config());
        let cache = Arc::new(MemoryCacheAdapter::new());
        let store = SecondaryStore::new(
            Arc::new(EphemeralStore::new(config.clone())),
            cache.clone(),
            config.clone(),
            Default::default(),
        )?;
        let mut ctx = initialize_test_context(config, Arc::new(store), &[&plugin]).await?;
        ctx.secondary_storage = Some(cache.clone());
        let previous = ctx
            .database
            .create_user(CreateUser {
                id: Some("previous".into()),
                email: Some("previous@anonymous.test".into()),
                is_anonymous: Some(true),
                ..Default::default()
            })
            .await?;
        let new_user = ctx
            .database
            .create_user(CreateUser {
                id: Some("current".into()),
                email: Some("current@anonymous.test".into()),
                ..Default::default()
            })
            .await?;
        let mut sessions = Vec::new();
        for user in [&previous, &new_user] {
            sessions.push(
                ctx.database
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
                    .await?,
            );
        }
        let previous_token = sessions[0].token.typed()?;
        let cached = cache.get(previous_token).await?.unwrap();
        let mut cached: Value = serde_json::from_str(cached.as_str().unwrap()).unwrap();
        cached["user"]["isAnonymous"] = "previous native value".into();
        cache.set(previous_token, &cached.to_string(), None).await?;
        let req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/sign-in/email".into(),
            HashMap::from([("authorization".into(), format!("Bearer {previous_token}"))]),
            None,
            None,
        );
        let mut new_fields = FieldMap::from(new_user.clone());
        let _ = new_fields.insert("isAnonymous".into(), new_anonymous.clone());
        let new_native: FieldValue = new_fields.into();
        ctx.session_manager().publish_session(
            &req,
            NativeSessionData::new(sessions[1].clone(), new_native.clone()),
        )?;
        let response = AuthResponse::json(200, &serde_json::json!({"success": true}))?.with_header(
            "set-cookie",
            format!(
                "{}={}",
                ctx.config
                    .auth_cookie("session_token", Default::default())
                    .name,
                sessions[1].token.typed()?,
            ),
        );
        plugin.link(&req, &response, &ctx).await?;
        {
            let links = links.lock().unwrap();
            assert_eq!(links.len(), 1, "{new_anonymous:?}");
            assert_eq!(links[0].anonymous_user.id, previous.id);
            assert_eq!(
                links[0].anonymous_user.is_anonymous.field_value(),
                FieldValue::Bool(true)
            );
            assert_eq!(links[0].anonymous_session, sessions[0]);
            assert_eq!(links[0].new_session, sessions[1]);
            assert!(links[0].new_user.strict_equals(&new_native));
        }
        assert_eq!(
            ctx.database.get_user_by_id("previous").await?.is_some(),
            retains_previous,
            "{new_anonymous:?}"
        );
        assert_eq!(
            ctx.database.get_session(previous_token).await?.is_some(),
            retains_previous,
            "{new_anonymous:?}"
        );
        assert!(ctx.database.get_user_by_id("current").await?.is_some());
        assert_eq!(
            ctx.database.get_session(sessions[1].token.typed()?).await?,
            Some(sessions[1].clone())
        );
    }
    Ok(())
}

#[tokio::test]
async fn anonymous_delete_reads_the_public_object_from_a_many_user_relationship() -> AuthResult<()>
{
    use better_auth_core::user_fields::{UserFieldConfig, UserFieldReference};
    for joins in [false, true] {
        let plugin = AnonymousPlugin::new();
        let mut config = create_test_config().disable_session_refresh(true);
        config.advanced.database.joins = Some(joins);
        let _ = config.user.fields_mut().insert(
            "image".into(),
            UserFieldConfig {
                references: Some(UserFieldReference {
                    model: "session".into(),
                    field: "id".into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let config = Arc::new(config);
        let ctx = initialize_test_context(
            config.clone(),
            Arc::new(EphemeralStore::new(config)),
            &[&plugin],
        )
        .await?;
        let session = ctx
            .database
            .create_session(CreateSession {
                user_id: "canonical-owner".into(),
                expires_at: (Utc::now() + Duration::hours(1)).into(),
                inherited_fields: Default::default(),
                additional_fields: Default::default(),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await?;
        let selected = ctx
            .database
            .create_user(CreateUser {
                id: Some("related-user".into()),
                email: Some("related@anonymous.test".into()),
                image: Some(session.id.typed()?.clone()).into(),
                is_anonymous: Some(true),
                ..Default::default()
            })
            .await?;
        let req = AuthRequest::from_parts(
            HttpMethod::Post,
            "/delete-anonymous-user".into(),
            HashMap::from([(
                "authorization".into(),
                format!("Bearer {}", session.token.typed()?),
            )]),
            None,
            None,
        );
        let observed = ctx.require_authoritative_native_session(&req).await?;
        assert!(observed.user_field("id")?.is_undefined());
        let selected_fields = observed
            .user_value()?
            .as_object()
            .unwrap()
            .snapshot_fields()?["0"]
            .as_object()
            .unwrap()
            .snapshot_fields()?;
        assert_eq!(selected_fields["id"], selected.id.field_value());
        crate::plugins::test_helpers::assert_coded_api_error(
            &plugin
                .delete(&req, &ctx)
                .await
                .err()
                .expect("expected builtin API error"),
            "FORBIDDEN",
            403,
            "USER_IS_NOT_ANONYMOUS",
            "User is not anonymous",
        );
        assert!(ctx.database.get_user_by_id("related-user").await?.is_some());
        assert_eq!(
            ctx.database.get_session(session.token.typed()?).await?,
            Some(session)
        );
    }
    Ok(())
}
