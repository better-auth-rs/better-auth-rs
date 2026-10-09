#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "Native User regressions compare complete callback, cookie, and storage results"
)]

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use better_auth_core::{
    AuthContext, AuthPlugin, AuthRequest, AuthResult, CreateAccount, CreateSession, CreateUser,
    CreateVerification, FieldMap, FieldValue, HttpMethod,
    config::CookieCacheConfig,
    id::IdGeneration,
    store::{EphemeralStore, StatelessSchema, StoreCapabilities},
    user_fields::{UserFieldConfig, UserFieldReference},
    wire::{SessionView, UserView},
};
use chrono::{Duration, Utc};
use serde_json::{Value, json};

use super::{AfterDeleteUser, BeforeDeleteUser, UserManagementCallbacks, UserManagementPlugin};
use crate::plugins::{
    email_verification::{EmailVerificationCallbacks, EmailVerificationPlugin},
    test_helpers::{
        create_test_config, initialize_test_context,
        native_session::{NativeSessionHook, dispatch_plugin},
    },
};

struct Fixture {
    ctx: AuthContext<StatelessSchema>,
    user: UserView,
    session: SessionView,
    hook: NativeSessionHook,
}

impl Fixture {
    async fn new(plugins: &[&dyn AuthPlugin<StatelessSchema>], serial: bool) -> AuthResult<Self> {
        let mut config = create_test_config();
        config.session.disable_session_refresh = Some(true);
        config.session.cookie_cache = Some(CookieCacheConfig {
            enabled: Some(true),
            ..Default::default()
        });
        if serial {
            config.advanced.database.generate_id = Some(IdGeneration::Serial);
        }
        let config = Arc::new(config);
        let mut ctx = initialize_test_context(
            config.clone(),
            Arc::new(EphemeralStore::new(config)),
            plugins,
        )
        .await?;
        ctx.extensions.insert(StoreCapabilities {
            database: false,
            secondary: false,
        });
        let hook =
            NativeSessionHook::install(&mut ctx, plugins.iter().flat_map(|plugin| plugin.routes()));
        let user = ctx
            .database
            .create_user(CreateUser::new().with_email("owner@native-user.test"))
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
        Ok(Self {
            ctx,
            user,
            session,
            hook,
        })
    }

    fn request(
        &self,
        user: FieldValue,
        method: HttpMethod,
        path: &str,
        input: Value,
    ) -> AuthResult<AuthRequest> {
        self.hook
            .request(&self.ctx, &self.session, user, method, path, input)
    }

    async fn verification(&self, token: &str, value: FieldValue) -> AuthResult<()> {
        let _ = self
            .ctx
            .database
            .create_verification(CreateVerification {
                identifier: format!("delete-account-{token}").into(),
                value: better_auth_core::SchemaValue::from_field(value),
                expires_at: (Utc::now() + Duration::hours(1)).into(),
                ..Default::default()
            })
            .await?;
        Ok(())
    }
}

#[tokio::test]
async fn change_email_spreads_raw_users_and_keeps_the_original_callback_session() -> AuthResult<()>
{
    for user in [
        FieldValue::Bool(false),
        0.0.into(),
        "hi".into(),
        FieldMap::from([(
            "0".into(),
            FieldMap::from([("id".into(), "related".into())]).into(),
        )])
        .into(),
        FieldMap::from([
            ("id".into(), true.into()),
            ("emailVerified".into(), 1.0.into()),
        ])
        .into(),
    ] {
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let captured = delivered.clone();
        let verification =
            EmailVerificationPlugin::new().callbacks(
                EmailVerificationCallbacks::<StatelessSchema>::send(move |message, endpoint| {
                    captured.lock().unwrap().push((
                        message.user.clone(),
                        endpoint.session.as_ref().unwrap().user.clone(),
                    ));
                    Ok(None)
                }),
            );
        let management = UserManagementPlugin::new().change_email_enabled(true).update_without_verification(true)
            .callbacks(UserManagementCallbacks::<StatelessSchema>::new().change_email_confirmation(|_, _| {
                Err(better_auth_core::AuthError::internal("Immediate updates must use verification delivery even when emailVerified is truthy"))
            }));
        let fixture = Fixture::new(&[&verification, &management], true).await?;
        let req = fixture.request(
            user.clone(),
            HttpMethod::Post,
            "/change-email",
            json!({"newEmail":"NEW@native-user.test"}),
        )?;
        let response = dispatch_plugin(&req, &fixture.ctx, &management)
            .await?
            .unwrap();
        assert_eq!(response.status, 200);
        let mut expected = user.enumerable_fields();
        let _ = expected.insert("email".into(), "new@native-user.test".into());
        let expected = FieldValue::from(expected);
        assert_eq!(req.new_session()?.unwrap().user, expected);
        assert_eq!(*delivered.lock().unwrap(), [(expected, user.clone())]);
        let stored = fixture
            .ctx
            .database
            .get_user_by_id(fixture.user.id.typed()?)
            .await?
            .unwrap();
        if user
            .as_object()
            .is_some_and(|fields| fields.contains_key("id"))
        {
            assert_eq!(
                stored.email.field_value(),
                FieldValue::from("new@native-user.test")
            );
        } else {
            assert_eq!(stored, fixture.user);
        }
    }
    Ok(())
}

#[derive(Default)]
struct DeletionTrace(Mutex<Vec<(&'static str, FieldValue)>>);

#[async_trait::async_trait]
impl BeforeDeleteUser for DeletionTrace {
    async fn before_delete(&self, user: &FieldValue, _: Option<&AuthRequest>) -> AuthResult<()> {
        self.0.lock().unwrap().push(("before", user.clone()));
        Ok(())
    }
}

#[async_trait::async_trait]
impl AfterDeleteUser for DeletionTrace {
    async fn after_delete(&self, user: &FieldValue, _: Option<&AuthRequest>) -> AuthResult<()> {
        self.0.lock().unwrap().push(("after", user.clone()));
        Ok(())
    }
}

#[tokio::test]
async fn deletion_hooks_receive_raw_users_before_required_id_access() -> AuthResult<()> {
    for user in [FieldValue::Null, false.into(), 0.0.into(), "".into()] {
        let trace = Arc::new(DeletionTrace::default());
        let plugin = UserManagementPlugin::new()
            .delete_user_enabled(true)
            .before_delete(trace.clone())
            .after_delete(trace.clone());
        let fixture = Fixture::new(&[&plugin], true).await?;
        let req = fixture.request(user.clone(), HttpMethod::Post, "/delete-user", json!({}))?;
        let result = dispatch_plugin(&req, &fixture.ctx, &plugin).await;
        if user.is_null() {
            assert_eq!(
                result.unwrap_err().to_string(),
                "Cannot read properties of null (reading 'id')"
            );
            assert_eq!(*trace.0.lock().unwrap(), [("before", user)]);
            assert!(
                req.take_response_headers()?
                    .get_all("set-cookie")
                    .next()
                    .is_none()
            );
        } else {
            let response = result?.unwrap();
            assert_eq!(response.status, 200);
            assert_eq!(
                *trace.0.lock().unwrap(),
                [("before", user.clone()), ("after", user)]
            );
            assert!(
                response
                    .headers
                    .get_all("set-cookie")
                    .any(|cookie| cookie.contains("Max-Age=0"))
            );
        }
        assert_eq!(
            fixture
                .ctx
                .database
                .get_user_by_id(fixture.user.id.typed()?)
                .await?,
            Some(fixture.user)
        );
        assert_eq!(
            fixture
                .ctx
                .database
                .get_session(fixture.session.token.typed()?)
                .await?,
            Some(fixture.session)
        );
    }
    Ok(())
}

#[tokio::test]
async fn deletion_callback_consumes_mismatched_native_tokens_without_deleting() -> AuthResult<()> {
    for token_value in [1.0.into(), "1".into(), FieldValue::Null] {
        let trace = Arc::new(DeletionTrace::default());
        let plugin = UserManagementPlugin::new()
            .delete_user_enabled(true)
            .before_delete(trace.clone())
            .after_delete(trace.clone());
        let fixture = Fixture::new(&[&plugin], true).await?;
        fixture.verification("strict", token_value).await?;
        let mut req = fixture.request(
            FieldMap::from([("id".into(), true.into())]).into(),
            HttpMethod::Get,
            "/delete-user/callback",
            Value::Null,
        )?;
        req.query = Some(json!({"token":"strict"}));
        let error = dispatch_plugin(&req, &fixture.ctx, &plugin)
            .await
            .unwrap_err();
        assert_eq!(error.status_code(), 404);
        let response = error.to_auth_response();
        assert_eq!(response.body.json()?.unwrap()["message"], "Invalid token");
        assert!(trace.0.lock().unwrap().is_empty());
        assert!(
            fixture
                .ctx
                .database
                .get_verification_by_identifier("delete-account-strict")
                .await?
                .is_none()
        );
        assert_eq!(
            fixture
                .ctx
                .database
                .get_user_by_id(fixture.user.id.typed()?)
                .await?,
            Some(fixture.user)
        );
        assert!(response.headers.get_all("set-cookie").next().is_none());
    }
    Ok(())
}

#[tokio::test]
async fn deletion_confirmation_keeps_raw_sender_payload_and_deletes_the_native_owner()
-> AuthResult<()> {
    let sent = Arc::new(Mutex::new(None));
    let captured = sent.clone();
    let trace = Arc::new(DeletionTrace::default());
    let plugin = UserManagementPlugin::new()
        .delete_user_enabled(true)
        .before_delete(trace.clone())
        .after_delete(trace.clone())
        .callbacks(
            UserManagementCallbacks::<StatelessSchema>::new().delete_account_verification(
                move |message, endpoint| {
                    assert_eq!(message.user, endpoint.session.as_ref().unwrap().user);
                    *captured.lock().unwrap() = Some((
                        message.user.clone(),
                        message.token.clone(),
                        message.url.clone(),
                    ));
                    Ok(None)
                },
            ),
        );
    let fixture = Fixture::new(&[&plugin], true).await?;
    let account = fixture
        .ctx
        .database
        .create_account(CreateAccount {
            user_id: fixture.user.id.clone(),
            provider_id: "test".into(),
            account_id: "native".into(),
            ..Default::default()
        })
        .await?;
    let raw: FieldValue =
        FieldMap::from([("id".into(), true.into()), ("native".into(), 17.0.into())]).into();
    let req = fixture.request(
        raw.clone(),
        HttpMethod::Post,
        "/delete-user",
        json!({"callbackURL":""}),
    )?;
    assert_eq!(
        dispatch_plugin(&req, &fixture.ctx, &plugin)
            .await?
            .unwrap()
            .status,
        200
    );
    let (observed, token, url) = sent.lock().unwrap().clone().unwrap();
    assert_eq!(observed, raw);
    assert!(url.ends_with("callbackURL=%2F"));
    assert_eq!(
        fixture
            .ctx
            .database
            .get_verification_by_identifier(&format!("delete-account-{token}"))
            .await?
            .unwrap()
            .value
            .field_value(),
        FieldValue::Bool(true)
    );
    assert!(trace.0.lock().unwrap().is_empty());
    let mut req = fixture.request(
        raw.clone(),
        HttpMethod::Get,
        "/delete-user/callback",
        Value::Null,
    )?;
    req.query = Some(json!({"token":token,"callbackURL":""}));
    let response = dispatch_plugin(&req, &fixture.ctx, &plugin).await?.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(
        *trace.0.lock().unwrap(),
        [("before", raw.clone()), ("after", raw)]
    );
    assert!(
        fixture
            .ctx
            .database
            .get_user_by_id(fixture.user.id.typed()?)
            .await?
            .is_none()
    );
    assert!(
        fixture
            .ctx
            .database
            .get_session(fixture.session.token.typed()?)
            .await?
            .is_none()
    );
    assert!(
        fixture
            .ctx
            .database
            .get_account(account.provider_id.typed()?, account.account_id.typed()?)
            .await?
            .is_none()
    );
    assert!(
        response
            .headers
            .get_all("set-cookie")
            .any(|cookie| cookie.contains("Max-Age=0"))
    );
    Ok(())
}

#[tokio::test]
async fn real_many_user_relationships_reach_change_and_delete_consumers() -> AuthResult<()> {
    for joins in [false, true] {
        let trace = Arc::new(DeletionTrace::default());
        let plugin = UserManagementPlugin::new()
            .change_email_enabled(true)
            .update_without_verification(true)
            .delete_user_enabled(true)
            .before_delete(trace.clone())
            .after_delete(trace.clone());
        let mut config = create_test_config();
        config.advanced.database.joins = Some(joins);
        config.session.disable_session_refresh = Some(true);
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
        let user = ctx
            .database
            .create_user(CreateUser {
                email: Some("related@native-user.test".into()),
                image: Some(session.id.typed()?.clone()).into(),
                ..Default::default()
            })
            .await?;
        let request = |path: &str, input: Value| {
            AuthRequest::from_parts(
                HttpMethod::Post,
                path.into(),
                HashMap::from([
                    (
                        "authorization".into(),
                        format!("Bearer {}", session.token.typed().unwrap()),
                    ),
                    ("content-type".into(), "application/json".into()),
                ]),
                Some(serde_json::to_vec(&input).unwrap()),
                None,
            )
        };
        let req = request(
            "/change-email",
            json!({"newEmail":"changed@native-user.test"}),
        );
        assert_eq!(plugin.on_request(&req, &ctx).await?.unwrap().status, 200);
        let published = req.new_session()?.unwrap();
        assert!(published.user_field("id").is_undefined());
        assert_eq!(
            published.user_field("email"),
            &FieldValue::from("changed@native-user.test")
        );
        assert_eq!(
            published.user.as_object().unwrap()["0"]
                .as_object()
                .unwrap()["id"],
            user.id.field_value()
        );
        let req = request("/delete-user", json!({}));
        assert_eq!(plugin.on_request(&req, &ctx).await?.unwrap().status, 200);
        let trace = trace.0.lock().unwrap().clone();
        assert_eq!(trace.len(), 2);
        assert_eq!(trace[0].0, "before");
        assert_eq!(trace[1].0, "after");
        assert_eq!(trace[0].1, trace[1].1);
        assert_eq!(
            trace[0].1.as_object().unwrap()["0"].as_object().unwrap()["id"],
            user.id.field_value()
        );
        assert_eq!(
            ctx.database.get_user_by_id(user.id.typed()?).await?,
            Some(user)
        );
        assert_eq!(
            ctx.database.get_session(session.token.typed()?).await?,
            Some(session)
        );
    }
    Ok(())
}
