#![expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "Admin regressions compare exact permission, callback, and storage outcomes"
)]

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, CreateSession, CreateUser,
    FieldMap, FieldValue, HttpMethod,
    config::CookieCacheConfig,
    session::NativeSessionData,
    store::{EphemeralStore, StatelessSchema, StoreCapabilities},
    wire::{SessionView, UserView},
};
use chrono::{Duration, Utc};
use serde_json::{Value, json};

use super::{AdminApi, AdminConfig, AdminPlugin, CreateAdminUser};
use crate::plugins::{
    endpoint_context::EndpointContext,
    test_helpers::{create_test_config, initialize_test_context},
    user_admission::{UserValidationData, UserValidationRejection, ValidateUserInfo},
};

struct Fixture {
    ctx: AuthContext<StatelessSchema>,
    session: SessionView,
    owner: UserView,
}

impl Fixture {
    async fn new(plugin: &AdminPlugin) -> AuthResult<Self> {
        let mut config = create_test_config();
        config.session.disable_session_refresh = Some(true);
        config.session.cookie_cache = Some(CookieCacheConfig {
            enabled: Some(true),
            ..Default::default()
        });
        let config = Arc::new(config);
        let mut ctx = initialize_test_context(
            config.clone(),
            Arc::new(EphemeralStore::new(config)),
            &[plugin],
        )
        .await?;
        ctx.extensions.insert(StoreCapabilities {
            database: false,
            secondary: false,
        });
        let owner = ctx
            .database
            .create_user(CreateUser {
                id: Some("17".into()),
                email: Some("owner@native-admin.test".into()),
                role: Some("admin".into()),
                ..Default::default()
            })
            .await?;
        let session = ctx
            .database
            .create_session(CreateSession {
                user_id: owner.id.clone(),
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
            session,
            owner,
        })
    }

    async fn request(&self, user: FieldValue, path: &str, body: Value) -> AuthResult<AuthRequest> {
        let issuance = AuthRequest::new(HttpMethod::Post, "/sign-in/email");
        self.ctx
            .session_manager()
            .set_native_session_cookie(
                &issuance,
                NativeSessionData {
                    session: self.session.clone(),
                    user,
                },
                None,
            )
            .await?;
        let cookies = issuance
            .take_response_headers()?
            .get_all("set-cookie")
            .map(|cookie| cookie.split(';').next().unwrap().to_owned())
            .collect::<Vec<_>>()
            .join("; ");
        Ok(AuthRequest::from_parts(
            HttpMethod::Post,
            path.into(),
            HashMap::from([
                ("cookie".into(), cookies),
                ("content-type".into(), "application/json".into()),
            ]),
            Some(serde_json::to_vec(&body)?),
            None,
        ))
    }
}

fn body(response: &AuthResponse) -> Value {
    serde_json::from_slice(&response.body.bytes().unwrap()).unwrap()
}

#[tokio::test]
async fn admin_permission_reads_reject_null_and_deny_primitive_users_before_writes()
-> AuthResult<()> {
    let plugin = AdminPlugin::new();
    let fixture = Fixture::new(&plugin).await?;
    for user in [FieldValue::Null, false.into(), 0.0.into(), "".into()] {
        let request = fixture
            .request(
                user.clone(),
                "/admin/update-user",
                json!({"userId":fixture.owner.id,"data":{"name":"must not persist"}}),
            )
            .await?;
        let error = plugin
            .handle_update_user(&request, &fixture.ctx)
            .await
            .unwrap_err();
        if user.is_null() {
            assert!(matches!(error, AuthError::TypeError(ref message)
                if message == "Cannot read properties of null (reading 'id')"));
        } else {
            assert_eq!(error.status_code(), 403);
            assert_eq!(error.to_string(), "You are not allowed to update users");
        }
        assert_eq!(
            fixture
                .ctx
                .database
                .get_user_by_id(fixture.owner.id.typed()?)
                .await?,
            Some(fixture.owner.clone())
        );
        assert_eq!(
            fixture
                .ctx
                .database
                .get_session(fixture.session.token.typed()?)
                .await?,
            Some(fixture.session.clone())
        );
        assert!(request.new_session()?.is_none());
    }
    Ok(())
}

#[derive(Default)]
struct Admission(Mutex<Vec<FieldValue>>);

#[async_trait::async_trait]
impl ValidateUserInfo<StatelessSchema> for Admission {
    async fn validate(
        &self,
        _data: &UserValidationData,
        context: &EndpointContext<'_, StatelessSchema>,
    ) -> AuthResult<Option<UserValidationRejection>> {
        self.0
            .lock()
            .unwrap()
            .push(context.session.as_ref().unwrap().user.clone());
        Ok(None)
    }
}

#[tokio::test]
async fn admin_create_retains_primitive_session_values_for_http_and_native_admission()
-> AuthResult<()> {
    let plugin = AdminPlugin::with_config(AdminConfig {
        default_role: "admin".into(),
        ..Default::default()
    });
    let mut fixture = Fixture::new(&plugin).await?;
    let admission = Arc::new(Admission::default());
    fixture
        .ctx
        .extensions
        .insert(admission.clone() as Arc<dyn ValidateUserInfo<StatelessSchema>>);
    for (index, user) in [FieldValue::Bool(false), 0.0.into(), "".into()]
        .into_iter()
        .enumerate()
    {
        for native in [false, true] {
            let email = format!("created-{index}-{native}@native-admin.test");
            let input =
                json!({"email":email,"name":"Created","role":"user","data":{"banned":false}});
            let request = fixture
                .request(user.clone(), "/admin/create-user", input.clone())
                .await?;
            if native {
                let input: CreateAdminUser = serde_json::from_value(input)?;
                let response = AdminApi::from_context(&fixture.ctx)?
                    .create_user(&input, Some(&request.headers))
                    .await?;
                assert_eq!(
                    response.user.email.field_value(),
                    FieldValue::from(email.clone())
                );
            } else {
                let response = plugin.handle_create_user(&request, &fixture.ctx).await?;
                assert_eq!(body(&response)["user"]["email"], email);
                assert!(request.new_session()?.is_none());
            }
            assert_eq!(admission.0.lock().unwrap().last(), Some(&user));
            let persisted = fixture
                .ctx
                .database
                .get_user_by_email(&email)
                .await?
                .unwrap();
            assert_eq!(persisted.role.field_value(), FieldValue::from("user"));
            assert_eq!(persisted.banned.field_value(), FieldValue::Bool(false));
        }
    }
    assert_eq!(admission.0.lock().unwrap().len(), 6);
    Ok(())
}

#[tokio::test]
async fn admin_has_permission_uses_user_truthiness_before_request_fallback() -> AuthResult<()> {
    let plugin = AdminPlugin::new();
    let fixture = Fixture::new(&plugin).await?;
    for user in [
        FieldValue::Null,
        false.into(),
        0.0.into(),
        "".into(),
        FieldMap::new().into(),
    ] {
        let request = fixture
            .request(
                user.clone(),
                "/admin/has-permission",
                json!({"role":"admin","permissions":{"user":["create"]}}),
            )
            .await?;
        let response = plugin.handle_has_permission(&request, &fixture.ctx).await?;
        assert_eq!(
            body(&response),
            json!({"error":null,"success":!user.is_truthy()})
        );
        if !user.is_truthy() {
            let request = fixture
                .request(
                    user.clone(),
                    "/admin/has-permission",
                    json!({"userId":fixture.owner.id,"permissions":{"user":["create"]}}),
                )
                .await?;
            assert_eq!(
                body(&plugin.handle_has_permission(&request, &fixture.ctx).await?)["success"],
                true
            );
            let request = fixture
                .request(
                    user,
                    "/admin/has-permission",
                    json!({"permissions":{"user":["create"]}}),
                )
                .await?;
            let error = plugin
                .handle_has_permission(&request, &fixture.ctx)
                .await
                .unwrap_err();
            assert_eq!(error.status_code(), 400);
            assert_eq!(error.to_string(), "user not found");
        }
    }
    Ok(())
}

#[tokio::test]
async fn admin_self_ban_compares_native_ids_without_string_coercion() -> AuthResult<()> {
    let plugin = AdminPlugin::new();
    for actor_id in [FieldValue::from("17"), FieldValue::from(17.0)] {
        let fixture = Fixture::new(&plugin).await?;
        let request = fixture
            .request(
                FieldMap::from([
                    ("id".into(), actor_id.clone()),
                    ("role".into(), "admin".into()),
                ])
                .into(),
                "/admin/update-user",
                json!({"userId":"17","data":{"banned":true}}),
            )
            .await?;
        let result = plugin.handle_update_user(&request, &fixture.ctx).await;
        let same_id = actor_id.strict_equals(&FieldValue::from("17"));
        if same_id {
            let error = result.unwrap_err();
            assert_eq!(error.status_code(), 400);
            assert_eq!(error.to_string(), "You cannot ban yourself");
        } else {
            assert_eq!(body(&result?)["banned"], true);
        }
        let stored = fixture.ctx.database.get_user_by_id("17").await?.unwrap();
        if same_id {
            assert_eq!(stored, fixture.owner);
        } else {
            assert_eq!(stored.banned.field_value(), FieldValue::Bool(true));
        }
        assert_eq!(
            fixture
                .ctx
                .database
                .get_session(fixture.session.token.typed()?)
                .await?
                .is_some(),
            same_id
        );
    }
    Ok(())
}

#[tokio::test]
async fn admin_impersonation_keeps_native_actor_ids_and_allows_authorized_self_targets()
-> AuthResult<()> {
    for allow_admins in [false, true] {
        let plugin = AdminPlugin::with_config(AdminConfig {
            allow_impersonating_admins: allow_admins,
            ..Default::default()
        });
        let fixture = Fixture::new(&plugin).await?;
        for actor_id in [FieldValue::from("17"), FieldValue::from(17.0)] {
            let request = fixture
                .request(
                    FieldMap::from([
                        ("id".into(), actor_id.clone()),
                        ("role".into(), "admin".into()),
                    ])
                    .into(),
                    "/admin/impersonate-user",
                    json!({"userId":"17"}),
                )
                .await?;
            let result = plugin.handle_impersonate_user(&request, &fixture.ctx).await;
            if allow_admins {
                let response = result?;
                let output = body(&response);
                assert_eq!(output["user"]["id"], "17");
                assert_eq!(
                    output["session"]["impersonatedBy"],
                    actor_id.json()?.unwrap()
                );
                let session = fixture
                    .ctx
                    .database
                    .get_session(output["session"]["token"].as_str().unwrap())
                    .await?
                    .unwrap();
                assert_eq!(session.user_id.field_value(), FieldValue::from("17"));
                assert_eq!(session.impersonated_by.field_value(), actor_id);
                assert_eq!(request.new_session()?.unwrap().session.token, session.token);
            } else {
                let error = result.unwrap_err();
                assert_eq!(error.status_code(), 403);
                assert_eq!(error.to_string(), "You cannot impersonate admins");
                assert!(request.new_session()?.is_none());
                assert_eq!(fixture.ctx.database.get_user_sessions("17").await?.len(), 1);
            }
            assert_eq!(
                fixture
                    .ctx
                    .database
                    .get_session(fixture.session.token.typed()?)
                    .await?,
                Some(fixture.session.clone())
            );
        }
    }
    Ok(())
}
