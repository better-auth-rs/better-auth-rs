#![cfg(feature = "seaorm2")]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    unreachable_pub,
    reason = "Contract fixtures fail fast and assert exact public values; SeaORM derives require public model items"
)]

use better_auth::plugins::test_utils::TestAuthOptions;
use better_auth::plugins::{OrganizationPlugin, TestUtilsPlugin};
use better_auth::seaorm::sea_orm::{self, ConnectionTrait, Schema, entity::prelude::*};
use better_auth::seaorm::{self, AuthEntity, Database, SeaOrmStore};
use better_auth::{AuthConfig, AuthSchema, BetterAuth};
use better_auth_core::store::database_hooks::{
    DatabaseHookContext, DatabaseHookControl, DatabaseHooks,
};
use better_auth_core::store::{EphemeralStore, StatelessSchema};
use better_auth_core::user_fields::{UserFieldConfig, UserFieldType};
use better_auth_core::{
    AuthError, AuthResult, CreateUser, CreateVerification, FieldDate, FieldMap, FieldValue,
    Organization,
};
use chrono::{Duration, Utc};
use serde_json::json;
use std::sync::{Arc, Mutex};

mod session {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "session")]
    #[sea_orm(table_name = "test_sessions")]
    #[serde(rename_all = "camelCase")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub expires_at: DateTimeUtc,
        pub token: String,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
        pub ip_address: Option<String>,
        pub user_agent: Option<String>,
        pub user_id: String,
        pub active: bool,
        pub impersonated_by: Option<String>,
        pub active_organization_id: Option<String>,
        pub active_team_id: Option<String>,
        pub label: Option<String>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
struct AppSchema;
impl AuthSchema for AppSchema {
    type User = better_auth_seaorm::store::entities::user::Model;
    type Session = session::Model;
    type Account = better_auth_seaorm::store::entities::account::Model;
    type Verification = better_auth_seaorm::store::entities::verification::Model;
}
fn config(calls: Arc<Mutex<Vec<String>>>) -> AuthConfig {
    let mut config = AuthConfig::new("test-utils-secret-that-is-at-least-thirty-two-characters")
        .base_url("https://test-utils.example/auth");
    config.base_path = "/auth".into();
    config.session.expires_in = Some(Duration::seconds(400));
    config.advanced.use_secure_cookies = Some(false);
    config.advanced.database.generate_id = Some(better_auth_core::id::IdGeneration::Custom(
        better_auth_core::id::IdGenerator::new(move |input| {
            let mut calls = calls.lock().unwrap();
            calls.push(input.model.into());
            Ok(Some(format!("{}-{}", input.model, calls.len())))
        }),
    ));
    let _ = config.advanced.cookies.get_or_insert_default().insert(
        "session_token".into(),
        better_auth_core::CookieOverride {
            name: Some("fixture.token".into()),
            attributes: better_auth_core::CookieAttributes {
                path: Some("/custom".into()),
                domain: Some(".ignored.example".into()),
                max_age: Some(90.0),
                same_site: Some(better_auth_core::SameSite::Strict),
                http_only: Some(false),
                ..Default::default()
            },
        },
    );
    let _ = config.session.fields_mut().insert(
        "label".into(),
        UserFieldConfig {
            field_type: UserFieldType::String,
            required: Some(false),
            default_value: Some("default".into()),
            ..Default::default()
        },
    );
    config
}
async fn database() -> AuthResult<seaorm::sea_orm::DatabaseConnection> {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&db)
        .await
        .unwrap();
    let _ = db
        .execute(&Schema::new(db.get_database_backend()).create_table_from_entity(session::Entity))
        .await
        .unwrap();
    Ok(db)
}
async fn contract<S: AuthSchema>(
    auth: BetterAuth<S>,
    generated: Arc<Mutex<Vec<String>>>,
) -> AuthResult<()> {
    let test = auth.test()?;
    assert!(test.organization().is_none());
    let date: FieldDate = chrono::DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc)
        .into();
    let input = test.create_user(CreateUser {
        id: Some("supplied-user".into()),
        email: Some("TEST@example.com".into()),
        created_at: Some(date.clone()),
        updated_at: Some(date.clone()),
        ..Default::default()
    })?;
    assert_eq!(*generated.lock().unwrap(), ["user"]);
    assert_eq!(input.email.as_deref(), Some("TEST@example.com"));
    assert_eq!(input.name.typed().unwrap().as_deref(), Some("Test User"));
    assert_eq!(input.email_verified, Some(true));
    assert!(
        auth.context()
            .database
            .get_user_by_id("supplied-user")
            .await?
            .is_none()
    );
    let user = test.save_user(input).await?.unwrap();
    assert_eq!(user.id, "supplied-user");
    assert_eq!(user.email.as_deref(), Some("test@example.com"));
    assert_eq!(user.created_at, date);
    assert_eq!(user.updated_at, date);
    let start = Utc::now();
    let login = test.login(TestAuthOptions { user_id: "supplied-user".into(), session: FieldMap::from_json(serde_json::from_value(json!({"id":"injected","userId":"other","token":"injected","createdAt":"2000-01-01T00:00:00Z","updatedAt":"2000-01-01T00:00:00Z","expiresAt":"2000-01-01T00:00:00Z","ipAddress":"injected","userAgent":"injected","label":"selected"}))?)? }).await?;
    assert_ne!(login.session.id, "injected");
    assert_ne!(login.token, "injected");
    assert_eq!(login.session.user_id, user.id);
    assert_eq!(
        login.session.additional_fields["label"],
        FieldValue::from("selected")
    );
    assert_eq!(login.session.ip_address.as_deref(), Some(""));
    assert_eq!(login.session.user_agent.as_deref(), Some(""));
    assert!(
        login.session.expires_at.milliseconds()
            >= (start + Duration::seconds(400)).timestamp_millis() as f64
    );
    assert!(
        login.session.expires_at.milliseconds()
            <= (Utc::now() + Duration::seconds(400)).timestamp_millis() as f64
    );
    assert_eq!(
        login.headers["cookie"],
        format!("fixture.token={}", login.cookies[0].value)
    );
    let cookie = &login.cookies[0];
    assert_eq!(cookie.domain, "test-utils.example");
    assert_eq!(cookie.path, "/custom");
    assert!(!cookie.http_only);
    assert!(!cookie.secure);
    assert_eq!(cookie.same_site, "Strict");
    assert!(cookie.expires.unwrap() >= start.timestamp() as f64 + 90.0);
    assert!(cookie.expires.unwrap() <= Utc::now().timestamp() as f64 + 90.0);
    assert_eq!(
        better_auth_core::utils::cookie_utils::verify_cookie_value(
            &cookie.value,
            &auth.context().config.secret
        ),
        Some(login.token.clone())
    );
    assert!(!cookie.value.contains('%'));
    let response = auth
        .call_endpoint(
            better_auth_core::HttpMethod::Get,
            "/get-session",
            better_auth::server_api::EndpointInput {
                headers: Some(login.headers.clone()),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(response.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&response.body.bytes()?)?;
    assert_eq!(body["user"]["id"], "supplied-user");
    assert_eq!(body["session"]["token"], login.token);
    let header = test
        .get_auth_headers(TestAuthOptions::new("supplied-user"))
        .await?;
    let mut options = TestAuthOptions::new("supplied-user");
    let _ = options.session.insert("label".into(), "browser".into());
    let cookies = test.get_cookies(options, Some("browser.example")).await?;
    assert_eq!(cookies[0].domain, "browser.example");
    assert!(!header["cookie"].contains(&cookies[0].value));
    let mut labels: Vec<_> = auth
        .context()
        .database
        .get_user_sessions("supplied-user")
        .await?
        .into_iter()
        .map(|session| {
            session.additional_fields["label"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    labels.sort();
    assert_eq!(labels, ["browser", "default", "selected"]);
    assert!(test.login(TestAuthOptions::new("missing")).await.is_err());
    for (prefix, key, otp) in [
        ("sign-in-otp-", "a@example.com", "123456"),
        ("email-verification-otp-", "b@example.com", "234567"),
        ("forget-password-otp-", "c@example.com", "345678"),
        ("phone-verification-otp-", "+1234", "456789"),
        ("", "custom-a", "raw"),
    ] {
        let _ = auth
            .context()
            .database
            .create_verification(CreateVerification {
                identifier: format!("{prefix}{key}").into(),
                value: format!("{otp}:3").into(),
                expires_at: (Utc::now() + Duration::seconds(60)).into(),
                ..Default::default()
            })
            .await?;
        assert_eq!(test.otps().unwrap().get(key)?.as_deref(), Some(otp));
    }
    let _ = auth
        .context()
        .database
        .create_verification(CreateVerification {
            identifier: "sign-in-otp-a@example.com".to_owned().into(),
            value: ":4".to_owned().into(),
            expires_at: (Utc::now() + Duration::seconds(60)).into(),
            ..Default::default()
        })
        .await?;
    assert_eq!(
        test.otps().unwrap().get("a@example.com")?.as_deref(),
        Some("123456")
    );
    test.otps().unwrap().clear()?;
    assert!(test.otps().unwrap().get("a@example.com")?.is_none());
    assert!(
        auth.context()
            .database
            .get_verification_by_identifier("sign-in-otp-a@example.com")
            .await?
            .is_some()
    );
    test.delete_user("supplied-user").await?;
    assert!(
        auth.context()
            .database
            .get_user_by_id("supplied-user")
            .await?
            .is_none()
    );
    assert!(
        auth.context()
            .database
            .get_user_sessions("supplied-user")
            .await?
            .is_empty()
    );
    Ok(())
}
#[tokio::test]
async fn memory_factories_authentication_cookies_capture_and_cleanup() -> AuthResult<()> {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let config = config(calls.clone());
    let auth = BetterAuth::<StatelessSchema>::new(config.clone())
        .store(EphemeralStore::new(Arc::new(config)))
        .plugin(better_auth::plugins::SessionManagementPlugin::new())
        .plugin(TestUtilsPlugin { capture_otp: true })
        .build()
        .await?;
    contract(auth, calls).await
}
#[tokio::test]
async fn sqlite_factories_authentication_cookies_capture_and_cleanup() -> AuthResult<()> {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let config = config(calls.clone());
    let auth = BetterAuth::<AppSchema>::new(config.clone())
        .store(SeaOrmStore::<AppSchema>::new(config, database().await?))
        .plugin(better_auth::plugins::SessionManagementPlugin::new())
        .plugin(TestUtilsPlugin { capture_otp: true })
        .build()
        .await?;
    contract(auth, calls).await
}

struct CancellingHooks;
#[better_auth::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for CancellingHooks {
    async fn before_create_user(
        &self,
        user: &mut CreateUser,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        match user.email.as_deref() {
            Some("cancel@example.com") => Ok(DatabaseHookControl::Cancel),
            Some("throw@example.com") => Err(AuthError::internal("before failed")),
            _ => Ok(DatabaseHookControl::Continue),
        }
    }
    async fn before_create_session(
        &self,
        input: &mut better_auth_core::CreateSession,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookControl> {
        Ok(
            if input.additional_fields.get("label") == Some(&FieldValue::from("cancel")) {
                DatabaseHookControl::Cancel
            } else {
                DatabaseHookControl::Continue
            },
        )
    }
    async fn after_create_session(
        &self,
        input: &better_auth_core::wire::SessionView,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        if input.additional_fields.get("label") == Some(&FieldValue::from("fail-after")) {
            Err(AuthError::internal("after failed"))
        } else {
            Ok(())
        }
    }
}
async fn failures<S: AuthSchema>(auth: BetterAuth<S>) -> AuthResult<()> {
    let helper = auth.test()?;
    for email in ["cancel@example.com", "throw@example.com"] {
        let result = helper
            .save_user(helper.create_user(CreateUser {
                email: Some(email.into()),
                ..Default::default()
            })?)
            .await;
        if email.starts_with("cancel") {
            assert!(result?.is_none());
        } else {
            assert!(result.is_err());
        }
        assert!(
            auth.context()
                .database
                .get_user_by_email(email)
                .await?
                .is_none()
        );
    }
    let user = helper
        .save_user(helper.create_user(CreateUser::default())?)
        .await?
        .unwrap();
    for label in ["cancel", "fail-after"] {
        let error = helper
            .login(TestAuthOptions {
                user_id: user.id.typed()?.clone(),
                session: [("label".into(), label.into())].into_iter().collect(),
            })
            .await;
        assert!(error.is_err());
    }
    let rows = auth
        .context()
        .database
        .get_user_sessions(user.id.typed()?)
        .await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].additional_fields["label"],
        FieldValue::from("fail-after")
    );
    Ok(())
}
#[tokio::test]
async fn hook_cancellation_and_errors_preserve_nullable_and_committed_results() -> AuthResult<()> {
    let c = config(Default::default());
    let memory = BetterAuth::new(c.clone())
        .store(EphemeralStore::new(Arc::new(c.clone())))
        .plugin(CancellingHooks)
        .plugin(TestUtilsPlugin::default())
        .build()
        .await?;
    failures(memory).await?;
    let sql = BetterAuth::<AppSchema>::new(c.clone())
        .store(SeaOrmStore::<AppSchema>::new(c, database().await?))
        .plugin(CancellingHooks)
        .plugin(TestUtilsPlugin::default())
        .build()
        .await?;
    failures(sql).await
}
#[tokio::test]
async fn raw_organization_cleanup_retains_earlier_deletes_when_parent_delete_fails()
-> AuthResult<()> {
    let c = config(Default::default());
    let db = database().await?;
    let auth = BetterAuth::<AppSchema>::new(c.clone())
        .store(SeaOrmStore::<AppSchema>::new(c, db.clone()))
        .plugin(OrganizationPlugin::new().teams(
            better_auth::plugins::organization::OrganizationTeamsConfig {
                enabled: true,
                ..Default::default()
            },
        ))
        .plugin(CancellingHooks)
        .plugin(TestUtilsPlugin::default())
        .build()
        .await?;
    let helper = auth.test()?;
    assert!(helper.otps().is_none());
    let org = helper.organization().unwrap();
    let user = helper
        .save_user(helper.create_user(CreateUser::default())?)
        .await?
        .unwrap();
    let login = helper
        .login(TestAuthOptions {
            user_id: user.id.typed()?.clone(),
            session: [
                ("activeOrganizationId".into(), "seed-org".into()),
                ("activeTeamId".into(), "seed-team".into()),
                ("impersonatedBy".into(), "disabled-admin".into()),
            ]
            .into_iter()
            .collect(),
        })
        .await?;
    assert_eq!(
        login.session.active_organization_id.as_deref(),
        Some("seed-org")
    );
    assert_eq!(login.session.active_team_id.as_deref(), Some("seed-team"));
    assert!(login.session.impersonated_by.is_none());
    let persisted = auth.store().get_session(&login.token).await?.unwrap();
    assert_eq!(
        persisted.active_organization_id.as_deref(),
        Some("seed-org")
    );
    assert_eq!(persisted.active_team_id.as_deref(), Some("seed-team"));
    let draft = org.create_organization(Organization {
        id: "seed-org".to_owned().into(),
        name: "Seed".to_owned().into(),
        slug: "seed".to_owned().into(),
        ..Default::default()
    })?;
    assert!(
        auth.context()
            .database
            .get_organization_by_id("seed-org")
            .await?
            .is_none()
    );
    let saved = org.save_organization(draft).await?;
    assert_eq!(saved.id, "seed-org");
    let member = org
        .add_member("seed-org", user.id.typed()?.clone(), Some("owner"))
        .await?;
    let _=db.execute_unprepared("CREATE TRIGGER reject_org_delete BEFORE DELETE ON organization BEGIN SELECT RAISE(FAIL, 'parent failed'); END").await.unwrap();
    assert!(org.delete_organization("seed-org").await.is_err());
    assert!(
        auth.context()
            .database
            .get_member_by_id(member.id.typed()?)
            .await?
            .is_none()
    );
    assert!(
        auth.context()
            .database
            .get_organization_by_id("seed-org")
            .await?
            .is_some()
    );
    let _ = db
        .execute_unprepared("DROP TRIGGER reject_org_delete")
        .await
        .unwrap();
    org.delete_organization("seed-org").await?;
    assert!(
        auth.context()
            .database
            .get_organization_by_id("seed-org")
            .await?
            .is_none()
    );
    assert!(
        auth.context()
            .database
            .get_user_by_id(user.id.typed()?)
            .await?
            .is_some()
    );
    Ok(())
}

#[async_trait::async_trait]
impl<S: AuthSchema> better_auth_core::AuthPlugin<S> for CancellingHooks {
    fn name(&self) -> &'static str {
        "test-hook-cancellation"
    }
    fn routes(&self) -> Vec<better_auth_core::AuthRoute> {
        vec![]
    }
    async fn on_init(&self, context: &mut better_auth_core::AuthInitContext<S>) -> AuthResult<()> {
        context.register_database_hook(Arc::new(CancellingHooks));
        Ok(())
    }
    async fn on_request(
        &self,
        _: &better_auth_core::AuthRequest,
        _: &better_auth_core::AuthContext<S>,
    ) -> AuthResult<Option<better_auth_core::AuthResponse>> {
        Ok(None)
    }
}

struct Admission(Arc<Mutex<Vec<String>>>);
#[async_trait::async_trait]
impl<S: AuthSchema> better_auth::plugins::user_admission::ValidateUserInfo<S> for Admission {
    async fn validate(
        &self,
        data: &better_auth::plugins::user_admission::UserValidationData,
        context: &better_auth::plugins::endpoint_context::EndpointContext<'_, S>,
    ) -> AuthResult<Option<better_auth::plugins::user_admission::UserValidationRejection>> {
        assert_eq!(data.source.method, "test");
        assert_eq!(
            data.source.action,
            better_auth::plugins::user_admission::UserValidationAction::CreateUser
        );
        assert_eq!(context.path, Some("/seed"));
        self.0
            .lock()
            .unwrap()
            .push(data.user["email"].as_str().unwrap().into());
        Ok(None)
    }
}
#[tokio::test]
async fn admission_requires_endpoint_and_transactional_helpers_commit_or_roll_back_together()
-> AuthResult<()> {
    let c = config(Default::default());
    let db = database().await?;
    let calls = Arc::new(Mutex::new(Vec::new()));
    let auth = Arc::new(
        BetterAuth::<AppSchema>::new(c.clone())
            .store(SeaOrmStore::<AppSchema>::new(c, db))
            .validate_user_info(Arc::new(Admission(calls.clone())))
            .plugin(OrganizationPlugin::new())
            .plugin(TestUtilsPlugin::default())
            .build()
            .await?,
    );
    let error = auth
        .test()?
        .save_user(auth.test()?.create_user(CreateUser::default())?)
        .await;
    let Err(error) = error else {
        return Err(AuthError::internal("missing endpoint must reject"));
    };
    assert!(error.is_api_error());
    assert!(calls.lock().unwrap().is_empty());
    for reject in [true, false] {
        let runtime = auth.clone();
        let result = better_auth_core::store::transaction(auth.store().as_ref(), move |tx| {
            Box::pin(async move {
                let mut endpoint = better_auth::plugins::endpoint_context::EndpointContext::new(
                    None,
                    json!({}),
                    runtime.context(),
                );
                endpoint.path = Some("/seed");
                endpoint.transaction = Some(tx);
                let api = endpoint.test()?;
                let user = api
                    .save_user(api.create_user(CreateUser {
                        id: Some("transaction-user".into()),
                        email: Some("TX@example.com".into()),
                        ..Default::default()
                    })?)
                    .await?
                    .unwrap();
                let login = api
                    .login(TestAuthOptions::new(user.id.typed()?.clone()))
                    .await?;
                assert_eq!(login.user.id, "transaction-user");
                if reject {
                    Err(AuthError::forbidden("rollback"))
                } else {
                    Ok(login.token)
                }
            })
        })
        .await;
        assert_eq!(result.is_err(), reject);
        assert_eq!(
            auth.store()
                .get_user_by_id("transaction-user")
                .await?
                .is_some(),
            !reject
        );
        assert_eq!(
            auth.store()
                .get_user_sessions("transaction-user")
                .await?
                .len(),
            usize::from(!reject)
        );
    }
    assert_eq!(*calls.lock().unwrap(), ["tx@example.com", "tx@example.com"]);
    Ok(())
}

#[tokio::test]
async fn shared_plugin_instances_keep_capture_isolated_and_secondary_helpers_publish_sessions()
-> AuthResult<()> {
    let plugin = TestUtilsPlugin { capture_otp: true };
    let c = config(Default::default());
    let first = BetterAuth::stateless(c.clone())
        .plugin(plugin.clone())
        .build()
        .await?;
    let second = BetterAuth::stateless(c.clone())
        .plugin(plugin)
        .build()
        .await?;
    let _ = first
        .store()
        .create_verification(CreateVerification {
            identifier: "sign-in-otp-a".to_owned().into(),
            value: "123:0".to_owned().into(),
            expires_at: (Utc::now() + Duration::seconds(60)).into(),
            ..Default::default()
        })
        .await?;
    assert_eq!(
        first.test()?.otps().unwrap().get("a")?.as_deref(),
        Some("123")
    );
    assert!(second.test()?.otps().unwrap().get("a")?.is_none());
    let mut c = c;
    c.session.store_session_in_database = Some(false);
    let cache = Arc::new(better_auth_core::store::MemoryCacheAdapter::new());
    let auth = BetterAuth::<AppSchema>::new(c.clone())
        .store(SeaOrmStore::<AppSchema>::new(c, database().await?))
        .secondary_storage(cache.clone())
        .plugin(CancellingHooks)
        .plugin(TestUtilsPlugin::default())
        .build()
        .await?;
    failures(auth).await
}

#[tokio::test]
async fn organization_helpers_keep_the_outer_adapter_inside_a_transaction() -> AuthResult<()> {
    let c = config(Default::default());
    let auth = Arc::new(
        BetterAuth::<StatelessSchema>::new(c.clone())
            .store(EphemeralStore::new(Arc::new(c)))
            .plugin(OrganizationPlugin::new())
            .plugin(TestUtilsPlugin::default())
            .build()
            .await?,
    );
    let runtime = auth.clone();
    let result: AuthResult<()> =
        better_auth_core::store::transaction(auth.store().as_ref(), move |tx| {
            Box::pin(async move {
                let mut endpoint = better_auth::plugins::endpoint_context::EndpointContext::new(
                    None,
                    json!({}),
                    runtime.context(),
                );
                endpoint.transaction = Some(tx);
                let api = endpoint.test()?;
                let _ = api
                    .save_user(api.create_user(CreateUser {
                        id: Some("rolled-back".into()),
                        ..Default::default()
                    })?)
                    .await?;
                let org = api.organization().unwrap();
                let _ = org
                    .save_organization(org.create_organization(Organization {
                        id: "outer-org".to_owned().into(),
                        ..Default::default()
                    })?)
                    .await?;
                Err(AuthError::forbidden("rollback"))
            })
        })
        .await;
    assert!(result.is_err());
    assert!(auth.store().get_user_by_id("rolled-back").await?.is_none());
    assert!(
        auth.store()
            .get_organization_by_id("outer-org")
            .await?
            .is_some()
    );
    Ok(())
}

async fn metadata_contract<S: AuthSchema>(auth: BetterAuth<S>, sql: bool) -> AuthResult<()> {
    let helper = auth.test()?;
    let organization = helper.organization().unwrap();
    for value in [
        json!(null),
        json!("plain"),
        json!("{\"key\":\"value\"}"),
        json!("null"),
        json!({"key":"value"}),
    ] {
        let draft = organization.create_organization(Organization {
            metadata: better_auth_core::SchemaValue::Dynamic(FieldValue::from_json(value.clone())?),
            ..Default::default()
        })?;
        assert_eq!(serde_json::to_value(&draft)?["metadata"], value);
        let result = organization.save_organization(draft).await;
        if sql && value.is_object() {
            assert!(result.is_err());
        } else {
            let saved = result?;
            assert_eq!(serde_json::to_value(&saved)?["metadata"], value);
            let read = auth
                .store()
                .get_organization_by_id(saved.id.typed()?)
                .await?
                .unwrap();
            assert_eq!(serde_json::to_value(&read)?["metadata"], value);
        }
    }
    let user = helper
        .save_user(helper.create_user(CreateUser::default())?)
        .await?
        .unwrap();
    let headers = helper
        .get_auth_headers(TestAuthOptions::new(user.id.typed()?.clone()))
        .await?;
    let created=auth.call_endpoint(better_auth_core::HttpMethod::Post,"/organization/create",better_auth::server_api::EndpointInput {headers:Some(headers.clone()),body:Some(json!({"name":"Route metadata","slug":"route-metadata","metadata":{"nested":{"value":1}}})),..Default::default()}).await?;
    let created: serde_json::Value = serde_json::from_slice(&created.body.bytes()?)?;
    assert_eq!(created["metadata"], json!({"nested":{"value":1}}));
    let id = created["id"].as_str().unwrap();
    let raw = auth.store().get_organization_by_id(id).await?.unwrap();
    assert_eq!(
        serde_json::to_value(raw)?["metadata"],
        "{\"nested\":{\"value\":1}}"
    );
    let updated = auth
        .call_endpoint(
            better_auth_core::HttpMethod::Post,
            "/organization/update",
            better_auth::server_api::EndpointInput {
                headers: Some(headers),
                body: Some(json!({"organizationId":id,"data":{"metadata":{}}})),
                ..Default::default()
            },
        )
        .await?;
    let updated: serde_json::Value = serde_json::from_slice(&updated.body.bytes()?)?;
    assert_eq!(updated["metadata"], json!({}));
    assert_eq!(
        serde_json::to_value(auth.store().get_organization_by_id(id).await?.unwrap())?["metadata"],
        "{}"
    );
    Ok(())
}

#[tokio::test]
async fn raw_metadata_retains_adapter_values_and_route_json_is_encoded_once() -> AuthResult<()> {
    let c = config(Default::default());
    let memory = BetterAuth::<StatelessSchema>::new(c.clone())
        .store(EphemeralStore::new(Arc::new(c.clone())))
        .plugin(OrganizationPlugin::new())
        .plugin(TestUtilsPlugin::default())
        .build()
        .await?;
    metadata_contract(memory, false).await?;
    let sql = BetterAuth::<AppSchema>::new(c.clone())
        .store(SeaOrmStore::<AppSchema>::new(c, database().await?))
        .plugin(OrganizationPlugin::new())
        .plugin(TestUtilsPlugin::default())
        .build()
        .await?;
    metadata_contract(sql, true).await
}
