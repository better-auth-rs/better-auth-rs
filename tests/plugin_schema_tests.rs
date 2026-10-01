//! Plugin initialization rejects entities that cannot persist plugin state.
#![cfg(feature = "seaorm2")]
#![allow(
    clippy::panic_in_result_fn,
    reason = "Tests propagate setup errors and use assertions to identify behavior regressions"
)]
#![allow(unreachable_pub, reason = "SeaORM derive requires public entity types")]

use better_auth::plugin::AuthPlugin;
use better_auth::plugins::{
    AdminPlugin, AnonymousPlugin, EmailPasswordPlugin, OrganizationPlugin, PhoneNumberPlugin,
    TwoFactorPlugin,
};
use better_auth::seaorm::sea_orm::entity::prelude::*;
use better_auth::seaorm::{AuthEntity, Database, SeaOrmStore, sea_orm};
use better_auth::{AuthConfig, AuthError, AuthSchema, BetterAuth};
use better_auth_seaorm::store::entities;

mod core_user {
    use super::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "user")]
    #[sea_orm(table_name = "users")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: Option<String>,
        pub email: Option<String>,
        pub email_verified: bool,
        pub image: Option<String>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

mod core_session {
    use super::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "session")]
    #[sea_orm(table_name = "sessions")]
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
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

struct CoreSchema;
impl AuthSchema for CoreSchema {
    type User = core_user::Model;
    type Session = core_session::Model;
    type Account = entities::account::Model;
    type Verification = entities::verification::Model;
}

struct MissingSessionFields;
impl AuthSchema for MissingSessionFields {
    type User = entities::user::Model;
    type Session = core_session::Model;
    type Account = entities::account::Model;
    type Verification = entities::verification::Model;
}

fn config() -> AuthConfig {
    let mut config = AuthConfig::new("plugin-schema-tests-secret-at-least-32-characters")
        .base_url("http://localhost:3000");
    config.session.bearer = Some(Default::default());
    config
}

#[tokio::test]
async fn plugins_reject_missing_user_fields_before_serving_requests()
-> Result<(), Box<dyn std::error::Error>> {
    let cases: Vec<(Box<dyn AuthPlugin<CoreSchema>>, &str, &str)> = vec![
        (
            Box::new(TwoFactorPlugin::new()),
            "two-factor",
            "two_factor_enabled",
        ),
        (Box::new(AdminPlugin::new()), "admin", "role"),
        (
            Box::new(AnonymousPlugin::new()),
            "anonymous",
            "is_anonymous",
        ),
        (
            Box::new(PhoneNumberPlugin::new()),
            "phone-number",
            "phone_number",
        ),
        (
            Box::new(EmailPasswordPlugin::new().username(true)),
            "username",
            "username",
        ),
    ];
    for (plugin, name, field) in cases {
        let store = std::sync::Arc::new(SeaOrmStore::<CoreSchema>::new(
            config(),
            Database::connect("sqlite::memory:").await?,
        ));
        let mut context =
            better_auth_core::AuthInitContext::new(std::sync::Arc::new(config()), store);
        let result = plugin.on_init(&mut context).await;
        assert!(
            matches!(result, Err(AuthError::Config(ref message)) if message.contains(name) && message.contains(field)),
            "unexpected initialization result: {result:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn build_rejects_missing_session_fields() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect("sqlite::memory:").await?;
    let admin = BetterAuth::<MissingSessionFields>::new(config())
        .store(SeaOrmStore::<MissingSessionFields>::new(
            config(),
            database.clone(),
        ))
        .plugin(AdminPlugin::new())
        .build()
        .await;
    assert!(
        matches!(admin, Err(AuthError::Config(ref message)) if message.contains("impersonated_by"))
    );
    let organization = BetterAuth::<MissingSessionFields>::new(config())
        .store(SeaOrmStore::<MissingSessionFields>::new(config(), database))
        .plugin(OrganizationPlugin::new())
        .build()
        .await;
    assert!(
        matches!(organization, Err(AuthError::Config(ref message)) if message.contains("active_organization_id"))
    );
    Ok(())
}

#[tokio::test]
async fn core_only_schema_builds_without_username_routes() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect("sqlite::memory:").await?;
    let auth = BetterAuth::<CoreSchema>::new(config())
        .store(SeaOrmStore::<CoreSchema>::new(config(), database))
        .plugin(EmailPasswordPlugin::new())
        .build()
        .await?;
    assert!(
        auth.routes()
            .iter()
            .any(|(path, _)| path == "/sign-in/email")
    );
    assert!(
        !auth
            .routes()
            .iter()
            .any(|(path, _)| path.contains("username"))
    );
    Ok(())
}

#[tokio::test]
async fn disabled_username_ignores_inputs_without_persisting_them()
-> Result<(), Box<dyn std::error::Error>> {
    use better_auth::prelude::{AuthRequest, HttpMethod};
    use better_auth_core::entity::AuthUser;
    use serde_json::json;
    use std::collections::HashMap;
    type FullSchema =
        better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
    let database = Database::connect("sqlite::memory:").await?;
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database).await?;
    let auth = BetterAuth::<FullSchema>::new(config())
        .store(SeaOrmStore::<FullSchema>::new(config(), database))
        .plugin(EmailPasswordPlugin::new())
        .build()
        .await?;
    let signup = AuthRequest::from_parts(
        HttpMethod::Post,
        "/sign-up/email".into(),
        HashMap::from([("content-type".into(), "application/json".into())]),
        Some(serde_json::to_vec(&json!({
            "name": "Core user", "email": "core@example.com", "password": "password123",
            "username": { "ignored": true }, "displayUsername": 42
        }))?),
        None,
    );
    let response = auth.handle_request(signup).await?;
    assert_eq!(response.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&response.body)?;
    let token = body
        .get("token")
        .and_then(serde_json::Value::as_str)
        .ok_or("missing session token")?;
    let update = AuthRequest::from_parts(
        HttpMethod::Post,
        "/update-user".into(),
        HashMap::from([
            ("authorization".into(), format!("Bearer {token}")),
            ("content-type".into(), "application/json".into()),
        ]),
        Some(serde_json::to_vec(&json!({
            "name": "Changed name", "username": "ignored_update", "displayUsername": []
        }))?),
        None,
    );
    assert_eq!(auth.handle_request(update).await?.status, 200);
    let user = auth
        .store()
        .get_user_by_email("core@example.com")
        .await?
        .ok_or("missing user")?;
    assert_eq!(user.name(), Some("Changed name"));
    assert_eq!(user.username(), None);
    assert_eq!(user.display_username(), None);
    Ok(())
}
