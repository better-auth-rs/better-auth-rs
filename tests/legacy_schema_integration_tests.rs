#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "integration tests intentionally use direct assertions over concrete JSON payloads"
)]

use std::borrow::Cow;

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use better_auth::plugins::{
    AccountManagementPlugin, EmailPasswordPlugin, PasswordManagementPlugin, SessionManagementPlugin,
};
use better_auth::prelude::{
    AuthAccount, AuthRequest, AuthSession, AuthUser, AuthVerification, CreateAccount,
    CreateSession, CreateUser, CreateVerification, HttpMethod, UpdateAccount, UpdateUser,
};
use better_auth::{AuthConfig, AuthError, AuthResult, AuthSchema, BetterAuth};
use better_auth_seaorm::sea_orm;
use better_auth_seaorm::sea_orm::entity::prelude::*;
use better_auth_seaorm::sea_orm::{ActiveValue::NotSet, ActiveValue::Set, ConnectionTrait, Schema};
use better_auth_seaorm::{
    Database, DatabaseConnection, SeaOrmAccountModel, SeaOrmSessionModel, SeaOrmStore,
    SeaOrmUserModel, SeaOrmVerificationModel,
};
use chrono::{DateTime, Utc};
use rand::rngs::OsRng;
use serde_json::json;

mod user {
    use super::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "users")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub name: Option<String>,
        pub email: Option<String>,
        pub email_verified: bool,
        pub image: Option<String>,
        pub username: Option<String>,
        pub display_username: Option<String>,
        pub two_factor_enabled: bool,
        pub role: Option<String>,
        pub banned: bool,
        pub ban_reason: Option<String>,
        pub ban_expires: Option<DateTimeUtc>,
        pub metadata: Json,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
        pub tenant_id: i64,
        pub locale: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}

    impl AuthUser for Model {
        fn id(&self) -> Cow<'_, str> {
            Cow::Owned(self.id.to_string())
        }
        fn email(&self) -> Option<&str> {
            self.email.as_deref()
        }
        fn name(&self) -> Option<&str> {
            self.name.as_deref()
        }
        fn email_verified(&self) -> bool {
            self.email_verified
        }
        fn image(&self) -> Option<&str> {
            self.image.as_deref()
        }
        fn created_at(&self) -> DateTime<Utc> {
            self.created_at
        }
        fn updated_at(&self) -> DateTime<Utc> {
            self.updated_at
        }
        fn username(&self) -> Option<&str> {
            self.username.as_deref()
        }
        fn display_username(&self) -> Option<&str> {
            self.display_username.as_deref()
        }
        fn two_factor_enabled(&self) -> bool {
            self.two_factor_enabled
        }
        fn role(&self) -> Option<&str> {
            self.role.as_deref()
        }
        fn banned(&self) -> bool {
            self.banned
        }
        fn ban_reason(&self) -> Option<&str> {
            self.ban_reason.as_deref()
        }
        fn ban_expires(&self) -> Option<DateTime<Utc>> {
            self.ban_expires
        }
        fn metadata(&self) -> &serde_json::Value {
            &self.metadata
        }
    }

    impl SeaOrmUserModel for Model {
        type Id = i32;
        type Entity = Entity;
        type ActiveModel = ActiveModel;
        type Column = Column;

        fn id_column() -> Self::Column {
            Column::Id
        }
        fn email_column() -> Self::Column {
            Column::Email
        }
        fn username_column() -> Self::Column {
            Column::Username
        }
        fn name_column() -> Self::Column {
            Column::Name
        }
        fn created_at_column() -> Self::Column {
            Column::CreatedAt
        }
        fn parse_id(id: &str) -> AuthResult<Self::Id> {
            id.parse()
                .map_err(|_| AuthError::bad_request("Invalid user id"))
        }
        fn new_active(
            id: Option<Self::Id>,
            create_user: CreateUser,
            now: DateTime<Utc>,
        ) -> Self::ActiveModel {
            ActiveModel {
                id: id.map_or(NotSet, Set),
                name: Set(create_user.name),
                email: Set(create_user.email),
                email_verified: Set(create_user.email_verified.unwrap_or(false)),
                image: Set(create_user.image),
                username: Set(create_user.username),
                display_username: Set(create_user.display_username),
                two_factor_enabled: Set(false),
                role: Set(create_user.role),
                banned: Set(false),
                ban_reason: Set(None),
                ban_expires: Set(None),
                metadata: Set(create_user.metadata.unwrap_or(json!({}))),
                created_at: Set(now),
                updated_at: Set(now),
                tenant_id: Set(1),
                locale: Set("en".to_string()),
            }
        }
        fn apply_update(active: &mut Self::ActiveModel, update: UpdateUser, now: DateTime<Utc>) {
            if let Some(email) = update.email {
                active.email = Set(Some(email));
            }
            if let Some(name) = update.name {
                active.name = Set(Some(name));
            }
            if let Some(image) = update.image {
                active.image = Set(Some(image));
            }
            if let Some(email_verified) = update.email_verified {
                active.email_verified = Set(email_verified);
            }
            if let Some(username) = update.username {
                active.username = Set(Some(username));
            }
            if let Some(display_username) = update.display_username {
                active.display_username = Set(Some(display_username));
            }
            if let Some(role) = update.role {
                active.role = Set(Some(role));
            }
            if let Some(two_factor_enabled) = update.two_factor_enabled {
                active.two_factor_enabled = Set(two_factor_enabled);
            }
            if let Some(metadata) = update.metadata {
                active.metadata = Set(metadata);
            }
            if let Some(banned) = update.banned {
                active.banned = Set(banned);
                if !banned {
                    active.ban_reason = Set(None);
                    active.ban_expires = Set(None);
                }
            }
            if update.banned != Some(false) {
                if let Some(ban_reason) = update.ban_reason {
                    active.ban_reason = Set(Some(ban_reason));
                }
                if let Some(ban_expires) = update.ban_expires {
                    active.ban_expires = Set(Some(ban_expires));
                }
            }
            active.updated_at = Set(now);
        }
    }
}

mod session {
    use super::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "sessions")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub expires_at: DateTimeUtc,
        pub token: String,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
        pub ip_address: Option<String>,
        pub user_agent: Option<String>,
        pub user_id: i32,
        pub impersonated_by: Option<String>,
        pub active_organization_id: Option<String>,
        pub active: bool,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}

    impl AuthSession for Model {
        fn id(&self) -> Cow<'_, str> {
            Cow::Owned(self.id.to_string())
        }
        fn expires_at(&self) -> DateTime<Utc> {
            self.expires_at
        }
        fn token(&self) -> &str {
            &self.token
        }
        fn created_at(&self) -> DateTime<Utc> {
            self.created_at
        }
        fn updated_at(&self) -> DateTime<Utc> {
            self.updated_at
        }
        fn ip_address(&self) -> Option<&str> {
            self.ip_address.as_deref()
        }
        fn user_agent(&self) -> Option<&str> {
            self.user_agent.as_deref()
        }
        fn user_id(&self) -> Cow<'_, str> {
            Cow::Owned(self.user_id.to_string())
        }
        fn impersonated_by(&self) -> Option<&str> {
            self.impersonated_by.as_deref()
        }
        fn active_organization_id(&self) -> Option<&str> {
            self.active_organization_id.as_deref()
        }
        fn active(&self) -> bool {
            self.active
        }
    }

    impl SeaOrmSessionModel for Model {
        type Id = i32;
        type UserId = i32;
        type Entity = Entity;
        type ActiveModel = ActiveModel;
        type Column = Column;

        fn id_column() -> Self::Column {
            Column::Id
        }
        fn token_column() -> Self::Column {
            Column::Token
        }
        fn user_id_column() -> Self::Column {
            Column::UserId
        }
        fn active_column() -> Self::Column {
            Column::Active
        }
        fn expires_at_column() -> Self::Column {
            Column::ExpiresAt
        }
        fn created_at_column() -> Self::Column {
            Column::CreatedAt
        }
        fn parse_id(id: &str) -> AuthResult<Self::Id> {
            id.parse()
                .map_err(|_| AuthError::bad_request("Invalid session id"))
        }
        fn parse_user_id(user_id: &str) -> AuthResult<Self::UserId> {
            user_id
                .parse()
                .map_err(|_| AuthError::bad_request("Invalid session user id"))
        }
        fn new_active(
            id: Option<Self::Id>,
            token: String,
            create_session: CreateSession,
            now: DateTime<Utc>,
        ) -> Self::ActiveModel {
            let user_id = create_session
                .user_id
                .parse()
                .expect("session user ids come from validated auth user identifiers");
            ActiveModel {
                id: id.map_or(NotSet, Set),
                expires_at: Set(create_session.expires_at),
                token: Set(token),
                created_at: Set(now),
                updated_at: Set(now),
                ip_address: Set(create_session.ip_address),
                user_agent: Set(create_session.user_agent),
                user_id: Set(user_id),
                impersonated_by: Set(create_session.impersonated_by),
                active_organization_id: Set(create_session.active_organization_id),
                active: Set(true),
            }
        }
        fn set_expires_at(active: &mut Self::ActiveModel, expires_at: DateTime<Utc>) {
            active.expires_at = Set(expires_at);
        }
        fn set_updated_at(active: &mut Self::ActiveModel, updated_at: DateTime<Utc>) {
            active.updated_at = Set(updated_at);
        }
        fn set_active_organization_id(
            active: &mut Self::ActiveModel,
            organization_id: Option<String>,
        ) {
            active.active_organization_id = Set(organization_id);
        }
    }
}

mod account {
    use super::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "accounts")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub account_id: String,
        pub provider_id: String,
        pub user_id: i32,
        pub access_token: Option<String>,
        pub refresh_token: Option<String>,
        pub id_token: Option<String>,
        pub access_token_expires_at: Option<DateTimeUtc>,
        pub refresh_token_expires_at: Option<DateTimeUtc>,
        pub scope: Option<String>,
        pub password: Option<String>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}

    impl AuthAccount for Model {
        fn id(&self) -> Cow<'_, str> {
            Cow::Owned(self.id.to_string())
        }
        fn account_id(&self) -> &str {
            &self.account_id
        }
        fn provider_id(&self) -> &str {
            &self.provider_id
        }
        fn user_id(&self) -> Cow<'_, str> {
            Cow::Owned(self.user_id.to_string())
        }
        fn access_token(&self) -> Option<&str> {
            self.access_token.as_deref()
        }
        fn refresh_token(&self) -> Option<&str> {
            self.refresh_token.as_deref()
        }
        fn id_token(&self) -> Option<&str> {
            self.id_token.as_deref()
        }
        fn access_token_expires_at(&self) -> Option<DateTime<Utc>> {
            self.access_token_expires_at
        }
        fn refresh_token_expires_at(&self) -> Option<DateTime<Utc>> {
            self.refresh_token_expires_at
        }
        fn scope(&self) -> Option<&str> {
            self.scope.as_deref()
        }
        fn password(&self) -> Option<&str> {
            self.password.as_deref()
        }
        fn created_at(&self) -> DateTime<Utc> {
            self.created_at
        }
        fn updated_at(&self) -> DateTime<Utc> {
            self.updated_at
        }
    }

    impl SeaOrmAccountModel for Model {
        type Id = i32;
        type UserId = i32;
        type Entity = Entity;
        type ActiveModel = ActiveModel;
        type Column = Column;

        fn id_column() -> Self::Column {
            Column::Id
        }
        fn provider_id_column() -> Self::Column {
            Column::ProviderId
        }
        fn account_id_column() -> Self::Column {
            Column::AccountId
        }
        fn user_id_column() -> Self::Column {
            Column::UserId
        }
        fn created_at_column() -> Self::Column {
            Column::CreatedAt
        }
        fn parse_id(id: &str) -> AuthResult<Self::Id> {
            id.parse()
                .map_err(|_| AuthError::bad_request("Invalid account id"))
        }
        fn parse_user_id(user_id: &str) -> AuthResult<Self::UserId> {
            user_id
                .parse()
                .map_err(|_| AuthError::bad_request("Invalid account user id"))
        }
        fn new_active(
            id: Option<Self::Id>,
            create_account: CreateAccount,
            now: DateTime<Utc>,
        ) -> Self::ActiveModel {
            let user_id = create_account
                .user_id
                .parse()
                .expect("account user ids come from validated auth user identifiers");
            ActiveModel {
                id: id.map_or(NotSet, Set),
                account_id: Set(create_account.account_id),
                provider_id: Set(create_account.provider_id),
                user_id: Set(user_id),
                access_token: Set(create_account.access_token),
                refresh_token: Set(create_account.refresh_token),
                id_token: Set(create_account.id_token),
                access_token_expires_at: Set(create_account.access_token_expires_at),
                refresh_token_expires_at: Set(create_account.refresh_token_expires_at),
                scope: Set(create_account.scope),
                password: Set(create_account.password),
                created_at: Set(now),
                updated_at: Set(now),
            }
        }
        fn apply_update(active: &mut Self::ActiveModel, update: UpdateAccount, now: DateTime<Utc>) {
            if let Some(access_token) = update.access_token {
                active.access_token = Set(Some(access_token));
            }
            if let Some(refresh_token) = update.refresh_token {
                active.refresh_token = Set(Some(refresh_token));
            }
            if let Some(id_token) = update.id_token {
                active.id_token = Set(Some(id_token));
            }
            if let Some(access_token_expires_at) = update.access_token_expires_at {
                active.access_token_expires_at = Set(Some(access_token_expires_at));
            }
            if let Some(refresh_token_expires_at) = update.refresh_token_expires_at {
                active.refresh_token_expires_at = Set(Some(refresh_token_expires_at));
            }
            if let Some(scope) = update.scope {
                active.scope = Set(Some(scope));
            }
            if let Some(password) = update.password {
                active.password = Set(Some(password));
            }
            active.updated_at = Set(now);
        }
    }
}

mod verification {
    use super::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "verifications")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub identifier: String,
        pub value: String,
        pub expires_at: DateTimeUtc,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}

    impl AuthVerification for Model {
        fn id(&self) -> Cow<'_, str> {
            Cow::Owned(self.id.to_string())
        }
        fn identifier(&self) -> &str {
            &self.identifier
        }
        fn value(&self) -> &str {
            &self.value
        }
        fn expires_at(&self) -> DateTime<Utc> {
            self.expires_at
        }
        fn created_at(&self) -> DateTime<Utc> {
            self.created_at
        }
        fn updated_at(&self) -> DateTime<Utc> {
            self.updated_at
        }
    }

    impl SeaOrmVerificationModel for Model {
        type Id = i32;
        type Entity = Entity;
        type ActiveModel = ActiveModel;
        type Column = Column;

        fn id_column() -> Self::Column {
            Column::Id
        }
        fn identifier_column() -> Self::Column {
            Column::Identifier
        }
        fn value_column() -> Self::Column {
            Column::Value
        }
        fn expires_at_column() -> Self::Column {
            Column::ExpiresAt
        }
        fn created_at_column() -> Self::Column {
            Column::CreatedAt
        }
        fn parse_id(id: &str) -> AuthResult<Self::Id> {
            id.parse()
                .map_err(|_| AuthError::bad_request("Invalid verification id"))
        }
        fn new_active(
            id: Option<Self::Id>,
            verification: CreateVerification,
            now: DateTime<Utc>,
        ) -> Self::ActiveModel {
            ActiveModel {
                id: id.map_or(NotSet, Set),
                identifier: Set(verification.identifier),
                value: Set(verification.value),
                expires_at: Set(verification.expires_at),
                created_at: Set(now),
                updated_at: Set(now),
            }
        }
    }
}

pub struct LegacySchema;

impl AuthSchema for LegacySchema {
    type User = crate::user::Model;
    type Session = crate::session::Model;
    type Account = crate::account::Model;
    type Verification = crate::verification::Model;
}

async fn test_database() -> DatabaseConnection {
    let database = Database::connect("sqlite::memory:")
        .await
        .expect("sqlite test database should connect");
    run_app_migrations(&database)
        .await
        .expect("legacy schema migrations should run");
    database
}

async fn run_app_migrations(database: &DatabaseConnection) -> Result<(), sea_orm::DbErr> {
    let schema = Schema::new(database.get_database_backend());
    for statement in [
        schema
            .create_table_from_entity(user::Entity)
            .if_not_exists()
            .to_owned(),
        schema
            .create_table_from_entity(session::Entity)
            .if_not_exists()
            .to_owned(),
        schema
            .create_table_from_entity(account::Entity)
            .if_not_exists()
            .to_owned(),
        schema
            .create_table_from_entity(verification::Entity)
            .if_not_exists()
            .to_owned(),
    ] {
        let _ = database.execute(&statement).await?;
    }
    Ok(())
}

fn test_config() -> AuthConfig {
    AuthConfig::new("test-secret-key-that-is-at-least-32-characters-long")
        .base_url("http://localhost:3000")
        .password_min_length(8)
}

async fn create_auth() -> BetterAuth<LegacySchema> {
    let config = test_config();
    let store = SeaOrmStore::<LegacySchema>::new(config.clone(), test_database().await);
    BetterAuth::<LegacySchema>::new(config)
        .store(store)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(SessionManagementPlugin::new())
        .plugin(PasswordManagementPlugin::new())
        .plugin(AccountManagementPlugin::new())
        .build()
        .await
        .expect("legacy auth should build")
}

fn request(method: HttpMethod, path: &str, body: Option<serde_json::Value>) -> AuthRequest {
    let mut req = AuthRequest::new(method, path);
    if let Some(body) = body {
        req.body = Some(body.to_string().into_bytes());
        let _ = req
            .headers
            .insert("content-type".to_string(), "application/json".to_string());
    }
    req
}

fn auth_request(method: HttpMethod, path: &str, token: &str) -> AuthRequest {
    let mut req = AuthRequest::new(method, path);
    let _ = req
        .headers
        .insert("authorization".to_string(), format!("Bearer {token}"));
    req
}

async fn seed_legacy_user(database: &DatabaseConnection) -> i32 {
    let now = Utc::now();
    let password_hash = hash_seed_password("legacy-password").expect("seed password should hash");
    let user = user::ActiveModel {
        id: NotSet,
        name: Set(Some("Legacy User".to_string())),
        email: Set(Some("legacy@example.com".to_string())),
        email_verified: Set(true),
        image: Set(None),
        username: Set(Some("legacy_user".to_string())),
        display_username: Set(Some("legacy_user".to_string())),
        two_factor_enabled: Set(false),
        role: Set(Some("user".to_string())),
        banned: Set(false),
        ban_reason: Set(None),
        ban_expires: Set(None),
        metadata: Set(json!({ "imported": true })),
        created_at: Set(now),
        updated_at: Set(now),
        tenant_id: Set(42),
        locale: Set("fr".to_string()),
    }
    .insert(database)
    .await
    .expect("legacy user should insert");

    let _ = account::ActiveModel {
        id: NotSet,
        account_id: Set(user.id.to_string()),
        provider_id: Set("credential".to_string()),
        user_id: Set(user.id),
        access_token: Set(None),
        refresh_token: Set(None),
        id_token: Set(None),
        access_token_expires_at: Set(None),
        refresh_token_expires_at: Set(None),
        scope: Set(None),
        password: Set(Some(password_hash)),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(database)
    .await
    .expect("legacy credential account should insert");

    user.id
}

fn hash_seed_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
}

#[tokio::test]
async fn legacy_numeric_schema_signup_flow_uses_numeric_ids_and_defaults() {
    let auth = create_auth().await;

    let signup = request(
        HttpMethod::Post,
        "/sign-up/email",
        Some(json!({
            "email": "new@example.com",
            "password": "Password123!",
            "name": "New User",
        })),
    );
    let response = auth
        .handle_request(signup)
        .await
        .expect("signup should succeed");
    assert_eq!(response.status, 200);

    let body: serde_json::Value = serde_json::from_slice(&response.body).expect("valid json");
    let token = body["token"]
        .as_str()
        .expect("token should exist")
        .to_string();

    let stored_user = auth
        .store()
        .get_user_by_email("new@example.com")
        .await
        .expect("lookup should succeed")
        .expect("user should exist");
    assert!(stored_user.id > 0);
    assert_eq!(stored_user.tenant_id, 1);
    assert_eq!(stored_user.locale, "en");
    assert_eq!(body["user"]["id"], stored_user.id.to_string());

    let session_response = auth
        .handle_request(auth_request(HttpMethod::Get, "/get-session", &token))
        .await
        .expect("get-session should succeed");
    assert_eq!(session_response.status, 200);
    let session_body: serde_json::Value =
        serde_json::from_slice(&session_response.body).expect("valid session json");
    assert_eq!(session_body["user"]["id"], stored_user.id.to_string());

    let accounts_response = auth
        .handle_request(auth_request(HttpMethod::Get, "/list-accounts", &token))
        .await
        .expect("list-accounts should succeed");
    assert_eq!(accounts_response.status, 200);
    let accounts_body: serde_json::Value =
        serde_json::from_slice(&accounts_response.body).expect("valid accounts json");
    assert_eq!(accounts_body.as_array().expect("array").len(), 1);
    assert_eq!(accounts_body[0]["userId"], stored_user.id.to_string());
    assert_eq!(accounts_body[0]["providerId"], "credential");
}

#[tokio::test]
async fn legacy_numeric_schema_existing_user_can_sign_in() {
    let database = test_database().await;
    let legacy_user_id = seed_legacy_user(&database).await;
    let config = test_config();
    let store = SeaOrmStore::<LegacySchema>::new(config.clone(), database);
    let auth = BetterAuth::<LegacySchema>::new(config)
        .store(store)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(SessionManagementPlugin::new())
        .plugin(PasswordManagementPlugin::new())
        .plugin(AccountManagementPlugin::new())
        .build()
        .await
        .expect("legacy auth should build");

    let signin = request(
        HttpMethod::Post,
        "/sign-in/email",
        Some(json!({
            "email": "legacy@example.com",
            "password": "legacy-password",
        })),
    );
    let response = auth
        .handle_request(signin)
        .await
        .expect("signin should succeed");
    assert_eq!(response.status, 200);

    let body: serde_json::Value = serde_json::from_slice(&response.body).expect("valid json");
    let token = body["token"]
        .as_str()
        .expect("token should exist")
        .to_string();
    assert_eq!(body["user"]["id"], legacy_user_id.to_string());

    let session_response = auth
        .handle_request(auth_request(HttpMethod::Get, "/get-session", &token))
        .await
        .expect("get-session should succeed");
    let session_body: serde_json::Value =
        serde_json::from_slice(&session_response.body).expect("valid session json");
    assert_eq!(session_body["user"]["id"], legacy_user_id.to_string());
    assert_eq!(
        session_body["session"]["userId"],
        legacy_user_id.to_string()
    );
}

#[tokio::test]
async fn legacy_numeric_schema_store_verifications_use_public_string_ids() {
    let auth = create_auth().await;

    let verification = auth
        .store()
        .create_verification(CreateVerification {
            identifier: "verify:legacy".to_string(),
            value: "token-123".to_string(),
            expires_at: Utc::now() + chrono::Duration::minutes(30),
        })
        .await
        .expect("verification should insert");

    assert!(!verification.id().is_empty());

    let loaded = auth
        .store()
        .get_verification_by_identifier("verify:legacy")
        .await
        .expect("lookup should succeed");
    assert!(loaded.is_some());

    auth.store()
        .delete_verification(&verification.id())
        .await
        .expect("delete should succeed");

    let loaded = auth
        .store()
        .get_verification_by_identifier("verify:legacy")
        .await
        .expect("lookup should succeed");
    assert!(loaded.is_none());
}
