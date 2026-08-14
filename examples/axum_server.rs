use axum::extract::{FromRef, State};
use axum::{Json as AxumJson, Router, response::IntoResponse, routing::get};
use better_auth::integrations::axum::{AxumIntegration, CurrentSession, OptionalSession};
use better_auth::plugins::{EmailPasswordPlugin, SessionManagementPlugin};
use better_auth::prelude::AuthUser;
use better_auth::seaorm::sea_orm;
use better_auth::seaorm::sea_orm::entity::prelude::*;
use better_auth::seaorm::sea_orm::{ConnectionTrait, Schema};
use better_auth::seaorm::{AuthEntity, Database, DatabaseConnection, SeaOrmStore};
use better_auth::{AuthConfig, AuthSchema, BetterAuth};
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;

// Only include the fields your plugins need.
// Core fields (id, name, email, etc.) are always required.
// Plugin fields (username, banned, etc.) are optional — the AuthEntity
// macro returns sensible defaults for any missing plugin field.
// Extra app-specific fields are also supported.

mod user {
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
        // Extra app-specific field — gets NotSet on creation,
        // populate via DB defaults or ActiveModelBehavior.
        pub locale: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

mod session {
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

mod account {
    use super::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "account")]
    #[sea_orm(table_name = "accounts")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub account_id: String,
        pub provider_id: String,
        pub user_id: String,
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
}

mod verification {
    use super::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "verification")]
    #[sea_orm(table_name = "verifications")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub identifier: String,
        pub value: String,
        pub expires_at: DateTimeUtc,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub struct AppAuthSchema;

impl AuthSchema for AppAuthSchema {
    type User = crate::user::Model;
    type Session = crate::session::Model;
    type Account = crate::account::Model;
    type Verification = crate::verification::Model;
}

#[derive(Clone)]
struct AppState {
    auth: Arc<BetterAuth<AppAuthSchema>>,
    db: DatabaseConnection,
    app_name: &'static str,
}

impl FromRef<AppState> for Arc<BetterAuth<AppAuthSchema>> {
    fn from_ref(state: &AppState) -> Self {
        state.auth.clone()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let config = AuthConfig::new("your-very-secure-secret-key-at-least-32-chars-long")
        .base_url("http://localhost:8080")
        .password_min_length(8);

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://better-auth-axum.db?mode=rwc".to_string());
    let database = Database::connect(&database_url).await?;
    run_app_migrations(&database).await?;
    let store = SeaOrmStore::<AppAuthSchema>::new(config.clone(), database.clone());

    let auth = Arc::new(
        BetterAuth::<AppAuthSchema>::new(config)
            .store(store)
            .plugin(EmailPasswordPlugin::new().enable_signup(true))
            .plugin(SessionManagementPlugin::new())
            .build()
            .await?,
    );

    let state = AppState {
        auth: auth.clone(),
        db: database,
        app_name: "axum-example",
    };

    let app = Router::new()
        .route("/api/profile", get(get_user_profile))
        .route("/api/public", get(public_route))
        .nest("/auth", auth.axum_router_with_state::<AppState>())
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = TcpListener::bind("0.0.0.0:8080").await?;
    axum::serve(listener, app).await?;
    Ok(())
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

async fn get_user_profile(session: CurrentSession<AppAuthSchema>) -> impl IntoResponse {
    AxumJson(serde_json::json!({
        "id": session.user.id(),
        "email": session.user.email(),
        "name": session.user.name(),
    }))
}

async fn public_route(
    session: OptionalSession<AppAuthSchema>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let database_backend = format!("{:?}", state.db.get_database_backend());
    AxumJson(serde_json::json!({
        "app": state.app_name,
        "authenticated": session.0.is_some(),
        "databaseBackend": database_backend,
    }))
}
