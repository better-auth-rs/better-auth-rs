use axum::{routing::get, Json, Router};
use better_auth::plugins::OAuthProxyPlugin;
use better_auth_seaorm::sea_orm::{DatabaseConnection, EntityTrait};
use better_auth_seaorm::store::entities::{session, user};

pub(super) fn plugin(port: u16) -> OAuthProxyPlugin {
    OAuthProxyPlugin::new()
        .production_url("https://production.example.com".to_owned())
        .current_url(format!("http://localhost:{port}"))
}

pub(super) fn router(database: DatabaseConnection) -> Router {
    Router::new().route("/__test/oauth-proxy/stats", get(move || {
        let database = database.clone();
        async move {
            Json(serde_json::json!({
                "users": user::Entity::find().all(&database).await.expect("count fixture users").len(),
                "sessions": session::Entity::find().all(&database).await.expect("count fixture sessions").len(),
            }))
        }
    }))
}
