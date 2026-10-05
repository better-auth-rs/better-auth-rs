use async_trait::async_trait;
use axum::{Json, Router, routing::post};
use better_auth::config::{FieldTransforms, UserFieldTransform};
use better_auth::plugins::{
    account_management::AccountManagementPlugin,
    oauth::{OAuthPlugin, OAuthProvider, OAuthRefreshTokenHandler, OAuthTokenSet},
};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult};
use better_auth_core::{
    AuthRequest, CreateAccount, CreateSession, CreateUser, HttpMethod, user_fields::UserFieldConfig,
};
use better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{Database, EntityTrait},
    store::{__private_test_support::migrator, entities::account},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

struct Refresh;
#[async_trait]
impl OAuthRefreshTokenHandler for Refresh {
    async fn refresh_access_token(
        &self,
        _: &str,
        _: Option<better_auth_core::NativeRequest<'_>>,
    ) -> Result<OAuthTokenSet, String> {
        Ok(OAuthTokenSet {
            access_token: Some("new-access".into()),
            access_token_expires_at: Some("2100-01-01T00:00:00Z".parse().unwrap()),
            ..Default::default()
        })
    }
}
#[derive(Deserialize)]
struct Input {
    operation: String,
}
fn db_error(error: better_auth_seaorm::sea_orm::DbErr) -> AuthError {
    AuthError::internal(format!("Account HTTP fixture database: {error}"))
}

async fn run(input: Input) -> AuthResult<Value> {
    let db = Database::connect("sqlite::memory:")
        .await
        .map_err(db_error)?;
    migrator::run_migrations(&db).await.map_err(db_error)?;
    let secret = "account-http-output-proof-secret-at-least-32-characters";
    let mut config = AuthConfig::new(secret);
    config.base_url = "http://localhost:3000".into();
    config.account.store_account_cookie = Some(true);
    for name in ["scope", "idToken"] {
        config.account.additional_fields.insert(
            name.into(),
            UserFieldConfig {
                required: Some(false),
                returned: Some(name != "scope" || input.operation != "list-accounts"),
                on_update: (name == "scope")
                    .then(|| Arc::new(|| json!("after")) as Arc<dyn Fn() -> Value + Send + Sync>),
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new(|value| {
                        Ok(value.map(|value| {
                            if value.is_null() {
                                value
                            } else {
                                json!(format!("{}:out", value.as_str().unwrap()))
                            }
                        }))
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
    }
    let mut provider = OAuthProvider::google("fixture", "fixture");
    provider.refresh_access_token = Some(Arc::new(Refresh));
    let auth = AuthBuilder::<BundledSchema>::new(config.clone())
        .store(SeaOrmStore::<BundledSchema>::new(config, db.clone()))
        .plugin(AccountManagementPlugin::new())
        .plugin(OAuthPlugin::new().add_provider("google", provider))
        .build()
        .await?;
    let user = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_email("account-output@example.test")
                .with_name("Account")
                .with_email_verified(true),
        )
        .await?;
    let session = auth
        .store()
        .create_session(CreateSession {
            additional_fields: Default::default(),
            user_id: user.id.clone(),
            expires_at: chrono::Utc::now() + chrono::Duration::days(1),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await?;
    let account = auth
        .store()
        .create_account(CreateAccount {
            user_id: user.id.into(),
            account_id: "google-account".into(),
            provider_id: "google".into(),
            access_token: Some("old-access".into()).into(),
            refresh_token: Some("old-refresh".into()).into(),
            id_token: Some("old-id".into()).into(),
            scope: Some("before".into()).into(),
            access_token_expires_at: Some(
                "2000-01-01T00:00:00Z"
                    .parse::<chrono::DateTime<chrono::Utc>>()
                    .unwrap(),
            )
            .into(),
            ..Default::default()
        })
        .await?;
    let list = input.operation == "list-accounts";
    let mut request = AuthRequest::new(
        if list {
            HttpMethod::Get
        } else {
            HttpMethod::Post
        },
        format!("/{}", input.operation),
    );
    request.headers.insert(
        "cookie".into(),
        format!(
            "better-auth.session_token={}",
            better_auth_core::utils::cookie_utils::sign_cookie_value(&session.token, secret)
        ),
    );
    request
        .headers
        .insert("content-type".into(), "application/json".into());
    request
        .headers
        .insert("origin".into(), "http://localhost:3000".into());
    if !list {
        request.body = Some(serde_json::to_vec(&json!({"accountId":account.id}))?);
    }
    let response = auth.handle_request(request).await?;
    let body: Value = serde_json::from_slice(&response.body)?;
    let body = if list {
        let row = body
            .as_array()
            .ok_or_else(|| AuthError::internal(format!("List failed: {body}")))?
            .iter()
            .find(|row| row["id"] == serde_json::to_value(&account.id).unwrap())
            .unwrap();
        json!({"scopes":row["scopes"],"hasIdToken":row.get("idToken").is_some()})
    } else {
        ["accessToken", "refreshToken", "idToken", "scope", "scopes"]
            .into_iter()
            .filter_map(|key| body.get(key).map(|value| (key.into(), value.clone())))
            .collect::<serde_json::Map<_, _>>()
            .into()
    };
    let stored = account::Entity::find_by_id(account.id.typed()?.clone())
        .one(&db)
        .await
        .map_err(db_error)?
        .unwrap();
    Ok(
        json!({"status":response.status,"body":body,"stored":{"scope":stored.scope,"idToken":stored.id_token}}),
    )
}
pub fn router() -> Router {
    Router::new().route(
        "/__test/account-http-output",
        post(|Json(input): Json<Input>| async move { run(input).await.map(Json) }),
    )
}
