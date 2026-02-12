use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use validator::Validate;

use better_auth_core::adapters::DatabaseAdapter;
use better_auth_core::entity::{AuthApiKey, AuthSession, AuthUser};
use better_auth_core::{AuthContext, AuthPlugin, AuthRoute};
use better_auth_core::{AuthError, AuthResult};
use better_auth_core::{AuthRequest, AuthResponse, CreateApiKey, HttpMethod, UpdateApiKey};

/// API Key management plugin.
pub struct ApiKeyPlugin {
    config: ApiKeyConfig,
}

#[derive(Debug, Clone)]
pub struct ApiKeyConfig {
    pub key_length: usize,
    pub prefix: Option<String>,
    pub default_remaining: Option<i64>,
}

impl Default for ApiKeyConfig {
    fn default() -> Self {
        Self {
            key_length: 32,
            prefix: None,
            default_remaining: None,
        }
    }
}

// -- Request types --

#[derive(Debug, Deserialize, Validate)]
struct CreateKeyRequest {
    name: Option<String>,
    prefix: Option<String>,
    #[serde(rename = "expiresIn")]
    #[validate(range(min = 1, message = "expiresIn must be greater than 0"))]
    expires_in: Option<i64>,
    remaining: Option<i64>,
    #[serde(rename = "rateLimitEnabled")]
    rate_limit_enabled: Option<bool>,
    #[serde(rename = "rateLimitTimeWindow")]
    rate_limit_time_window: Option<i64>,
    #[serde(rename = "rateLimitMax")]
    rate_limit_max: Option<i64>,
    #[serde(rename = "refillInterval")]
    refill_interval: Option<i64>,
    #[serde(rename = "refillAmount")]
    refill_amount: Option<i64>,
    permissions: Option<serde_json::Value>,
    metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Validate)]
struct UpdateKeyRequest {
    #[validate(length(min = 1, message = "Key ID is required"))]
    id: String,
    name: Option<String>,
    enabled: Option<bool>,
    remaining: Option<i64>,
    #[serde(rename = "rateLimitEnabled")]
    rate_limit_enabled: Option<bool>,
    #[serde(rename = "rateLimitTimeWindow")]
    rate_limit_time_window: Option<i64>,
    #[serde(rename = "rateLimitMax")]
    rate_limit_max: Option<i64>,
    #[serde(rename = "refillInterval")]
    refill_interval: Option<i64>,
    #[serde(rename = "refillAmount")]
    refill_amount: Option<i64>,
    permissions: Option<serde_json::Value>,
    metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Validate)]
struct DeleteKeyRequest {
    #[validate(length(min = 1, message = "Key ID is required"))]
    id: String,
}

// -- Response types --

#[derive(Debug, Serialize)]
struct ApiKeyView {
    id: String,
    name: Option<String>,
    start: Option<String>,
    prefix: Option<String>,
    #[serde(rename = "userId")]
    user_id: String,
    #[serde(rename = "refillInterval")]
    refill_interval: Option<i64>,
    #[serde(rename = "refillAmount")]
    refill_amount: Option<i64>,
    #[serde(rename = "lastRefillAt")]
    last_refill_at: Option<String>,
    enabled: bool,
    #[serde(rename = "rateLimitEnabled")]
    rate_limit_enabled: bool,
    #[serde(rename = "rateLimitTimeWindow")]
    rate_limit_time_window: Option<i64>,
    #[serde(rename = "rateLimitMax")]
    rate_limit_max: Option<i64>,
    #[serde(rename = "requestCount")]
    request_count: Option<i64>,
    remaining: Option<i64>,
    #[serde(rename = "lastRequest")]
    last_request: Option<String>,
    #[serde(rename = "expiresAt")]
    expires_at: Option<String>,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "updatedAt")]
    updated_at: String,
    permissions: Option<serde_json::Value>,
    metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct CreateKeyResponse {
    key: String,
    #[serde(flatten)]
    api_key: ApiKeyView,
}

impl ApiKeyView {
    fn from_entity(ak: &impl AuthApiKey) -> Self {
        Self {
            id: ak.id().to_string(),
            name: ak.name().map(|s| s.to_string()),
            start: ak.start().map(|s| s.to_string()),
            prefix: ak.prefix().map(|s| s.to_string()),
            user_id: ak.user_id().to_string(),
            refill_interval: ak.refill_interval(),
            refill_amount: ak.refill_amount(),
            last_refill_at: ak.last_refill_at().map(|s| s.to_string()),
            enabled: ak.enabled(),
            rate_limit_enabled: ak.rate_limit_enabled(),
            rate_limit_time_window: ak.rate_limit_time_window(),
            rate_limit_max: ak.rate_limit_max(),
            request_count: ak.request_count(),
            remaining: ak.remaining(),
            last_request: ak.last_request().map(|s| s.to_string()),
            expires_at: ak.expires_at().map(|s| s.to_string()),
            created_at: ak.created_at().to_string(),
            updated_at: ak.updated_at().to_string(),
            permissions: ak.permissions().and_then(|s| serde_json::from_str(s).ok()),
            metadata: ak.metadata().and_then(|s| serde_json::from_str(s).ok()),
        }
    }
}

impl ApiKeyPlugin {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            config: ApiKeyConfig::default(),
        }
    }

    pub fn with_config(config: ApiKeyConfig) -> Self {
        Self { config }
    }

    pub fn key_length(mut self, length: usize) -> Self {
        self.config.key_length = length;
        self
    }

    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.config.prefix = Some(prefix.into());
        self
    }

    pub fn default_remaining(mut self, remaining: i64) -> Self {
        self.config.default_remaining = Some(remaining);
        self
    }

    fn generate_key(&self, custom_prefix: Option<&str>) -> (String, String, String) {
        let mut bytes = vec![0u8; self.config.key_length];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let raw = URL_SAFE_NO_PAD.encode(&bytes);

        let start = raw.chars().take(4).collect::<String>();

        let prefix = custom_prefix
            .or(self.config.prefix.as_deref())
            .unwrap_or("");
        let full_key = format!("{}{}", prefix, raw);

        let mut hasher = Sha256::new();
        hasher.update(full_key.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        (full_key, hash, start)
    }

    async fn get_authenticated_user<DB: DatabaseAdapter>(
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<(DB::User, DB::Session)> {
        let token = req
            .headers
            .get("authorization")
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(AuthError::Unauthenticated)?;

        let session = ctx
            .database
            .get_session(token)
            .await?
            .ok_or(AuthError::Unauthenticated)?;

        if session.expires_at() < chrono::Utc::now() {
            return Err(AuthError::Unauthenticated);
        }

        let user = ctx
            .database
            .get_user_by_id(session.user_id())
            .await?
            .ok_or(AuthError::UserNotFound)?;

        Ok((user, session))
    }

    async fn handle_create<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = Self::get_authenticated_user(req, ctx).await?;

        let create_req: CreateKeyRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let (full_key, hash, start) = self.generate_key(create_req.prefix.as_deref());

        let expires_at = if let Some(ms) = create_req.expires_in {
            let duration = chrono::Duration::try_milliseconds(ms)
                .ok_or_else(|| AuthError::bad_request("expiresIn is out of range"))?;
            let dt = chrono::Utc::now()
                .checked_add_signed(duration)
                .ok_or_else(|| AuthError::bad_request("expiresIn is out of range"))?;
            Some(dt.to_rfc3339())
        } else {
            None
        };

        let remaining = create_req.remaining.or(self.config.default_remaining);

        let input = CreateApiKey {
            user_id: user.id().to_string(),
            name: create_req.name,
            prefix: create_req.prefix.or_else(|| self.config.prefix.clone()),
            key_hash: hash,
            start: Some(start),
            expires_at,
            remaining,
            rate_limit_enabled: create_req.rate_limit_enabled.unwrap_or(false),
            rate_limit_time_window: create_req.rate_limit_time_window,
            rate_limit_max: create_req.rate_limit_max,
            refill_interval: create_req.refill_interval,
            refill_amount: create_req.refill_amount,
            permissions: create_req
                .permissions
                .map(|v| serde_json::to_string(&v).unwrap_or_default()),
            metadata: create_req
                .metadata
                .map(|v| serde_json::to_string(&v).unwrap_or_default()),
            enabled: true,
        };

        let api_key = ctx.database.create_api_key(input).await?;

        let response = CreateKeyResponse {
            key: full_key,
            api_key: ApiKeyView::from_entity(&api_key),
        };

        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_get<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = Self::get_authenticated_user(req, ctx).await?;

        let id = req
            .query
            .get("id")
            .ok_or_else(|| AuthError::bad_request("Query parameter 'id' is required"))?;

        let api_key = ctx
            .database
            .get_api_key_by_id(id)
            .await?
            .ok_or_else(|| AuthError::not_found("API key not found"))?;

        if api_key.user_id() != user.id() {
            return Err(AuthError::not_found("API key not found"));
        }

        Ok(AuthResponse::json(200, &ApiKeyView::from_entity(&api_key))?)
    }

    async fn handle_list<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = Self::get_authenticated_user(req, ctx).await?;

        let keys = ctx.database.list_api_keys_by_user(user.id()).await?;

        let views: Vec<ApiKeyView> = keys.iter().map(ApiKeyView::from_entity).collect();

        Ok(AuthResponse::json(200, &views)?)
    }

    async fn handle_update<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = Self::get_authenticated_user(req, ctx).await?;

        let update_req: UpdateKeyRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Ownership check
        let existing = ctx
            .database
            .get_api_key_by_id(&update_req.id)
            .await?
            .ok_or_else(|| AuthError::not_found("API key not found"))?;

        if existing.user_id() != user.id() {
            return Err(AuthError::not_found("API key not found"));
        }

        let update = UpdateApiKey {
            name: update_req.name,
            enabled: update_req.enabled,
            remaining: update_req.remaining,
            rate_limit_enabled: update_req.rate_limit_enabled,
            rate_limit_time_window: update_req.rate_limit_time_window,
            rate_limit_max: update_req.rate_limit_max,
            refill_interval: update_req.refill_interval,
            refill_amount: update_req.refill_amount,
            permissions: update_req
                .permissions
                .map(|v| serde_json::to_string(&v).unwrap_or_default()),
            metadata: update_req
                .metadata
                .map(|v| serde_json::to_string(&v).unwrap_or_default()),
        };

        let updated = ctx.database.update_api_key(&update_req.id, update).await?;

        Ok(AuthResponse::json(200, &ApiKeyView::from_entity(&updated))?)
    }

    async fn handle_delete<DB: DatabaseAdapter>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = Self::get_authenticated_user(req, ctx).await?;

        let delete_req: DeleteKeyRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        // Ownership check
        let existing = ctx
            .database
            .get_api_key_by_id(&delete_req.id)
            .await?
            .ok_or_else(|| AuthError::not_found("API key not found"))?;

        if existing.user_id() != user.id() {
            return Err(AuthError::not_found("API key not found"));
        }

        ctx.database.delete_api_key(&delete_req.id).await?;

        Ok(AuthResponse::json(
            200,
            &serde_json::json!({ "status": true }),
        )?)
    }
}

#[async_trait]
impl<DB: DatabaseAdapter> AuthPlugin<DB> for ApiKeyPlugin {
    fn name(&self) -> &'static str {
        "api-key"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::post("/api-key/create", "api_key_create"),
            AuthRoute::get("/api-key/get", "api_key_get"),
            AuthRoute::post("/api-key/update", "api_key_update"),
            AuthRoute::post("/api-key/delete", "api_key_delete"),
            AuthRoute::get("/api-key/list", "api_key_list"),
        ]
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<DB>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Post, "/api-key/create") => Ok(Some(self.handle_create(req, ctx).await?)),
            (HttpMethod::Get, "/api-key/get") => Ok(Some(self.handle_get(req, ctx).await?)),
            (HttpMethod::Post, "/api-key/update") => Ok(Some(self.handle_update(req, ctx).await?)),
            (HttpMethod::Post, "/api-key/delete") => Ok(Some(self.handle_delete(req, ctx).await?)),
            (HttpMethod::Get, "/api-key/list") => Ok(Some(self.handle_list(req, ctx).await?)),
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::adapters::{ApiKeyOps, MemoryDatabaseAdapter, SessionOps, UserOps};
    use better_auth_core::{CreateSession, CreateUser, Session, User};
    use chrono::{Duration, Utc};
    use std::collections::HashMap;
    use std::sync::Arc;

    async fn create_test_context_with_user() -> (AuthContext<MemoryDatabaseAdapter>, User, Session)
    {
        let config = Arc::new(better_auth_core::AuthConfig::new(
            "test-secret-key-at-least-32-chars-long",
        ));
        let database = Arc::new(MemoryDatabaseAdapter::new());
        let ctx = AuthContext::new(config, database.clone());

        let user = database
            .create_user(
                CreateUser::new()
                    .with_email("test@example.com")
                    .with_name("Test User"),
            )
            .await
            .unwrap();

        let session = database
            .create_session(CreateSession {
                user_id: user.id.clone(),
                expires_at: Utc::now() + Duration::hours(24),
                ip_address: Some("127.0.0.1".to_string()),
                user_agent: Some("test-agent".to_string()),
                impersonated_by: None,
                active_organization_id: None,
            })
            .await
            .unwrap();

        (ctx, user, session)
    }

    async fn create_user_with_session(
        ctx: &AuthContext<MemoryDatabaseAdapter>,
        email: &str,
    ) -> (User, Session) {
        let user = ctx
            .database
            .create_user(
                CreateUser::new()
                    .with_email(email.to_string())
                    .with_name("Another User"),
            )
            .await
            .unwrap();

        let session = ctx
            .database
            .create_session(CreateSession {
                user_id: user.id.clone(),
                expires_at: Utc::now() + Duration::hours(24),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await
            .unwrap();

        (user, session)
    }

    fn create_auth_request(
        method: HttpMethod,
        path: &str,
        token: Option<&str>,
        body: Option<serde_json::Value>,
        query: Option<HashMap<String, String>>,
    ) -> AuthRequest {
        let mut headers = HashMap::new();
        if let Some(token) = token {
            headers.insert("authorization".to_string(), format!("Bearer {}", token));
        }

        AuthRequest {
            method,
            path: path.to_string(),
            headers,
            body: body.map(|b| serde_json::to_vec(&b).unwrap()),
            query: query.unwrap_or_default(),
        }
    }

    fn json_body(response: &AuthResponse) -> serde_json::Value {
        serde_json::from_slice(&response.body).unwrap()
    }

    async fn create_key_and_get_id(
        plugin: &ApiKeyPlugin,
        ctx: &AuthContext<MemoryDatabaseAdapter>,
        token: &str,
        name: &str,
    ) -> String {
        let req = create_auth_request(
            HttpMethod::Post,
            "/api-key/create",
            Some(token),
            Some(serde_json::json!({ "name": name })),
            None,
        );
        let response = plugin.handle_create(&req, ctx).await.unwrap();
        assert_eq!(response.status, 200);
        json_body(&response)["id"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn test_create_and_get_do_not_expose_hash() {
        let plugin = ApiKeyPlugin::new().prefix("ba_");
        let (ctx, _user, session) = create_test_context_with_user().await;

        let create_req = create_auth_request(
            HttpMethod::Post,
            "/api-key/create",
            Some(&session.token),
            Some(serde_json::json!({ "name": "primary" })),
            None,
        );
        let create_response = plugin.handle_create(&create_req, &ctx).await.unwrap();
        assert_eq!(create_response.status, 200);

        let body = json_body(&create_response);
        assert!(body.get("key").is_some());
        assert!(body.get("key_hash").is_none());
        assert!(body.get("hash").is_none());

        let id = body["id"].as_str().unwrap();
        let mut query = HashMap::new();
        query.insert("id".to_string(), id.to_string());

        let get_req = create_auth_request(
            HttpMethod::Get,
            "/api-key/get",
            Some(&session.token),
            None,
            Some(query),
        );
        let get_response = plugin.handle_get(&get_req, &ctx).await.unwrap();
        assert_eq!(get_response.status, 200);

        let get_body = json_body(&get_response);
        assert!(get_body.get("key").is_none());
        assert!(get_body.get("key_hash").is_none());
    }

    #[tokio::test]
    async fn test_create_rejects_invalid_expires_in() {
        let plugin = ApiKeyPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;

        let req = create_auth_request(
            HttpMethod::Post,
            "/api-key/create",
            Some(&session.token),
            Some(serde_json::json!({ "expiresIn": i64::MIN })),
            None,
        );
        let response = plugin.handle_create(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 422);
    }

    #[tokio::test]
    async fn test_get_update_delete_return_404_for_non_owner() {
        let plugin = ApiKeyPlugin::new();
        let (ctx, _user1, session1) = create_test_context_with_user().await;
        let (_user2, session2) = create_user_with_session(&ctx, "other@example.com").await;
        let key_id = create_key_and_get_id(&plugin, &ctx, &session1.token, "owner-key").await;

        let mut get_query = HashMap::new();
        get_query.insert("id".to_string(), key_id.clone());
        let get_req = create_auth_request(
            HttpMethod::Get,
            "/api-key/get",
            Some(&session2.token),
            None,
            Some(get_query),
        );
        let get_err = plugin.handle_get(&get_req, &ctx).await.unwrap_err();
        assert_eq!(get_err.status_code(), 404);

        let update_req = create_auth_request(
            HttpMethod::Post,
            "/api-key/update",
            Some(&session2.token),
            Some(serde_json::json!({ "id": key_id, "name": "new-name" })),
            None,
        );
        let update_err = plugin.handle_update(&update_req, &ctx).await.unwrap_err();
        assert_eq!(update_err.status_code(), 404);

        let delete_req = create_auth_request(
            HttpMethod::Post,
            "/api-key/delete",
            Some(&session2.token),
            Some(serde_json::json!({ "id": key_id })),
            None,
        );
        let delete_err = plugin.handle_delete(&delete_req, &ctx).await.unwrap_err();
        assert_eq!(delete_err.status_code(), 404);
    }

    #[tokio::test]
    async fn test_list_returns_only_user_keys() {
        let plugin = ApiKeyPlugin::new();
        let (ctx, user1, session1) = create_test_context_with_user().await;
        let (_user2, session2) = create_user_with_session(&ctx, "other@example.com").await;

        let _ = create_key_and_get_id(&plugin, &ctx, &session1.token, "u1-key").await;
        let _ = create_key_and_get_id(&plugin, &ctx, &session2.token, "u2-key").await;

        let list_req = create_auth_request(
            HttpMethod::Get,
            "/api-key/list",
            Some(&session1.token),
            None,
            None,
        );
        let list_response = plugin.handle_list(&list_req, &ctx).await.unwrap();
        assert_eq!(list_response.status, 200);

        let list_body = json_body(&list_response);
        let list = list_body.as_array().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["userId"].as_str().unwrap(), user1.id);
        assert!(list[0].get("key").is_none());
        assert!(list[0].get("key_hash").is_none());
    }

    #[tokio::test]
    async fn test_owner_can_delete_key() {
        let plugin = ApiKeyPlugin::new();
        let (ctx, _user, session) = create_test_context_with_user().await;
        let key_id = create_key_and_get_id(&plugin, &ctx, &session.token, "to-delete").await;

        let delete_req = create_auth_request(
            HttpMethod::Post,
            "/api-key/delete",
            Some(&session.token),
            Some(serde_json::json!({ "id": key_id })),
            None,
        );
        let delete_response = plugin.handle_delete(&delete_req, &ctx).await.unwrap();
        assert_eq!(delete_response.status, 200);

        let deleted = ctx.database.get_api_key_by_id(&key_id).await.unwrap();
        assert!(deleted.is_none());
    }
}
