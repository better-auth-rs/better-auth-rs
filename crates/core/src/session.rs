use chrono::Utc;
use std::sync::Arc;

use crate::config::AuthConfig;
use crate::entity::{AuthSession, AuthUser};
use crate::error::AuthResult;
use crate::schema::AuthSchema;
use crate::store::{AuthStore, JoinValue};
use crate::types::CreateSession;
use crate::utils::cookie_utils::{
    get_cookie, related_cookie_name, session_cookie_headers, verify_cookie_value,
};
use crate::wire::{SessionView, UserView};
use crate::{AuthError, AuthRequest, HttpMethod};
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod cache_tests;
mod cookie_cache;
mod native;
mod response;
mod signer;
pub use native::NativeSessionData;
pub use signer::{SessionCookieContext, SessionCookieSigner};
#[cfg(test)]
mod response_tests;
mod view;

/// A session and its selected User value, independent of the application's storage models.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData<U = UserView> {
    /// Session visible to the caller.
    pub session: SessionView,
    /// User visible to the caller.
    pub user: U,
}

/// Session read result, including the deferred-refresh signal.
pub struct SessionResolution<T = SessionData> {
    /// Authenticated session, when a valid credential was supplied.
    pub data: Option<T>,
    /// Whether a deferred GET requires a subsequent POST refresh.
    pub needs_refresh: Option<bool>,
}

/// Select whether an authentication check may use a cookie cache.
#[derive(Clone, Copy)]
pub enum SessionRead {
    /// Allow a valid signed cookie cache.
    Cached,
    /// Read the session from the server store, for sensitive operations.
    Authoritative,
}

/// Session manager handles session creation, validation, and cleanup
pub struct SessionManager<S: AuthSchema> {
    capabilities: crate::store::StoreCapabilities,
    user_metadata: crate::plugin::MetadataMap,
    adapter_user_fields: crate::user_fields::UserConfig,
    config: Arc<AuthConfig>,
    database: Arc<dyn AuthStore<S>>,
    signer: Option<Arc<dyn SessionCookieSigner<S>>>,
}

impl<S: AuthSchema> Clone for SessionManager<S> {
    fn clone(&self) -> Self {
        Self {
            capabilities: self.capabilities,
            user_metadata: self.user_metadata.clone(),
            adapter_user_fields: self.adapter_user_fields.clone(),
            config: self.config.clone(),
            database: self.database.clone(),
            signer: self.signer.clone(),
        }
    }
}

impl<S: AuthSchema> SessionManager<S> {
    pub fn new(config: Arc<AuthConfig>, database: Arc<dyn AuthStore<S>>) -> Self {
        Self {
            capabilities: Default::default(),
            adapter_user_fields: config.user.clone(),
            config,
            database,
            user_metadata: Default::default(),
            signer: None,
        }
    }

    /// Select adapter transforms separately from public field visibility.
    pub fn with_adapter_user_fields(mut self, fields: crate::user_fields::UserConfig) -> Self {
        self.adapter_user_fields = fields;
        self
    }

    /// Attach enabled user plugin schemas for database and cache projections.
    pub fn with_user_metadata(mut self, metadata: crate::plugin::MetadataMap) -> Self {
        self.user_metadata = metadata;
        self
    }

    pub(crate) fn with_store_capabilities(
        mut self,
        capabilities: crate::store::StoreCapabilities,
    ) -> Self {
        self.capabilities = capabilities;
        self
    }

    async fn user_view(&self, user: &impl AuthUser) -> AuthResult<UserView> {
        UserView::with_field_policies(
            user,
            &self.adapter_user_fields,
            &self.config.user,
            &self.user_metadata,
            self.database.supports_native_json(),
        )
        .await
    }

    pub async fn session_view(&self, session: &impl AuthSession) -> AuthResult<SessionView> {
        let mut view = self.internal_session_view(session).await?;
        view.filter_returned_fields(&self.config.session);
        Ok(view)
    }

    /// Include hidden session fields for trusted callbacks before public output filtering.
    pub async fn internal_session_view(
        &self,
        session: &impl AuthSession,
    ) -> AuthResult<SessionView> {
        let mut view = SessionView::with_internal_fields_for_adapter(
            session,
            &self.config.session,
            self.database.supports_native_json(),
        )
        .await?;
        view.visible_fields = Some(
            SessionView::active_plugin_fields(&self.user_metadata)
                .filter(|name| {
                    session
                        .field_presence()
                        .is_none_or(|fields| fields.contains(*name))
                })
                .map(str::to_owned)
                .collect(),
        );
        Ok(view)
    }

    async fn internal_user_view(&self, user: &impl AuthUser) -> AuthResult<UserView> {
        UserView::with_internal_fields_for_adapter(
            user,
            &self.adapter_user_fields,
            &self.user_metadata,
            self.database.supports_native_json(),
        )
        .await
    }

    /// Project an adapter result without removing fields available to trusted callbacks.
    pub async fn internal_data(
        &self,
        user: &impl AuthUser,
        session: &impl AuthSession,
    ) -> AuthResult<SessionData> {
        Ok(SessionData {
            user: self.internal_user_view(user).await?,
            session: self.internal_session_view(session).await?,
        })
    }

    /// Publish the issued snapshot for endpoint hooks without writing cookies or storage.
    pub fn publish_session(&self, req: &AuthRequest, data: NativeSessionData) -> AuthResult<()> {
        req.set_new_session(data)
    }

    /// Write session credentials and retain the supplied identity for endpoint after hooks.
    pub async fn set_session_cookie(
        &self,
        req: &AuthRequest,
        data: SessionData,
        dont_remember: Option<bool>,
    ) -> AuthResult<()> {
        self.set_native_session_cookie(req, data.into(), dont_remember)
            .await
    }

    /// Write credentials while preserving the native User value for endpoint after hooks.
    pub async fn set_native_session_cookie(
        &self,
        req: &AuthRequest,
        data: NativeSessionData,
        dont_remember: Option<bool>,
    ) -> AuthResult<()> {
        self.issue_session_cookie(req, data, dont_remember, None)
            .await
    }

    /// Issue credentials while keeping signing-key reads and writes in the active transaction.
    pub async fn set_session_cookie_in_transaction(
        &self,
        req: &AuthRequest,
        data: SessionData,
        dont_remember: Option<bool>,
        transaction: &dyn crate::store::AuthTransaction<S>,
    ) -> AuthResult<()> {
        self.issue_session_cookie(req, data.into(), dont_remember, Some(transaction))
            .await
    }

    async fn issue_session_cookie(
        &self,
        req: &AuthRequest,
        data: NativeSessionData,
        dont_remember: Option<bool>,
        transaction: Option<&dyn crate::store::AuthTransaction<S>>,
    ) -> AuthResult<()> {
        let dont_remember = dont_remember.unwrap_or_else(|| self.dont_remember(req));
        for cookie in session_cookie_headers(&data.session.token, dont_remember, &self.config) {
            req.append_response_header("Set-Cookie", cookie?)?;
        }
        self.write_cache_with_response(req, &data, dont_remember, None, transaction)
            .await?;
        req.set_new_session(data)
    }

    fn public_data(
        &self,
        mut data: SessionData<JoinValue<UserView>>,
    ) -> SessionData<JoinValue<UserView>> {
        if let JoinValue::One(Some(user)) = &mut data.user {
            user.filter_cached_fields(&self.config.user);
        }
        data.session.filter_returned_fields(&self.config.session);
        data
    }

    /// Install a plugin-provided signer without coupling core to the plugin implementation.
    pub fn with_cookie_signer(mut self, signer: Option<Arc<dyn SessionCookieSigner<S>>>) -> Self {
        self.signer = signer;
        self
    }

    /// Create a new session for a user
    pub async fn create_session(
        &self,
        user: &impl AuthUser,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> AuthResult<crate::wire::SessionView> {
        self.create_session_for_id(user.id().into_owned(), ip_address, user_agent)
            .await
    }

    /// Preserve the selected runtime User ID, including an omitted ID, during session creation.
    pub async fn create_session_for_id(
        &self,
        user_id: crate::SchemaValue<String>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> AuthResult<SessionView> {
        self.create_session_for_id_with_lifetime(
            user_id,
            ip_address,
            user_agent,
            self.config.session.expires_in(),
        )
        .await
    }

    /// Create a session with a lifetime that overrides the configured default.
    pub async fn create_session_with_lifetime(
        &self,
        user: &impl AuthUser,
        ip_address: Option<String>,
        user_agent: Option<String>,
        expires_in: chrono::Duration,
    ) -> AuthResult<crate::wire::SessionView> {
        self.create_session_for_id_with_lifetime(
            user.id().into_owned(),
            ip_address,
            user_agent,
            expires_in,
        )
        .await
    }

    /// Create a session from a native User ID with an explicit lifetime.
    pub async fn create_session_for_id_with_lifetime(
        &self,
        user_id: crate::SchemaValue<String>,
        ip_address: Option<String>,
        user_agent: Option<String>,
        expires_in: chrono::Duration,
    ) -> AuthResult<SessionView> {
        self.create_session_for_id_with_lifetime_optional(
            user_id, ip_address, user_agent, expires_in,
        )
        .await?
        .ok_or_else(|| AuthError::forbidden("session creation cancelled by database hook"))
    }

    /// Preserve before-hook cancellation for endpoints that return a specific creation error.
    pub async fn create_session_for_id_with_lifetime_optional(
        &self,
        user_id: crate::SchemaValue<String>,
        ip_address: Option<String>,
        user_agent: Option<String>,
        expires_in: chrono::Duration,
    ) -> AuthResult<Option<SessionView>> {
        let expires_at = Utc::now() + expires_in;

        let create_session = CreateSession {
            additional_fields: Default::default(),
            user_id,
            expires_at: expires_at.into(),
            ip_address,
            user_agent,
            impersonated_by: None,
            active_organization_id: None,
        };

        self.database.create_session_optional(create_session).await
    }

    /// Read a session directly from the server store and refresh its expiry.
    pub async fn get_session(&self, token: &str) -> AuthResult<Option<crate::wire::SessionView>> {
        let Some(session) = self.database.get_session(token).await? else {
            return Ok(None);
        };
        if session.expires_at().milliseconds() < Utc::now().timestamp_millis() as f64
            || !session.active()
        {
            self.database.delete_session(token).await?;
            return Ok(None);
        }
        if self.needs_refresh(&session) {
            let new_expires_at = Utc::now() + self.config.session.expires_in();
            return self
                .database
                .update_session_expiry(token, new_expires_at)
                .await
                .map(Some);
        }
        Ok(Some(session))
    }

    fn needs_refresh(&self, session: &impl AuthSession) -> bool {
        !self.config.session.disable_session_refresh()
            && session.expires_at().milliseconds()
                - self.config.session.expires_in().num_milliseconds() as f64
                + self.config.session.update_age().num_milliseconds() as f64
                <= Utc::now().timestamp_millis() as f64
    }

    /// Resolve an HTTP session and queue any cookie updates on the request.
    pub async fn resolve(
        &self,
        req: &AuthRequest,
        read: SessionRead,
    ) -> AuthResult<SessionResolution> {
        let resolved = self.resolve_relations(req, read, true).await?;
        Ok(SessionResolution {
            data: resolved
                .data
                .map(SessionData::into_typed)
                .transpose()?
                .flatten(),
            needs_refresh: resolved.needs_refresh,
        })
    }

    /// Resolve a session while preserving the User value selected by the adapter.
    pub async fn resolve_native(
        &self,
        req: &AuthRequest,
        read: SessionRead,
    ) -> AuthResult<SessionResolution<NativeSessionData>> {
        let resolved = self.resolve_relations(req, read, false).await?;
        Ok(SessionResolution {
            data: resolved.data.map(Into::into),
            needs_refresh: resolved.needs_refresh,
        })
    }

    async fn resolve_relations(
        &self,
        req: &AuthRequest,
        read: SessionRead,
        typed_user: bool,
    ) -> AuthResult<SessionResolution<SessionData<JoinValue<UserView>>>> {
        let raw = if req.path() == "/get-session" {
            req.query.clone()
        } else {
            Some(
                req.query
                    .as_ref()
                    .filter(|value| value.is_object())
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({})),
            )
        };
        let query = crate::query::session_query(raw)?;
        crate::query::with_validated_query(query, self.resolve_inner(req, read, typed_user)).await
    }

    async fn resolve_inner(
        &self,
        req: &AuthRequest,
        read: SessionRead,
        typed_user: bool,
    ) -> AuthResult<SessionResolution<SessionData<JoinValue<UserView>>>> {
        let none = || SessionResolution {
            data: None,
            needs_refresh: None,
        };
        if let Some(session) = req.virtual_session() {
            let Some(user_id) = session.user_id.as_str() else {
                return Ok(none());
            };
            let user = self
                .database
                .get_user_by_id(user_id)
                .await?
                .ok_or(AuthError::UserNotFound)?;
            let data = SessionData {
                session: session.clone(),
                user: self.user_view(&user).await?,
            };
            req.set_session_snapshot(Some(data.clone().into()))?;
            return Ok(SessionResolution {
                data: Some(data.into()),
                needs_refresh: None,
            });
        }
        let cache = self
            .config
            .session
            .cookie_cache
            .as_ref()
            .filter(|cache| cache.enabled());
        let token = self.extract_session_token(req);
        if token.is_none() && cache.is_some() {
            return Ok(none());
        }
        let cache_value =
            cookie_cache::read(req, &related_cookie_name(&self.config, "session_data"));
        if cache.is_none() && cache_value.is_some() {
            cookie_cache::clear_existing(req, &self.config)?;
        }
        let Some(token) = token else {
            return Ok(none());
        };
        let disable_cache = (matches!(read, SessionRead::Authoritative)
            && self.capabilities.server_sessions())
            || query_flag(req, "disableCookieCache")?;
        if !disable_cache && let (Some(cache), Some(value)) = (cache, cache_value.as_deref()) {
            let decoded = if let Some(signer) = &self.signer {
                signer
                    .verify(
                        value,
                        SessionCookieContext {
                            request: req,
                            config: &self.config,
                            transaction: None,
                        },
                    )
                    .await?
                    .and_then(cookie_cache::parse_jwt)
            } else {
                cookie_cache::decode(value, &self.config, cache)
            };
            if let Some((mut payload, expires)) = decoded
                && payload.data.session.token == token
                && (if payload.version.is_empty() {
                    "1"
                } else {
                    &payload.version
                }) == cache.version.resolve(&payload.data.clone().into()).await?
                && expires >= Utc::now().timestamp_millis()
                && payload.data.session.expires_at.milliseconds()
                    >= Utc::now().timestamp_millis() as f64
            {
                if !self.capabilities.server_sessions()
                    && let Some(update_age) = cache.refresh_age()
                    && expires - Utc::now().timestamp_millis() < update_age.num_milliseconds()
                {
                    self.write_cache(req, &payload.data, false).await?;
                    let max_age = (!self.dont_remember(req))
                        .then_some(self.config.session.expires_in().as_seconds_f64());
                    req.append_response_header(
                        "Set-Cookie",
                        crate::utils::cookie_utils::create_session_cookie_with_max_age(
                            Some(&payload.data.session.token),
                            max_age,
                            &self.config,
                        )?,
                    )?;
                }
                let raw_snapshot =
                    self.capabilities.server_sessions() || cache.refresh_age().is_none();
                if raw_snapshot {
                    req.set_session_snapshot(Some(payload.data.clone().into()))?;
                }
                payload.data.user.filter_cached_fields(&self.config.user);
                payload
                    .data
                    .session
                    .filter_returned_fields(&self.config.session);
                if !raw_snapshot {
                    req.set_session_snapshot(Some(payload.data.clone().into()))?;
                }
                return Ok(SessionResolution {
                    data: Some(payload.data.into()),
                    needs_refresh: None,
                });
            }
            cookie_cache::expire(req, &self.config)?;
        }
        let is_post = req.path().ends_with("/get-session") && req.method() == &HttpMethod::Post;
        let stored = self.database.get_session_snapshot(&token).await?;
        let Some((session, cached_data)) = stored else {
            req.set_session_snapshot(None)?;
            self.clear_cookies(req)?;
            return Ok(none());
        };
        let mut data = if let Some(mut data) = cached_data {
            match &mut data.user {
                JoinValue::One(Some(user)) => *user = self.user_view(user).await?,
                JoinValue::One(None) => {
                    req.set_session_snapshot(None)?;
                    self.clear_cookies(req)?;
                    return Ok(none());
                }
                JoinValue::Many(_) if typed_user => return Err(relationship_array_error()),
                JoinValue::Many(_) => {}
            }
            data.session.filter_returned_fields(&self.config.session);
            data
        } else {
            let Some(user_id) = session.user_id.as_str() else {
                return Ok(none());
            };
            let Some(user) = self.database.get_user_by_id(user_id).await? else {
                req.set_session_snapshot(None)?;
                self.clear_cookies(req)?;
                return Ok(none());
            };
            SessionData {
                session: self.session_view(&session).await?,
                user: JoinValue::One(Some(self.user_view(&user).await?)),
            }
        };
        req.set_session_snapshot(Some(data.clone()))?;
        if session.expires_at().milliseconds() < Utc::now().timestamp_millis() as f64
            || !session.active()
        {
            self.clear_cookies(req)?;
            if !self.config.session.defer_session_refresh || is_post {
                self.database.delete_session(&token).await?;
            }
            return Ok(none());
        }
        let dont_remember = self.dont_remember(req);
        if dont_remember || query_flag(req, "disableRefresh")? {
            return Ok(SessionResolution {
                data: Some(self.public_data(data)),
                needs_refresh: None,
            });
        }
        let needs_refresh = self.needs_refresh(&session);
        if self.config.session.defer_session_refresh && !is_post {
            self.write_cache_with_response(req, &data.clone().into(), false, None, None)
                .await?;
            return Ok(SessionResolution {
                data: Some(self.public_data(data)),
                needs_refresh: Some(needs_refresh),
            });
        }
        if needs_refresh {
            let updated = match self
                .database
                .update_session_expiry(&token, Utc::now() + self.config.session.expires_in())
                .await
            {
                Err(AuthError::SessionNotFound) => {
                    self.clear_cookies(req)?;
                    return Err(failed_session_update());
                }
                result => result?,
            };
            data.session = self.internal_session_view(&updated).await?;
            self.set_native_session_cookie(req, data.clone().into(), Some(false))
                .await?;
        } else {
            self.write_cache_with_response(req, &data.clone().into(), false, None, None)
                .await?;
        }
        Ok(SessionResolution {
            data: Some(self.public_data(data)),
            needs_refresh: None,
        })
    }

    /// Write the configured cache from authenticated session data.
    pub async fn write_cache(
        &self,
        req: &AuthRequest,
        data: &SessionData,
        dont_remember: bool,
    ) -> AuthResult<()> {
        self.write_cache_with_response(req, &data.clone().into(), dont_remember, None, None)
            .await
    }

    async fn write_cache_with_response(
        &self,
        req: &AuthRequest,
        data: &NativeSessionData,
        dont_remember: bool,
        response_headers: Option<&crate::Headers>,
        transaction: Option<&dyn crate::store::AuthTransaction<S>>,
    ) -> AuthResult<()> {
        let signed = if let (Some(signer), Some(cache)) = (
            &self.signer,
            self.config
                .session
                .cookie_cache
                .as_ref()
                .filter(|cache| cache.enabled()),
        ) {
            let (payload, max_age) =
                cookie_cache::payload(data, &self.config, cache, dont_remember).await?;
            Some(
                signer
                    .sign(
                        payload,
                        max_age,
                        SessionCookieContext {
                            request: req,
                            config: &self.config,
                            transaction,
                        },
                    )
                    .await?,
            )
        } else {
            None
        };
        cookie_cache::write(
            req,
            data,
            &self.config,
            dont_remember,
            signed,
            self.capabilities.database,
            response_headers,
        )
        .await
    }

    /// Read the signed marker for a browser-session-only login.
    pub fn dont_remember(&self, req: &AuthRequest) -> bool {
        get_cookie(req, &related_cookie_name(&self.config, "dont_remember"))
            .and_then(|value| verify_cookie_value(&value, self.config.signing_secret()))
            .is_some()
    }

    /// Expire session credentials and every cache chunk received on the request.
    pub fn clear_cookies(&self, req: &AuthRequest) -> AuthResult<()> {
        crate::utils::cookie_utils::delete_session_cookies(req, &self.config, false, None)
    }

    /// Delete a session
    pub async fn delete_session(&self, token: &str) -> AuthResult<()> {
        self.database.delete_session(token).await?;
        Ok(())
    }

    /// Delete all sessions for a user
    pub async fn delete_user_sessions(&self, user_id: impl AsRef<str>) -> AuthResult<()> {
        self.database.delete_user_sessions(user_id.as_ref()).await?;
        Ok(())
    }

    /// Get all active sessions for a user
    pub async fn list_user_sessions(
        &self,
        user_id: impl AsRef<str>,
    ) -> AuthResult<Vec<crate::wire::SessionView>> {
        let sessions = self.database.get_user_sessions(user_id.as_ref()).await?;
        let now = Utc::now();

        // Filter out expired sessions
        let active_sessions = sessions
            .into_iter()
            .filter(|session| {
                session.expires_at().milliseconds() > now.timestamp_millis() as f64
                    && session.active()
            })
            .collect();

        Ok(active_sessions)
    }

    /// Project active sessions while preserving cached undefined application fields.
    pub async fn list_user_session_views(
        &self,
        user_id: impl AsRef<str>,
    ) -> AuthResult<Vec<SessionView>> {
        let snapshots = self
            .database
            .get_user_session_snapshots(user_id.as_ref())
            .await?;
        let mut views = Vec::new();
        for (session, cached) in snapshots.into_iter().filter(|(session, _)| {
            session.expires_at().milliseconds() > Utc::now().timestamp_millis() as f64
                && session.active()
        }) {
            let view = if let Some(mut view) = cached {
                view.filter_returned_fields(&self.config.session);
                view
            } else {
                SessionView::with_fields_for_adapter(
                    &session,
                    &self.config.session,
                    self.database.supports_native_json(),
                )
                .await?
            };
            views.push(view);
        }
        Ok(views)
    }

    /// Revoke a specific session by token
    pub async fn revoke_session(&self, token: &str) -> AuthResult<bool> {
        // Check if session exists before trying to delete
        let session_exists = self.get_session(token).await?.is_some();

        if session_exists {
            self.delete_session(token).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Revoke all sessions for a user
    pub async fn revoke_all_user_sessions(&self, user_id: impl AsRef<str>) -> AuthResult<usize> {
        // Get count of sessions before deletion for return value
        let user_id = user_id.as_ref();
        let sessions = self.list_user_sessions(user_id).await?;
        let count = sessions.len();

        self.delete_user_sessions(user_id).await?;
        Ok(count)
    }

    /// Revoke all sessions for a user except the current one
    pub async fn revoke_other_user_sessions(
        &self,
        user_id: impl AsRef<str>,
        current_token: &str,
    ) -> AuthResult<usize> {
        let sessions = self.list_user_sessions(user_id).await?;
        let mut count = 0;

        for session in sessions {
            if session.token() != current_token {
                self.delete_session(session.token()).await?;
                count += 1;
            }
        }

        Ok(count)
    }

    /// Cleanup expired sessions
    pub async fn cleanup_expired_sessions(&self) -> AuthResult<usize> {
        let count = self.database.delete_expired_sessions().await?;
        Ok(count)
    }

    /// Check whether a session is "fresh" (created recently enough for
    /// sensitive operations like password change or account deletion).
    ///
    /// Returns `true` when `fresh_age` is set and
    /// `session.created_at() + fresh_age > now`.
    /// If `fresh_age` is `None`, the session is never considered fresh.
    pub fn is_session_fresh(&self, session: &impl AuthSession) -> bool {
        match self.config.session.fresh_age {
            Some(fresh_age) => {
                session.created_at().milliseconds() + fresh_age.num_milliseconds() as f64
                    > Utc::now().timestamp_millis() as f64
            }
            None => false,
        }
    }

    /// Validate session token format
    pub fn validate_token_format(&self, token: &str) -> bool {
        token.starts_with("session_") && token.len() > 40
    }

    /// Extract and verify a session cookie or an explicitly enabled Bearer token.
    pub fn extract_session_token(&self, req: &AuthRequest) -> Option<String> {
        if let Some(bearer) = &self.config.session.bearer
            && let Some(header) = req.headers.get("authorization")
            && header
                .get(..7)
                .is_some_and(|scheme| scheme.eq_ignore_ascii_case("bearer "))
        {
            let token = header.get(7..)?.trim();
            if !token.is_empty() {
                if token.contains('.') {
                    if let Some(value) = verify_cookie_value(token, self.config.signing_secret()) {
                        return Some(value);
                    }
                } else if !bearer.require_signature {
                    return Some(token.to_string());
                }
            }
        }
        get_cookie(
            req,
            &self
                .config
                .auth_cookie("session_token", Default::default())
                .name,
        )
        .and_then(|value| verify_cookie_value(&value, self.config.signing_secret()))
    }
}

fn query_flag(req: &AuthRequest, name: &str) -> AuthResult<bool> {
    req.query
        .as_ref()
        .and_then(|query| query.get(name))
        .map(|value| crate::FieldValue::from_json(value.clone()).map(|value| value.is_truthy()))
        .transpose()
        .map(|value| value.unwrap_or(false))
}

fn relationship_array_error() -> AuthError {
    AuthError::internal("A User relationship array cannot authenticate a typed User")
}

fn failed_session_update() -> AuthError {
    AuthError::Upstream {
        status: 401,
        code: "FAILED_TO_GET_SESSION",
        message: "Failed to get session",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::AuthSession;
    use crate::test_store::{BundledSchema, test_config, test_database};
    use crate::types::AuthRequest;
    use crate::types::HttpMethod;
    use crate::utils::cookie_utils::sign_cookie_value;
    use crate::wire::SessionView;
    use chrono::Duration;

    fn test_manager() -> SessionManager<BundledSchema> {
        let runtime = tokio::runtime::Runtime::new().expect("runtime should build");
        SessionManager::new(test_config(), runtime.block_on(test_database()))
    }

    // ── validate_token_format ───────────────────────────────────────────

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[test]
    fn valid_token_format() {
        let mgr = test_manager();
        let token = "session_abcdefghijklmnopqrstuvwxyz1234567890";
        assert!(mgr.validate_token_format(token));
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[test]
    fn invalid_token_no_prefix() {
        let mgr = test_manager();
        assert!(!mgr.validate_token_format("abcdefghijklmnopqrstuvwxyz1234567890"));
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[test]
    fn invalid_token_too_short() {
        let mgr = test_manager();
        assert!(!mgr.validate_token_format("session_short"));
    }

    // ── extract_session_token ───────────────────────────────────────────

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[test]
    fn extract_from_bearer() {
        let mgr = test_manager();
        let mut req = AuthRequest::new(HttpMethod::Get, "/test");
        let _ = req
            .headers
            .insert("authorization".into(), "Bearer my-token".into());
        assert_eq!(mgr.extract_session_token(&req), Some("my-token".into()));
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[test]
    fn extract_from_cookie() {
        let mgr = test_manager();
        let mut req = AuthRequest::new(HttpMethod::Get, "/test");
        let _ = req.headers.insert(
            "cookie".into(),
            format!(
                "better-auth.session_token={}; other=val",
                sign_cookie_value("tok123", &mgr.config.secret)
            ),
        );
        assert_eq!(mgr.extract_session_token(&req), Some("tok123".into()));
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[test]
    fn extract_bearer_takes_precedence_over_cookie() {
        let mgr = test_manager();
        let mut req = AuthRequest::new(HttpMethod::Get, "/test");
        let _ = req
            .headers
            .insert("authorization".into(), "Bearer bearer-tok".into());
        let _ = req.headers.insert(
            "cookie".into(),
            format!(
                "better-auth.session_token={}",
                sign_cookie_value("cookie-tok", &mgr.config.secret)
            ),
        );
        assert_eq!(mgr.extract_session_token(&req), Some("bearer-tok".into()));
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[test]
    fn extract_returns_none_without_auth() {
        let mgr = test_manager();
        let req = AuthRequest::new(HttpMethod::Get, "/test");
        assert_eq!(mgr.extract_session_token(&req), None);
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[test]
    fn extract_skips_empty_cookie_value() {
        let mgr = test_manager();
        let mut req = AuthRequest::new(HttpMethod::Get, "/test");
        let _ = req
            .headers
            .insert("cookie".into(), "better-auth.session_token=".into());
        assert_eq!(mgr.extract_session_token(&req), None);
    }

    // ── is_session_fresh ────────────────────────────────────────────────

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[test]
    fn session_fresh_when_within_window() {
        let mut config = AuthConfig::new("test-secret-min-32-chars-1234567");
        config.session.fresh_age = Some(Duration::minutes(10));
        let runtime = tokio::runtime::Runtime::new().expect("runtime should build");
        let mgr = SessionManager::new(Arc::new(config), runtime.block_on(test_database()));

        // A session created "now" is fresh within a 10-minute window.
        let session = SessionView {
            visible_fields: None,
            id: "s1".into(),
            expires_at: (Utc::now() + Duration::hours(1)).into(),
            token: "tok".into(),
            created_at: Utc::now().into(),
            updated_at: Utc::now().into(),
            ip_address: None,
            user_agent: None,
            user_id: "u1".into(),
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
            active: true,
            additional_fields: Default::default(),
        };
        assert!(mgr.is_session_fresh(&session));
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[test]
    fn session_not_fresh_when_old() {
        let mut config = AuthConfig::new("test-secret-min-32-chars-1234567");
        config.session.fresh_age = Some(Duration::minutes(10));
        let runtime = tokio::runtime::Runtime::new().expect("runtime should build");
        let mgr = SessionManager::new(Arc::new(config), runtime.block_on(test_database()));

        let session = SessionView {
            visible_fields: None,
            id: "s1".into(),
            expires_at: (Utc::now() + Duration::hours(1)).into(),
            token: "tok".into(),
            created_at: (Utc::now() - Duration::minutes(20)).into(),
            updated_at: Utc::now().into(),
            ip_address: None,
            user_agent: None,
            user_id: "u1".into(),
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
            active: true,
            additional_fields: Default::default(),
        };
        assert!(!mgr.is_session_fresh(&session));
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[test]
    fn session_never_fresh_when_no_fresh_age() {
        let mgr = test_manager(); // default: fresh_age = None
        let session = SessionView {
            visible_fields: None,
            id: "s1".into(),
            expires_at: (Utc::now() + Duration::hours(1)).into(),
            token: "tok".into(),
            created_at: Utc::now().into(),
            updated_at: Utc::now().into(),
            ip_address: None,
            user_agent: None,
            user_id: "u1".into(),
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
            active: true,
            additional_fields: Default::default(),
        };
        assert!(!mgr.is_session_fresh(&session));
    }

    // ── async operations ────────────────────────────────────────────────

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[tokio::test]
    async fn create_and_get_session() {
        let db = test_database().await;
        let mgr = SessionManager::new(test_config(), db.clone());

        // Create a user first
        let user = db
            .create_user(crate::types::CreateUser::new().with_email("test@test.com"))
            .await
            .unwrap();

        let session = mgr.create_session(&user, None, None).await.unwrap();
        let token = session.token().to_string();

        let retrieved = mgr.get_session(&token).await.unwrap();
        assert!(retrieved.is_some());
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[tokio::test]
    async fn refresh_returns_the_persisted_expiry() {
        let db = test_database().await;
        let mut config = AuthConfig::new("test-secret-min-32-chars-1234567");
        // Refresh on every access so a single `get_session` exercises the path.
        config.session.update_age = Some(Duration::zero());
        let mgr = SessionManager::new(Arc::new(config), db.clone());

        let user = db
            .create_user(crate::types::CreateUser::new().with_email("refresh@test.com"))
            .await
            .unwrap();
        let session = mgr.create_session(&user, None, None).await.unwrap();
        let token = session.token().to_string();

        // Move the stored expiry back so the refresh is observable.
        let stale = session.expires_at().to_datetime().unwrap().unwrap() - Duration::minutes(30);
        let _ = db.update_session_expiry(&token, stale).await.unwrap();

        let returned = mgr
            .get_session(&token)
            .await
            .unwrap()
            .expect("session should still be live");
        let stored = db
            .get_session(&token)
            .await
            .unwrap()
            .expect("session should still be stored");

        assert!(
            returned.expires_at().milliseconds() > stale.timestamp_millis() as f64,
            "refresh should have extended the expiry"
        );
        assert_eq!(
            returned.expires_at(),
            stored.expires_at(),
            "returned session must reflect the persisted expiry, not the pre-refresh value"
        );
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[tokio::test]
    async fn create_session_without_metadata_uses_empty_strings() {
        let db = test_database().await;
        let mgr = SessionManager::new(test_config(), db.clone());

        let user = db
            .create_user(crate::types::CreateUser::new().with_email("test@test.com"))
            .await
            .unwrap();

        let session = mgr.create_session(&user, None, None).await.unwrap();
        assert_eq!(session.ip_address.as_deref(), Some(""));
        assert_eq!(session.user_agent.as_deref(), Some(""));
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[tokio::test]
    async fn delete_session_removes_it() {
        let db = test_database().await;
        let mgr = SessionManager::new(test_config(), db.clone());

        let user = db
            .create_user(crate::types::CreateUser::new().with_email("test@test.com"))
            .await
            .unwrap();

        let session = mgr.create_session(&user, None, None).await.unwrap();
        let token = session.token().to_string();

        mgr.delete_session(&token).await.unwrap();
        let retrieved = mgr.get_session(&token).await.unwrap();
        assert!(retrieved.is_none());
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[tokio::test]
    async fn revoke_session_returns_true_when_found() {
        let db = test_database().await;
        let mgr = SessionManager::new(test_config(), db.clone());

        let user = db
            .create_user(crate::types::CreateUser::new().with_email("test@test.com"))
            .await
            .unwrap();

        let session = mgr.create_session(&user, None, None).await.unwrap();
        let result = mgr.revoke_session(session.token()).await.unwrap();
        assert!(result);
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[tokio::test]
    async fn revoke_session_returns_false_when_not_found() {
        let mgr = SessionManager::new(test_config(), test_database().await);
        let result = mgr.revoke_session("nonexistent-token").await.unwrap();
        assert!(!result);
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[tokio::test]
    async fn list_user_sessions_excludes_expired() {
        let db = test_database().await;
        let mgr = SessionManager::new(test_config(), db.clone());

        let user = db
            .create_user(crate::types::CreateUser::new().with_email("test@test.com"))
            .await
            .unwrap();

        // Create two sessions
        let _ = mgr.create_session(&user, None, None).await.unwrap();
        let _ = mgr.create_session(&user, None, None).await.unwrap();

        let sessions = mgr
            .list_user_sessions(user.id().typed().unwrap())
            .await
            .unwrap();
        assert_eq!(sessions.len(), 2);
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[tokio::test]
    async fn revoke_all_user_sessions() {
        let db = test_database().await;
        let mgr = SessionManager::new(test_config(), db.clone());

        let user = db
            .create_user(crate::types::CreateUser::new().with_email("test@test.com"))
            .await
            .unwrap();

        let _ = mgr.create_session(&user, None, None).await.unwrap();
        let _ = mgr.create_session(&user, None, None).await.unwrap();

        let count = mgr
            .revoke_all_user_sessions(user.id().typed().unwrap())
            .await
            .unwrap();
        assert_eq!(count, 2);

        let sessions = mgr
            .list_user_sessions(user.id().typed().unwrap())
            .await
            .unwrap();
        assert!(sessions.is_empty());
    }

    // Rust-specific surface: `SessionManager` and its token/session helper APIs are public Rust APIs with no direct TS analogue.
    #[tokio::test]
    async fn revoke_other_sessions_keeps_current() {
        let db = test_database().await;
        let mgr = SessionManager::new(test_config(), db.clone());

        let user = db
            .create_user(crate::types::CreateUser::new().with_email("test@test.com"))
            .await
            .unwrap();

        let current = mgr.create_session(&user, None, None).await.unwrap();
        let _ = mgr.create_session(&user, None, None).await.unwrap();
        let _ = mgr.create_session(&user, None, None).await.unwrap();

        let count = mgr
            .revoke_other_user_sessions(user.id().typed().unwrap(), current.token())
            .await
            .unwrap();
        assert_eq!(count, 2);

        let remaining = mgr
            .list_user_sessions(user.id().typed().unwrap())
            .await
            .unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].token(), current.token());
    }
}
