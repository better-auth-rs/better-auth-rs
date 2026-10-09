use super::SessionData;
use crate::{
    AuthError, AuthResult, FieldMap, FieldValue, StructuredCloneContext,
    store::JoinValue,
    user_fields::UserConfig,
    wire::{SessionView, UserView},
};

/// Session data before the selected User value crosses a typed authentication boundary.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct NativeSessionData {
    /// Session passed to the credential writer.
    pub session: SessionView,
    /// Preserve the selected User object or relationship array for trusted callbacks.
    #[serde(
        default,
        deserialize_with = "crate::field_value::serde::value::deserialize"
    )]
    pub user: FieldValue,
}

/// Retain relationship cardinality after public projection changes an array into an object.
#[derive(Debug, Clone)]
pub(crate) struct SessionSnapshot {
    pub(crate) data: NativeSessionData,
    relationship_array: bool,
}

impl SessionSnapshot {
    pub(crate) fn into_typed(self) -> AuthResult<Option<SessionData>> {
        if self.relationship_array {
            return Err(super::relationship_array_error());
        }
        match self.data.user {
            FieldValue::Null => Ok(None),
            FieldValue::Object(fields) => Ok(Some(SessionData {
                session: self.data.session,
                user: UserView::try_from(fields.snapshot_fields()?)?,
            })),
            _ => Err(AuthError::internal("Session User must be an object")),
        }
    }
}

impl From<SessionData> for SessionSnapshot {
    fn from(data: SessionData) -> Self {
        Self {
            data: data.into(),
            relationship_array: false,
        }
    }
}

impl From<NativeSessionData> for SessionSnapshot {
    fn from(data: NativeSessionData) -> Self {
        let relationship_array = matches!(&data.user, FieldValue::Array(_));
        Self {
            data,
            relationship_array,
        }
    }
}

impl From<SessionData<JoinValue<UserView>>> for SessionSnapshot {
    fn from(data: SessionData<JoinValue<UserView>>) -> Self {
        let relationship_array = matches!(&data.user, JoinValue::Many(_));
        Self {
            data: data.into(),
            relationship_array,
        }
    }
}

impl NativeSessionData {
    /// Read a User model field. Relationship arrays have no User model fields.
    pub fn user_field(&self, name: &str) -> AuthResult<FieldValue> {
        Ok(self
            .user
            .as_object()
            .map(|fields| fields.get(name))
            .transpose()?
            .flatten()
            .unwrap_or_default())
    }

    /// Read a User property at a required property-access boundary.
    /// Non-null primitives have no User fields; null and undefined reject property access.
    pub fn user_property(&self, name: &str) -> AuthResult<FieldValue> {
        self.user.model_property(name)
    }

    /// Read an object through native User slots without requiring a typed User identity.
    /// Preserve numeric keys, absent fields, explicit null, and callback replacement values.
    pub fn user_view(&self) -> AuthResult<UserView> {
        let fields = self
            .user
            .as_object()
            .ok_or_else(|| AuthError::internal("Session User must be an object"))?;
        UserView::try_from(fields.snapshot_fields()?)
    }

    /// Consume public object fields without rejecting the selected relationship cardinality.
    /// Use the session manager's typed resolution when the caller requires one User.
    pub fn into_views(self) -> AuthResult<(UserView, SessionView)> {
        let user = self.user_view()?;
        Ok((user, self.session))
    }

    /// Clone enumerable User fields and remove fields with `returned: false`.
    /// Arrays become numeric-key objects only at this output boundary.
    pub fn public_user(&self, config: &UserConfig) -> AuthResult<FieldValue> {
        if !self.user.is_truthy() {
            return Ok(self.user.clone());
        }
        let value = StructuredCloneContext::new().clone_value(&self.user)?;
        let mut fields = value.enumerable_fields()?;
        fields.retain(|name, _| {
            config
                .fields()
                .get(name)
                .is_none_or(|field| field.returned())
        });
        Ok(fields.into())
    }
}

impl crate::FromFieldMap for NativeSessionData {
    fn from_field_values(mut fields: FieldMap) -> AuthResult<Self> {
        let session = fields.shift_remove("session").unwrap_or_default();
        let session = session.as_object().ok_or_else(|| {
            AuthError::internal("Session response must contain a `session` object")
        })?;
        Ok(Self {
            session: <SessionView as crate::FromFieldMap>::from_field_values(
                session.snapshot_fields()?,
            )?,
            user: fields.shift_remove("user").unwrap_or_default(),
        })
    }
}

impl From<(UserView, SessionView)> for NativeSessionData {
    fn from((user, session): (UserView, SessionView)) -> Self {
        SessionData { session, user }.into()
    }
}

impl From<SessionData> for NativeSessionData {
    fn from(data: SessionData) -> Self {
        Self {
            session: data.session,
            user: FieldMap::from(data.user).into(),
        }
    }
}

impl From<SessionData> for SessionData<JoinValue<UserView>> {
    fn from(data: SessionData) -> Self {
        Self {
            session: data.session,
            user: JoinValue::One(Some(data.user)),
        }
    }
}

impl SessionData<JoinValue<UserView>> {
    /// A typed authentication caller requires one User; a relationship page has no User identity.
    pub fn into_typed(self) -> AuthResult<Option<SessionData>> {
        match self.user {
            JoinValue::One(user) => Ok(user.map(|user| SessionData {
                session: self.session,
                user,
            })),
            JoinValue::Many(_) => Err(super::relationship_array_error()),
        }
    }
}

impl From<SessionData<JoinValue<UserView>>> for NativeSessionData {
    fn from(data: SessionData<JoinValue<UserView>>) -> Self {
        Self {
            session: data.session,
            user: match data.user {
                JoinValue::One(Some(user)) => FieldMap::from(user).into(),
                JoinValue::One(None) => FieldValue::Null,
                JoinValue::Many(users) => users
                    .into_iter()
                    .map(|user| FieldValue::from(FieldMap::from(user)))
                    .collect::<Vec<_>>()
                    .into(),
            },
        }
    }
}

impl From<NativeSessionData> for FieldMap {
    fn from(data: NativeSessionData) -> Self {
        Self::from([
            ("session".into(), Self::from(data.session).into()),
            ("user".into(), data.user),
        ])
    }
}

impl serde::Serialize for NativeSessionData {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        crate::field_value::serde::map::serialize(&FieldMap::from(self.clone()), serializer)
    }
}

#[cfg(test)]
mod function_tests;
#[cfg(test)]
mod value_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuthConfig, AuthRequest, CreateSession, CreateUser, FieldDate, FromFieldMap, HttpMethod,
        config::{CookieCacheConfig, CookieCacheVersion},
        session::{SessionManager, SessionRead, cookie_cache},
        store::{EphemeralStore, StatelessSchema},
        user_fields::{UserFieldConfig, UserFieldReference},
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    fn session() -> AuthResult<SessionView> {
        let now = FieldDate::from_milliseconds(1_000.0);
        SessionView::from_field_values(FieldMap::from([
            ("id".into(), "session".into()),
            ("token".into(), "session-token".into()),
            ("expiresAt".into(), now.clone().into()),
            ("createdAt".into(), now.clone().into()),
            ("updatedAt".into(), now.into()),
        ]))
    }

    #[tokio::test]
    async fn hidden_native_session_fields_control_expiry_and_revocation() -> AuthResult<()> {
        for hidden in ["expiresAt", "token"] {
            let mut config = AuthConfig::new("hidden-session-field-secret-at-least-32-characters");
            let _ = config.session.fields_mut().insert(
                hidden.into(),
                UserFieldConfig {
                    returned: Some(false),
                    ..Default::default()
                },
            );
            let config = Arc::new(config);
            let manager = SessionManager::<StatelessSchema>::new(
                config.clone(),
                Arc::new(EphemeralStore::new(config.clone())),
            );
            let user = manager
                .database
                .create_user(CreateUser::new().with_email("hidden-session@example.test"))
                .await?;
            let session = manager
                .database
                .create_session(CreateSession {
                    inherited_fields: Default::default(),
                    user_id: user.id.clone(),
                    expires_at: (chrono::Utc::now() - chrono::Duration::hours(1)).into(),
                    additional_fields: Default::default(),
                    ip_address: None,
                    user_agent: None,
                    impersonated_by: None,
                    active_organization_id: None,
                })
                .await?;
            let token = session.token.typed()?.clone();
            let mut request = AuthRequest::new(HttpMethod::Get, "/get-session");
            request.query = Some(serde_json::json!({"disableRefresh": true}));
            let _ = request.headers.insert(
                "cookie".into(),
                format!(
                    "{}={}",
                    config.auth_cookie("session_token", Default::default()).name,
                    crate::utils::cookie_utils::sign_cookie_value(&token, config.signing_secret()),
                ),
            );
            let resolved = manager
                .resolve_native(&request, SessionRead::Authoritative)
                .await?;
            assert_eq!(resolved.data.is_some(), hidden == "expiresAt");
            let snapshot = request.session_snapshot()?.ok_or_else(|| {
                AuthError::internal("Expected public Session snapshot before expiry handling")
            })?;
            assert!(!FieldMap::from(snapshot.session).contains_key(hidden));
            assert!(request.new_session()?.is_none());
            let stored = manager.database.get_session(&token).await?.ok_or_else(|| {
                AuthError::internal("Hidden expiry or token must preserve the stored Session")
            })?;
            assert_eq!(stored.expires_at, session.expires_at);
        }
        Ok(())
    }

    #[tokio::test]
    async fn typed_relationship_consumption_follows_native_refresh_and_cookie_callbacks()
    -> AuthResult<()> {
        let calls = Arc::new(AtomicUsize::new(0));
        let recorded = calls.clone();
        let mut config =
            AuthConfig::new("typed-session-relationship-secret-at-least-32-characters");
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
        config.session.cookie_cache = Some(CookieCacheConfig {
            enabled: Some(true),
            version: CookieCacheVersion::dynamic(move |_| {
                let recorded = recorded.clone();
                async move {
                    let _ = recorded.fetch_add(1, Ordering::SeqCst);
                    Ok("selected-relation".into())
                }
            }),
            ..Default::default()
        });
        let config = Arc::new(config);
        let manager = SessionManager::<StatelessSchema>::new(
            config.clone(),
            Arc::new(EphemeralStore::new(config.clone())),
        );
        let session = manager
            .database
            .create_session(CreateSession {
                inherited_fields: Default::default(),
                user_id: "canonical-owner".into(),
                expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).into(),
                additional_fields: Default::default(),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await?;
        let mut user = CreateUser::new()
            .with_email("selected-owner@example.test")
            .with_name("Selected owner");
        user.image = Some(session.id.typed()?.clone()).into();
        let user = manager.database.create_user(user).await?;
        assert!(manager.needs_refresh(&session).unwrap());
        let mut request = AuthRequest::new(HttpMethod::Get, "/get-session");
        let _ = request.headers.insert(
            "cookie".into(),
            format!(
                "{}={}",
                config.auth_cookie("session_token", Default::default()).name,
                crate::utils::cookie_utils::sign_cookie_value(
                    session.token.typed().unwrap(),
                    config.signing_secret()
                ),
            ),
        );
        assert!(matches!(
            manager.resolve(&request, SessionRead::Authoritative).await,
            Err(AuthError::Internal(message)) if message == "A User relationship array cannot authenticate a typed User"
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(
            request
                .take_response_headers()?
                .get_all("set-cookie")
                .count()
                >= 2
        );
        let stored = manager
            .database
            .get_session(session.token.typed().unwrap())
            .await?
            .ok_or_else(|| AuthError::internal("Selected Session must remain stored"))?;
        assert!(stored.expires_at.date_milliseconds()? > session.expires_at.date_milliseconds()?);
        let issued = request
            .new_session()?
            .ok_or_else(|| AuthError::internal("Native refresh must publish the issued Session"))?;
        assert!(issued.user.is_object());
        assert!(issued.user_field("id")?.is_undefined());
        assert!(matches!(
            request.session_snapshot(),
            Err(AuthError::Internal(message)) if message == "A User relationship array cannot authenticate a typed User"
        ));
        let snapshot = request.native_session_snapshot()?.ok_or_else(|| {
            AuthError::internal("Native Session snapshot must preserve the selected relationship")
        })?;
        assert_eq!(snapshot.user, issued.user);

        let mut native_request = AuthRequest::new(HttpMethod::Get, "/get-session");
        native_request.headers = request.headers.clone();
        native_request.query = Some(serde_json::json!({"disableRefresh": true}));
        let native = manager
            .resolve_native(&native_request, SessionRead::Authoritative)
            .await?
            .data
            .ok_or_else(|| {
                AuthError::internal("Native resolution must preserve the selected relationship")
            })?;
        let selected = native
            .user
            .as_object()
            .ok_or_else(|| {
                AuthError::internal("Native User relationship must become a numeric-key object")
            })?
            .snapshot_fields()?;
        assert_eq!(selected.len(), 1);
        assert_eq!(
            selected
                .get("0")
                .and_then(FieldValue::as_object)
                .map(|fields| fields.get("id"))
                .transpose()?
                .flatten(),
            Some(user.id.field_value())
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let context = crate::AuthContext::new(config, manager.database.clone());
        for authoritative in [false, true] {
            let mut request = AuthRequest::new(HttpMethod::Get, "/native-business-consumer");
            request.headers = native_request.headers.clone();
            request.query = Some(serde_json::json!({"disableRefresh": true}));
            let resolved = if authoritative {
                context
                    .require_authoritative_native_session(&request)
                    .await?
            } else {
                context.require_native_session(&request).await?
            };
            let view = resolved.user_view()?;
            assert!(view.id.is_undefined());
            assert_eq!(FieldValue::from(FieldMap::from(view)), resolved.user);
            assert!(request.server_context("auth.current-user-id")?.is_none());
            assert!(
                request
                    .native_session_snapshot()?
                    .unwrap()
                    .user
                    .strict_equals(&resolved.user)
            );
            assert!(matches!(
                request.session_snapshot(),
                Err(AuthError::Internal(message)) if message == "A User relationship array cannot authenticate a typed User"
            ));
        }
        Ok(())
    }

    #[test]
    fn native_user_output_keeps_array_members_and_clone_identity() -> AuthResult<()> {
        let date = FieldDate::from_milliseconds(123.0);
        let user: FieldValue = FieldMap::from([
            ("id".into(), "user-b".into()),
            ("secretNote".into(), "private".into()),
            ("ownUndefined".into(), FieldValue::Undefined),
            ("when".into(), date.clone().into()),
            ("sameWhen".into(), date.clone().into()),
        ])
        .into();
        let mut config = UserConfig::default();
        let _ = config.fields_mut().insert(
            "secretNote".into(),
            UserFieldConfig {
                returned: Some(false),
                ..Default::default()
            },
        );
        let mut data = NativeSessionData {
            session: session()?,
            user: user.clone(),
        };
        let public = data.public_user(&config)?;
        let public = public
            .as_object()
            .ok_or_else(|| AuthError::internal("Expected User object"))?
            .snapshot_fields()?;
        assert!(!public.contains_key("secretNote"));
        assert_eq!(public.get("ownUndefined"), Some(&FieldValue::Undefined));
        data.user = vec![user.clone()].into();
        assert!(data.user_field("id")?.is_undefined());
        let public = data.public_user(&config)?;
        assert_eq!(
            public,
            FieldValue::from(FieldMap::from([("0".into(), user)]))
        );
        let child = public.model_property("0")?;
        let child = child
            .as_object()
            .ok_or_else(|| AuthError::internal("Expected numeric-key User output"))?
            .snapshot_fields()?;
        let date_field = |name: &str| {
            child
                .get(name)
                .and_then(FieldValue::as_date)
                .ok_or_else(|| AuthError::internal(format!("Expected Date field: {name}")))
        };
        assert!(date_field("when")?.same_object(date_field("sameWhen")?));
        assert!(!date_field("when")?.same_object(&date));
        assert!(matches!(data.user, FieldValue::Array(_)));
        Ok(())
    }

    #[tokio::test]
    async fn native_cookie_issuance_keeps_array_for_callbacks_and_snapshot() -> AuthResult<()> {
        let user: FieldValue = vec![FieldValue::from(FieldMap::from([
            ("id".into(), "user-b".into()),
            ("secretNote".into(), "child-value".into()),
        ]))]
        .into();
        let calls = Arc::new(AtomicUsize::new(0));
        let recorded = calls.clone();
        let expected = user.clone();
        let mut config = AuthConfig::new("native-session-cookie-secret-at-least-32-characters");
        config.session.cookie_cache = Some(CookieCacheConfig {
            enabled: Some(true),
            version: CookieCacheVersion::dynamic(move |data| {
                let expected = expected.clone();
                let recorded = recorded.clone();
                async move {
                    assert!(data.user.strict_equals(&expected));
                    assert!(data.session.user_id.is_undefined());
                    let _ = recorded.fetch_add(1, Ordering::SeqCst);
                    Ok("native".into())
                }
            }),
            ..Default::default()
        });
        let config = Arc::new(config);
        let manager = SessionManager::<StatelessSchema>::new(
            config.clone(),
            Arc::new(EphemeralStore::new(config.clone())),
        );
        let session = manager
            .create_session_for_id(Default::default(), None, None)
            .await?;
        assert!(session.user_id.is_undefined());
        let token = session.token.typed()?.clone();
        let data = NativeSessionData {
            session,
            user: user.clone(),
        };
        let request = AuthRequest::new(HttpMethod::Post, "/sign-in/social");
        manager
            .set_native_session_cookie(&request, data.clone(), None)
            .await?;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let snapshot = request
            .new_session()?
            .ok_or_else(|| AuthError::internal("Missing issued snapshot"))?;
        assert!(snapshot.user.strict_equals(&user));
        assert!(snapshot.session.user_id.is_undefined());
        let headers = request.take_response_headers()?;
        let cookies = headers
            .get_all("set-cookie")
            .map(|value| {
                cookie::Cookie::parse(value.as_str())
                    .map_err(|error| AuthError::internal(format!("Parsing test cookie: {error}")))
            })
            .collect::<AuthResult<Vec<_>>>()?;
        let mut browser = AuthRequest::new(HttpMethod::Get, "/get-session");
        let _ = browser.headers.insert(
            "cookie".into(),
            cookies
                .iter()
                .map(|cookie| format!("{}={}", cookie.name(), cookie.value()))
                .collect::<Vec<_>>()
                .join("; "),
        );
        assert_eq!(manager.extract_session_token(&browser), Some(token));
        let cache = config
            .session
            .cookie_cache
            .as_ref()
            .ok_or_else(|| AuthError::internal("Missing cache config"))?;
        let encoded = cookie_cache::read(&browser, "better-auth.session_data")
            .ok_or_else(|| AuthError::internal("Missing issued cache cookie"))?;
        let bytes = URL_SAFE_NO_PAD
            .decode(&encoded)
            .map_err(|error| AuthError::internal(format!("Decoding test cache: {error}")))?;
        let payload: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(
            payload
                .get("session")
                .and_then(|data| data.get("user"))
                .cloned(),
            data.public_user(&config.user)?.json()?
        );
        assert!(cookie_cache::decode(&encoded, &config, cache).is_none());
        Ok(())
    }
}
