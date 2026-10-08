use super::SessionData;
use crate::{
    AuthError, AuthResult, FieldMap, FieldValue, StructuredCloneContext,
    store::JoinValue,
    user_fields::UserConfig,
    wire::{SessionView, UserView},
};

/// Session data before the selected User value crosses a typed authentication boundary.
#[derive(Debug, Clone)]
pub struct NativeSessionData {
    /// Session passed to the credential writer.
    pub session: SessionView,
    /// Preserve the selected User object or relationship array for trusted callbacks.
    pub user: FieldValue,
}

impl NativeSessionData {
    /// Read a User model field. Relationship arrays have no User model fields.
    pub fn user_field(&self, name: &str) -> &FieldValue {
        self.user
            .as_object()
            .and_then(|fields| fields.get(name))
            .unwrap_or(&FieldValue::Undefined)
    }

    /// Clone enumerable User fields and remove fields with `returned: false`.
    /// Arrays become numeric-key objects only at this output boundary.
    pub fn public_user(&self, config: &UserConfig) -> AuthResult<FieldValue> {
        let value = StructuredCloneContext::new().clone_value(&self.user);
        let mut fields = match value {
            FieldValue::Object(fields) => (*fields).clone(),
            FieldValue::Array(values) => values
                .iter()
                .enumerate()
                .map(|(index, value)| (index.to_string(), value.clone()))
                .collect(),
            _ => {
                return Err(AuthError::internal(
                    "Session User must be an object or an array",
                ));
            }
        };
        fields.retain(|name, _| {
            config
                .fields()
                .get(name)
                .is_none_or(|field| field.returned())
        });
        Ok(fields.into())
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
    async fn typed_relationship_array_rejection_precedes_refresh_and_cookie_callbacks()
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
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            request
                .take_response_headers()?
                .get_all("set-cookie")
                .count(),
            0
        );
        let stored = manager
            .database
            .get_session(session.token.typed().unwrap())
            .await?
            .ok_or_else(|| AuthError::internal("Selected Session must remain stored"))?;
        assert_eq!(stored.expires_at, session.expires_at);
        assert!(request.new_session()?.is_none());

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
            .as_array()
            .ok_or_else(|| AuthError::internal("Native User relationship must remain an array"))?;
        assert_eq!(selected.len(), 1);
        assert_eq!(
            selected
                .first()
                .and_then(FieldValue::as_object)
                .and_then(|fields| fields.get("id")),
            Some(&user.id.field_value())
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
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
            .ok_or_else(|| AuthError::internal("Expected User object"))?;
        assert!(!public.contains_key("secretNote"));
        assert_eq!(public.get("ownUndefined"), Some(&FieldValue::Undefined));
        data.user = vec![user.clone()].into();
        assert!(data.user_field("id").is_undefined());
        let public = data.public_user(&config)?;
        assert_eq!(
            public,
            FieldValue::from(FieldMap::from([("0".into(), user)]))
        );
        let child = public
            .as_object()
            .and_then(|fields| fields.get("0"))
            .and_then(FieldValue::as_object)
            .ok_or_else(|| AuthError::internal("Expected numeric-key User output"))?;
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
