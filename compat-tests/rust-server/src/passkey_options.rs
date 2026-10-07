use async_trait::async_trait;
use axum::{Json, Router, extract::Query, routing::get};
use better_auth::{AuthConfig, AuthError, AuthResult, AuthSchema, plugins::passkey::*};
use better_auth_core::{CreateUser, FieldMap, store::AuthStore};
use better_auth_seaorm::{DatabaseHookUpdate, SeaOrmHookContext, SeaOrmHooks};
use serde_json::{Map, Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct State {
    events: Vec<Value>,
    control: Map<String, Value>,
}
#[derive(Clone, Default)]
pub(super) struct PasskeyOptions {
    state: Arc<Mutex<State>>,
    profile: String,
}
impl PasskeyOptions {
    pub(super) fn new(profile: &str) -> Self {
        Self {
            profile: profile.into(),
            ..Self::default()
        }
    }
    pub(super) fn enabled(&self) -> bool {
        self.profile.starts_with("passkey-")
    }
    pub(super) fn configure(&self, config: &mut AuthConfig) {
        if self.enabled() {
            config.app_name = "Passkey Configuration".into();
        }
        if self.profile == "passkey-stale" {
            config.session.fresh_age = Some(chrono::Duration::seconds(-1));
        }
    }
    pub(super) fn apply(&self, original: PasskeyPlugin) -> PasskeyPlugin {
        if !self.enabled() {
            return original;
        }
        let callback = Arc::new(self.clone());
        PasskeyPlugin::new()
            .rp_id("localhost")
            .origin(vec![
                "https://passkeys.example".into(),
                "https://secondary.example".into(),
            ])
            .web_authn_challenge_cookie("ceremony")
            .authenticator_selection(AuthenticatorSelection {
                authenticator_attachment: Some(AuthenticatorAttachment::Platform),
                resident_key: Some(PasskeyRequirement::Required),
                user_verification: Some(PasskeyRequirement::Required),
                ..Default::default()
            })
            .registration(PasskeyRegistrationOptions {
                require_session: !matches!(
                    self.profile.as_str(),
                    "passkey-first" | "passkey-no-resolver"
                ),
                resolve_user: (self.profile != "passkey-no-resolver")
                    .then(|| callback.clone() as Arc<dyn PasskeyUserResolver>),
                after_verification: Some(callback.clone()),
                extensions: PasskeyExtensions::Dynamic(callback.clone()),
            })
            .authentication(PasskeyAuthenticationOptions {
                after_verification: Some(callback),
                extensions: PasskeyExtensions::Static(Map::from_iter([(
                    "uvm".into(),
                    true.into(),
                )])),
            })
    }
    fn event(&self, event: Value) {
        self.state.lock().unwrap().events.push(event);
    }
    fn control(&self) -> Map<String, Value> {
        self.state.lock().unwrap().control.clone()
    }
    pub(super) fn reset(&self) {
        *self.state.lock().unwrap() = State::default();
    }
    pub(super) fn hooks<S: AuthSchema>(&self) -> Arc<dyn SeaOrmHooks<S>> {
        Arc::new(self.clone())
    }
    pub(super) fn router<S: AuthSchema>(&self, store: Arc<dyn AuthStore<S>>) -> Router {
        let read = self.clone();
        let write = self.clone();
        Router::new().route(
            "/__test/passkey-options",
            get(move |Query(query): Query<HashMap<String, String>>| {
                let fixture = read.clone();
                let store = store.clone();
                async move {
                    let events = fixture.state.lock().unwrap().events.clone();
                    if let Some(id) = query.get("userId") {
                        let user = store.get_user_by_id(id).await?.is_some();
                        let passkeys = store
                            .list_passkeys_by_user(id)
                            .await?
                            .iter()
                            .map(better_auth_core::wire::PasskeyView::from)
                            .collect::<Vec<_>>();
                        Ok::<_, AuthError>(Json(
                            json!({"user": user, "passkeys": passkeys, "events": events}),
                        ))
                    } else {
                        Ok(Json(json!({"events": events})))
                    }
                }
            })
            .post(move |Json(body): Json<Map<String, Value>>| {
                let fixture = write.clone();
                async move {
                    let mut state = fixture.state.lock().unwrap();
                    if body.get("clear") != Some(&Value::Bool(false)) {
                        state.events.clear();
                    }
                    state.control.extend(body);
                    Json(json!({"events": state.events}))
                }
            }),
        )
    }
}
fn fail(value: Option<&Value>) -> AuthResult<()> {
    match value.and_then(Value::as_str) {
        Some("api-error") => Err(AuthError::Upstream {
            status: 403,
            code: "PASSKEY_CALLBACK_REJECTED",
            message: "Passkey callback rejected",
        }),
        Some("error") => Err(AuthError::internal("Passkey callback failed")),
        _ => Ok(()),
    }
}
fn event(name: &str, ctx: PasskeyEndpoint<'_>) -> Value {
    json!({"event": name, "path": ctx.request.path, "hasRequest": true, "context": ctx.request.query.as_ref().and_then(|query| query.get("context"))})
}
#[async_trait]
impl PasskeyUserResolver for PasskeyOptions {
    async fn resolve(
        &self,
        ctx: PasskeyEndpoint<'_>,
        context: Option<&str>,
    ) -> AuthResult<PasskeyRegistrationUser> {
        let mut value = event("resolve", ctx);
        value["context"] = json!(context);
        self.event(value);
        let control = self.control();
        fail(control.get("resolveMode"))?;
        Ok(PasskeyRegistrationUser {
            id: control
                .get("userId")
                .and_then(Value::as_str)
                .unwrap_or("provisional-user")
                .into(),
            name: if control.get("invalidUser") == Some(&Value::Bool(true)) {
                ""
            } else {
                "Resolved User"
            }
            .into(),
            display_name: Some("Resolved Display".into()),
        })
    }
}
#[async_trait]
impl PasskeyExtensionsResolver for PasskeyOptions {
    async fn extensions(&self, ctx: PasskeyEndpoint<'_>) -> AuthResult<Option<Map<String, Value>>> {
        self.event(event("registration.extensions", ctx));
        let control = self.control();
        fail(control.get("extensionsMode"))?;
        Ok(
            (control.get("noExtensions") != Some(&Value::Bool(true))).then(|| {
                Map::from_iter([
                    ("credProps".into(), false.into()),
                    ("largeBlob".into(), json!({"support": "preferred"})),
                ])
            }),
        )
    }
}
#[async_trait]
impl PasskeyRegistrationHook for PasskeyOptions {
    async fn after_verification(
        &self,
        ctx: PasskeyEndpoint<'_>,
        verification: &PasskeyRegistrationVerification,
        user: &PasskeyRegistrationUser,
        client_data: &Value,
        context: Option<&str>,
    ) -> AuthResult<PasskeyRegistrationResult> {
        let info = &verification.registration_info;
        let mut value = event("registration.verified", ctx);
        value.as_object_mut().unwrap().extend(Map::from_iter([
            ("context".into(), json!(context)), ("user".into(), json!(user)), ("verified".into(), json!(verification.verified)),
            ("name".into(), ctx.body.get("name").cloned().unwrap_or(Value::Null)), ("createSession".into(), ctx.body.get("createSession").cloned().unwrap_or(Value::Null)),
            ("clientID".into(), client_data.get("id").cloned().unwrap_or(Value::Null)),
            ("info".into(), json!({"fmt": info.fmt, "aaguid": info.aaguid, "credentialID": info.credential.id, "counter": info.credential.counter, "publicKeyLength": info.credential.public_key.len(), "attestationLength": info.attestation_object.len(), "credentialType": info.credential_type, "userVerified": info.user_verified, "deviceType": info.credential_device_type, "backedUp": info.credential_backed_up, "origin": info.origin, "rpID": info.rp_id, "transports": info.credential.transports})),
        ]));
        self.event(value);
        let control = self.control();
        if let Some(user) = control.get("createUser") {
            let mut input = CreateUser::new()
                .with_name(
                    user.get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("Passkey User"),
                )
                .with_email(user.get("email").and_then(Value::as_str).unwrap());
            input.id = user.get("id").and_then(Value::as_str).map(str::to_owned);
            let created = ctx.users.create_user(input).await?;
            if let Some(banned) = user.get("banned").and_then(Value::as_bool) {
                let _ = ctx
                    .users
                    .update_user(
                        created.id.typed().unwrap(),
                        better_auth_core::UpdateUser {
                            banned: Some(banned),
                            ban_expires: user.get("banExpires").and_then(Value::as_str).map(
                                |value| {
                                    Some(
                                        chrono::DateTime::parse_from_rfc3339(value)
                                            .unwrap()
                                            .with_timezone(&chrono::Utc),
                                    )
                                },
                            ),
                            ..Default::default()
                        },
                    )
                    .await?;
            }
            if let Some(name) = control.get("updateUserName").and_then(Value::as_str) {
                let found = ctx
                    .users
                    .get_user_by_email(user.get("email").and_then(Value::as_str).unwrap())
                    .await?;
                let updated = ctx
                    .users
                    .update_user(
                        created.id.typed().unwrap(),
                        better_auth_core::UpdateUser {
                            name: Some(name.into()).into(),
                            ..Default::default()
                        },
                    )
                    .await?;
                self.event(json!({"event": "users", "found": found.is_some_and(|user| user.id == created.id), "name": updated.name}));
            }
            if control.get("deleteTemporary") == Some(&Value::Bool(true)) {
                let mut input = CreateUser::new().with_name("Temporary").with_email(format!(
                    "temporary-{}",
                    user.get("email").and_then(Value::as_str).unwrap()
                ));
                input.id = Some("temporary-user".into());
                let temporary = ctx.users.create_user(input).await?;
                ctx.users.delete_user(temporary.id.typed().unwrap()).await?;
                self.event(json!({"event": "users.deleted", "missing": ctx.users.get_user_by_id(temporary.id.typed().unwrap()).await?.is_none()}));
            }
        }
        fail(control.get("registrationMode"))?;
        Ok(PasskeyRegistrationResult {
            user_id: control
                .get("targetUserId")
                .and_then(Value::as_str)
                .map(str::to_owned),
            name: Some(
                control
                    .get("hookName")
                    .and_then(Value::as_str)
                    .unwrap_or("  Hook Key  ")
                    .into(),
            ),
        })
    }
}
#[async_trait]
impl PasskeyAuthenticationHook for PasskeyOptions {
    async fn after_verification(
        &self,
        ctx: PasskeyEndpoint<'_>,
        verification: &PasskeyAuthenticationVerification,
        client_data: &Value,
    ) -> AuthResult<()> {
        let mut value = event("authentication.verified", ctx);
        value.as_object_mut().unwrap().extend(Map::from_iter([
            ("verified".into(), json!(verification.verified)),
            ("info".into(), json!(verification.authentication_info)),
            (
                "clientID".into(),
                client_data.get("id").cloned().unwrap_or(Value::Null),
            ),
        ]));
        self.event(value);
        fail(self.control().get("authenticationMode"))
    }
}
#[better_auth::database_hooks()]
impl<S: AuthSchema> SeaOrmHooks<S> for PasskeyOptions {
    async fn before_create_session(
        &self,
        _: &mut FieldMap,
        _: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        self.event(json!({"event": "session.before"}));
        if self.control().get("failSession") == Some(&Value::Bool(true)) {
            return Err(AuthError::Upstream {
                status: 403,
                code: "SESSION_REJECTED",
                message: "Session rejected",
            });
        }
        Ok(DatabaseHookUpdate::Continue)
    }
    async fn after_create_session(
        &self,
        _: &better_auth_core::wire::SessionView,
        _: &SeaOrmHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.event(json!({"event": "session.after"}));
        Ok(())
    }
}
