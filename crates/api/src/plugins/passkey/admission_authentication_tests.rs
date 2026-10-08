use super::*;
use crate::plugins::admin::{AdminPlugin, BannedUserMessage};
use better_auth_core::{
    AuthConfig, AuthInitContext, AuthPlugin, AuthRecordFields, FieldMap, FieldValue,
    store::{
        AuthStore, EphemeralStore, StatelessSchema,
        database_hooks::{DatabaseHookContext, DatabaseHookUpdate, DatabaseHooks},
        schema::EntityRole,
    },
    user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform},
    wire::{SessionView, UserView},
};
use std::sync::Mutex;
use tracing::instrument::WithSubscriber;

#[path = "admission_trace.rs"]
mod trace;
use trace::{AdmissionTrace, DatabaseSpans};

fn output(callback: UserFieldTransform) -> UserFieldConfig {
    UserFieldConfig {
        required: Some(false),
        transform: Some(FieldTransforms {
            input: None,
            output: Some(callback),
        }),
        ..Default::default()
    }
}

struct MemoryFixture {
    ctx: AuthContext<StatelessSchema>,
    raw: Arc<dyn AuthStore<StatelessSchema>>,
    owner: UserView,
    passkey: Passkey,
    authenticator: Authenticator,
    user_handle: Vec<u8>,
    trace: Arc<AdmissionTrace>,
}

impl MemoryFixture {
    async fn new(user: CreateUser) -> TestResult<Self> {
        let mut config = test_helpers::create_test_config().base_url(ORIGIN);
        config.telemetry.enabled = false;
        let config = Arc::new(config);
        let raw: Arc<dyn AuthStore<StatelessSchema>> =
            Arc::new(EphemeralStore::new(config.clone()));
        let mut init = AuthInitContext::new(config.clone(), raw.clone());
        AuthPlugin::on_init(&PasskeyPlugin::new(), &mut init).await?;
        let raw = raw.with_runtime(config.clone(), Vec::new(), init.into_parts().plugin_fields)?;
        let ctx = AuthContext::new(config, raw.clone());
        let owner = raw.create_user(user).await?;
        let session = ctx
            .session_manager()
            .create_session_for_id_with_lifetime(
                owner.id.clone(),
                None,
                None,
                chrono::Duration::hours(1),
            )
            .await?;
        let authenticator = Authenticator::new()?;
        let (registration, cookie) = options(
            route(
                &ctx,
                &request(
                    "/passkey/generate-register-options",
                    Some(session.token.typed().unwrap()),
                    None,
                    None,
                ),
            )
            .await?,
        )?;
        let user_handle = URL_SAFE_NO_PAD.decode(
            registration["user"]["id"]
                .as_str()
                .ok_or("Missing registration user handle")?,
        )?;
        let signed = authenticator.register(&challenge(&registration)?, Some(TRANSPORTS))?;
        let registered = route(
            &ctx,
            &request(
                "/passkey/verify-registration",
                Some(session.token.typed().unwrap()),
                Some(json!({"response": signed, "name": "Admission authenticator"})),
                Some(&cookie),
            ),
        )
        .await?;
        assert_eq!(registered.status, 200);
        let passkey = raw
            .get_passkey_by_credential_id(&URL_SAFE_NO_PAD.encode(CREDENTIAL_ID))
            .await?
            .ok_or("Missing registered credential")?;
        assert_eq!(passkey.counter, 0);
        assert_eq!(passkey.user_id, *owner.id.typed()?);
        raw.delete_session(session.token.typed().unwrap()).await?;
        assert!(raw.get_user_sessions(owner.id.typed()?).await?.is_empty());
        Ok(Self {
            ctx,
            raw,
            owner,
            passkey,
            authenticator,
            user_handle,
            trace: Arc::default(),
        })
    }

    async fn configure(
        &mut self,
        config: AuthConfig,
        admin: bool,
        owner: Option<FieldValue>,
    ) -> TestResult {
        let config = Arc::new(config);
        let mut init = AuthInitContext::new(config.clone(), self.raw.clone());
        AuthPlugin::on_init(&PasskeyPlugin::new(), &mut init).await?;
        if admin {
            let trace = self.trace.clone();
            let plugin =
                AdminPlugin::new().banned_user_message(BannedUserMessage::callback(move |user| {
                    trace.events.lock().unwrap().push("ban:message".into());
                    trace.banned_users.lock().unwrap().push(user.clone().into());
                    Box::pin(async { Ok("Admission denied".into()) })
                }));
            AuthPlugin::on_init(&plugin, &mut init).await?;
        }
        let trace = self.trace.clone();
        let mut fields = UserConfig::default();
        let _ = fields.fields_mut().insert(
            "counter".into(),
            output(UserFieldTransform::new(move |value| {
                trace
                    .events
                    .lock()
                    .unwrap()
                    .push(format!("counter:{}", value.stringify()?.unwrap()));
                Ok(value)
            })),
        );
        if let Some(owner) = owner {
            let _ = fields.fields_mut().insert(
                "userId".into(),
                output(UserFieldTransform::new(move |_| Ok(owner.clone()))),
            );
        }
        init.register_model_fields(EntityRole::Passkey, fields)?;
        let parts = init.into_parts();
        let database = self.raw.with_runtime(
            config.clone(),
            vec![self.trace.clone()],
            parts.plugin_fields,
        )?;
        self.ctx = AuthContext::new(config, database);
        self.ctx.metadata = parts.metadata;
        self.ctx.extensions = parts.extensions;
        Ok(())
    }

    async fn authenticate(&self) -> TestResult<(AuthRequest, AuthResponse)> {
        let (pending, cookie) = options(
            route(
                &self.ctx,
                &request("/passkey/generate-authenticate-options", None, None, None),
            )
            .await?,
        )?;
        let signed =
            self.authenticator
                .authenticate(&challenge(&pending)?, 1, &self.user_handle)?;
        let request = request(
            "/passkey/verify-authentication",
            None,
            Some(json!({"response": signed})),
            Some(&cookie),
        );
        let result = route(&self.ctx, &request)
            .with_subscriber(DatabaseSpans(self.trace.clone()))
            .await;
        let response = match result {
            Ok(response) => response,
            Err(error) => {
                test_helpers::finalize_response(&self.ctx, &request, error.to_auth_response())
            }
        };
        Ok((request, response))
    }

    async fn assert_counter_persisted(&self) -> TestResult {
        let stored = self
            .raw
            .get_passkey_by_id(self.passkey.id.typed()?)
            .await?
            .ok_or("Missing credential after authentication")?;
        let mut expected = self.passkey.clone();
        expected.counter = 1.into();
        let mut credential: Value = serde_json::from_str(expected.credential.typed()?)?;
        credential["cred"]["counter"] = json!(1);
        assert_eq!(
            serde_json::from_str::<Value>(stored.credential.typed()?)?,
            credential
        );
        expected.credential = stored.credential.clone();
        assert!(
            stored.updated_at.typed()?.milliseconds()
                >= expected.updated_at.typed()?.milliseconds()
        );
        expected.updated_at = stored.updated_at.clone();
        assert_eq!(stored.field_values()?, expected.field_values()?);
        Ok(())
    }

    async fn assert_session_persisted(&self, owner: &FieldValue) -> TestResult<SessionView> {
        let owners = self.trace.owners.lock().unwrap().clone();
        assert_eq!(owners.len(), 1);
        assert!(owners[0].same_value_zero(owner));
        let created = self.trace.sessions.lock().unwrap().clone();
        assert_eq!(created.len(), 1);
        let stored = self
            .raw
            .get_session(created[0].token.typed().unwrap())
            .await?
            .ok_or("Missing issued Session")?;
        assert_eq!(
            FieldMap::from(stored.clone()),
            FieldMap::from(created[0].clone())
        );
        Ok(stored)
    }
}

fn user() -> CreateUser {
    CreateUser::new()
        .with_name("Owner")
        .with_email("owner@admission.example")
}

fn counter_events() -> Vec<&'static str> {
    vec![
        "db findOne passkey",
        "counter:0",
        "db update passkey",
        "counter:1",
    ]
}

fn session_events() -> [&'static str; 3] {
    ["session:before", "db create session", "session:after"]
}

fn assert_failure(
    request: &AuthRequest,
    response: &AuthResponse,
    status: u16,
    code: &str,
    message: &str,
) -> TestResult {
    assert_eq!(response.status, status);
    assert_eq!(
        serde_json::from_slice::<Value>(&response.body.bytes()?)?,
        json!({"code": code, "message": message})
    );
    assert!(!response.headers.contains_key("Set-Cookie"));
    assert!(request.new_session()?.is_none());
    Ok(())
}

#[tokio::test]
async fn signed_authentication_creates_orphan_session_before_missing_owner_error() -> TestResult {
    for admin in [false, true] {
        for owner in [
            FieldValue::Undefined,
            FieldValue::Null,
            false.into(),
            0.0.into(),
            FieldValue::Number(f64::NAN),
            "".into(),
            "missing-user".into(),
        ] {
            let mut fixture = MemoryFixture::new(user()).await?;
            fixture
                .configure(
                    fixture.ctx.config.as_ref().clone(),
                    admin,
                    Some(owner.clone()),
                )
                .await?;
            let (request, response) = fixture.authenticate().await?;
            assert_failure(&request, &response, 500, "USER_NOT_FOUND", "User not found")?;
            let mut events = counter_events();
            if admin && owner.is_truthy() {
                events.push("db findOne user");
            }
            events.extend(session_events());
            if owner.is_truthy() {
                events.push("db findOne user");
            }
            assert_eq!(
                *fixture.trace.events.lock().unwrap(),
                events,
                "admin={admin}, owner={owner:?}"
            );
            fixture.assert_counter_persisted().await?;
            let _ = fixture.assert_session_persisted(&owner).await?;
            assert!(fixture.trace.banned_users.lock().unwrap().is_empty());
            assert_eq!(
                FieldMap::from(
                    fixture
                        .raw
                        .get_user_by_id(fixture.owner.id.typed()?)
                        .await?
                        .ok_or("Missing original owner")?
                ),
                FieldMap::from(fixture.owner.clone())
            );
            assert!(
                fixture
                    .raw
                    .get_user_sessions(fixture.owner.id.typed()?)
                    .await?
                    .is_empty()
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn signed_authentication_consumes_projected_admin_bans_after_counter_write() -> TestResult {
    let past = chrono::Utc::now() - chrono::Duration::days(1);
    let future = chrono::Utc::now() + chrono::Duration::days(1);
    for (name, banned, expiry, projected_ban, projected_expiry, allowed, cleared) in [
        ("active", true, None, None, None, false, false),
        ("future", true, Some(future), None, None, false, false),
        ("expired", true, Some(past), None, None, true, true),
        (
            "projected truthy ban",
            false,
            None,
            Some(FieldValue::from("blocked")),
            None,
            false,
            false,
        ),
        (
            "projected falsy ban",
            true,
            None,
            Some(FieldValue::from(false)),
            None,
            true,
            false,
        ),
        (
            "projected expired date",
            true,
            Some(future),
            None,
            Some(FieldValue::from("2000-01-01T00:00:00Z")),
            true,
            true,
        ),
        (
            "projected falsy date",
            true,
            Some(past),
            None,
            Some(FieldValue::from(0.0)),
            false,
            false,
        ),
        (
            "projected invalid date",
            true,
            Some(past),
            None,
            Some(FieldValue::from("invalid")),
            false,
            false,
        ),
    ] {
        let mut fixture = MemoryFixture::new(CreateUser {
            banned: Some(banned),
            ban_reason: Some("Stored reason".into()),
            ban_expires: expiry.map(Into::into),
            ..user()
        })
        .await?;
        let mut config = fixture.ctx.config.as_ref().clone();
        for (field, value) in [
            ("banned", projected_ban.clone()),
            ("banExpires", projected_expiry.clone()),
        ] {
            if let Some(value) = value {
                let _ = config.user.fields_mut().insert(
                    field.into(),
                    output(UserFieldTransform::new(move |_| Ok(value.clone()))),
                );
            }
        }
        fixture.configure(config, true, None).await?;
        let selected = fixture
            .ctx
            .database
            .get_user_by_id(fixture.owner.id.typed()?)
            .await?
            .ok_or("Missing projected owner")?;
        let selected = FieldMap::from(fixture.ctx.internal_user_view(&selected).await?);
        let (request, response) = fixture.authenticate().await?;
        let mut events = counter_events();
        events.push("db findOne user");
        if cleared {
            events.push("db update user");
        }
        if allowed {
            events.extend(session_events());
            events.push("db findOne user");
            assert_eq!(response.status, 200, "{name}");
            assert!(response.headers.contains_key("Set-Cookie"), "{name}");
            let created = fixture
                .assert_session_persisted(&fixture.owner.id.field_value())
                .await?;
            let stored_owner = fixture
                .ctx
                .database
                .get_user_by_id(fixture.owner.id.typed()?)
                .await?
                .ok_or("Missing owner after admission")?;
            let expected: FieldValue = FieldMap::from(better_auth_core::session::SessionData {
                session: fixture.ctx.session_view(&created).await?,
                user: fixture.ctx.user_view(&stored_owner).await?,
            })
            .into();
            assert_eq!(response.body.field_value()?, expected, "{name}");
            assert_eq!(
                FieldValue::parse_json(std::str::from_utf8(&response.body.bytes()?)?)?,
                FieldValue::parse_json(
                    &expected.stringify()?.ok_or("Missing serialized response")?
                )?,
                "{name}"
            );
            let published = request.new_session()?.ok_or("Session was not published")?;
            assert_eq!(
                FieldMap::from(published.session),
                FieldMap::from(
                    fixture
                        .ctx
                        .session_manager()
                        .internal_session_view(&created)
                        .await?
                ),
                "{name}"
            );
            assert_eq!(
                published.user,
                FieldValue::from(FieldMap::from(
                    fixture.ctx.internal_user_view(&stored_owner).await?
                )),
                "{name}"
            );
            assert!(fixture.trace.banned_users.lock().unwrap().is_empty());
        } else {
            events.push("ban:message");
            assert_failure(&request, &response, 403, "BANNED_USER", "Admission denied")?;
            assert_eq!(
                *fixture.trace.banned_users.lock().unwrap(),
                vec![selected],
                "{name}"
            );
            assert!(fixture.trace.owners.lock().unwrap().is_empty());
            assert!(fixture.trace.sessions.lock().unwrap().is_empty());
        }
        assert_eq!(*fixture.trace.events.lock().unwrap(), events, "{name}");
        fixture.assert_counter_persisted().await?;
        let stored = fixture
            .raw
            .get_user_by_id(fixture.owner.id.typed()?)
            .await?
            .ok_or("Missing stored owner")?;
        let mut expected = fixture.owner.clone();
        if cleared {
            expected.banned = false;
            expected.ban_reason = None;
            expected.ban_expires = None;
            assert!(stored.updated_at.milliseconds() >= expected.updated_at.milliseconds());
            expected.updated_at = stored.updated_at.clone();
        }
        assert_eq!(FieldMap::from(stored), FieldMap::from(expected), "{name}");
        assert_eq!(
            fixture
                .raw
                .get_user_sessions(fixture.owner.id.typed()?)
                .await?
                .len(),
            usize::from(allowed),
            "{name}"
        );
    }
    Ok(())
}
