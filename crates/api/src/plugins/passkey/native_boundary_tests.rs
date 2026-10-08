use super::*;
use better_auth_core::{
    AuthConfig, AuthInitContext, AuthPlugin, CreatePasskey, FieldMap, FieldValue,
    PasskeyCredentialState, UpdatePasskeyAuthentication, Utf16String,
    store::{
        AuthStore,
        database_hooks::{DatabaseHookContext, DatabaseHookUpdate, DatabaseHooks},
        schema::EntityRole,
    },
    user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform},
    wire::{SessionView, UserView},
};
use std::sync::Mutex;

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

async fn install_fields(
    fixture: &mut Fixture,
    raw: Arc<dyn AuthStore<BundledSchema>>,
    config: AuthConfig,
    fields: UserConfig,
    hooks: Vec<Arc<dyn DatabaseHooks<BundledSchema>>>,
) -> TestResult {
    let config = Arc::new(config);
    let mut init = AuthInitContext::new(config.clone(), raw.clone());
    AuthPlugin::on_init(&PasskeyPlugin::new(), &mut init).await?;
    init.register_model_fields(EntityRole::Passkey, fields)?;
    let parts = init.into_parts();
    let database = raw.with_runtime(config.clone(), hooks, parts.plugin_fields)?;
    fixture.ctx = AuthContext::new(config, database);
    fixture.ctx.metadata = parts.metadata;
    fixture.ctx.extensions = parts.extensions;
    Ok(())
}

async fn seed_native(
    fixture: &Fixture,
    owner: &UserView,
    authenticator: &Authenticator,
) -> TestResult<Passkey> {
    Ok(fixture
        .ctx
        .database
        .create_passkey(CreatePasskey {
            additional_fields: Default::default(),
            user_id: owner.id.clone(),
            name: Some("Native authenticator".into()).into(),
            public_key: STANDARD.encode(&authenticator.cose),
            credential_id: URL_SAFE_NO_PAD.encode(CREDENTIAL_ID),
            counter: 0,
            device_type: "singleDevice".into(),
            backed_up: false,
            transports: Some("internal".into()),
            credential: PasskeyCredentialState::Native,
            aaguid: None.into(),
        })
        .await?)
}

async fn authenticate(
    fixture: &Fixture,
    authenticator: &Authenticator,
    owner: &str,
) -> TestResult<AuthResponse> {
    let (pending, cookie) = options(
        fixture
            .route(&request(
                "/passkey/generate-authenticate-options",
                None,
                None,
                None,
            ))
            .await?,
    )?;
    let signed = authenticator.authenticate(&challenge(&pending)?, 1, owner.as_bytes())?;
    Ok(fixture
        .route(&request(
            "/passkey/verify-authentication",
            None,
            Some(json!({"response":signed})),
            Some(&cookie),
        ))
        .await?)
}

#[derive(Default)]
struct SessionTrace {
    events: Mutex<Vec<String>>,
    owners: Mutex<Vec<FieldValue>>,
}

#[better_auth_core::database_hooks()]
impl DatabaseHooks<BundledSchema> for SessionTrace {
    async fn before_create_session(
        &self,
        fields: &mut FieldMap,
        _: &DatabaseHookContext<'_, BundledSchema>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        self.events.lock().unwrap().push("session:before".into());
        self.owners
            .lock()
            .unwrap()
            .push(fields.get("userId").cloned().unwrap_or_default());
        Ok(DatabaseHookUpdate::Continue)
    }

    async fn after_create_session(
        &self,
        _: Option<&SessionView>,
        _: &DatabaseHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        self.events.lock().unwrap().push("session:after".into());
        Ok(())
    }
}

#[tokio::test]
async fn authentication_preserves_native_owner_and_creates_session_before_user_lookup() -> TestResult
{
    let path = std::env::temp_dir().join(format!(
        "better-auth-passkey-owner-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    drop(std::fs::File::create_new(&path)?);
    let mut fixture = Fixture::create(&path).await?;
    let raw = fixture.ctx.database.clone();
    let owner = raw
        .create_user(CreateUser {
            id: Some("7".into()),
            ..CreateUser::new()
                .with_name("Owner")
                .with_email("owner@passkey.example")
        })
        .await?;
    let authenticator = Authenticator::new()?;
    let passkey = seed_native(&fixture, &owner, &authenticator).await?;
    let trace = Arc::new(SessionTrace::default());
    let mut config = fixture.ctx.config.as_ref().clone();
    let user_trace = trace.clone();
    let _ = config.user.fields_mut().insert(
        "name".into(),
        output(UserFieldTransform::new(move |value| {
            user_trace.events.lock().unwrap().push("user".into());
            Ok(value)
        })),
    );
    let counter_trace = trace.clone();
    install_fields(
        &mut fixture,
        raw.clone(),
        config,
        UserConfig {
            additional_fields: Some(
                [
                    (
                        "userId".into(),
                        output(UserFieldTransform::new(|_| Ok(7.0.into()))),
                    ),
                    (
                        "counter".into(),
                        output(UserFieldTransform::new(move |value| {
                            counter_trace
                                .events
                                .lock()
                                .unwrap()
                                .push(format!("counter:{}", value.stringify()?.unwrap()));
                            Ok(value)
                        })),
                    ),
                ]
                .into(),
            ),
        },
        vec![trace.clone()],
    )
    .await?;
    assert_login(authenticate(&fixture, &authenticator, "7").await?, "7")?;
    assert_eq!(*trace.owners.lock().unwrap(), vec![FieldValue::Number(7.0)]);
    assert_eq!(
        *trace.events.lock().unwrap(),
        [
            "counter:0",
            "counter:1",
            "session:before",
            "session:after",
            "user"
        ]
    );
    let sessions = raw.get_user_sessions("7").await?;
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].user_id, "7");
    assert_eq!(
        raw.get_passkey_by_id(passkey.id.typed()?)
            .await?
            .ok_or("Missing passkey")?
            .counter,
        1
    );
    drop(raw);
    fixture.close().await?;
    std::fs::remove_file(path)?;
    Ok(())
}

fn field<'a>(value: &'a FieldValue, name: &str) -> TestResult<&'a FieldValue> {
    value
        .as_object()
        .and_then(|fields| fields.get(name))
        .ok_or_else(|| format!("Missing {name}").into())
}

fn assert_surrogate_response(response: &AuthResponse, registration: bool) -> TestResult {
    assert_eq!(response.status, 200);
    let native = response.body.field_value()?;
    let encoded = FieldValue::parse_json(std::str::from_utf8(&response.body.bytes()?)?)?;
    let surrogate: FieldValue = Utf16String::from_units(vec![0xd800]).into();
    for body in [&native, &encoded] {
        if registration {
            assert_eq!(field(body, "name")?, &surrogate);
            let fields = body.as_object().ok_or("Expected registration object")?;
            assert!(!fields.contains_key("credential"));
            assert!(!fields.contains_key("updatedAt"));
        }
        assert_eq!(field(field(body, "user")?, "name")?, &surrogate);
        assert_eq!(field(field(body, "session")?, "userAgent")?, &surrogate);
    }
    assert!(response.headers.contains_key("Set-Cookie"));
    Ok(())
}

#[tokio::test]
async fn registration_and_authentication_preserve_utf16_response_fields() -> TestResult {
    let path = std::env::temp_dir().join(format!(
        "better-auth-passkey-response-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    drop(std::fs::File::create_new(&path)?);
    let mut fixture = Fixture::create(&path).await?;
    let raw = fixture.ctx.database.clone();
    let (owner, session) = test_helpers::create_user_and_session(
        &fixture.ctx,
        CreateUser::new()
            .with_name("Stored owner")
            .with_email("response@passkey.example"),
        chrono::Duration::hours(1),
    )
    .await;
    let authenticator = Authenticator::new()?;
    let (pending, cookie) = options(
        fixture
            .route(&request(
                "/passkey/generate-register-options",
                Some(session.token.typed().unwrap()),
                None,
                None,
            ))
            .await?,
    )?;
    let signed = authenticator.register(&challenge(&pending)?, Some(TRANSPORTS))?;
    let surrogate = UserFieldTransform::new(|_| Ok(Utf16String::from_units(vec![0xd800]).into()));
    let mut config = fixture.ctx.config.as_ref().clone();
    let _ = config
        .user
        .fields_mut()
        .insert("name".into(), output(surrogate.clone()));
    let _ = config
        .session
        .fields_mut()
        .insert("userAgent".into(), output(surrogate.clone()));
    install_fields(
        &mut fixture,
        raw.clone(),
        config,
        UserConfig {
            additional_fields: Some([("name".into(), output(surrogate))].into()),
        },
        Vec::new(),
    )
    .await?;
    let response = fixture
        .route(&request(
            "/passkey/verify-registration",
            Some(session.token.typed().unwrap()),
            Some(json!({"response":signed,"name":"Stored authenticator","createSession":true})),
            Some(&cookie),
        ))
        .await?;
    assert_surrogate_response(&response, true)?;
    let stored = raw
        .get_passkey_by_credential_id(&URL_SAFE_NO_PAD.encode(CREDENTIAL_ID))
        .await?
        .ok_or("Missing passkey")?;
    assert_eq!(stored.name, Some("Stored authenticator".to_owned()));
    assert_eq!(stored.counter, 0);
    assert_eq!(raw.get_user_sessions(owner.id.typed()?).await?.len(), 2);
    let response = authenticate(&fixture, &authenticator, owner.id.typed()?).await?;
    assert_surrogate_response(&response, false)?;
    assert_eq!(raw.get_user_sessions(owner.id.typed()?).await?.len(), 3);
    assert_eq!(
        raw.get_passkey_by_id(stored.id.typed()?)
            .await?
            .ok_or("Missing passkey")?
            .counter,
        1
    );
    assert_eq!(
        raw.get_user_by_id(owner.id.typed()?)
            .await?
            .ok_or("Missing owner")?
            .name,
        Some("Stored owner".to_owned())
    );
    drop(raw);
    fixture.close().await?;
    std::fs::remove_file(path)?;
    Ok(())
}

#[path = "public_key_authentication_tests.rs"]
mod public_key_authentication_tests;

#[path = "credential_id_authentication_tests.rs"]
mod credential_id_authentication_tests;
