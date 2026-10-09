use super::*;
use crate::plugins::test_helpers;
use better_auth_core::{
    AuthConfig, AuthContext, FieldDate, FieldValue, UserView,
    store::database_hooks::{DatabaseHookContext, DatabaseHookUpdate, DatabaseHooks},
    store::{AuthStore, EphemeralStore, StatelessSchema, secondary::SecondaryStore},
    user_fields::{UserFieldConfig, UserFieldType},
};
use std::sync::Mutex;

#[derive(Default)]
struct Trace(Mutex<Vec<(&'static str, FieldMap, bool)>>);

#[async_trait]
impl<S: AuthSchema> ValidateUserInfo<S> for Trace {
    async fn validate(
        &self,
        data: &UserValidationData,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<Option<UserValidationRejection>> {
        assert_eq!(data.source.method, "contract");
        self.0.lock().unwrap().push((
            "admission",
            data.user.clone(),
            endpoint.transaction.is_some(),
        ));
        Ok(None)
    }
}

#[better_auth_core::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for Trace {
    async fn before_create_user(
        &self,
        input: &mut FieldMap,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        self.0
            .lock()
            .unwrap()
            .push(("before", input.clone(), context.transaction.is_some()));
        Ok(DatabaseHookUpdate::Continue)
    }

    async fn after_create_user(
        &self,
        user: Option<&UserView>,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.0.lock().unwrap().push((
            "after",
            user.unwrap().clone().into(),
            context.transaction.is_some(),
        ));
        Ok(())
    }
}

fn config() -> Arc<AuthConfig> {
    let mut config = test_helpers::create_test_config();
    let _ = config.user.fields_mut().insert(
        "metadata".into(),
        UserFieldConfig {
            field_type: UserFieldType::Json,
            required: Some(false),
            ..Default::default()
        },
    );
    Arc::new(config)
}

fn context<S: AuthSchema>(
    config: Arc<AuthConfig>,
    store: Arc<dyn AuthStore<S>>,
    trace: &Arc<Trace>,
    secondary: bool,
) -> AuthResult<AuthContext<S>> {
    let store = store.with_runtime(config.clone(), vec![trace.clone()], Default::default())?;
    let store = if secondary {
        Arc::new(SecondaryStore::without_secondary(
            store,
            config.clone(),
            Default::default(),
        )) as Arc<dyn AuthStore<S>>
    } else {
        store
    };
    let mut context = AuthContext::new(config, store);
    context
        .extensions
        .insert(trace.clone() as Arc<dyn ValidateUserInfo<S>>);
    Ok(context)
}

async fn check_prepared_creation<S: AuthSchema>(
    context: AuthContext<S>,
    trace: Arc<Trace>,
) -> AuthResult<()> {
    let context = Arc::new(context);
    for mode in ["plain", "commit", "rollback"] {
        trace.0.lock().unwrap().clear();
        let created: FieldValue = FieldDate::from_milliseconds(1_600_000_000_000.0).into();
        let metadata: FieldValue = FieldMap::from([("source".into(), "runtime".into())]).into();
        let email = format!("{mode}@admission.test");
        let input = CreateUser {
            name: Some("Typed name".into()).into(),
            email: Some("typed@admission.test".into()),
            email_verified: Some(true),
            created_at: Some(FieldDate::from_milliseconds(0.0)),
            additional_fields: FieldMap::from([
                ("name".into(), "Runtime name".into()),
                ("email".into(), email.to_uppercase().into()),
                ("emailVerified".into(), FieldValue::Undefined),
                ("createdAt".into(), created.clone()),
                ("metadata".into(), metadata.clone()),
                ("ownUndefined".into(), FieldValue::Undefined),
            ]),
            ..Default::default()
        };
        let result = if mode == "plain" {
            create_user_optional(
                input,
                "contract",
                &EndpointContext::new(None, FieldValue::Null, &context),
            )
            .await
        } else {
            let active = context.clone();
            better_auth_core::store::transaction(context.database.as_ref(), move |tx| {
                Box::pin(async move {
                    let mut endpoint = EndpointContext::new(None, FieldValue::Null, &active);
                    endpoint.transaction = Some(tx);
                    let user = create_user_optional(input, "contract", &endpoint).await?;
                    if mode == "rollback" {
                        Err(AuthError::internal("admission-test-rollback"))
                    } else {
                        Ok(user)
                    }
                })
            })
            .await
        };
        let events = trace.0.lock().unwrap().clone();
        assert_eq!(
            events.iter().map(|event| event.0).collect::<Vec<_>>(),
            if mode == "rollback" {
                vec!["admission", "before"]
            } else {
                vec!["admission", "before", "after"]
            },
        );
        let admitted = &events[0].1;
        let before = &events[1].1;
        assert_eq!(admitted, before);
        assert_eq!(
            admitted.keys().collect::<Vec<_>>(),
            before.keys().collect::<Vec<_>>()
        );
        for (name, value) in admitted {
            assert!(
                value.strict_equals(&before[name]),
                "changed {name} identity"
            );
        }
        assert_eq!(admitted["name"], FieldValue::from("Runtime name"));
        assert_eq!(admitted["email"], FieldValue::from(email.clone()));
        assert!(admitted["emailVerified"].is_undefined());
        assert!(admitted["ownUndefined"].is_undefined());
        assert!(admitted["createdAt"].strict_equals(&created));
        assert!(admitted["metadata"].strict_equals(&metadata));
        assert!(matches!(admitted["updatedAt"], FieldValue::Date(_)));
        assert_eq!(events[0].2, mode != "plain");
        assert_eq!(events[1].2, mode != "plain");
        let stored = context.database.get_user_by_email(&email).await?;
        if mode == "rollback" {
            assert_eq!(
                result.unwrap_err().instrumentation_message(),
                "admission-test-rollback"
            );
            assert!(stored.is_none());
        } else {
            assert!(!events[2].2);
            let created = result?.unwrap();
            assert_eq!(stored.unwrap().id, created.id);
            assert_eq!(created.email_verified, false);
        }
    }
    Ok(())
}

#[tokio::test]
async fn admission_and_hooks_share_prepared_values_across_adapters_and_transactions()
-> AuthResult<()> {
    for secondary in [false, true] {
        let config = config();
        let trace = Arc::new(Trace::default());
        let memory: Arc<dyn AuthStore<StatelessSchema>> =
            Arc::new(EphemeralStore::new(config.clone()));
        check_prepared_creation(context(config.clone(), memory, &trace, secondary)?, trace).await?;
        let trace = Arc::new(Trace::default());
        let sqlite = test_helpers::create_test_database().await;
        check_prepared_creation(context(config, sqlite, &trace, secondary)?, trace).await?;
    }
    Ok(())
}

#[tokio::test]
async fn invalid_runtime_email_fails_before_admission_and_database_hooks() -> AuthResult<()> {
    let config = config();
    let trace = Arc::new(Trace::default());
    let memory: Arc<dyn AuthStore<StatelessSchema>> = Arc::new(EphemeralStore::new(config.clone()));
    let context = context(config, memory, &trace, false)?;
    let input = CreateUser {
        email: Some("typed@admission.test".into()),
        additional_fields: FieldMap::from([("email".into(), FieldMap::new().into())]),
        ..Default::default()
    };
    let error = create_user_optional(
        input,
        "contract",
        &EndpointContext::new(None, FieldValue::Null, &context),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.instrumentation_message(),
        "user.email.toLowerCase is not a function"
    );
    assert!(trace.0.lock().unwrap().is_empty());
    assert!(
        context
            .database
            .get_user_by_email("typed@admission.test")
            .await?
            .is_none()
    );
    Ok(())
}

struct SignupTrace {
    mode: &'static str,
    events: Mutex<Vec<&'static str>>,
    users: Mutex<Vec<FieldMap>>,
}

#[async_trait]
impl<S: AuthSchema> ValidateUserInfo<S> for SignupTrace {
    async fn validate(
        &self,
        data: &UserValidationData,
        _: &EndpointContext<'_, S>,
    ) -> AuthResult<Option<UserValidationRejection>> {
        self.events.lock().unwrap().push("admission");
        self.users.lock().unwrap().push(data.user.clone());
        assert_eq!(data.user["emailVerified"], FieldValue::Bool(false));
        assert_eq!(data.user.get("image"), Some(&FieldValue::Undefined));
        Ok(None)
    }
}

#[async_trait]
impl better_auth_core::utils::password::PasswordHasher for SignupTrace {
    async fn hash(&self, password: &str) -> AuthResult<String> {
        Ok(format!("fixture:{password}"))
    }

    async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
        Ok(hash == format!("fixture:{password}"))
    }
}

#[better_auth_core::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for SignupTrace {
    async fn before_create_user(
        &self,
        input: &mut FieldMap,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        self.events.lock().unwrap().push("before");
        self.users.lock().unwrap().push(input.clone());
        assert_eq!(input.get("image"), Some(&FieldValue::Undefined));
        match self.mode {
            "native" => Err(AuthError::internal("private user failure")),
            "api" => Err(AuthResponse::json(
                500,
                &serde_json::json!({"code":"APPLICATION_FAILURE", "message":"Public failure"}),
            )?
            .with_header("x-hook", "preserved")
            .into()),
            "forbidden" => Err(AuthError::Upstream {
                status: 403,
                code: "APPLICATION_DENIED",
                message: "Application denied user",
            }),
            "cancel" => Ok(DatabaseHookUpdate::Cancel),
            _ => Ok(DatabaseHookUpdate::Continue),
        }
    }

    async fn after_create_user(
        &self,
        user: Option<&UserView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.events.lock().unwrap().push("after");
        self.users
            .lock()
            .unwrap()
            .push(user.unwrap().clone().into());
        if self.mode == "after" {
            return Err(AuthError::internal("private committed failure"));
        }
        Ok(())
    }

    async fn before_create_account(
        &self,
        _: &mut better_auth_core::CreateAccount,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<better_auth_core::store::database_hooks::DatabaseHookControl> {
        self.events.lock().unwrap().push("account");
        if self.mode == "account" {
            return Err(AuthError::internal("private account failure"));
        }
        Ok(better_auth_core::store::database_hooks::DatabaseHookControl::Continue)
    }
}

async fn check_signup_failure<S: AuthSchema>(
    store: Arc<dyn AuthStore<S>>,
    mode: &'static str,
    protected: bool,
) -> AuthResult<()> {
    use better_auth_core::{AuthPlugin, HttpMethod};

    let mut config = test_helpers::create_test_config();
    let _ = config.user.fields_mut().insert(
        "emailVerified".into(),
        UserFieldConfig {
            field_type: UserFieldType::Boolean,
            required: Some(false),
            ..Default::default()
        },
    );
    if mode == "normalize" {
        let _ = config.user.fields_mut().insert(
            "email".into(),
            UserFieldConfig {
                field_type: UserFieldType::Json,
                default_value: Some(FieldMap::new().into()),
                ..Default::default()
            },
        );
    }
    let config = Arc::new(config);
    let trace = Arc::new(SignupTrace {
        mode,
        events: Mutex::default(),
        users: Mutex::default(),
    });
    let store = store.with_runtime(config.clone(), vec![trace.clone()], Default::default())?;
    let mut context = AuthContext::new(config, store);
    context.password_policy.hasher = Some(trace.clone());
    context
        .extensions
        .insert(trace.clone() as Arc<dyn ValidateUserInfo<S>>);
    let plugin =
        crate::plugins::email_password::EmailPasswordPlugin::new().auto_sign_in(!protected);
    let request = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/sign-up/email",
        None,
        Some(
            serde_json::json!({
                "name":"Signup", "email":"signup@admission.test", "password":"Password123!",
                "emailVerified":true,
            })
            .to_string()
            .into_bytes(),
        ),
    );
    let response = match plugin.on_request(&request, &context).await {
        Ok(response) => response.unwrap(),
        Err(error) => error.to_http_response(),
    };
    let expected_status = match mode {
        "normalize" | "native" => 422,
        "cancel" => 400,
        "forbidden" if protected => 200,
        "forbidden" => 403,
        _ => 500,
    };
    assert_eq!(response.status, expected_status, "{mode}");
    if matches!(mode, "normalize" | "native" | "cancel") {
        assert_eq!(
            response.body.json()?,
            Some(serde_json::json!({
                "code":"FAILED_TO_CREATE_USER", "message":"Failed to create user",
            }))
        );
    } else if mode == "api" {
        assert_eq!(
            response.body.json()?,
            Some(serde_json::json!({
                "code":"APPLICATION_FAILURE", "message":"Public failure",
            }))
        );
        assert_eq!(
            response.headers.get("x-hook").map(String::as_str),
            Some("preserved")
        );
    } else if mode == "forbidden" && !protected {
        assert_eq!(
            response.body.json()?,
            Some(serde_json::json!({
                "code":"APPLICATION_DENIED", "message":"Application denied user",
            }))
        );
    } else if matches!(mode, "account" | "after") {
        assert!(response.body.is_empty());
    } else {
        let body = response.body.json()?.unwrap();
        assert_eq!(body["token"], serde_json::Value::Null);
        assert_eq!(body["user"]["email"], "signup@admission.test");
    }
    let expected_events = match mode {
        "normalize" => vec![],
        "account" => vec!["admission", "before", "account"],
        "after" => vec!["admission", "before", "account", "after"],
        _ => vec!["admission", "before"],
    };
    assert_eq!(*trace.events.lock().unwrap(), expected_events, "{mode}");
    let (users, total) = context.database.list_users(Default::default()).await?;
    assert_eq!(total, usize::from(mode == "after"), "{mode}");
    if mode == "after" {
        let user = &users[0];
        assert_eq!(
            context
                .database
                .get_user_accounts(user.id.typed()?)
                .await?
                .len(),
            1
        );
        assert!(
            context
                .database
                .get_user_sessions(user.id.typed()?)
                .await?
                .is_empty()
        );
    }
    Ok(())
}

#[tokio::test]
async fn signup_keeps_the_creation_error_boundary_and_transaction_lifecycle() -> AuthResult<()> {
    for (mode, protected) in [
        ("normalize", true),
        ("native", true),
        ("api", true),
        ("forbidden", true),
        ("forbidden", false),
        ("cancel", true),
        ("account", true),
        ("after", true),
    ] {
        let memory: Arc<dyn AuthStore<StatelessSchema>> = Arc::new(EphemeralStore::new(config()));
        check_signup_failure(memory, mode, protected).await?;
        check_signup_failure(test_helpers::create_test_database().await, mode, protected).await?;
    }
    Ok(())
}

#[derive(Default)]
struct EmailOtpTrace {
    events: Mutex<Vec<(&'static str, FieldMap)>>,
    validators: Mutex<Vec<&'static str>>,
    deliveries: Mutex<Vec<serde_json::Value>>,
}

#[async_trait]
impl<S: AuthSchema> ValidateUserInfo<S> for EmailOtpTrace {
    async fn validate(
        &self,
        data: &UserValidationData,
        _: &EndpointContext<'_, S>,
    ) -> AuthResult<Option<UserValidationRejection>> {
        assert_eq!(
            serde_json::to_value(&data.source)?,
            serde_json::json!({"method":"email-otp", "action":"create-user"}),
        );
        self.events
            .lock()
            .unwrap()
            .push(("admission", data.user.clone()));
        Ok(None)
    }
}

#[async_trait]
impl crate::plugins::email_otp::SendEmailOtp for EmailOtpTrace {
    async fn send(&self, message: &crate::plugins::email_otp::EmailOtpMessage) -> AuthResult<()> {
        self.deliveries
            .lock()
            .unwrap()
            .push(serde_json::to_value(message)?);
        Ok(())
    }
}

#[better_auth_core::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for EmailOtpTrace {
    async fn before_create_user(
        &self,
        input: &mut FieldMap,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        self.events.lock().unwrap().push(("before", input.clone()));
        Ok(DatabaseHookUpdate::Continue)
    }

    async fn after_create_user(
        &self,
        user: Option<&UserView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.events
            .lock()
            .unwrap()
            .push(("after", user.unwrap().clone().into()));
        Ok(())
    }
}

async fn check_email_otp_fields<S: AuthSchema>(
    store: Arc<dyn AuthStore<S>>,
    sqlite: bool,
    image_provided: bool,
) -> AuthResult<()> {
    use better_auth_core::{AuthPlugin, HttpMethod, user_fields::FieldValidators};

    let trace = Arc::new(EmailOtpTrace::default());
    let mut config = test_helpers::create_test_config();
    for name in ["email", "name", "image", "otp"] {
        let observer = trace.clone();
        let _ = config.user.fields_mut().insert(
            name.into(),
            UserFieldConfig {
                field_type: UserFieldType::String,
                required: Some(false),
                field_name: (name == "otp").then(|| "username".into()),
                validator: Some(FieldValidators {
                    input: Some(Arc::new(move |_| {
                        observer.validators.lock().unwrap().push(name);
                        Ok(format!("parsed-{name}").into())
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
    }
    let _ = config.user.fields_mut().insert(
        "emailVerified".into(),
        UserFieldConfig {
            field_type: UserFieldType::Boolean,
            required: Some(false),
            default_value: Some(false.into()),
            ..Default::default()
        },
    );
    let config = Arc::new(config);
    let store = store.with_runtime(config.clone(), vec![trace.clone()], Default::default())?;
    let mut context = AuthContext::new(config, store);
    context
        .extensions
        .insert(trace.clone() as Arc<dyn ValidateUserInfo<S>>);
    let plugin = crate::plugins::email_otp::EmailOtpPlugin::with_config(
        crate::plugins::email_otp::EmailOtpConfig {
            sender: Some(trace.clone()),
            generate_otp: Some(Arc::new(|_, _| Some("123456".into()))),
            ..Default::default()
        },
    );
    let request = |path, body: serde_json::Value| {
        test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            path,
            None,
            Some(body.to_string().into_bytes()),
        )
    };
    let email = "otp@admission.test";
    let image = "https://admission.test/avatar.png";
    let sent = plugin
        .on_request(
            &request(
                "/email-otp/send-verification-otp",
                serde_json::json!({"email":email.to_uppercase(), "type":"sign-in"}),
            ),
            &context,
        )
        .await?
        .unwrap();
    assert_eq!(sent.status, 200);
    assert_eq!(sent.body.json()?, Some(serde_json::json!({"success":true})));
    assert_eq!(
        *trace.deliveries.lock().unwrap(),
        [serde_json::json!({"email":email, "otp":"123456", "type":"sign-in"})],
    );
    let mut body = serde_json::json!({
        "email":email.to_uppercase(), "otp":"123456", "name":"OTP Owner",
    });
    if image_provided {
        body["image"] = image.into();
    }
    let response = plugin
        .on_request(&request("/sign-in/email-otp", body), &context)
        .await?
        .unwrap();
    assert_eq!(response.status, 200);
    assert!(trace.validators.lock().unwrap().is_empty());
    let events = trace.events.lock().unwrap().clone();
    assert_eq!(
        events.iter().map(|event| event.0).collect::<Vec<_>>(),
        ["admission", "before", "after"],
    );
    let admitted = &events[0].1;
    assert!(matches!(admitted["createdAt"], FieldValue::Date(_)));
    assert!(matches!(admitted["updatedAt"], FieldValue::Date(_)));
    let expected_input = FieldMap::from([
        ("createdAt".into(), admitted["createdAt"].clone()),
        ("updatedAt".into(), admitted["updatedAt"].clone()),
        ("emailVerified".into(), true.into()),
        ("email".into(), email.into()),
        ("name".into(), "OTP Owner".into()),
        (
            "image".into(),
            if image_provided {
                image.into()
            } else {
                FieldValue::Undefined
            },
        ),
    ]);
    assert_eq!(admitted, &expected_input);
    assert_eq!(
        admitted.keys().collect::<Vec<_>>(),
        expected_input.keys().collect::<Vec<_>>(),
    );
    assert_eq!(events[1].1, expected_input);
    let user = context.database.get_user_by_email(email).await?.unwrap();
    assert!(!user.id.typed()?.is_empty());
    let absent = if sqlite {
        FieldValue::Null
    } else {
        FieldValue::Undefined
    };
    let expected_stored = FieldMap::from([
        ("id".into(), user.id.field_value()),
        ("name".into(), "OTP Owner".into()),
        ("email".into(), email.into()),
        ("emailVerified".into(), true.into()),
        (
            "image".into(),
            if image_provided {
                image.into()
            } else {
                absent.clone()
            },
        ),
        ("createdAt".into(), admitted["createdAt"].clone()),
        ("updatedAt".into(), admitted["updatedAt"].clone()),
        ("otp".into(), absent),
    ]);
    assert_eq!(FieldMap::from(user.clone()), expected_stored);
    assert_eq!(events[2].1, expected_stored);
    let sessions = context.database.get_user_sessions(user.id.typed()?).await?;
    assert_eq!(sessions.len(), 1);
    assert!(!sessions[0].token.typed()?.is_empty());
    assert_eq!(
        response.body.json()?,
        Some(serde_json::json!({
            "token":sessions[0].token.typed()?, "user":expected_stored.json()?,
        })),
    );
    assert_eq!(context.database.list_users(Default::default()).await?.1, 1);
    assert!(
        context
            .database
            .get_verification_by_identifier(&format!("sign-in-otp-{email}"))
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn email_otp_owns_verified_and_reserved_user_fields() -> AuthResult<()> {
    for image_provided in [false, true] {
        let memory: Arc<dyn AuthStore<StatelessSchema>> = Arc::new(EphemeralStore::new(config()));
        check_email_otp_fields(memory, false, image_provided).await?;
        check_email_otp_fields(
            test_helpers::create_test_database().await,
            true,
            image_provided,
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn signup_preserves_native_phone_fields_from_enabled_plugin_declarations() -> AuthResult<()> {
    use better_auth_core::{
        AuthInitContext, AuthPlugin, HttpMethod, plugin_runtime::AdapterUserFields,
        store::schema::SchemaConfiguration,
    };

    let config = Arc::new(test_helpers::create_test_config());
    let store: Arc<dyn AuthStore<StatelessSchema>> = Arc::new(EphemeralStore::new(config.clone()));
    let mut init = AuthInitContext::new(config.clone(), store.clone());
    crate::plugins::phone_number::PhoneNumberPlugin::new()
        .on_init(&mut init)
        .await?;
    crate::plugins::anonymous::AnonymousPlugin::new()
        .on_init(&mut init)
        .await?;
    let parts = init.into_parts();
    let (adapter, endpoint, mut fields) = parts.plugin_fields.clone().resolve(&config);
    let adapter_fields = adapter.user.clone();
    let adapter = Arc::new(adapter);
    fields.set_schema_configuration(&SchemaConfiguration {
        config: adapter.clone(),
        plugins: vec!["phone-number", "anonymous"],
        metadata: parts.metadata.clone(),
        secondary_storage: false,
        database_rate_limit: false,
    });
    let trace = Arc::new(SignupTrace {
        mode: "native-phone",
        events: Mutex::default(),
        users: Mutex::default(),
    });
    let store = store.with_runtime(adapter, vec![trace.clone()], fields)?;
    let mut context = AuthContext::new(Arc::new(endpoint), store);
    context.metadata = parts.metadata;
    context.extensions = parts.extensions;
    context.extensions.insert(AdapterUserFields(adapter_fields));
    context
        .extensions
        .insert(trace.clone() as Arc<dyn ValidateUserInfo<StatelessSchema>>);
    context.password_policy.hasher = Some(trace.clone());
    let plugin = crate::plugins::email_password::EmailPasswordPlugin::new().auto_sign_in(false);
    let request = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/sign-up/email",
        None,
        Some(
            serde_json::json!({
                "name":"Phone Owner", "email":"phone@admission.test",
                "password":"Password123!", "phoneNumber":7,
            })
            .to_string()
            .into_bytes(),
        ),
    );
    let response = plugin.on_request(&request, &context).await?.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(
        *trace.events.lock().unwrap(),
        ["admission", "before", "account", "after"],
    );
    let users = trace.users.lock().unwrap().clone();
    assert_eq!(users.len(), 3);
    let admitted = &users[0];
    assert!(matches!(admitted["createdAt"], FieldValue::Date(_)));
    assert!(matches!(admitted["updatedAt"], FieldValue::Date(_)));
    let expected_input = FieldMap::from([
        ("createdAt".into(), admitted["createdAt"].clone()),
        ("updatedAt".into(), admitted["updatedAt"].clone()),
        ("email".into(), "phone@admission.test".into()),
        ("name".into(), "Phone Owner".into()),
        ("image".into(), FieldValue::Undefined),
        ("phoneNumber".into(), 7.into()),
        ("isAnonymous".into(), false.into()),
        ("emailVerified".into(), false.into()),
    ]);
    assert_eq!(admitted, &expected_input);
    assert_eq!(
        admitted.keys().collect::<Vec<_>>(),
        expected_input.keys().collect::<Vec<_>>(),
    );
    assert_eq!(users[1], expected_input);
    assert_eq!(
        users[1].keys().collect::<Vec<_>>(),
        expected_input.keys().collect::<Vec<_>>(),
    );
    let user = context
        .database
        .get_user_by_email("phone@admission.test")
        .await?
        .unwrap();
    assert!(!user.id.typed()?.is_empty());
    let mut expected_stored = expected_input;
    let _ = expected_stored.insert("id".into(), user.id.field_value());
    let _ = expected_stored.insert("phoneNumberVerified".into(), FieldValue::Undefined);
    assert_eq!(FieldMap::from(user.clone()), expected_stored);
    assert_eq!(users[2], expected_stored);
    assert_eq!(
        response.body.json()?,
        Some(serde_json::json!({"token":null, "user":expected_stored.json()?})),
    );
    assert_eq!(context.database.list_users(Default::default()).await?.1, 1);
    assert_eq!(
        context
            .database
            .get_user_accounts(user.id.typed()?)
            .await?
            .len(),
        1,
    );
    assert!(
        context
            .database
            .get_user_sessions(user.id.typed()?)
            .await?
            .is_empty()
    );
    Ok(())
}
