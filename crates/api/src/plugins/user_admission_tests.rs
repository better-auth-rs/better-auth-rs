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
}

#[async_trait]
impl<S: AuthSchema> ValidateUserInfo<S> for SignupTrace {
    async fn validate(
        &self,
        data: &UserValidationData,
        _: &EndpointContext<'_, S>,
    ) -> AuthResult<Option<UserValidationRejection>> {
        self.events.lock().unwrap().push("admission");
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
        _: Option<&UserView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.events.lock().unwrap().push("after");
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
