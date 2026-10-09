use super::*;
use better_auth_core::{
    AuthSchema, CreateUser, CreateVerification, FieldDate, FieldMap, FieldValue,
    plugin_runtime::{AdapterUserFields, ApplicationUserFields, resolve_user_fields},
    store::database_hooks::{DatabaseHookContext, DatabaseHookUpdate, DatabaseHooks},
    store::{AuthStore, EphemeralStore, RuntimeStore, StatelessSchema, UserStore},
    user_fields::{UserConfig, UserFieldConfig},
};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

struct Password;

#[async_trait]
impl PasswordHasher for Password {
    async fn hash(&self, password: &str) -> AuthResult<String> {
        Ok(format!("hashed:{password}"))
    }

    async fn verify(&self, hash: &str, password: &str) -> AuthResult<bool> {
        Ok(hash == format!("hashed:{password}"))
    }
}

#[tokio::test]
async fn duplicate_signup_filters_custom_synthetic_user_without_writes() -> AuthResult<()> {
    let mut config = crate::plugins::test_helpers::create_test_config();
    let store = Arc::new(EphemeralStore::new(Arc::new(config.clone())));
    let existing = store
        .create_user(CreateUser {
            email_verified: Some(true),
            ..CreateUser::new()
                .with_name("Existing")
                .with_email("owner@synthetic.test")
        })
        .await?;
    config.user.fields_mut().extend([
        (
            "id".into(),
            UserFieldConfig {
                required: Some(false),
                returned: Some(false),
                ..Default::default()
            },
        ),
        (
            "fallback".into(),
            UserFieldConfig {
                required: Some(false),
                default_value: Some("default".into()),
                ..Default::default()
            },
        ),
        (
            "factory".into(),
            UserFieldConfig {
                required: Some(false),
                default_value_fn: Some(Arc::new(|| Ok(FieldValue::Undefined))),
                ..Default::default()
            },
        ),
        (
            "choice".into(),
            UserFieldConfig {
                required: Some(false),
                default_value: Some("application".into()),
                ..Default::default()
            },
        ),
        (
            "username".into(),
            UserFieldConfig {
                required: Some(false),
                default_value: Some("application-user".into()),
                ..Default::default()
            },
        ),
    ]);
    let application = config.user.clone();
    let (adapter, endpoint) = resolve_user_fields(
        &application,
        UserConfig {
            additional_fields: Some(
                [
                    (
                        "choice".into(),
                        UserFieldConfig {
                            required: Some(false),
                            default_value: Some("plugin".into()),
                            ..Default::default()
                        },
                    ),
                    (
                        "pluginOnly".into(),
                        UserFieldConfig {
                            required: Some(false),
                            default_value: Some("plugin-only".into()),
                            ..Default::default()
                        },
                    ),
                ]
                .into(),
            ),
        },
    );
    config.user = adapter.clone();
    let store = store.with_runtime(Arc::new(config.clone()), vec![], Default::default())?;
    config.user = endpoint;
    let mut context = AuthContext::new(Arc::new(config), store);
    context.extensions.insert(AdapterUserFields(adapter));
    context
        .extensions
        .insert(ApplicationUserFields(application));
    context.password_policy.hasher = Some(Arc::new(Password));
    let before: FieldMap = context
        .database
        .get_user_by_email("owner@synthetic.test")
        .await?
        .unwrap()
        .into();
    let synthetic_id = Arc::new(Mutex::new(String::new()));
    let captured_id = synthetic_id.clone();
    let plugin = EmailPasswordPlugin::new()
        .auto_sign_in(false)
        .custom_synthetic_user(Arc::new(move |input| {
            assert_eq!(
                input.additional_fields,
                FieldMap::from([
                    ("fallback".into(), "default".into()),
                    ("factory".into(), FieldValue::Undefined),
                    ("choice".into(), "plugin".into()),
                    ("username".into(), "application-user".into()),
                ])
            );
            assert_eq!(
                input
                    .additional_fields
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                ["fallback", "factory", "choice", "username"]
            );
            captured_id.lock().unwrap().clone_from(&input.id);
            let mut fields = input.core_fields;
            fields.extend([
                ("id".into(), input.id.into()),
                ("createdAt".into(), FieldDate::from_milliseconds(0.0).into()),
                ("updatedAt".into(), FieldDate::from_milliseconds(0.0).into()),
                ("fallback".into(), FieldValue::Undefined),
                ("factory".into(), FieldValue::Undefined),
            ]);
            Ok(fields)
        }));
    let request = crate::plugins::test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/sign-up/email",
        None,
        Some(
            serde_json::json!({
                "name": "Submitted", "email": "owner@synthetic.test", "password": "Password123!",
            })
            .to_string()
            .into_bytes(),
        ),
    );
    let response = plugin.on_request(&request, &context).await?.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(
        response.body.json()?,
        Some(serde_json::json!({"token": null, "user": {
            "name": "Submitted", "email": "owner@synthetic.test", "emailVerified": false,
            "image": null, "createdAt": "1970-01-01T00:00:00.000Z",
            "updatedAt": "1970-01-01T00:00:00.000Z", "fallback": "default",
            "choice": "plugin", "pluginOnly": "plugin-only", "username": "application-user",
        }}))
    );
    let response = crate::plugins::test_helpers::finalize_response(&context, &request, response);
    assert!(!response.headers.contains_key("set-cookie"));
    let (users, total) = context.database.list_users(Default::default()).await?;
    assert_eq!(total, 1);
    assert_eq!(FieldMap::from(users[0].clone()), before);
    let ids = [
        existing.id.typed()?.clone(),
        synthetic_id.lock().unwrap().clone(),
    ];
    for id in ids {
        assert!(context.database.get_user_sessions(&id).await?.is_empty());
        assert!(context.database.get_user_accounts(&id).await?.is_empty());
    }
    Ok(())
}

struct RejectAfterWrite {
    events: Arc<Mutex<Vec<&'static str>>>,
    denied: Arc<AtomicBool>,
}

#[better_auth_core::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for RejectAfterWrite {
    async fn before_create_user(
        &self,
        _: &mut FieldMap,
        context: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        self.events.lock().unwrap().push("before");
        let tx = context.transaction.unwrap();
        let _ = tx
            .create_verification(CreateVerification {
                identifier: "synthetic-effect".to_string().into(),
                value: "written-before-denial".to_string().into(),
                expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).into(),
                ..Default::default()
            })
            .await?;
        assert_eq!(
            tx.get_verification_including_expired("synthetic-effect")
                .await?
                .unwrap()
                .value,
            "written-before-denial"
        );
        self.events.lock().unwrap().push("write");
        self.denied.store(true, Ordering::SeqCst);
        Err(AuthError::Upstream {
            status: 403,
            code: "APPLICATION_DENIED",
            message: "Application denied user",
        })
    }
}

async fn check_synthetic_transaction<S: AuthSchema>(
    store: Arc<dyn AuthStore<S>>,
    mode: &'static str,
) -> AuthResult<()> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let denied = Arc::new(AtomicBool::new(false));
    let hooks = Arc::new(RejectAfterWrite {
        events: events.clone(),
        denied: denied.clone(),
    });
    let mut config = crate::plugins::test_helpers::create_test_config();
    let default_events = events.clone();
    let _ = config.user.fields_mut().insert(
        "probe".into(),
        UserFieldConfig {
            required: Some(false),
            default_value_fn: Some(Arc::new(move || {
                if denied.load(Ordering::SeqCst) {
                    default_events.lock().unwrap().push("default");
                    if mode == "default" {
                        return Err(AuthError::internal("synthetic default failed"));
                    }
                }
                Ok("parsed".into())
            })),
            ..Default::default()
        },
    );
    let config = Arc::new(config);
    let store = store.with_runtime(config.clone(), vec![hooks], Default::default())?;
    let mut context = AuthContext::new(config, store);
    context.password_policy.hasher = Some(Arc::new(Password));
    let factory_events = events.clone();
    let plugin = EmailPasswordPlugin::new()
        .auto_sign_in(false)
        .custom_synthetic_user(Arc::new(move |input| {
            factory_events.lock().unwrap().push("factory");
            if mode == "factory" {
                return Err(AuthError::internal("synthetic factory failed"));
            }
            let mut fields = input.core_fields;
            fields.extend([
                ("id".into(), input.id.into()),
                ("createdAt".into(), FieldDate::from_milliseconds(0.0).into()),
                ("updatedAt".into(), FieldDate::from_milliseconds(0.0).into()),
            ]);
            Ok(fields)
        }));
    let request = crate::plugins::test_helpers::create_auth_request_no_query(
        HttpMethod::Post, "/sign-up/email", None,
        Some(serde_json::json!({"name":"Denied", "email":"denied@synthetic.test", "password":"Password123!"}).to_string().into_bytes()),
    );
    let result = plugin.on_request(&request, &context).await;
    if mode == "success" {
        let response = result?.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body.json()?.unwrap()["user"]["probe"], "parsed");
    } else {
        let error = result.unwrap_err();
        assert_eq!(error.status_code(), 500);
        assert_eq!(
            error.instrumentation_message(),
            format!("synthetic {mode} failed")
        );
    }
    assert_eq!(
        *events.lock().unwrap(),
        if mode == "factory" {
            vec!["before", "write", "factory"]
        } else {
            vec!["before", "write", "factory", "default"]
        },
    );
    let effect = context
        .database
        .get_verification_including_expired("synthetic-effect")
        .await?;
    assert_eq!(effect.is_some(), mode == "success");
    if let Some(effect) = effect {
        assert_eq!(effect.value, "written-before-denial");
    }
    assert_eq!(context.database.list_users(Default::default()).await?.1, 0);
    Ok(())
}

#[tokio::test]
async fn synthetic_factory_failure_rolls_back_protected_signup_hook_writes() -> AuthResult<()> {
    for mode in ["success", "factory", "default"] {
        let memory: Arc<dyn AuthStore<StatelessSchema>> = Arc::new(EphemeralStore::default());
        check_synthetic_transaction(memory, mode).await?;
        check_synthetic_transaction(
            crate::plugins::test_helpers::create_test_database().await,
            mode,
        )
        .await?;
    }
    Ok(())
}
