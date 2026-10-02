use better_auth::__private_core::__private_async_trait::async_trait;
use better_auth::{
    __private_core::{
        AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
        AuthRoute, AuthSchema, AuthStore, CreateDeviceCode, CreateUser, DeviceCode,
        DeviceCodeOwnership, UpdateDeviceCode,
        store::schema::EntityRole,
        user_fields::{
            FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
        },
    },
    AuthConfig, BetterAuth,
    plugins::DeviceAuthorizationPlugin,
};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};

pub(crate) struct Fields(pub(crate) UserConfig);

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Fields {
    fn name(&self) -> &'static str {
        "ordinary-device-additional-fields"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        context.register_model_fields(EntityRole::DeviceCode, self.0.clone())
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

pub(crate) fn config() -> AuthConfig {
    AuthConfig::new("ordinary-device-extra-fields-secret-at-least-32-characters")
        .base_url("http://device-fields.test")
}

pub(crate) fn policies(failure: Arc<AtomicU8>) -> UserConfig {
    let input_failure = failure.clone();
    UserConfig {
        additional_fields: Some(
            [
                (
                    "label".into(),
                    UserFieldConfig {
                        field_name: Some("stored_label".into()),
                        required: Some(false),
                        default_value: Some(json!(" Default ")),
                        transform: Some(FieldTransforms {
                            input: Some(UserFieldTransform::new(move |value| {
                                if input_failure.load(Ordering::SeqCst) == 1 {
                                    return Err(AuthError::internal(
                                        "ordinary additional input error",
                                    ));
                                }
                                Ok(value.map(|value| match value {
                                    Value::String(value) => json!(value.trim()),
                                    value => value,
                                }))
                            })),
                            output: Some(UserFieldTransform::new(move |value| {
                                if failure.load(Ordering::SeqCst) == 2 {
                                    return Err(AuthError::internal(
                                        "ordinary additional output error",
                                    ));
                                }
                                Ok(value.map(|value| match value {
                                    Value::String(value) => json!(format!("{value}:out")),
                                    value => value,
                                }))
                            })),
                        }),
                        ..Default::default()
                    },
                ),
                (
                    "activatedAt".into(),
                    UserFieldConfig {
                        field_type: UserFieldType::Date,
                        field_name: Some("stored_activation".into()),
                        required: Some(false),
                        ..Default::default()
                    },
                ),
                (
                    "details".into(),
                    UserFieldConfig {
                        field_type: UserFieldType::Json,
                        field_name: Some("stored_details".into()),
                        required: Some(false),
                        ..Default::default()
                    },
                ),
                (
                    "revision".into(),
                    UserFieldConfig {
                        field_type: UserFieldType::Number,
                        field_name: Some("stored_revision".into()),
                        required: Some(false),
                        default_value: Some(json!(1.5)),
                        on_update: Some(Arc::new(|| json!(2.5))),
                        ..Default::default()
                    },
                ),
            ]
            .into(),
        ),
    }
}

pub(crate) fn input(label: &str) -> CreateDeviceCode {
    CreateDeviceCode {
        device_code: format!("ordinary-device:{label}"),
        user_code: format!("ordinary-user:{label}"),
        user_id: None,
        expires_at: "2030-01-01T00:00:00Z"
            .parse()
            .expect("fixed fixture date parses"),
        status: "pending".into(),
        last_polled_at: None,
        polling_interval: Some(5000.0),
        client_id: Some("ordinary-client".into()),
        scope: Some("read".into()).into(),
        additional_fields: [
            ("activatedAt".into(), json!("2029-01-02T03:04:05.000Z")),
            (
                "details".into(),
                json!({"channel":"ordinary","enabled":true}),
            ),
        ]
        .into_iter()
        .collect(),
    }
}

fn observe(name: &str, row: &DeviceCode) -> AuthResult<Value> {
    let serialized = serde_json::to_value(row)?;
    assert_eq!(serialized.get("label"), row.additional_fields.get("label"));
    assert!(serialized.get("additional_fields").is_none());
    Ok(json!({"name":name, "scope":row.scope.json()?, "fields":row.additional_fields}))
}

pub(crate) async fn contract<S: AuthSchema>(
    raw: Arc<dyn AuthStore<S>>,
    backend: &str,
) -> AuthResult<()> {
    let failure = Arc::new(AtomicU8::new(0));
    let auth = BetterAuth::new(config())
        .store_arc(raw.clone())
        .plugin(DeviceAuthorizationPlugin::new())
        .plugin(Fields(policies(failure.clone())))
        .build()
        .await?;
    let owner = raw
        .create_user(
            CreateUser::new()
                .with_name("Owner")
                .with_email("owner@device-fields.test"),
        )
        .await?
        .id
        .typed()?
        .clone();
    let store = auth.store();
    let created = store.create_device_code(input("main")).await?;
    let mut cases = vec![observe("create", &created)?];
    let read = store
        .get_device_code_by_user_code(&created.user_code)
        .await?
        .expect("created Device exists");
    cases.push(observe("read", &read)?);
    let updated = store
        .update_device_code(
            &created.id,
            UpdateDeviceCode {
                additional_fields: [("label".into(), json!(" Changed "))].into_iter().collect(),
                ..Default::default()
            },
        )
        .await?;
    cases.push(observe("update", &updated)?);
    assert!(store.claim_device_code(&created.id, &owner).await?);
    let claimed = store
        .get_device_code_by_device_code(&created.device_code)
        .await?
        .expect("claimed Device exists");
    assert_eq!(claimed.user_id.as_deref(), Some(owner.as_str()));
    cases.push(observe("claim", &claimed)?);
    assert!(
        store
            .update_device_code_if_status(
                &created.id,
                "pending",
                UpdateDeviceCode {
                    status: Some("approved".into()),
                    ..Default::default()
                }
            )
            .await?
    );
    let approved = store
        .get_device_code_by_device_code(&created.device_code)
        .await?
        .expect("approved Device exists");
    cases.push(observe("approve", &approved)?);
    let _ = store
        .update_device_code(
            &created.id,
            UpdateDeviceCode {
                additional_fields: [("label".into(), json!(" Final "))].into_iter().collect(),
                ..Default::default()
            },
        )
        .await?;
    let consumed = store
        .consume_device_code(
            &approved,
            &DeviceCodeOwnership::ClientId("ordinary-client".into()),
        )
        .await?
        .expect("approved Device is consumed");
    assert_eq!(consumed.id, created.id);
    assert_eq!(consumed.device_code, created.device_code);
    assert_eq!(consumed.client_id, created.client_id);
    assert_eq!(consumed.user_id.as_deref(), Some(owner.as_str()));
    assert_eq!(consumed.status, "approved");
    assert!(
        store
            .get_device_code_by_device_code(&created.device_code)
            .await?
            .is_none()
    );
    cases.push(observe("consume", &consumed)?);
    for (mode, label, message) in [
        (1, "input-error", "ordinary additional input error"),
        (2, "output-error", "ordinary additional output error"),
    ] {
        failure.store(mode, Ordering::SeqCst);
        let error = store
            .create_device_code(input(label))
            .await
            .expect_err("application callback returns its original error");
        assert!(matches!(error, AuthError::Internal(ref value) if value == message));
        failure.store(0, Ordering::SeqCst);
        let persisted = raw
            .get_device_code_by_device_code(&format!("ordinary-device:{label}"))
            .await?
            .is_some();
        cases.push(json!({"name":label, "sameError":true, "persisted":persisted}));
    }
    let expected: Value = serde_json::from_str(include_str!(
        "../fixtures/device-additional-fields-1.7.6.json"
    ))?;
    assert_eq!(expected["version"], "1.7.6");
    let expected = expected["backends"]
        .as_array()
        .expect("fixture contains backends")
        .iter()
        .find(|value| value["backend"] == backend)
        .expect("fixture contains this backend");
    assert_eq!(json!({"backend":backend,"cases":cases}), *expected);
    Ok(())
}
