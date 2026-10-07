use better_auth::{AuthConfig, BetterAuth, plugins::DeviceAuthorizationPlugin};
use better_auth_core::{
    AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
    AuthRoute, AuthSchema, CreateDeviceCode, CreateUser, DeviceCode, DeviceCodeOwnership,
    DeviceCodeWhere, FieldDate, FieldMap, FieldValue, SchemaValue, UpdateDeviceCode, WhereMode,
    WhereOperator,
    store::{AuthTransaction, EphemeralStore, StatelessSchema, schema::EntityRole, transaction},
    user_fields::{UserConfig, UserFieldConfig, UserFieldType},
};
use std::sync::Arc;

struct Fields;

#[async_trait::async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Fields {
    fn name(&self) -> &'static str {
        "device-runtime-transaction-fields"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        context.register_model_fields(
            EntityRole::DeviceCode,
            UserConfig {
                additional_fields: Some(
                    [
                        ("quantity", UserFieldType::Number, "stored_quantity"),
                        ("scope", UserFieldType::String, "scope"),
                        ("runtime", UserFieldType::NumberArray, "stored_runtime"),
                    ]
                    .into_iter()
                    .map(|(name, field_type, storage)| {
                        (
                            name.into(),
                            UserFieldConfig {
                                field_type,
                                field_name: Some(storage.into()),
                                required: Some(false),
                                ..Default::default()
                            },
                        )
                    })
                    .collect(),
                ),
            },
        )
    }

    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

fn nested(value: FieldValue) -> FieldValue {
    vec![FieldValue::from(FieldMap::from([
        ("value".into(), value),
        ("date".into(), FieldValue::Date(FieldDate::invalid())),
        ("optional".into(), FieldValue::Undefined),
    ]))]
    .into()
}

fn update(field: &str, value: FieldValue) -> UpdateDeviceCode {
    if field == "scope" {
        UpdateDeviceCode {
            scope: SchemaValue::Dynamic(value),
            ..Default::default()
        }
    } else {
        UpdateDeviceCode {
            additional_fields: [(field.into(), value)].into(),
            ..Default::default()
        }
    }
}

async fn setup(
    field: &str,
    value: FieldValue,
) -> AuthResult<(BetterAuth<StatelessSchema>, DeviceCode)> {
    let mut config = AuthConfig::new("device-runtime-transaction-secret-at-least-32-characters")
        .base_url("http://device-runtime.test");
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    let raw = Arc::new(EphemeralStore::new(Arc::new(config.clone())));
    let auth = BetterAuth::new(config)
        .store_arc(raw)
        .plugin(DeviceAuthorizationPlugin::new())
        .plugin(Fields)
        .build()
        .await?;
    let owner = auth
        .store()
        .create_user(CreateUser::new().with_email("owner@device-runtime.test"))
        .await?;
    let fields = update(field, value);
    let row = auth
        .store()
        .create_device_code(CreateDeviceCode {
            device_code: "runtime-device".into(),
            user_code: "runtime-user".into(),
            user_id: Some(owner.id.typed()?.clone()),
            expires_at: FieldDate::from_milliseconds(4_102_444_800_000.0),
            status: "approved".into(),
            last_polled_at: None,
            polling_interval: Some(5000.0),
            client_id: Some("runtime-client".into()),
            scope: fields.scope,
            additional_fields: fields.additional_fields,
        })
        .await?;
    Ok((auth, row))
}

async fn consume(tx: &dyn AuthTransaction<StatelessSchema>, field: &str) -> AuthResult<DeviceCode> {
    let row = tx
        .get_device_code_by_device_code("runtime-device")
        .await?
        .ok_or_else(|| AuthError::internal("Transaction must read the seeded Device code"))?;
    let value = ownership_value(&row, field)?;
    tx.consume_device_code(
        &row,
        &DeviceCodeOwnership::Where(DeviceCodeWhere {
            field: field.into(),
            operator: WhereOperator::In,
            value: vec![value].into(),
            mode: WhereMode::Sensitive,
        }),
    )
    .await?
    .ok_or_else(|| AuthError::internal("Transaction must consume the matching Device code"))
}

fn ownership_value(row: &DeviceCode, field: &str) -> AuthResult<FieldValue> {
    if field == "scope" {
        Ok(row.scope.field_value())
    } else {
        row.additional_fields
            .get(field)
            .cloned()
            .ok_or_else(|| AuthError::internal("Device code must retain the ownership value"))
    }
}

#[expect(
    clippy::expect_used,
    reason = "The seeded row must retain native NaN before transaction comparison"
)]
fn assert_native_nan(row: &DeviceCode, field: &str) {
    let value = ownership_value(row, field).expect("seeded ownership value");
    let number = if field == "runtime" {
        let object = value
            .as_array()
            .and_then(|array| array.first())
            .and_then(FieldValue::as_object)
            .expect("nested native object");
        assert_eq!(object.get("optional"), Some(&FieldValue::Undefined));
        assert!(
            matches!(object.get("date"), Some(FieldValue::Date(date)) if date.milliseconds().is_nan())
        );
        object.get("value").expect("nested NaN")
    } else {
        &value
    };
    assert!(matches!(number, FieldValue::Number(value) if value.is_nan()));
}

#[tokio::test]
#[expect(
    clippy::expect_used,
    reason = "The regression requires successful setup, consumption, commit, and final reads"
)]
async fn memory_device_consumption_commits_unchanged_native_snapshots() {
    for (field, value) in [
        ("quantity", FieldValue::Number(f64::NAN)),
        ("scope", FieldValue::Number(f64::NAN)),
        ("runtime", nested(FieldValue::Number(f64::NAN))),
    ] {
        let (auth, seeded) = setup(field, value).await.expect("native Device setup");
        assert_native_nan(&seeded, field);
        let consumed = transaction(auth.store().as_ref(), move |tx| {
            Box::pin(async move { consume(tx, field).await })
        })
        .await
        .expect("unchanged native ownership must commit");
        assert_eq!(consumed.id, seeded.id);
        assert_eq!(consumed.user_id, seeded.user_id);
        assert_eq!(consumed.client_id, seeded.client_id);
        assert_eq!(consumed.status, "approved");
        assert_native_nan(&consumed, field);
        assert!(
            auth.store()
                .get_device_code_by_device_code(&seeded.device_code)
                .await
                .expect("read after commit")
                .is_none(),
            "committed consumption must remove {field} ownership"
        );
    }
}

#[tokio::test]
#[expect(
    clippy::expect_used,
    reason = "The regression requires a rejected commit and the retained concurrent Device update"
)]
async fn memory_device_consumption_rejects_native_ownership_changes_before_commit() {
    for (field, original, replacement) in [
        ("quantity", FieldValue::Number(f64::NAN), FieldValue::Null),
        ("scope", FieldValue::Number(f64::NAN), FieldValue::Null),
        (
            "runtime",
            nested(FieldValue::Number(f64::NAN)),
            nested(FieldValue::Null),
        ),
    ] {
        let (auth, seeded) = setup(field, original).await.expect("native Device setup");
        assert_native_nan(&seeded, field);
        let live = auth.store().clone();
        let changed = replacement.clone();
        let error = transaction(auth.store().as_ref(), move |tx| {
            Box::pin(async move {
                let consumed = consume(tx, field).await?;
                let _ = live
                    .update_device_code(&consumed.id, update(field, changed))
                    .await?;
                Ok(())
            })
        })
        .await
        .expect_err("a concurrent ownership change must reject the commit");
        assert!(
            matches!(error, AuthError::Internal(ref message) if message == "Device code changed before transaction commit"),
            "unexpected error: {error}"
        );
        let remaining = auth
            .store()
            .get_device_code_by_device_code(&seeded.device_code)
            .await
            .expect("read after rejected commit")
            .expect("the live Device row must remain");
        assert_eq!(remaining.id, seeded.id);
        assert_eq!(remaining.user_id, seeded.user_id);
        assert_eq!(remaining.client_id, seeded.client_id);
        assert_eq!(remaining.status, "approved");
        if field == "scope" {
            assert_eq!(remaining.scope.field_value(), replacement);
        } else {
            assert_eq!(remaining.additional_fields.get(field), Some(&replacement));
        }
    }
}
