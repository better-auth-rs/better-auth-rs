use super::*;
use better_auth_core::{
    AuthRecordFields, StructuredCloneContext,
    user_fields::{FieldTransforms, UserFieldTransform},
};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Policy(UserConfig);

#[async_trait::async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Policy {
    fn name(&self) -> &'static str {
        "device-consumption-binding-fields"
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

async fn configured(
    name: &str,
    storage_name: Option<&str>,
    output: UserFieldTransform,
) -> AuthResult<(BetterAuth<StatelessSchema>, Arc<EphemeralStore>)> {
    let mut config = AuthConfig::new("device-consumption-bindings-secret-at-least-32-characters")
        .base_url("http://device-bindings.test");
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    let raw = Arc::new(EphemeralStore::new(Arc::new(config.clone())));
    let auth = BetterAuth::new(config)
        .store_arc(raw.clone())
        .plugin(DeviceAuthorizationPlugin::new())
        .plugin(Policy(UserConfig {
            additional_fields: Some(
                [(
                    name.into(),
                    UserFieldConfig {
                        required: Some(false),
                        field_name: storage_name.map(str::to_owned),
                        transform: Some(FieldTransforms {
                            output: Some(output),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                )]
                .into(),
            ),
        }))
        .build()
        .await?;
    Ok((auth, raw))
}

fn input(label: &str, scope: FieldValue) -> CreateDeviceCode {
    CreateDeviceCode {
        device_code: format!("binding-device-{label}"),
        user_code: format!("binding-user-{label}"),
        user_id: Some("binding-owner".into()),
        expires_at: FieldDate::from_milliseconds(4_102_444_800_000.0),
        status: "approved".into(),
        last_polled_at: None,
        polling_interval: Some(5000.0),
        client_id: Some("binding-client".into()),
        scope: SchemaValue::from_field(scope),
        additional_fields: FieldMap::new(),
    }
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions preserve the query error, complete storage snapshot, and callback count"
)]
async fn unrelated_device_query_errors_preserve_every_row_and_skip_output() -> AuthResult<()> {
    for target_first in [true, false] {
        for in_transaction in [false, true] {
            let outputs = Arc::new(AtomicUsize::new(0));
            let observed = outputs.clone();
            let (auth, raw) = configured(
                "scope",
                None,
                UserFieldTransform::new(move |value| {
                    let _ = observed.fetch_add(1, Ordering::SeqCst);
                    Ok(value)
                }),
            )
            .await?;
            let target = input("target", "alpha".into());
            let decoy = input("decoy", FieldValue::Number(7.0));
            let inputs = if target_first {
                [target, decoy]
            } else {
                [decoy, target]
            };
            for row in inputs {
                let _ = auth.store().create_device_code(row).await?;
            }
            let target = auth
                .store()
                .get_device_code_by_device_code("binding-device-target")
                .await?
                .ok_or_else(|| AuthError::internal("Expected the target Device row"))?;
            let before = raw.plugin_storage_rows(EntityRole::DeviceCode)?;
            assert_eq!(before.len(), 2);
            outputs.store(0, Ordering::SeqCst);
            let ownership = DeviceCodeOwnership::Where(DeviceCodeWhere {
                field: "scope".into(),
                operator: WhereOperator::StartsWith,
                value: "a".into(),
                mode: WhereMode::Sensitive,
            });
            let result = if in_transaction {
                transaction(auth.store().as_ref(), move |tx| {
                    Box::pin(async move { tx.consume_device_code(&target, &ownership).await })
                })
                .await
            } else {
                auth.store().consume_device_code(&target, &ownership).await
            };
            assert!(
                matches!(result, Err(AuthError::Internal(ref message))
                if message == "record[field].startsWith is not a function"),
                "{result:?}"
            );
            assert_eq!(raw.plugin_storage_rows(EntityRole::DeviceCode)?, before);
            assert_eq!(outputs.load(Ordering::SeqCst), 0);
        }
    }
    Ok(())
}

fn object() -> FieldValue {
    FieldMap::from([("value".into(), "projected-binding".into())]).into()
}

fn replace_binding(row: &mut DeviceCode, name: &str, value: FieldValue) -> AuthResult<()> {
    match name {
        "id" => row.id = SchemaValue::from_field(value),
        "deviceCode" => row.device_code = SchemaValue::from_field(value),
        "clientId" => row.client_id = SchemaValue::from_field(value),
        "userId" => row.user_id = SchemaValue::from_field(value),
        "status" => row.status = SchemaValue::from_field(value),
        _ => return Err(AuthError::internal("Unknown Device binding field")),
    }
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions distinguish cloned binding identities from caller-forged replacements"
)]
async fn projected_device_bindings_preserve_clone_identity_and_reject_forgery() -> AuthResult<()> {
    for name in ["deviceCode", "clientId", "userId", "status"] {
        for projection in [
            object(),
            FieldValue::Number(f64::NAN),
            FieldValue::Undefined,
            "alias".into(),
        ] {
            for structured in [false, true] {
                let output = projection.clone();
                let (auth, raw) = configured(
                    name,
                    None,
                    UserFieldTransform::new(move |_| Ok(output.clone())),
                )
                .await?;
                let seeded = auth
                    .store()
                    .create_device_code(input("target", "alpha".into()))
                    .await?;
                let expected = if structured {
                    seeded.structured_clone(&mut StructuredCloneContext::new())?
                } else {
                    seeded.clone()
                };
                let fields = expected.field_values()?;
                let projected = fields
                    .get(name)
                    .ok_or_else(|| AuthError::internal("Expected the projected binding"))?;
                if projection.is_object() {
                    assert_eq!(projected, &projection);
                    assert_eq!(projected.strict_equals(&projection), !structured);
                } else {
                    assert!(projected.same_value_zero(&projection));
                }
                assert!(expected.consumption_bindings()?.1);
                let before = raw.plugin_storage_rows(EntityRole::DeviceCode)?;
                let ownership = DeviceCodeOwnership::ClientId("binding-client".into());
                let mut forged = expected.clone();
                replace_binding(&mut forged, name, object())?;
                assert!(!forged.consumption_bindings()?.1);
                assert!(
                    auth.store()
                        .consume_device_code(&forged, &ownership)
                        .await?
                        .is_none()
                );
                assert_eq!(raw.plugin_storage_rows(EntityRole::DeviceCode)?, before);
                let consumed = auth
                    .store()
                    .consume_device_code(&expected, &ownership)
                    .await?
                    .ok_or_else(|| {
                        AuthError::internal(
                            "Unchanged projected bindings must consume the stored row",
                        )
                    })?;
                assert!(consumed.consumption_bindings()?.1);
                assert!(raw.plugin_storage_rows(EntityRole::DeviceCode)?.is_empty());
            }
        }
    }
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions require canonical ID guards even when the application declares an ID alias"
)]
async fn declared_id_alias_cannot_bypass_device_consumption_bindings() -> AuthResult<()> {
    let (auth, raw) = configured(
        "id",
        Some("shadow_id"),
        UserFieldTransform::new(|_| {
            Err(AuthError::internal(
                "Adapter-owned ID callbacks must not run",
            ))
        }),
    )
    .await?;
    let seeded = auth
        .store()
        .create_device_code(input("target", "alpha".into()))
        .await?;
    let ownership = DeviceCodeOwnership::ClientId("binding-client".into());
    let before = raw.plugin_storage_rows(EntityRole::DeviceCode)?;
    assert_eq!(
        seeded.consumption_bindings()?.0.get("id"),
        Some(&seeded.id.field_value())
    );
    assert!(seeded.clone().consumption_bindings()?.1);
    let mut forged = seeded.clone();
    forged.id = "forged-id".into();
    assert!(!forged.consumption_bindings()?.1);
    assert!(
        auth.store()
            .consume_device_code(&forged, &ownership)
            .await?
            .is_none()
    );
    assert_eq!(raw.plugin_storage_rows(EntityRole::DeviceCode)?, before);

    let changed = auth
        .store()
        .update_device_code_record(&seeded.id, [("id".into(), "changed-id".into())].into())
        .await?
        .ok_or_else(|| AuthError::internal("Expected the renamed Device row"))?;
    assert_eq!(changed.get("id"), Some(&FieldValue::from("changed-id")));
    let changed_storage = raw.plugin_storage_rows(EntityRole::DeviceCode)?;
    assert!(
        auth.store()
            .consume_device_code(&seeded, &ownership)
            .await?
            .is_none()
    );
    assert_eq!(
        raw.plugin_storage_rows(EntityRole::DeviceCode)?,
        changed_storage
    );
    let current = auth
        .store()
        .get_device_code_by_device_code("binding-device-target")
        .await?
        .ok_or_else(|| AuthError::internal("The renamed Device row must remain"))?;
    assert!(
        auth.store()
            .consume_device_code(&current, &ownership)
            .await?
            .is_some()
    );
    assert!(raw.plugin_storage_rows(EntityRole::DeviceCode)?.is_empty());
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions require a transaction conflict after a concurrent owner change despite renamed Device bindings"
)]
async fn renamed_device_bindings_retain_the_original_transaction_conflict_guard() -> AuthResult<()>
{
    for field in ["id", "deviceCode"] {
        let (auth, raw) = configured("scope", None, UserFieldTransform::new(Ok)).await?;
        let seeded = auth
            .store()
            .create_device_code(input("target", "alpha".into()))
            .await?;
        let original_id = seeded.id.clone();
        let live = auth.store().clone();
        let mut expected = raw.plugin_storage_rows(EntityRole::DeviceCode)?;
        let result = transaction(auth.store().as_ref(), move |tx| {
            Box::pin(async move {
                let changed = tx
                    .update_device_code_record(
                        &seeded.id,
                        [(field.into(), "renamed-binding".into())].into(),
                    )
                    .await?
                    .ok_or_else(|| AuthError::internal("Expected the renamed transaction row"))?;
                assert_eq!(
                    changed.get(field),
                    Some(&FieldValue::from("renamed-binding"))
                );
                let token = if field == "deviceCode" {
                    "renamed-binding"
                } else {
                    "binding-device-target"
                };
                let current = tx
                    .get_device_code_by_device_code(token)
                    .await?
                    .ok_or_else(|| AuthError::internal("Expected the renamed transaction row"))?;
                assert!(
                    tx.consume_device_code(
                        &current,
                        &DeviceCodeOwnership::ClientId("binding-client".into())
                    )
                    .await?
                    .is_some()
                );
                let _ = live
                    .update_device_code_record(
                        &original_id,
                        [("userId".into(), "concurrent-owner".into())].into(),
                    )
                    .await?
                    .ok_or_else(|| AuthError::internal("Expected the concurrent owner update"))?;
                Ok(())
            })
        })
        .await;
        assert!(
            matches!(result, Err(AuthError::Internal(ref message))
            if message == "Device code changed before transaction commit"),
            "{result:?}"
        );
        let row = expected
            .first_mut()
            .ok_or_else(|| AuthError::internal("Expected the original storage row"))?;
        let _ = row.insert("userId".into(), "concurrent-owner".into());
        assert_eq!(raw.plugin_storage_rows(EntityRole::DeviceCode)?, expected);
    }
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions distinguish a concurrent ownership object replacement from the transaction's original object"
)]
async fn equal_content_new_ownership_object_rejects_device_transaction_commit() -> AuthResult<()> {
    let (auth, raw) = configured("scope", None, UserFieldTransform::new(Ok)).await?;
    let original = object();
    let replacement = object();
    assert_eq!(original, replacement);
    assert!(!original.strict_equals(&replacement));
    let seeded = auth
        .store()
        .create_device_code(input("target", original.clone()))
        .await?;
    let live = auth.store().clone();
    let replacement_for_write = replacement.clone();
    let mut expected = raw.plugin_storage_rows(EntityRole::DeviceCode)?;
    let result = transaction(auth.store().as_ref(), move |tx| {
        Box::pin(async move {
            let current = tx
                .get_device_code_by_device_code("binding-device-target")
                .await?
                .ok_or_else(|| AuthError::internal("Expected the transaction row"))?;
            let ownership = DeviceCodeOwnership::Where(DeviceCodeWhere {
                field: "scope".into(),
                operator: WhereOperator::In,
                value: vec![current.scope.field_value()].into(),
                mode: WhereMode::Sensitive,
            });
            assert!(
                tx.consume_device_code(&current, &ownership)
                    .await?
                    .is_some()
            );
            let _ = live
                .update_device_code_record(
                    &seeded.id,
                    [("scope".into(), replacement_for_write)].into(),
                )
                .await?
                .ok_or_else(|| {
                    AuthError::internal("Expected the concurrent ownership replacement")
                })?;
            Ok(())
        })
    })
    .await;
    assert!(
        matches!(result, Err(AuthError::Internal(ref message))
        if message == "Device code changed before transaction commit"),
        "{result:?}"
    );
    let row = expected
        .first_mut()
        .ok_or_else(|| AuthError::internal("Expected the original storage row"))?;
    let _ = row.insert("scope".into(), replacement.clone());
    let actual = raw.plugin_storage_rows(EntityRole::DeviceCode)?;
    assert_eq!(actual, expected);
    assert!(
        actual
            .first()
            .and_then(|row| row.get("scope"))
            .is_some_and(|value| value.strict_equals(&replacement))
    );
    Ok(())
}
