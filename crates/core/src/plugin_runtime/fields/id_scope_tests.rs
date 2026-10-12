#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify shared ID history across reentrant callbacks and suspended conversion failures"
)]

use super::*;
use crate::user_fields::{UserFieldTransform, await_adapter_boundary};

#[tokio::test]
async fn id_input_sync_callback_keeps_reentrant_output_policy() -> AuthResult<()> {
    let fields = ModelFields::default();
    let role = EntityRole::Session;
    fields.begin_id_query(role)?;
    let callback_fields = fields.clone();
    let callback = UserFieldTransform::new(move |value| {
        assert!(
            callback_fields
                .id_input_policy(role)?
                .is_some_and(|policy| policy.force_allow_id && policy.supports_native_uuid)
        );
        callback_fields.begin_id_output(role)?;
        Ok(value)
    });
    let output = fields
        .with_id_input(
            role,
            AdapterIdInput {
                force_allow_id: true,
                supports_native_uuid: true,
            },
            async { callback.call_sync("retained".into()) },
        )
        .await?;
    assert_eq!(output, Value::from("retained"));
    assert!(fields.id_input_policy(role)?.is_none());
    Ok(())
}

#[tokio::test]
async fn id_input_resume_keeps_peer_output_policy_and_original_error() -> AuthResult<()> {
    let fields = ModelFields::default();
    let role = EntityRole::Session;
    let original: Value = FieldMap::from([("cause".into(), "conversion failed".into())]).into();
    let input = fields.with_id_input(
        role,
        AdapterIdInput {
            force_allow_id: true,
            supports_native_uuid: true,
        },
        async {
            assert!(
                fields
                    .id_input_policy(role)?
                    .is_some_and(|policy| policy.force_allow_id && policy.supports_native_uuid)
            );
            await_adapter_boundary().await;
            assert!(fields.id_input_policy(role)?.is_none());
            Err::<(), _>(AuthError::from_thrown(original.clone()))
        },
    );
    assert!(fields.id_input_policy(role)?.is_none());
    let output = async {
        assert!(
            fields
                .id_input_policy(role)?
                .is_some_and(|policy| policy.force_allow_id && policy.supports_native_uuid)
        );
        fields.id_output_initializer(role)()
    };
    let (input, output) = tokio::join!(biased; input, output);
    output?;
    let error = input
        .err()
        .ok_or_else(|| AuthError::internal("Suspended conversion unexpectedly succeeded"))?;
    assert!(
        error
            .raw_value()
            .is_some_and(|cause| cause.strict_equals(&original))
    );
    assert!(fields.id_input_policy(role)?.is_none());
    Ok(())
}

#[test]
fn model_alias_replacement_keeps_logical_id_history_and_fresh_runtime_isolates_it() -> AuthResult<()>
{
    let declared_id = UserConfig {
        additional_fields: Some(
            [(
                "id".into(),
                crate::user_fields::UserFieldConfig {
                    field_name: Some("declared_id".into()),
                    ..Default::default()
                },
            )]
            .into(),
        ),
    };
    let mut fields = ModelFields::default();
    fields.register_custom_model("badge", Some("shared"), declared_id.clone())?;
    fields.register_model_schema(EntityRole::Jwk, Some("shared"), declared_id.clone())?;
    fields.register_custom_model("other", Some("shared"), declared_id.clone())?;
    let alias = fields.resolve_model_key("shared", &|_, _| false)?;
    let badge = fields.resolve_model_key("badge", &|_, _| false)?;
    let other = fields.resolve_model_key("other", &|_, _| false)?;
    let native = fields.resolve_model_key("jwks", &|_, _| false)?;
    assert_eq!(alias, badge);
    assert_eq!(fields.storage_name(&native, "jwks"), "shared");
    assert_eq!(fields.storage_name(&other, "other"), "shared");
    let policy = AdapterIdInput {
        force_allow_id: true,
        supports_native_uuid: true,
    };
    fields.begin_id_input(&alias, policy)?;
    assert!(
        fields
            .id_input_policy(&badge)?
            .is_some_and(|current| current.force_allow_id && current.supports_native_uuid)
    );
    for independent in [&native, &other] {
        assert!(fields.id_input_policy(independent)?.is_none());
        assert_eq!(
            fields
                .runtime_fields(independent, &declared_id)?
                .fields()
                .get("id")
                .and_then(|field| field.field_name.as_deref()),
            Some("declared_id")
        );
    }
    assert!(
        fields
            .runtime_fields(&badge, &declared_id)?
            .fields()
            .get("id")
            .is_some_and(|field| field.field_name.is_none())
    );
    let initialize = fields.id_output_initializer(&badge);
    fields.register_custom_model("badge", Some("renamed"), UserConfig::default())?;
    assert_eq!(fields.resolve_model_key("renamed", &|_, _| false)?, badge);
    assert_eq!(fields.resolve_model_key("shared", &|_, _| false)?, native);
    assert!(fields.id_input_policy(&badge)?.is_some());
    initialize()?;
    assert!(fields.id_input_policy(&badge)?.is_none());
    assert!(
        fields
            .runtime_fields(&badge, &declared_id)?
            .fields()
            .get("id")
            .is_some_and(|field| field.field_name.is_none())
    );
    let fresh = fields.fresh_runtime();
    assert_eq!(
        fresh
            .runtime_fields(&badge, &declared_id)?
            .fields()
            .get("id")
            .and_then(|field| field.field_name.as_deref()),
        Some("declared_id")
    );
    fresh.begin_id_query(&badge)?;
    assert!(fresh.id_input_active(&badge)?);
    assert!(!fields.id_input_active(&badge)?);
    Ok(())
}
