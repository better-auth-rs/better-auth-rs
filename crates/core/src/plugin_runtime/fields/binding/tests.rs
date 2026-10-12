#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions compare complete policy binding, callback failures, and unchanged runtime history."
)]

use super::*;
use crate::{
    AuthError, FieldValue,
    id::AdapterIdInput,
    user_fields::{UserFieldConfig, UserFieldFactory, UserFieldType},
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn required<T>(value: Option<T>) -> AuthResult<T> {
    value.ok_or_else(|| AuthError::internal("The configured field must remain present"))
}

#[tokio::test]
async fn core_binding_keeps_complete_replacements_lazy_callbacks_and_id_history() -> AuthResult<()>
{
    for (role, target, native) in [
        (EntityRole::User, "name", "email"),
        (EntityRole::Session, "token", "expiresAt"),
        (EntityRole::Account, "userId", "accountId"),
        (EntityRole::Verification, "identifier", "value"),
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let original: FieldValue = FieldMap::from([("source".into(), "factory".into())]).into();
        let factory = UserFieldFactory::new({
            let calls = calls.clone();
            let original = original.clone();
            move || {
                let _ = calls.fetch_add(1, Ordering::SeqCst);
                Err(AuthError::from_thrown(original.clone()))
            }
        });
        let replacement = UserFieldConfig {
            field_type: UserFieldType::Boolean,
            field_name: Some("replaced".into()),
            default_value_fn: Some(factory.clone()),
            on_update: Some(factory.clone()),
            ..Default::default()
        };
        let mut application = AuthConfig::default();
        let declarations = match role {
            EntityRole::User => application.user.fields_mut(),
            EntityRole::Session => application.session.fields_mut(),
            EntityRole::Account => &mut application.account.additional_fields,
            EntityRole::Verification => &mut application.verification.additional_fields,
            _ => return Err(AuthError::internal("Expected a core model")),
        };
        declarations.extend([
            (target.into(), replacement),
            ("0".into(), UserFieldConfig::default()),
            (
                "id".into(),
                UserFieldConfig {
                    field_name: Some("declared_id".into()),
                    ..Default::default()
                },
            ),
        ]);
        let mut runtime = ModelFields::default();
        runtime.register_model_fields(
            role,
            UserConfig {
                additional_fields: Some(
                    [
                        (
                            target.into(),
                            UserFieldConfig {
                                required: Some(true),
                                unique: Some(true),
                                ..Default::default()
                            },
                        ),
                        ("pluginField".into(), UserFieldConfig::default()),
                    ]
                    .into(),
                ),
            },
        )?;
        let (adapter, _, runtime) = runtime.resolve(&application);
        runtime.begin_id_input(
            role,
            AdapterIdInput {
                force_allow_id: true,
                supports_native_uuid: true,
            },
        )?;
        let schema = runtime.bind(&adapter).fields(role, || {
            Err(AuthError::internal(
                "Core policies must not read Organization options",
            ))
        })?;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(runtime.declared_fields(&role.into())?.fields().is_empty());
        assert!(schema.fields().contains_key(native));
        assert!(schema.fields().contains_key("pluginField"));
        assert_eq!(
            schema.fields().first().map(|(name, _)| name.as_str()),
            Some("0")
        );
        assert_eq!(
            schema.fields().last().map(|(name, _)| name.as_str()),
            Some("id")
        );
        let field = required(schema.fields().get(target))?;
        assert!(matches!(field.field_type, UserFieldType::Boolean));
        assert_eq!(field.field_name.as_deref(), Some("replaced"));
        assert!(field.required.is_none());
        assert!(field.unique.is_none());
        assert!(field.references.is_none());
        assert_eq!(
            required(schema.fields().get("id"))?.field_name.as_deref(),
            Some("declared_id")
        );
        for callback in [&field.default_value_fn, &field.on_update] {
            let actual = FieldValue::from(required(callback.as_ref())?.function().clone());
            let expected = FieldValue::from(factory.function().clone());
            assert!(actual.strict_equals(&expected));
        }
        assert!(
            runtime
                .id_input_policy(role)?
                .is_some_and(|policy| policy.force_allow_id && policy.supports_native_uuid)
        );
        for (index, create) in [true, false].into_iter().enumerate() {
            let error = schema
                .storage_fields_with_bound_id(
                    FieldMap::new(),
                    create,
                    || Ok(None),
                    |_, _, value| Ok(value),
                )
                .await
                .err()
                .ok_or_else(|| AuthError::internal("The original factory error must propagate"))?;
            assert!(
                error
                    .raw_value()
                    .is_some_and(|value| value.strict_equals(&original))
            );
            assert_eq!(calls.load(Ordering::SeqCst), index + 1);
        }
    }
    Ok(())
}

#[test]
fn binding_reads_current_organization_policies_and_separate_session_options() -> AuthResult<()> {
    let runtime = ModelFields::default();
    let mut application = AuthConfig::default();
    let _ = application
        .session
        .fields_mut()
        .insert("application".into(), UserFieldConfig::default());
    let mut session = SessionConfig::default();
    let _ = session
        .fields_mut()
        .insert("isolated".into(), UserFieldConfig::default());
    let binding = runtime.bind(&application).with_session_config(&session);
    let input = FieldMap::from([("activeTeamId".into(), "team".into())]);
    let schema = binding.session(&input);
    assert_eq!(
        schema
            .fields()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "expiresAt",
            "token",
            "createdAt",
            "updatedAt",
            "ipAddress",
            "userAgent",
            "userId",
            "activeTeamId",
            "isolated",
        ]
    );
    let generic = binding.fields(EntityRole::Session, || {
        Err(AuthError::internal(
            "Session policies must not read Organization options",
        ))
    })?;
    assert!(!generic.fields().contains_key("application"));
    assert!(generic.fields().contains_key("isolated"));
    assert!(!generic.fields().contains_key("activeTeamId"));

    let mut owner = OrganizationFields::default().into_storage();
    for physical in ["first_name", "second_name"] {
        let _ = owner.organization.fields_mut().insert(
            "name".into(),
            UserFieldConfig {
                field_name: Some(physical.into()),
                ..Default::default()
            },
        );
        let schema = binding.fields(EntityRole::Organization, || Ok(owner.clone()))?;
        assert_eq!(
            required(schema.fields().get("name"))?.field_name.as_deref(),
            Some(physical)
        );
        assert!(schema.fields().contains_key("slug"));
        assert!(schema.fields().contains_key("createdAt"));
        assert!(runtime.id_input_policy(EntityRole::Organization)?.is_none());
    }
    let original: FieldValue = FieldMap::from([("source".into(), "owner".into())]).into();
    let error = binding
        .fields(EntityRole::Organization, || {
            Err(AuthError::from_thrown(original.clone()))
        })
        .err()
        .ok_or_else(|| AuthError::internal("The owner error must propagate"))?;
    assert!(
        error
            .raw_value()
            .is_some_and(|value| value.strict_equals(&original))
    );
    Ok(())
}
