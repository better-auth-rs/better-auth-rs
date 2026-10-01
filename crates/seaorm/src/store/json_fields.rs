use better_auth_core::user_fields::{UserConfig, UserFieldType};
use sea_orm::DbBackend;
use std::sync::Arc;

/// Match the Kysely adapter's JSON conversion around application transforms.
pub(crate) fn configure_json_fields(
    fields: &mut UserConfig,
    backend: DbBackend,
    native_json_field: impl Fn(&str) -> bool,
) {
    for (name, field) in &mut fields.additional_fields {
        if name == "id"
            || (!field.references_id()
                && (backend == DbBackend::Postgres
                    || !matches!(field.field_type, UserFieldType::Json)))
        {
            continue;
        }
        let input_policy = field.clone();
        let output_policy = field.clone();
        let native_json = native_json_field(field.field_name.as_deref().unwrap_or(name));
        let input = field.input_transform.take();
        field.input_transform = Some(Arc::new(move |value| {
            let value = match &input {
                Some(transform) => transform(value)?,
                None => value,
            };
            Ok(value.map(|value| {
                input_policy.adapter_input(value, backend == DbBackend::Postgres, native_json)
            }))
        }));
        field.output_transform = Some(Arc::new(move |value| {
            output_policy.adapter_output(value, backend == DbBackend::Postgres)
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::{AuthResult, user_fields::UserFieldConfig};
    use serde_json::{Map, Value, json};

    #[test]
    fn backend_conversion_runs_between_input_and_output_policies() -> AuthResult<()> {
        for backend in [DbBackend::Sqlite, DbBackend::Postgres] {
            let mut fields = UserConfig {
                additional_fields: [(
                    "payload".into(),
                    UserFieldConfig {
                        field_type: UserFieldType::Json,
                        input_transform: Some(Arc::new(|value| {
                            Ok(value.map(|value| json!({"input":value})))
                        })),
                        output_transform: Some(Arc::new(move |value| {
                            let value = value.unwrap();
                            assert_eq!(value.is_string(), backend != DbBackend::Postgres);
                            Ok(Some(value))
                        })),
                        ..Default::default()
                    },
                )]
                .into(),
            };
            configure_json_fields(&mut fields, backend, |_| false);
            let stored = fields.storage_fields(
                Map::from_iter([("payload".into(), json!({"at":"2026-01-02T03:04:05Z"}))]),
                true,
            )?;
            let output = fields.output_fields(&stored)?;
            assert_eq!(
                output["payload"],
                json!({"input":{"at":if backend == DbBackend::Postgres { "2026-01-02T03:04:05Z" } else { "2026-01-02T03:04:05.000Z" }}})
            );
        }
        Ok(())
    }

    #[test]
    fn invalid_json_is_null_after_the_application_output_transform() -> AuthResult<()> {
        let mut fields = UserConfig {
            additional_fields: [(
                "payload".into(),
                UserFieldConfig {
                    field_type: UserFieldType::Json,
                    output_transform: Some(Arc::new(|_| Ok(Some(json!("not JSON"))))),
                    ..Default::default()
                },
            )]
            .into(),
        };
        configure_json_fields(&mut fields, DbBackend::Sqlite, |_| false);
        assert_eq!(fields.output_fields(&Map::new())?["payload"], Value::Null);
        Ok(())
    }
}
