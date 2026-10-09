//! Read each Memory field at its output-policy boundary without holding a row lock across callbacks.

use super::{EphemeralStore, rows::RecordSource};
use crate::store::schema::{EntityRole, resolve_field_name};
use crate::user_fields::{UserConfig, project_adapter_value, project_source_fields_then};
use crate::{AuthResult, FieldMap, SchemaValue};

impl EphemeralStore {
    pub(super) async fn project_record_sources(
        &self,
        role: EntityRole,
        configured: &UserConfig,
        sources: Vec<RecordSource>,
    ) -> AuthResult<Vec<FieldMap>> {
        if !sources.is_empty() {
            self.model_fields.begin_id_output(role)?;
        }
        let schema = configured.adapter_fields(&[]);
        let mut rows: Vec<_> = sources
            .into_iter()
            .map(|source| (FieldMap::new(), source))
            .collect();
        project_source_fields_then(
            &mut rows,
            schema.fields(),
            |(_, source), name, field| {
                source.read(|row| {
                    Ok(row
                        .get(resolve_field_name(field.field_name.as_deref(), name))
                        .cloned()
                        .unwrap_or_default())
                })
            },
            |(output, _), name, field, value| {
                Box::pin(async move {
                    let value = if name == "id" {
                        Self::project_id(&SchemaValue::from_field(value))?.into_field_value()
                    } else {
                        project_adapter_value(value, field, field.references_id(), true).await?
                    };
                    let _ = output.insert(name.to_owned(), value);
                    Ok(())
                })
            },
            |_, (output, _)| Ok(std::mem::take(output)),
        )
        .await
    }
}
