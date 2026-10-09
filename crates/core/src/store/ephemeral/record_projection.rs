//! Read each Memory field at its output-policy boundary without holding a row lock across callbacks.

use super::{EphemeralStore, rows::RecordSource};
use crate::store::schema::{EntityRole, resolve_field_name};
use crate::user_fields::{UserConfig, project_adapter_value, project_source_fields_batches_then};
use crate::{AuthResult, FieldMap, SchemaValue};

impl EphemeralStore {
    pub(super) async fn project_record_sources(
        &self,
        role: EntityRole,
        configured: &UserConfig,
        sources: Vec<RecordSource>,
    ) -> AuthResult<Vec<FieldMap>> {
        self.project_record_sources_batches_then(role, configured, sources, |ready| {
            std::future::ready(Ok(ready))
        })
        .await
    }

    pub(super) async fn project_record_sources_batches_then<R: Send, F>(
        &self,
        role: EntityRole,
        configured: &UserConfig,
        sources: Vec<RecordSource>,
        complete: impl Fn(Vec<(usize, FieldMap)>) -> F + Sync,
    ) -> AuthResult<Vec<R>>
    where
        F: std::future::Future<Output = AuthResult<Vec<(usize, R)>>> + Send,
    {
        let schema = configured.adapter_fields(&[]);
        let mut rows: Vec<_> = sources
            .into_iter()
            .map(|source| (FieldMap::new(), source, false))
            .collect();
        project_source_fields_batches_then(
            &mut rows,
            schema.fields(),
            |(_, source, started), name, field| {
                if !*started {
                    self.model_fields.begin_id_output(role)?;
                    *started = true;
                }
                source.read(|row| {
                    Ok(row
                        .get(resolve_field_name(field.field_name.as_deref(), name))
                        .cloned()
                        .unwrap_or_default())
                })
            },
            |(output, _, _), name, field, value| {
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
            |_, (output, _, _)| Ok(std::mem::take(output)),
            complete,
        )
        .await
    }
}
