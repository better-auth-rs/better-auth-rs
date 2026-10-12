//! Read each Memory field at its output-policy boundary without holding a row lock across callbacks.

use super::{EphemeralStore, rows::RecordSource};
use crate::store::schema::resolve_field_name;
use crate::user_fields::{
    UserConfig, UserFieldConfig, project_adapter_value, project_owned_source_fields_batches_then,
};
use crate::{
    AuthResult, FieldMap, FieldValue, SchemaValue,
    plugin_runtime::{ModelFields, ModelKey},
};
use futures_util::future::BoxFuture;

type ProjectionRow = (FieldMap, RecordSource, bool);

fn read_field(
    runtime: &ModelFields,
    model: &ModelKey,
    (_, source, started): &mut ProjectionRow,
    name: &str,
    field: &UserFieldConfig,
) -> AuthResult<FieldValue> {
    if !*started {
        runtime.begin_id_output(model)?;
        *started = true;
    }
    Ok(source
        .field(resolve_field_name(field.field_name.as_deref(), name))?
        .unwrap_or_default())
}

fn apply_field<'a>(
    (output, _, _): &'a mut ProjectionRow,
    name: &'a str,
    field: &'a UserFieldConfig,
    value: FieldValue,
) -> BoxFuture<'a, AuthResult<()>> {
    Box::pin(async move {
        let value = if name == "id" {
            EphemeralStore::project_id(&SchemaValue::from_field(value))?.into_field_value()
        } else {
            project_adapter_value(value, field, field.references_id(), true).await?
        };
        let _ = output.insert(name.to_owned(), value);
        Ok(())
    })
}

impl EphemeralStore {
    pub(super) fn project_id(
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<crate::SchemaValue<String>> {
        let value = id.field_value();
        if value.is_null() || value.is_undefined() {
            Ok(crate::SchemaValue::from_field(value))
        } else {
            Ok(crate::SchemaValue::from_field(
                value.display_utf16()?.into(),
            ))
        }
    }

    pub(super) async fn project_record_sources(
        &self,
        model: impl Into<ModelKey>,
        configured: &UserConfig,
        sources: Vec<RecordSource>,
    ) -> AuthResult<Vec<FieldMap>> {
        self.project_record_sources_owned_batches_then(
            model,
            configured,
            sources,
            |_, fields| Ok(fields),
            |ready| std::future::ready(Ok(ready)),
        )
        .await
    }

    pub(super) async fn project_record_sources_owned_batches_then<
        V: Send + 'static,
        R: Send + 'static,
        F,
    >(
        &self,
        model: impl Into<ModelKey>,
        configured: &UserConfig,
        sources: Vec<RecordSource>,
        decode: impl Fn(usize, FieldMap) -> AuthResult<V> + Send + Sync + 'static,
        complete: impl Fn(Vec<(usize, V)>) -> F + Send + Sync + 'static,
    ) -> AuthResult<Vec<R>>
    where
        F: std::future::Future<Output = AuthResult<Vec<(usize, R)>>> + Send + 'static,
    {
        let model = model.into();
        let schema = configured.adapter_fields(&[]);
        let runtime = self.model_fields.clone();
        project_owned_source_fields_batches_then(
            sources
                .into_iter()
                .map(|source| (FieldMap::new(), source, false))
                .collect(),
            schema.fields().clone(),
            move |row, name, field| read_field(&runtime, &model, row, name, field),
            apply_field,
            move |index, (output, _, _)| decode(index, std::mem::take(output)),
            complete,
        )
        .await
    }
}
