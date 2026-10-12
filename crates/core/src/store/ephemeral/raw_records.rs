//! Bind raw Memory records to one declaration without adding business hooks or cache operations.

use super::{
    EphemeralStore,
    rows::{RecordSource, RowRef},
};
use crate::{
    AuthError, AuthResult, FieldMap, FieldValue, id::AdapterIdInput, plugin_runtime::ModelKey,
    user_fields::UserConfig,
};

#[cfg(test)]
#[path = "raw_record_tests.rs"]
mod tests;

pub(super) struct MemoryRecordModel<'a> {
    store: &'a EphemeralStore,
    model: ModelKey,
    fields: UserConfig,
}

impl<'a> MemoryRecordModel<'a> {
    pub(super) fn new(
        store: &'a EphemeralStore,
        model: impl Into<ModelKey>,
        fields: UserConfig,
    ) -> Self {
        Self {
            store,
            model: model.into(),
            fields,
        }
    }

    /// Apply the caller's resolved ID admission without rereading property presence.
    pub(super) async fn prepare(
        &self,
        input: FieldValue,
        create: bool,
        force_allow_id: bool,
    ) -> AuthResult<FieldMap> {
        self.store
            .model_fields
            .with_id_input(
                &self.model,
                AdapterIdInput {
                    force_allow_id,
                    supports_native_uuid: false,
                },
                self.fields.storage_fields_from_source_with_bound_id(
                    create,
                    |name| input.model_property(name).map(Some),
                    || {
                        let supplied = input.model_property("id")?;
                        let Some(policy) = self.store.model_fields.id_input_policy(&self.model)?
                        else {
                            return Ok(Some(supplied));
                        };
                        if create {
                            self.store
                                .memory_create_id_input(&self.model, Some(supplied), policy)
                        } else {
                            self.store
                                .config
                                .advanced
                                .database
                                .generate_id()
                                .adapter_id_input(supplied, policy)
                        }
                    },
                    |name, field, value| {
                        self.store
                            .memory_record_input(&self.model, name, field, value, create)
                    },
                ),
            )
            .await
    }

    pub(super) async fn project(
        &self,
        sources: Vec<RowRef<FieldMap>>,
    ) -> AuthResult<Vec<FieldMap>> {
        self.store
            .project_record_sources(
                &self.model,
                &self.fields,
                sources.into_iter().map(RecordSource::Live).collect(),
            )
            .await
    }

    fn query_id(&self, id: FieldValue) -> AuthResult<(String, FieldValue)> {
        self.store
            .memory_query_field(&self.model, &self.fields, "id", id)
    }

    fn model(&self) -> AuthResult<&str> {
        self.model.logical_name()
    }

    pub(super) async fn create(
        &self,
        input: FieldValue,
        internal: FieldMap,
        force_allow_id: bool,
    ) -> AuthResult<FieldMap> {
        let source = self.create_ref(input, internal, force_allow_id).await?;
        self.project(vec![source])
            .await?
            .pop()
            .ok_or_else(|| AuthError::internal("Created plugin record was not projected"))
    }

    pub(super) async fn create_ref(
        &self,
        input: FieldValue,
        internal: FieldMap,
        force_allow_id: bool,
    ) -> AuthResult<RowRef<FieldMap>> {
        let mut storage = self.prepare(input, true, force_allow_id).await?;
        storage.extend(internal);
        self.store
            .raw(self.model()?, "create", |op| {
                let table = op.create_table(&self.model)?;
                if let Some(id) = self.store.next_serial_id(table.len()?) {
                    let _ = storage.insert("id".into(), id);
                }
                table.push(storage)
            })
            .await
    }

    pub(super) async fn find_by_id(&self, id: FieldValue) -> AuthResult<Option<FieldMap>> {
        let (column, id) = self.query_id(id)?;
        let selected = self
            .store
            .raw(self.model()?, "findOne", |op| {
                Ok(op
                    .capture_table(&self.model)?
                    .select_refs(|row| {
                        Ok(crate::query::field_matches_equality(
                            &row.field(&column)?.unwrap_or_default(),
                            &id,
                        ))
                    })?
                    .into_iter()
                    .next())
            })
            .await?;
        Ok(self.project(selected.into_iter().collect()).await?.pop())
    }

    pub(super) async fn update_by_id(
        &self,
        id: FieldValue,
        input: FieldValue,
        internal: FieldMap,
    ) -> AuthResult<Option<FieldMap>> {
        let selected = self.update_ref_by_id(id, input, internal).await?;
        Ok(self.project(selected.into_iter().collect()).await?.pop())
    }

    pub(super) async fn update_ref_by_id(
        &self,
        id: FieldValue,
        input: FieldValue,
        internal: FieldMap,
    ) -> AuthResult<Option<RowRef<FieldMap>>> {
        let (column, id) = self.query_id(id)?;
        let mut patch = self.prepare(input, false, false).await?;
        patch.extend(internal);
        self.store
            .raw(self.model()?, "update", |op| {
                let matches = op.capture_table(&self.model)?.select_refs(|row| {
                    Ok(crate::query::field_matches_equality(
                        &row.field(&column)?.unwrap_or_default(),
                        &id,
                    ))
                })?;
                for source in &matches {
                    source.apply_patch(patch.clone())?;
                }
                Ok(matches.into_iter().next())
            })
            .await
    }

    pub(super) async fn delete_by_id(&self, id: FieldValue) -> AuthResult<()> {
        let (column, id) = self.query_id(id)?;
        self.store
            .raw(self.model()?, "delete", |op| {
                let table = op.capture_table(&self.model)?;
                let selected = table.select_refs(|row| {
                    Ok(crate::query::field_matches_equality(
                        &row.field(&column)?.unwrap_or_default(),
                        &id,
                    ))
                })?;
                op.replace_table(&self.model, table.without_refs(&selected)?)
            })
            .await
    }
}
