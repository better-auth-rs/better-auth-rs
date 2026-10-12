use super::{EphemeralStore, raw_records::MemoryRecordModel, rows::RowRef};
use crate::store::schema::EntityRole;
use crate::{AuthResult, FieldMap, FieldValue, SchemaValue};

impl EphemeralStore {
    pub(super) fn plugin_record_model(&self, role: EntityRole) -> MemoryRecordModel<'_> {
        MemoryRecordModel::new(self, role, self.model_fields.plugin_fields(role))
    }

    pub(super) fn plugin_query_value(
        &self,
        role: EntityRole,
        name: &str,
        value: FieldValue,
    ) -> AuthResult<FieldValue> {
        self.plugin_query_field(role, name, value)
            .map(|(_, value)| value)
    }

    pub(super) fn plugin_query_field(
        &self,
        role: EntityRole,
        name: &str,
        value: FieldValue,
    ) -> AuthResult<(String, FieldValue)> {
        self.memory_query_field(role, &self.model_fields.plugin_fields(role), name, value)
    }

    pub(super) async fn project_plugin_refs(
        &self,
        role: EntityRole,
        sources: Vec<RowRef<FieldMap>>,
    ) -> AuthResult<Vec<FieldMap>> {
        self.plugin_record_model(role).project(sources).await
    }

    pub(super) async fn prepare_plugin_fields(
        &self,
        role: EntityRole,
        input: FieldMap,
        create: bool,
    ) -> AuthResult<FieldMap> {
        let force_allow_id = create && input.contains_key("id");
        self.plugin_record_model(role)
            .prepare(input.into(), create, force_allow_id)
            .await
    }

    pub(super) async fn create_plugin_record(
        &self,
        role: EntityRole,
        input: FieldMap,
        internal: FieldMap,
    ) -> AuthResult<FieldMap> {
        let force_allow_id = input.contains_key("id");
        self.plugin_record_model(role)
            .create(input.into(), internal, force_allow_id)
            .await
    }

    pub(super) async fn create_plugin_ref(
        &self,
        role: EntityRole,
        input: FieldMap,
        internal: FieldMap,
    ) -> AuthResult<RowRef<FieldMap>> {
        let force_allow_id = input.contains_key("id");
        self.plugin_record_model(role)
            .create_ref(input.into(), internal, force_allow_id)
            .await
    }

    pub(super) async fn get_plugin_record(
        &self,
        role: EntityRole,
        id: &SchemaValue<String>,
    ) -> AuthResult<Option<FieldMap>> {
        self.plugin_record_model(role)
            .find_by_id(id.field_value())
            .await
    }

    pub(super) async fn update_plugin_record(
        &self,
        role: EntityRole,
        id: &SchemaValue<String>,
        input: FieldMap,
        internal: FieldMap,
    ) -> AuthResult<Option<FieldMap>> {
        self.plugin_record_model(role)
            .update_by_id(id.field_value(), input.into(), internal)
            .await
    }

    pub(super) async fn update_plugin_ref(
        &self,
        role: EntityRole,
        id: &SchemaValue<String>,
        input: FieldMap,
        internal: FieldMap,
    ) -> AuthResult<Option<RowRef<FieldMap>>> {
        self.plugin_record_model(role)
            .update_ref_by_id(id.field_value(), input.into(), internal)
            .await
    }

    pub(super) async fn delete_plugin_records(
        &self,
        role: EntityRole,
        id: &SchemaValue<String>,
    ) -> AuthResult<()> {
        self.plugin_record_model(role)
            .delete_by_id(id.field_value())
            .await
    }

    /// Observe complete physical records without invoking output callbacks.
    #[doc(hidden)]
    pub fn plugin_storage_rows(&self, role: EntityRole) -> AuthResult<Vec<FieldMap>> {
        self.storage_rows(role)
    }

    /// Observe complete physical records without applying query limits or output callbacks.
    #[doc(hidden)]
    pub fn storage_rows(&self, role: EntityRole) -> AuthResult<Vec<FieldMap>> {
        self.operation(|op| op.capture_table(role)?.snapshot())
    }
}
