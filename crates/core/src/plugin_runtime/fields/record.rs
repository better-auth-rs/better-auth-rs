use super::*;
use crate::FromFieldMap;
use crate::user_fields::FieldOutputCapabilities;

impl ModelFields {
    /// Construct runtime records only after all adapter output policies complete.
    #[doc(hidden)]
    pub async fn project_plugin_records<T: FromFieldMap>(
        &self,
        role: EntityRole,
        records: Vec<AdapterRecord>,
        capabilities: FieldOutputCapabilities,
    ) -> AuthResult<Vec<T>> {
        let records = records
            .into_iter()
            .map(|record| record.with_id_output(self, role))
            .collect();
        let schema = self.plugin_fields(role).adapter_fields(&[]);
        schema
            .project_adapter_records_with_capabilities(records, capabilities)
            .await?
            .into_iter()
            .map(|mut fields| {
                let mut ordered = FieldMap::new();
                for name in schema.fields().keys() {
                    if let Some(value) = fields.shift_remove(name) {
                        let _ = ordered.insert(name.clone(), value);
                    }
                }
                ordered.extend(fields);
                T::from_field_values(ordered)
            })
            .collect()
    }
}
