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
        supports_native_dates: bool,
    ) -> AuthResult<Vec<T>> {
        if !records.is_empty() {
            self.begin_id_output(role)?;
        }
        self.plugin_fields(role)
            .adapter_fields(&[])
            .project_adapter_records_with_capabilities(records, capabilities, supports_native_dates)
            .await?
            .into_iter()
            .map(T::from_field_values)
            .collect()
    }
}
