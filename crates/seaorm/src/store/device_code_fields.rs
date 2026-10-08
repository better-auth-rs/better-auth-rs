use super::SeaOrmStore;
use crate::schema::AuthSchema;
use better_auth_core::{AuthResult, DeviceCode, FieldMap, store::schema::EntityRole};
use sea_orm::{IdenStatic, QueryResult};

impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    SeaOrmStore<S, O, P>
{
    pub(super) fn validate_device_code_fields(&self) -> AuthResult<()> {
        self.validate_plugin_fields::<P::DeviceCode>(EntityRole::DeviceCode)
    }

    pub(super) fn device_code_storage_bindings(&self, row: &QueryResult) -> AuthResult<FieldMap> {
        ["id", "deviceCode", "clientId", "userId", "status"]
            .into_iter()
            .map(|name| {
                let column = self.plugin_column::<P::DeviceCode>(EntityRole::DeviceCode, name)?;
                super::plugin_rows::value(row, column.as_str())
                    .map(|value| (name.to_owned(), value))
            })
            .collect()
    }

    pub(super) async fn project_device_code_models(
        &self,
        rows: Vec<QueryResult>,
    ) -> AuthResult<Vec<DeviceCode>> {
        let bindings = rows
            .iter()
            .map(|row| self.device_code_storage_bindings(row))
            .collect::<AuthResult<Vec<_>>>()?;
        Ok(self
            .project_plugin_rows::<P::DeviceCode, DeviceCode>(EntityRole::DeviceCode, rows)
            .await?
            .into_iter()
            .zip(bindings)
            .map(|(row, bindings)| row.with_storage_bindings(bindings))
            .collect())
    }
}
