use super::SeaOrmStore;
use crate::{SeaOrmPluginModel, schema::AuthSchema};
use better_auth_core::FieldMap;
use better_auth_core::store::schema::resolve_field_name;
use better_auth_core::{
    AuthError, AuthResult, DeviceCode, SchemaValue,
    store::schema::{EntityRole, core_fields},
};
use sea_orm::{ColumnTrait, DbBackend, IdenStatic};

impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    SeaOrmStore<S, O, P>
{
    pub(super) fn validate_device_code_fields(&self) -> AuthResult<()> {
        let fields = self.model_fields.fields(EntityRole::DeviceCode);
        super::plugin_models::validate_field_columns(
            "DeviceCode schema",
            fields,
            P::DeviceCode::column,
            P::DeviceCode::core_field_name,
        )?;
        for (name, field) in fields.fields().iter().filter(|(name, _)| *name != "scope") {
            let storage = resolve_field_name(field.field_name.as_deref(), name);
            for core in core_fields(EntityRole::DeviceCode) {
                let column = P::DeviceCode::column(core.name)?;
                if [name.as_str(), storage].contains(&column.as_str()) {
                    return Err(AuthError::config(format!(
                        "DeviceCode additional field {name} cannot replace native column {storage}"
                    )));
                }
            }
        }
        Ok(())
    }

    pub(super) async fn prepare_device_code_fields(
        &self,
        scope: SchemaValue<Option<String>>,
        additional_fields: FieldMap,
        create: bool,
    ) -> AuthResult<super::plugin_models::Write<P::DeviceCode>> {
        let config = self.model_fields.fields(EntityRole::DeviceCode);
        let mut fields = self
            .model_fields
            .device_code_fields_for_storage(scope, additional_fields, create)
            .await?;
        let backend = self.connection().get_database_backend();
        for (name, field) in config.fields() {
            let storage = resolve_field_name(field.field_name.as_deref(), name);
            if let Some(value) = fields.get_mut(storage) {
                *value = crate::reference_id::input_binding(
                    storage,
                    field,
                    std::mem::take(value),
                    self.config().advanced.database.generate_id(),
                    P::DeviceCode::column,
                    |name| {
                        P::DeviceCode::column(name).is_ok_and(|column| {
                            matches!(
                                column.def().get_column_type(),
                                sea_orm::ColumnType::Json | sea_orm::ColumnType::JsonBinary
                            )
                        })
                    },
                    backend,
                )?;
            }
        }
        let mut active = super::plugin_models::Write::<P::DeviceCode>::default();
        for (name, value) in fields {
            active.field(P::DeviceCode::column(&name)?, value);
        }
        Ok(active)
    }

    pub(super) async fn project_device_code_models(
        &self,
        models: Vec<P::DeviceCode>,
    ) -> AuthResult<Vec<DeviceCode>> {
        let fields = self.model_fields.fields(EntityRole::DeviceCode);
        let records = models
            .iter()
            .map(|model| {
                super::plugin_models::record_fields(
                    model,
                    fields,
                    self.connection().get_database_backend(),
                )
            })
            .collect::<AuthResult<Vec<_>>>()?;
        let rows = models
            .iter()
            .map(SeaOrmPluginModel::record)
            .collect::<AuthResult<Vec<_>>>()?;
        self.model_fields
            .project_device_code_records(
                rows,
                records,
                super::field_output::capabilities(self.connection().get_database_backend()),
                self.connection().get_database_backend() != DbBackend::Sqlite,
            )
            .await
    }
}
