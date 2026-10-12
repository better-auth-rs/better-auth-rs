use crate::{SeaOrmPluginModel, schema::AuthSchema};
use better_auth_core::AuthResult;
use better_auth_core::store::schema::{EntityRole, resolve_field_name};
use better_auth_core::{FieldMap, FromFieldMap};
use sea_orm::QueryResult;

pub(super) type Write<M> = super::record_write::RecordWrite<Entity<M>>;

pub(super) type Entity<M> = <M as SeaOrmPluginModel>::Entity;

impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    super::SeaOrmStore<S, O, P>
{
    pub(super) fn plugin_record_model<M: SeaOrmPluginModel>(
        &self,
        role: EntityRole,
    ) -> super::raw_records::SqlRecordModel<'_, Entity<M>> {
        super::raw_records::SqlRecordModel::new(
            self.config(),
            &self.model_fields,
            role,
            self.model_fields.plugin_fields(role),
            self.connection().get_database_backend(),
            M::column,
        )
    }

    pub(super) fn plugin_column<M: SeaOrmPluginModel>(
        &self,
        role: EntityRole,
        name: &str,
    ) -> AuthResult<M::Column> {
        if name == "id" {
            return M::column("id");
        }
        let fields = self.model_fields.plugin_fields(role);
        let storage = fields.fields().get(name).map_or(name, |field| {
            resolve_field_name(field.field_name.as_deref(), name)
        });
        M::column(storage)
    }

    pub(super) fn validate_plugin_fields<M: SeaOrmPluginModel>(
        &self,
        role: EntityRole,
    ) -> AuthResult<()> {
        for name in self.model_fields.plugin_fields(role).fields().keys() {
            let _ = self.plugin_column::<M>(role, name)?;
        }
        let _ = M::column("id")?;
        Ok(())
    }

    pub(super) fn bind_plugin_query_field(
        &self,
        role: EntityRole,
        name: &str,
        value: better_auth_core::FieldValue,
    ) -> AuthResult<super::value_filter::BoundQueryField> {
        let fields = self.model_fields.plugin_fields(role);
        let backend = self.connection().get_database_backend();
        self.bind_query_field(role, &fields, name, &value, backend)
    }

    pub(super) fn resolve_plugin_query_field<M: SeaOrmPluginModel>(
        &self,
        role: EntityRole,
        bound: super::value_filter::BoundQueryField,
    ) -> AuthResult<(M::Column, better_auth_core::FieldValue)> {
        let (column, value) = bound.resolve(role, &self.model_fields.plugin_fields(role))?;
        Ok((M::column(&column)?, value))
    }

    pub(super) fn plugin_equals<M: SeaOrmPluginModel>(
        &self,
        role: EntityRole,
        name: &str,
        value: better_auth_core::FieldValue,
    ) -> AuthResult<sea_orm::sea_query::SimpleExpr> {
        let bound = self.bind_plugin_query_field(role, name, value)?;
        self.resolve_plugin_equals::<M>(role, bound)
    }

    pub(super) fn resolve_plugin_equals<M: SeaOrmPluginModel>(
        &self,
        role: EntityRole,
        bound: super::value_filter::BoundQueryField,
    ) -> AuthResult<sea_orm::sea_query::SimpleExpr> {
        let (column, value) = self.resolve_plugin_query_field::<M>(role, bound)?;
        super::value_filter::equals(column, &value, self.connection().get_database_backend())
    }

    pub(super) fn plugin_id_filter<M: SeaOrmPluginModel>(
        &self,
        role: EntityRole,
        id: &better_auth_core::SchemaValue<String>,
    ) -> AuthResult<sea_orm::sea_query::SimpleExpr> {
        self.plugin_equals::<M>(role, "id", id.field_value())
    }

    pub(super) async fn prepare_plugin_fields<M: SeaOrmPluginModel>(
        &self,
        role: EntityRole,
        model: &str,
        input: FieldMap,
        create: bool,
    ) -> AuthResult<Write<M>> {
        let force_allow_id = create && input.contains_key("id");
        self.plugin_record_model::<M>(role)
            .prepare(input.into(), create.then_some(model), force_allow_id)
            .await
    }

    pub(super) async fn project_plugin_rows<M: SeaOrmPluginModel, T: FromFieldMap>(
        &self,
        role: EntityRole,
        rows: &[QueryResult],
    ) -> AuthResult<Vec<T>> {
        self.plugin_record_model::<M>(role).project(rows).await
    }
}
