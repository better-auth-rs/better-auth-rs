use better_auth_core::{
    AuthResult, FieldMap, UserView,
    store::schema::{EntityRole, resolve_field_name},
    user_fields::{AdapterRecord, UserConfig},
};
use sea_orm::{ConnectionTrait, DbBackend, IdenStatic};

use crate::{SeaOrmUserModel, schema::AuthSchema};

use super::{SeaOrmStore, plugin_rows::SqlRow};

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
{
    pub(super) fn user_field_schema(&self) -> UserConfig {
        self.config()
            .user
            .user_field_schema_with_plugins(self.model_fields.user_plugin_fields())
    }

    pub(super) async fn output_users(
        &self,
        rows: &[SqlRow],
        db: &impl ConnectionTrait,
    ) -> AuthResult<Vec<UserView>> {
        let backend = db.get_database_backend();
        let records = rows
            .iter()
            .map(|row| self.user_record(row, backend))
            .collect::<AuthResult<Vec<_>>>()?;
        self.output_user_records(records, backend).await
    }

    pub(super) fn user_record(
        &self,
        row: &SqlRow,
        backend: DbBackend,
    ) -> AuthResult<AdapterRecord> {
        row.record::<<S::User as SeaOrmUserModel>::Entity>(
            &self.user_field_schema().adapter_fields(&[]),
            backend,
            S::User::id_column(),
            S::User::field_column,
        )
        .map(|record| record.with_id_output(&self.model_fields, EntityRole::User))
    }

    pub(super) async fn output_user_records(
        &self,
        records: Vec<AdapterRecord>,
        backend: DbBackend,
    ) -> AuthResult<Vec<UserView>> {
        let fields = self.user_field_schema().adapter_fields(&[]);
        fields
            .project_adapter_records_with_capabilities(
                records,
                super::field_output::capabilities(backend),
            )
            .await?
            .into_iter()
            .map(|output| super::plugin_rows::ordered_output(&fields, output))
            .map(UserView::try_from)
            .collect()
    }

    pub(super) async fn output_user(
        &self,
        row: &SqlRow,
        db: &impl ConnectionTrait,
    ) -> AuthResult<UserView> {
        Ok(self
            .output_users(std::slice::from_ref(row), db)
            .await?
            .remove(0))
    }

    pub(super) async fn output_native_user_pages(
        &self,
        pages: Vec<&[SqlRow]>,
    ) -> AuthResult<Vec<Vec<FieldMap>>> {
        let fields = self.user_field_schema().adapter_fields(&[]);
        let backend = self.connection().get_database_backend();
        let pages = super::joins::project_child_pages(&fields, pages, backend, &|row| {
            row.native_record::<<S::User as SeaOrmUserModel>::Entity>(
                &fields,
                backend,
                S::User::id_column(),
                S::User::field_column,
            )
            .map(|record| record.with_id_output(&self.model_fields, EntityRole::User))
        })
        .await?;
        Ok(pages
            .into_iter()
            .map(|page| {
                page.into_iter()
                    .map(|output| super::plugin_rows::ordered_output(&fields, output))
                    .collect()
            })
            .collect())
    }

    pub(super) fn query_user_record(
        &self,
        row: SqlRow,
    ) -> AuthResult<(UserView, FieldMap, SqlRow)> {
        let schema = self.user_field_schema().adapter_fields(&[]);
        let mut native = FieldMap::new();
        let mut storage = FieldMap::new();
        for (name, field) in schema.fields() {
            let physical = resolve_field_name(field.field_name.as_deref(), name);
            let value = row.value(S::User::field_column(physical)?.as_str())?;
            let selected = match (name.as_str(), &field.field_type, &value) {
                ("id", _, value) if !value.is_null() => value.display_utf16()?.into(),
                (_, better_auth_core::user_fields::UserFieldType::Date, value)
                    if !value.is_null() =>
                {
                    better_auth_core::query::field_date(value)?.into()
                }
                (
                    _,
                    better_auth_core::user_fields::UserFieldType::Boolean,
                    better_auth_core::FieldValue::Number(value),
                ) => (*value != 0.0).into(),
                _ => value.clone(),
            };
            let _ = native.insert(name.clone(), selected);
            let _ = storage.insert(physical.to_owned(), value);
        }
        Ok((UserView::try_from(native)?, storage, row))
    }
}
