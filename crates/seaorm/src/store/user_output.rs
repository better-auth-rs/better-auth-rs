use better_auth_core::{
    AuthResult, FieldMap, UserView, store::schema::EntityRole, user_fields::AdapterRecord,
};
use sea_orm::{ConnectionTrait, DbBackend};

use crate::{SeaOrmUserModel, schema::AuthSchema};

use super::{SeaOrmStore, plugin_rows::SqlRow};

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
{
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
            &self.field_policy().user().adapter_fields(&[]),
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
        let fields = self.field_policy().user().adapter_fields(&[]);
        super::plugin_rows::project_records(&fields, records, backend, UserView::try_from).await
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
        let fields = self.field_policy().user().adapter_fields(&[]);
        let backend = self.connection().get_database_backend();
        let record_fields = fields.clone();
        let runtime = self.model_fields.clone();
        super::joins::project_child_pages(&fields, pages, backend, &move |row| {
            row.native_record(&record_fields, backend, S::User::field_column)
                .map(|record| record.with_id_output(&runtime, EntityRole::User))
        })
        .await
    }
}
