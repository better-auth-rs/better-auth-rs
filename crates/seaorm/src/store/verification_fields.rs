use super::value_filter::{self, QueryPredicate};
use super::{
    SeaOrmStore,
    plugin_rows::{self, SqlRow},
};
use crate::schema::{AuthSchema, SeaOrmVerificationModel};
use better_auth_core::{
    AuthError, AuthResult, CreateVerification, FieldValue,
    store::schema::{EntityRole, resolve_field_name},
    wire::VerificationView,
};
use sea_orm::{Condition, ConnectionTrait, DbBackend, sea_query::SimpleExpr};

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S: AuthSchema,
    S::Verification: SeaOrmVerificationModel,
{
    pub(super) fn verification_column(
        &self,
        name: &str,
    ) -> AuthResult<<S::Verification as SeaOrmVerificationModel>::Column> {
        let fields = self.field_policy().verification().adapter_fields(&[]);
        let field = fields
            .fields()
            .get(name)
            .ok_or_else(|| AuthError::config(format!("Unknown verification field: {name}")))?;
        S::Verification::field_column(resolve_field_name(field.field_name.as_deref(), name))
    }

    pub(super) fn verification_query_field(
        &self,
        name: &str,
        original: &FieldValue,
        backend: DbBackend,
    ) -> AuthResult<(
        <S::Verification as SeaOrmVerificationModel>::Column,
        FieldValue,
    )> {
        let (column, value) = self.query_field_binding(
            EntityRole::Verification,
            &self.field_policy().verification(),
            name,
            original,
            backend,
        )?;
        Ok((S::Verification::field_column(&column)?, value))
    }

    pub(super) fn verification_selector(
        &self,
        name: &str,
        value: &FieldValue,
        backend: DbBackend,
    ) -> AuthResult<SimpleExpr> {
        let (column, value) = self.verification_query_field(name, value, backend)?;
        super::value_filter::equals(column, &value, backend)
    }

    pub(super) fn verification_live_selector<const N: usize>(
        &self,
        selectors: [(&str, &FieldValue); N],
        backend: DbBackend,
    ) -> AuthResult<Condition> {
        let fields = self.field_policy().verification();
        let expires = self.bind_query_field(
            EntityRole::Verification,
            &fields,
            "expiresAt",
            &chrono::Utc::now().into(),
            backend,
        )?;
        let selectors = selectors
            .into_iter()
            .map(|(name, value)| {
                self.bind_query_field(EntityRole::Verification, &fields, name, value, backend)
            })
            .collect::<AuthResult<Vec<_>>>()?;
        let (column, now) = expires.resolve(EntityRole::Verification, &fields)?;
        let column = S::Verification::field_column(&column)?;
        let mut predicates = vec![
            QueryPredicate::new(
                column,
                better_auth_core::WhereOperator::Gt,
                better_auth_core::WhereMode::Sensitive,
                now,
            )
            .with_save_as(),
        ];
        for selector in selectors {
            let (column, value) = selector.resolve(EntityRole::Verification, &fields)?;
            predicates.push(QueryPredicate::equals(
                S::Verification::field_column(&column)?,
                value,
            ));
        }
        value_filter::all(predicates, backend)
    }

    pub(super) async fn output_verifications(
        &self,
        rows: &[SqlRow],
        db: &impl ConnectionTrait,
    ) -> AuthResult<Vec<VerificationView>> {
        let fields = self.field_policy().verification().adapter_fields(&[]);
        let backend = db.get_database_backend();
        let records = rows
            .iter()
            .map(|row| {
                row.record::<<S::Verification as SeaOrmVerificationModel>::Entity>(
                    &fields,
                    backend,
                    S::Verification::id_column(),
                    S::Verification::field_column,
                )
                .map(|record| record.with_id_output(&self.model_fields, EntityRole::Verification))
            })
            .collect::<AuthResult<Vec<_>>>()?;
        plugin_rows::project_records(&fields, records, backend, |fields| {
            Ok(VerificationView::from_adapter_fields(fields))
        })
        .await
    }

    pub(super) async fn output_verification(
        &self,
        row: &SqlRow,
        db: &impl ConnectionTrait,
    ) -> AuthResult<VerificationView> {
        Ok(self
            .output_verifications(std::slice::from_ref(row), db)
            .await?
            .remove(0))
    }

    pub(super) async fn output_verification_raw(
        &self,
        row: &sea_orm::QueryResult,
        db: &impl ConnectionTrait,
    ) -> AuthResult<VerificationView> {
        let fields = self.field_policy().verification().adapter_fields(&[]);
        let backend = db.get_database_backend();
        let record = plugin_rows::record_from_columns::<
            <S::Verification as SeaOrmVerificationModel>::Entity,
        >(
            row,
            &fields,
            backend,
            S::Verification::id_column(),
            S::Verification::field_column,
        )?
        .with_id_output(&self.model_fields, EntityRole::Verification);
        Ok(
            plugin_rows::project_records(&fields, vec![record], backend, |fields| {
                Ok(VerificationView::from_adapter_fields(fields))
            })
            .await?
            .remove(0),
        )
    }

    pub(super) async fn new_verification_active(
        &self,
        db: &impl ConnectionTrait,
        input: CreateVerification,
    ) -> AuthResult<
        super::record_write::RecordWrite<<S::Verification as SeaOrmVerificationModel>::Entity>,
    > {
        let fields = self.field_policy().verification();
        let backend = db.get_database_backend();
        let input = input.fields()?;
        let policy = self.config().advanced.database.generate_id();
        let input = super::record_write::prepare_fields(
            &fields,
            input,
            Some("verification"),
            (&self.model_fields, EntityRole::Verification),
            policy,
            backend,
            |name, field, value| {
                crate::reference_id::input_binding(
                    name,
                    field,
                    value,
                    policy,
                    S::Verification::field_column,
                    S::Verification::native_json_field,
                    backend,
                )
            },
        )
        .await?;
        super::record_write::RecordWrite::from_initialized_fields(
            &fields,
            input,
            S::Verification::field_column,
            S::Verification::extra_insert_columns(),
            |fields| S::Verification::new_active(None, fields),
        )
    }
}
