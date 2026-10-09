use super::{
    SeaOrmStore,
    plugin_rows::{self, SqlRow},
};
use crate::schema::{AuthSchema, SeaOrmVerificationModel};
use better_auth_core::{
    AuthError, AuthResult, CreateVerification, FieldValue,
    id::AdapterIdInput,
    store::schema::{EntityRole, resolve_field_name},
    user_fields::{AdapterRecord, UserConfig},
    wire::VerificationView,
};
use sea_orm::{
    ColumnTrait, Condition, ConnectionTrait, DbBackend,
    sea_query::{ExprTrait, SimpleExpr},
};

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S: AuthSchema,
    S::Verification: SeaOrmVerificationModel,
{
    pub(super) fn verification_column(
        &self,
        name: &str,
    ) -> AuthResult<<S::Verification as SeaOrmVerificationModel>::Column> {
        let fields = self
            .config()
            .verification
            .field_schema()
            .adapter_fields(&[]);
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
            &self.config().verification.field_schema(),
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
        let fields = self.config().verification.field_schema();
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
        let now = super::record_bindings::parameter(now, backend)?;
        let mut condition = Condition::all();
        for selector in selectors {
            let (column, value) = selector.resolve(EntityRole::Verification, &fields)?;
            condition = condition.add(super::value_filter::equals(
                S::Verification::field_column(&column)?,
                &value,
                backend,
            )?);
        }
        Ok(condition.add(column.into_expr().gt(column.save_as(now))))
    }

    async fn project_verification_records(
        &self,
        fields: &UserConfig,
        records: Vec<AdapterRecord>,
        backend: DbBackend,
    ) -> AuthResult<Vec<VerificationView>> {
        Ok(fields
            .project_adapter_records_with_capabilities(
                records,
                super::field_output::capabilities(backend),
            )
            .await?
            .into_iter()
            .map(|output| plugin_rows::ordered_output(fields, output))
            .map(VerificationView::from_adapter_fields)
            .collect())
    }

    pub(super) async fn output_verifications(
        &self,
        rows: &[SqlRow],
        db: &impl ConnectionTrait,
    ) -> AuthResult<Vec<VerificationView>> {
        if !rows.is_empty() {
            self.model_fields
                .begin_id_output(EntityRole::Verification)?;
        }
        let fields = self
            .config()
            .verification
            .field_schema()
            .adapter_fields(&[]);
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
            })
            .collect::<AuthResult<Vec<_>>>()?;
        self.project_verification_records(&fields, records, backend)
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
        self.model_fields
            .begin_id_output(EntityRole::Verification)?;
        let fields = self
            .config()
            .verification
            .field_schema()
            .adapter_fields(&[]);
        let backend = db.get_database_backend();
        let record = plugin_rows::record_from_columns::<
            <S::Verification as SeaOrmVerificationModel>::Entity,
        >(
            row,
            &fields,
            backend,
            S::Verification::id_column(),
            S::Verification::field_column,
        )?;
        Ok(self
            .project_verification_records(&fields, vec![record], backend)
            .await?
            .remove(0))
    }

    pub(super) async fn new_verification_active(
        &self,
        db: &impl ConnectionTrait,
        input: CreateVerification,
        forced_id: Option<&str>,
    ) -> AuthResult<
        super::record_write::RecordWrite<<S::Verification as SeaOrmVerificationModel>::Entity>,
    > {
        let fields = self.config().verification.field_schema();
        let backend = db.get_database_backend();
        let mut input = input.fields()?;
        let forced_id = forced_id
            .map(|id| {
                crate::field_value::from_column(
                    self.parse_id(id, S::Verification::parse_id)?.into(),
                )
            })
            .transpose()?;
        if let Some(id) = &forced_id {
            let _ = input.insert("id".into(), id.clone());
        }
        let supplied = input.get("id").cloned();
        self.model_fields.begin_id_input(
            EntityRole::Verification,
            AdapterIdInput {
                force_allow_id: supplied.is_some(),
                supports_native_uuid: backend == DbBackend::Postgres,
            },
        )?;
        let input = fields
            .storage_fields_with_bound_id(
                input,
                true,
                || {
                    if let Some(id) = &forced_id {
                        Ok(Some(id.clone()))
                    } else {
                        match self
                            .model_fields
                            .id_input_policy(EntityRole::Verification)?
                        {
                            Some(policy) => self
                                .config()
                                .advanced
                                .database
                                .generate_id()
                                .adapter_create_id_input("verification", supplied.clone(), policy),
                            None => Ok(supplied.clone()),
                        }
                    }
                },
                |name, field, value| {
                    crate::reference_id::input_binding(
                        name,
                        field,
                        value,
                        self.config().advanced.database.generate_id(),
                        S::Verification::field_column,
                        S::Verification::native_json_field,
                        backend,
                    )
                },
            )
            .await?;
        super::record_write::RecordWrite::from_initialized_fields(
            input,
            S::Verification::field_column,
            S::Verification::extra_insert_columns(),
            |fields| S::Verification::new_active(None, fields),
        )
    }
}
