use super::instrumentation::database_operation;
use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect,
    SqliteTransactionMode, TransactionOptions, TransactionTrait, sea_query::ExprTrait,
};

use better_auth_core::store::VerificationStore;

use crate::error::AuthResult;
use crate::hooks::VerificationUpdate;
use crate::schema::{AuthSchema, SeaOrmVerificationModel};
use crate::types::CreateVerification;
use better_auth_core::store::VerificationCreateWriter;
use better_auth_core::wire::VerificationView;

use super::{SeaOrmStore, cancelled_by_hook, map_db_err};

#[cfg(test)]
#[path = "verification_concurrency_tests.rs"]
mod concurrency_tests;

#[async_trait]
impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> VerificationStore<S>
    for SeaOrmStore<S, O, P>
where
    S: AuthSchema + Send + Sync,
    S::Verification: SeaOrmVerificationModel,
    S::User: crate::schema::SeaOrmUserModel,
    S::Account: crate::schema::SeaOrmAccountModel,
    S::Session: crate::schema::SeaOrmSessionModel,
{
    async fn reserve_verification(
        &self,
        id: &str,
        verification: CreateVerification,
    ) -> AuthResult<bool> {
        let reservation_id = self.parse_id(id, S::Verification::parse_id)?;
        let result: AuthResult<()> =
            async {
                let active = self
                    .new_verification_active(
                        self.connection(),
                        Some((id.to_owned(), reservation_id.clone())),
                        verification.with_timestamps(Utc::now().into()),
                    )
                    .await?;
                let row = database_operation::<
                    <S::Verification as SeaOrmVerificationModel>::Entity,
                    _,
                >(self.config(), "create", async {
                    active
                        .insert_raw(
                            self.connection(),
                            super::create_readback::CreateReadback {
                                schema: &self.config().verification.field_schema(),
                                policy: self.config().advanced.database.generate_id(),
                                scope: super::create_readback::ReadbackScope::Direct(
                                    self.connection(),
                                ),
                                column: S::Verification::field_column,
                            },
                        )
                        .await
                })
                .await?;
                if let Some(row) = row {
                    let _ = self
                        .output_verification_raw(&row, self.connection())
                        .await?;
                }
                Ok(())
            }
            .await;
        match result {
            Ok(()) => Ok(true),
            Err(cause) => {
                if match database_operation::<<S::Verification as SeaOrmVerificationModel>::Entity, _>(
                    self.config(),
                    "findOne",
                    async {
                        <S::Verification as SeaOrmVerificationModel>::Entity::find()
                            .filter(super::value_filter::equals_native(
                                S::Verification::id_column(),
                                reservation_id,
                                self.connection().get_database_backend(),
                            )?)
                            .one(self.connection())
                            .await
                            .map_err(map_db_err)
                    },
                )
                .await?
                .as_ref() { Some(row) => self.output_verification(row, self.connection()).await.map(Some), None => Ok(None) }?
                .is_some()
                {
                    Ok(false)
                } else {
                    Err(cause)
                }
            }
        }
    }

    async fn get_verification_including_expired(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        self.find_verification_with_connection(self.connection(), identifier)
            .await
    }

    async fn update_verification_by_identifier(
        &self,
        identifier: &str,
        value: Option<String>,
        expires_at: Option<chrono::DateTime<Utc>>,
    ) -> AuthResult<()> {
        let _ = self
            .update_verification(
                identifier,
                VerificationUpdate {
                    value: value.map(Into::into).unwrap_or_default(),
                    expires_at: expires_at.map(Into::into).unwrap_or_default(),
                    ..Default::default()
                },
            )
            .await?;
        Ok(())
    }

    async fn update_verification(
        &self,
        identifier: &str,
        update: VerificationUpdate,
    ) -> AuthResult<Option<VerificationView>> {
        self.update_verification_with_connection(self.connection(), None, identifier, update)
            .await
    }

    async fn delete_verification_by_identifier(&self, identifier: &str) -> AuthResult<()> {
        self.delete_single_verification(
            self.connection(),
            None,
            super::value_filter::equals(
                S::Verification::identifier_column(),
                &identifier.into(),
                self.connection().get_database_backend(),
            )?,
        )
        .await
    }

    async fn create_verification(
        &self,
        verification: CreateVerification,
    ) -> AuthResult<VerificationView> {
        self.create_verification_optional(verification)
            .await?
            .ok_or_else(|| super::AuthError::internal("Verification creation returned no record"))
    }

    async fn create_verification_optional(
        &self,
        verification: CreateVerification,
    ) -> AuthResult<Option<VerificationView>> {
        self.create_verification_with_writer(verification, None)
            .await
    }

    async fn create_verification_with_writer(
        &self,
        verification: CreateVerification,
        writer: Option<VerificationCreateWriter>,
    ) -> AuthResult<Option<VerificationView>> {
        self.create_verification_with_connection(self.connection(), None, verification, writer)
            .await
    }

    async fn before_create_runtime_verification_optional(
        &self,
        verification: &mut CreateVerification,
    ) -> AuthResult<bool> {
        self.before_runtime_verification_optional_in_tx(verification, None)
            .await
    }

    async fn before_create_runtime_verification(
        &self,
        verification: &mut CreateVerification,
    ) -> AuthResult<()> {
        self.before_runtime_verification_in_tx(verification, None)
            .await
    }

    async fn after_create_runtime_verification(
        &self,
        verification: Option<&VerificationView>,
        request: Option<better_auth_core::hooks::RequestHookContext>,
    ) -> AuthResult<()> {
        self.after_creation(
            None,
            super::transaction_hooks::Effect::Created(verification.cloned().map(Box::new)),
            request,
        )
        .await
    }

    async fn get_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<VerificationView>> {
        match database_operation::<<S::Verification as SeaOrmVerificationModel>::Entity, _>(
            self.config(),
            "findOne",
            async {
                let now = super::record_bindings::Binding::Date(Utc::now().into())
                    .bind(self.connection().get_database_backend())?;
                let expires_at = S::Verification::expires_at_column();
                <S::Verification as SeaOrmVerificationModel>::Entity::find()
                    .filter(super::value_filter::equals(
                        S::Verification::identifier_column(),
                        &identifier.into(),
                        self.connection().get_database_backend(),
                    )?)
                    .filter(super::value_filter::equals(
                        S::Verification::value_column(),
                        &value.into(),
                        self.connection().get_database_backend(),
                    )?)
                    .filter(expires_at.into_expr().gt(expires_at.save_as(now)))
                    .one(self.connection())
                    .await
                    .map_err(map_db_err)
            },
        )
        .await?
        .as_ref()
        {
            Some(row) => self
                .output_verification(row, self.connection())
                .await
                .map(Some),
            None => Ok(None),
        }
    }

    async fn get_verification_by_value(&self, value: &str) -> AuthResult<Option<VerificationView>> {
        match database_operation::<<S::Verification as SeaOrmVerificationModel>::Entity, _>(
            self.config(),
            "findOne",
            async {
                let now = super::record_bindings::Binding::Date(Utc::now().into())
                    .bind(self.connection().get_database_backend())?;
                let expires_at = S::Verification::expires_at_column();
                <S::Verification as SeaOrmVerificationModel>::Entity::find()
                    .filter(super::value_filter::equals(
                        S::Verification::value_column(),
                        &value.into(),
                        self.connection().get_database_backend(),
                    )?)
                    .filter(expires_at.into_expr().gt(expires_at.save_as(now)))
                    .one(self.connection())
                    .await
                    .map_err(map_db_err)
            },
        )
        .await?
        .as_ref()
        {
            Some(row) => self
                .output_verification(row, self.connection())
                .await
                .map(Some),
            None => Ok(None),
        }
    }

    async fn get_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        match database_operation::<<S::Verification as SeaOrmVerificationModel>::Entity, _>(
            self.config(),
            "findOne",
            async {
                let now = super::record_bindings::Binding::Date(Utc::now().into())
                    .bind(self.connection().get_database_backend())?;
                let expires_at = S::Verification::expires_at_column();
                <S::Verification as SeaOrmVerificationModel>::Entity::find()
                    .filter(super::value_filter::equals(
                        S::Verification::identifier_column(),
                        &identifier.into(),
                        self.connection().get_database_backend(),
                    )?)
                    .filter(expires_at.into_expr().gt(expires_at.save_as(now)))
                    .one(self.connection())
                    .await
                    .map_err(map_db_err)
            },
        )
        .await?
        .as_ref()
        {
            Some(row) => self
                .output_verification(row, self.connection())
                .await
                .map(Some),
            None => Ok(None),
        }
    }

    async fn consume_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<VerificationView>> {
        let record = self
            .consume_latest_verification(identifier, Some(value))
            .await?;
        match record {
            Some(record) if !record.expires_at.is_before(Utc::now())? => Ok(Some(record)),
            _ => Ok(None),
        }
    }

    async fn consume_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        let record = self.consume_latest_verification(identifier, None).await?;
        match record {
            Some(record) if !record.expires_at.is_before(Utc::now())? => Ok(Some(record)),
            _ => Ok(None),
        }
    }

    async fn consume_verification_including_expired(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        self.consume_latest_verification(identifier, None).await
    }

    async fn delete_verification(&self, id: &str) -> AuthResult<()> {
        self.delete_single_verification(
            self.connection(),
            None,
            super::value_filter::equals_native(
                S::Verification::id_column(),
                self.parse_id(id, S::Verification::parse_id)?,
                self.connection().get_database_backend(),
            )?,
        )
        .await
    }

    async fn delete_expired_verifications(&self) -> AuthResult<usize> {
        let (count, records) = self
            .delete_expired_verifications_with_connection(self.connection(), None)
            .await?;
        let context = self.hook_context(None);
        for record in &records {
            for hook in self.hooks() {
                better_auth_core::observability::database::with_database_hook(context.config, hook.hook_metadata(), better_auth_core::observability::database::DatabaseHook::AfterDeleteVerification, hook.after_delete_verification(record, &context)).await?;
            }
        }
        Ok(count)
    }
}

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S: AuthSchema + Send + Sync,
    S::Verification: SeaOrmVerificationModel,
    S::User: crate::schema::SeaOrmUserModel,
    S::Account: crate::schema::SeaOrmAccountModel,
    S::Session: crate::schema::SeaOrmSessionModel,
{
    pub(super) async fn delete_expired_verifications_with_connection<C: ConnectionTrait>(
        &self,
        connection: &C,
        tx: Option<super::HookTransaction<'_, S>>,
    ) -> AuthResult<(usize, Vec<VerificationView>)> {
        let now = super::record_bindings::Binding::Date(Utc::now().into())
            .bind(connection.get_database_backend())?;
        let expires_at = S::Verification::expires_at_column();
        let filter = expires_at.into_expr().lt(expires_at.save_as(now));
        // Only the upstream deleteMany snapshot is best-effort. Hook and write errors propagate.
        let snapshot: AuthResult<Vec<VerificationView>> = async {
            match database_operation::<<S::Verification as SeaOrmVerificationModel>::Entity, _>(
                self.config(),
                "findMany",
                async {
                    <S::Verification as SeaOrmVerificationModel>::Entity::find()
                        .filter(filter.clone())
                        .limit(super::pagination::default_limit(
                            self.config(),
                            connection.get_database_backend(),
                        )?)
                        .all(connection)
                        .await
                        .map_err(map_db_err)
                },
            )
            .await
            {
                Ok(rows) => self.output_verifications(&rows, connection).await,
                Err(error) => Err(error),
            }
        }
        .await;
        let records = snapshot.unwrap_or_default();
        let context = self.hook_context(tx);
        for record in &records {
            for hook in self.hooks() {
                if better_auth_core::observability::database::with_database_hook(context.config, hook.hook_metadata(), better_auth_core::observability::database::DatabaseHook::BeforeDeleteVerification, hook
                    .before_delete_verification(record, &context)).await?
                    .is_cancelled()
                {
                    return Ok((0, Vec::new()));
                }
            }
        }
        let deleted =
            database_operation::<<S::Verification as SeaOrmVerificationModel>::Entity, _>(
                self.config(),
                "deleteMany",
                async {
                    <S::Verification as SeaOrmVerificationModel>::Entity::delete_many()
                        .filter(filter)
                        .exec(connection)
                        .await
                        .map_err(map_db_err)
                },
            )
            .await?;
        Ok((deleted.rows_affected as usize, records))
    }
}

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S: AuthSchema + Send + Sync,
    S::Verification: SeaOrmVerificationModel,
    S::User: crate::schema::SeaOrmUserModel,
    S::Account: crate::schema::SeaOrmAccountModel,
    S::Session: crate::schema::SeaOrmSessionModel,
{
    pub(super) async fn output_verifications(
        &self,
        rows: &[S::Verification],
        db: &impl ConnectionTrait,
    ) -> AuthResult<Vec<better_auth_core::wire::VerificationView>> {
        let fields = self.config().verification.field_schema();
        let records = rows
            .iter()
            .map(|row| row.record_fields(&fields))
            .collect::<AuthResult<Vec<_>>>()?;
        Ok(fields
            .project_adapter_records(
                records,
                db.get_database_backend() == sea_orm::DbBackend::Postgres,
                db.get_database_backend() != sea_orm::DbBackend::Sqlite,
            )
            .await?
            .into_iter()
            .map(better_auth_core::wire::VerificationView::from_adapter_fields)
            .collect())
    }

    async fn output_verification_raw(
        &self,
        row: &sea_orm::QueryResult,
        db: &impl ConnectionTrait,
    ) -> AuthResult<VerificationView> {
        let fields = self
            .config()
            .verification
            .field_schema()
            .adapter_fields(&[]);
        let backend = db.get_database_backend();
        let record = super::plugin_rows::record_from_columns::<
            <S::Verification as SeaOrmVerificationModel>::Entity,
        >(
            row,
            &fields,
            backend,
            S::Verification::id_column(),
            S::Verification::field_column,
        )?;
        let projected = fields
            .project_adapter_records_with_capabilities(
                vec![record],
                super::field_output::capabilities(backend),
            )
            .await?
            .remove(0);
        Ok(VerificationView::from_adapter_fields(
            projected.in_field_order(&fields.fields().keys().cloned().collect::<Vec<_>>()),
        ))
    }

    pub(super) async fn output_verification(
        &self,
        row: &S::Verification,
        db: &impl ConnectionTrait,
    ) -> AuthResult<VerificationView> {
        row.record(
            &self.config().verification.field_schema(),
            db.get_database_backend() == sea_orm::DbBackend::Postgres,
            db.get_database_backend() != sea_orm::DbBackend::Sqlite,
        )
        .await
    }

    async fn new_verification_active(
        &self,
        db: &impl ConnectionTrait,
        id: Option<(String, <S::Verification as SeaOrmVerificationModel>::Id)>,
        input: CreateVerification,
    ) -> AuthResult<
        super::record_write::RecordWrite<<S::Verification as SeaOrmVerificationModel>::Entity>,
    > {
        let fields = self.config().verification.field_schema();
        let backend = db.get_database_backend();
        let (mut logical_id, id) = id.map_or((None, None), |(logical, native)| {
            (Some(logical.into()), Some(native))
        });
        let input = fields
            .storage_fields_with_bound_id(
                input.fields()?,
                true,
                || Ok(logical_id.take()),
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
        let mut active = super::record_write::RecordWrite::from_initialized_fields(
            input,
            S::Verification::field_column,
            S::Verification::extra_insert_columns(),
            |input| S::Verification::new_active(id.clone(), input),
        )?;
        if let Some(id) = id {
            active.set(S::Verification::id_column(), id.into());
        } else {
            active.not_set(S::Verification::id_column());
        }
        Ok(active)
    }

    pub(super) async fn update_verification_with_connection(
        &self,
        db: &impl ConnectionTrait,
        tx: Option<super::HookTransaction<'_, S>>,
        identifier: &str,
        update: VerificationUpdate,
    ) -> AuthResult<Option<VerificationView>> {
        let mut prepared =
            better_auth_core::store::database_hooks::PreparedRecordWrite::new(update.fields()?);
        let context = self.hook_context(tx);
        for hook in self.hooks() {
            let outcome = better_auth_core::observability::database::with_database_hook(
                context.config,
                hook.hook_metadata(),
                better_auth_core::observability::database::DatabaseHook::BeforeUpdateVerification,
                hook.before_update_verification(prepared.original_fields_mut(), &context),
            )
            .await?;
            if !prepared.apply(outcome) {
                return Ok(None);
            }
        }
        better_auth_core::store::database_hooks::await_adapter_lookup().await;
        let fields = self.config().verification.field_schema();
        let backend = db.get_database_backend();
        let input = fields
            .record_storage_fields_with_binding(
                prepared.into_fields(),
                false,
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
        let active = super::record_write::RecordWrite::<
            <S::Verification as SeaOrmVerificationModel>::Entity,
        >::from_fields(input, S::Verification::field_column)?;
        let filter = super::value_filter::equals(
            S::Verification::identifier_column(),
            &identifier.into(),
            backend,
        )?;
        let row =
            match database_operation::<<S::Verification as SeaOrmVerificationModel>::Entity, _>(
                self.config(),
                "update",
                async {
                    super::updates::execute_update_returning_raw(
                        db,
                        active.update_returning(backend)?.filter(filter.clone()),
                        filter,
                    )
                    .await
                },
            )
            .await?
            .as_ref()
            {
                Some(row) => self.output_verification_raw(row, db).await.map(Some),
                None => Ok(None),
            }?;
        let updated = row.clone();
        let request = context.request.clone();
        let store = self.clone();
        super::transaction_hooks::after_write(
            tx,
            Box::pin(async move {
                let mut context = store.hook_context(None);
                context.request = request;
                for hook in store.hooks() {
                    better_auth_core::observability::database::with_database_hook(context.config, hook.hook_metadata(), better_auth_core::observability::database::DatabaseHook::AfterUpdateVerification, hook.after_update_verification(updated.as_ref(), &context)).await?;
                }
                Ok(())
            }),
        )
        .await?;
        Ok(row)
    }

    pub(super) async fn delete_single_verification(
        &self,
        db: &impl ConnectionTrait,
        tx: Option<super::HookTransaction<'_, S>>,
        condition: sea_orm::sea_query::SimpleExpr,
    ) -> AuthResult<()> {
        // A failed findMany projection is caught before single-delete hooks or writes run.
        let snapshot: AuthResult<Option<VerificationView>> = async {
            match database_operation::<<S::Verification as SeaOrmVerificationModel>::Entity, _>(
                self.config(),
                "findMany",
                async {
                    <S::Verification as SeaOrmVerificationModel>::Entity::find()
                        .filter(condition.clone())
                        .limit(1)
                        .all(db)
                        .await
                        .map(|rows| rows.into_iter().next())
                        .map_err(map_db_err)
                },
            )
            .await?
            .as_ref()
            {
                Some(row) => self.output_verification(row, db).await.map(Some),
                None => Ok(None),
            }
        }
        .await;
        let Ok(Some(row)) = snapshot else {
            return Ok(());
        };
        let context = self.hook_context(tx);
        for hook in self.hooks() {
            if better_auth_core::observability::database::with_database_hook(
                context.config,
                hook.hook_metadata(),
                better_auth_core::observability::database::DatabaseHook::BeforeDeleteVerification,
                hook.before_delete_verification(&row, &context),
            )
            .await?
            .is_cancelled()
            {
                return Ok(());
            }
        }
        let _ = database_operation::<<S::Verification as SeaOrmVerificationModel>::Entity, _>(
            self.config(),
            "delete",
            async {
                <S::Verification as SeaOrmVerificationModel>::Entity::delete_many()
                    .filter(condition)
                    .exec(db)
                    .await
                    .map_err(map_db_err)
            },
        )
        .await?;
        let store = self.clone();
        let request = context.request.clone();
        super::transaction_hooks::after_write(tx, Box::pin(async move {
            let mut context = store.hook_context(None);
            context.request = request;
            for hook in store.hooks() {
                better_auth_core::observability::database::with_database_hook(
                    context.config,
                    hook.hook_metadata(),
                    better_auth_core::observability::database::DatabaseHook::AfterDeleteVerification,
                    hook.after_delete_verification(&row, &context),
                ).await?;
            }
            Ok(())
        })).await
    }

    pub(super) async fn before_runtime_verification_in_tx(
        &self,
        verification: &mut CreateVerification,
        tx: Option<super::HookTransaction<'_, S>>,
    ) -> AuthResult<()> {
        if self
            .before_runtime_verification_optional_in_tx(verification, tx)
            .await?
        {
            Ok(())
        } else {
            Err(cancelled_by_hook("verification creation"))
        }
    }

    pub(super) async fn before_runtime_verification_optional_in_tx(
        &self,
        verification: &mut CreateVerification,
        tx: Option<super::HookTransaction<'_, S>>,
    ) -> AuthResult<bool> {
        let context = self.hook_context(tx);
        for hook in self.hooks() {
            if better_auth_core::observability::database::with_database_hook(
                context.config,
                hook.hook_metadata(),
                better_auth_core::observability::database::DatabaseHook::BeforeCreateVerification,
                hook.before_create_verification(verification, &context),
            )
            .await?
            .is_cancelled()
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(super) async fn create_verification_with_connection<C: ConnectionTrait>(
        &self,
        connection: &C,
        tx: Option<super::HookTransaction<'_, S>>,
        mut verification: CreateVerification,
        writer: Option<VerificationCreateWriter>,
    ) -> AuthResult<Option<VerificationView>> {
        let request = crate::hooks::current_request_hook_context();
        verification = verification.with_timestamps(Utc::now().into());
        if !self
            .before_runtime_verification_optional_in_tx(&mut verification, tx)
            .await?
        {
            return Ok(None);
        }
        let actual = verification.fields()?;
        let id = self.generated_id(
            "verification",
            verification.id.field_value().as_str().map(str::to_owned),
        )?;
        let parsed = id
            .as_deref()
            .map(|id| S::Verification::parse_id(id).map(|parsed| (id.to_owned(), parsed)))
            .transpose()?;
        let mut active = self
            .new_verification_active(connection, parsed, verification)
            .await?;
        if id.is_none() {
            active.not_set(S::Verification::id_column());
        }
        let row = database_operation::<<S::Verification as SeaOrmVerificationModel>::Entity, _>(
            self.config(),
            "create",
            async {
                active
                    .insert_raw(
                        connection,
                        super::create_readback::CreateReadback {
                            schema: &self.config().verification.field_schema(),
                            policy: self.config().advanced.database.generate_id(),
                            scope: self.readback_scope(tx),
                            column: S::Verification::field_column,
                        },
                    )
                    .await
            },
        )
        .await?;
        let mut result = match row {
            Some(row) => Some(self.output_verification_raw(&row, connection).await?),
            None => None,
        };
        if let Some(writer) = writer {
            let fields = match &result {
                Some(record) => record.fields()?,
                None => actual,
            };
            writer(fields.clone()).await?;
            if result.is_none() {
                result = Some(VerificationView::from_adapter_fields(fields));
            }
        }
        self.after_creation(
            tx,
            super::transaction_hooks::Effect::Created(result.clone().map(Box::new)),
            request,
        )
        .await?;
        Ok(result)
    }

    pub(super) async fn find_verification_with_connection<C: ConnectionTrait>(
        &self,
        connection: &C,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        match database_operation::<<S::Verification as SeaOrmVerificationModel>::Entity, _>(
            self.config(),
            "findMany",
            async {
                <S::Verification as SeaOrmVerificationModel>::Entity::find()
                    .filter(super::value_filter::equals(
                        S::Verification::identifier_column(),
                        &identifier.into(),
                        connection.get_database_backend(),
                    )?)
                    .order_by_desc(S::Verification::created_at_column())
                    .one(connection)
                    .await
                    .map_err(map_db_err)
            },
        )
        .await?
        .as_ref()
        {
            Some(row) => self.output_verification(row, connection).await.map(Some),
            None => Ok(None),
        }
    }

    pub(super) async fn consume_verification_with_transaction(
        &self,
        hook_transaction: &super::SeaOrmTransaction<S, O, P>,
        identifier: &str,
        expected_value: Option<&str>,
    ) -> AuthResult<Option<VerificationView>> {
        let transaction = &hook_transaction.tx;
        let Some(model) = database_operation::<
            <S::Verification as SeaOrmVerificationModel>::Entity,
            _,
        >(self.config(), "findMany", async {
            <S::Verification as SeaOrmVerificationModel>::Entity::find()
                .filter(super::value_filter::equals(
                    S::Verification::identifier_column(),
                    &identifier.into(),
                    transaction.get_database_backend(),
                )?)
                .order_by_desc(<S::Verification as SeaOrmVerificationModel>::created_at_column())
                .lock_exclusive()
                .one(transaction)
                .await
                .map_err(map_db_err)
        })
        .await?
        else {
            return Ok(None);
        };
        let snapshot = self.output_verification(&model, transaction).await?;
        if let Some(expected) = expected_value
            && snapshot.value.typed()? != expected
        {
            return Ok(None);
        }
        let hook_context = self.hook_context(Some((transaction, hook_transaction)));
        for hook in self.hooks() {
            if better_auth_core::observability::database::with_database_hook(
                hook_context.config,
                hook.hook_metadata(),
                better_auth_core::observability::database::DatabaseHook::BeforeDeleteVerification,
                hook.before_delete_verification(&snapshot, &hook_context),
            )
            .await?
            .is_cancelled()
            {
                return Ok(None);
            }
        }
        let id = self.parse_id(
            snapshot.id.typed()?,
            <S::Verification as SeaOrmVerificationModel>::parse_id,
        )?;
        let deleted =
            database_operation::<<S::Verification as SeaOrmVerificationModel>::Entity, _>(
                self.config(),
                "consumeOne",
                async {
                    <S::Verification as SeaOrmVerificationModel>::Entity::delete_many()
                        .filter(super::value_filter::equals_native(
                            S::Verification::id_column(),
                            id,
                            transaction.get_database_backend(),
                        )?)
                        .exec(transaction)
                        .await
                        .map_err(map_db_err)
                },
            )
            .await?;
        if deleted.rows_affected == 0 {
            return Ok(None);
        }
        // consumeOne output runs before removing older rows, inside the same transaction.
        let consumed = self.output_verification(&model, transaction).await?;
        let _ = database_operation::<<S::Verification as SeaOrmVerificationModel>::Entity, _>(
            self.config(),
            "deleteMany",
            async {
                <S::Verification as SeaOrmVerificationModel>::Entity::delete_many()
                    .filter(super::value_filter::equals(
                        S::Verification::identifier_column(),
                        &identifier.into(),
                        transaction.get_database_backend(),
                    )?)
                    .exec(transaction)
                    .await
                    .map_err(map_db_err)
            },
        )
        .await?;
        Ok(Some(consumed))
    }

    async fn consume_latest_verification(
        &self,
        identifier: &str,
        expected_value: Option<&str>,
    ) -> AuthResult<Option<VerificationView>> {
        let transaction = self
            .connection()
            .begin_with_options(TransactionOptions {
                sqlite_transaction_mode: Some(SqliteTransactionMode::Immediate),
                ..Default::default()
            })
            .await
            .map_err(map_db_err)?;
        let transaction = crate::TransactionConnection::new(transaction);
        let effects = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let hook_transaction = super::SeaOrmTransaction {
            store: self.clone(),
            tx: transaction.clone(),
            effects: std::sync::Arc::downgrade(&effects),
        };
        let result = self
            .consume_verification_with_transaction(&hook_transaction, identifier, expected_value)
            .await;
        if result.is_ok() {
            transaction.commit().await.map_err(map_db_err)?;
            self.finish_queued_transaction_effects(&effects).await?;
        } else {
            transaction.rollback().await.map_err(map_db_err)?;
        }
        let Some(model) = result? else {
            return Ok(None);
        };
        let hook_context = self.hook_context(None);
        for hook in self.hooks() {
            better_auth_core::observability::database::with_database_hook(
                hook_context.config,
                hook.hook_metadata(),
                better_auth_core::observability::database::DatabaseHook::AfterDeleteVerification,
                hook.after_delete_verification(&model, &hook_context),
            )
            .await?;
        }
        Ok(Some(model))
    }
}
