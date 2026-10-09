//! Apply complete Session field policies while retaining lifecycle and transaction boundaries.

use super::instrumentation::database_operation;
use sea_orm::ConnectionTrait;

use super::{SeaOrmStore, cancelled_by_hook};
use crate::error::{AuthError, AuthResult};
use crate::hooks::SessionUpdate;
use crate::schema::{AuthSchema, SeaOrmSessionModel};
use crate::types::CreateSession;
use better_auth_core::id::AdapterIdInput;
use better_auth_core::store::schema::EntityRole;

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S: AuthSchema,
    S::Session: SeaOrmSessionModel,
{
    pub(super) fn validate_session_fields(&self) -> AuthResult<()> {
        if S::Session::active_column().is_some() {
            return Ok(());
        }
        for (name, field) in self.config().session.field_schema().fields() {
            let storage = better_auth_core::store::schema::resolve_field_name(
                field.field_name.as_deref(),
                name,
            );
            if name == "active" || storage == "active" {
                let _ = S::Session::field_column(storage)?;
                return Err(AuthError::config(
                    "The active field policy requires an active-column Session model",
                ));
            }
        }
        Ok(())
    }

    pub(crate) async fn before_runtime_session_in_tx(
        &self,
        session: &mut better_auth_core::store::PreparedSessionCreate,
        tx: Option<super::HookTransaction<'_, S>>,
    ) -> AuthResult<()> {
        if self
            .before_runtime_session_optional_in_tx(session, tx)
            .await?
        {
            Ok(())
        } else {
            Err(cancelled_by_hook("session creation"))
        }
    }
    pub(crate) async fn before_runtime_session_optional_in_tx(
        &self,
        session: &mut better_auth_core::store::PreparedSessionCreate,
        tx: Option<super::HookTransaction<'_, S>>,
    ) -> AuthResult<bool> {
        let context = self.hook_context(tx);
        for hook in self.hooks() {
            let outcome = better_auth_core::observability::database::with_database_hook(
                context.config,
                hook.hook_metadata(),
                better_auth_core::observability::database::DatabaseHook::BeforeCreateSession,
                hook.before_create_session(session.fields_mut(), &context),
            )
            .await?;
            if !session.apply(outcome) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(super) async fn after_runtime_session(
        &self,
        session: Option<&better_auth_core::wire::SessionView>,
        request: Option<better_auth_core::hooks::RequestHookContext>,
    ) -> AuthResult<()> {
        self.after_creation(
            None,
            super::transaction_hooks::Effect::SessionCreated(session.cloned().map(Box::new)),
            request,
        )
        .await
    }

    pub(crate) async fn create_session_with_connection<C>(
        &self,
        db: &C,
        tx: Option<super::HookTransaction<'_, S>>,
        input: CreateSession,
        writer: Option<better_auth_core::store::SessionCreateWriter>,
    ) -> AuthResult<Option<better_auth_core::wire::SessionView>>
    where
        C: ConnectionTrait,
    {
        let request = crate::hooks::current_request_hook_context();
        let write_database = writer.as_ref().is_none_or(|writer| writer.write_database);
        let mut prepared = better_auth_core::store::PreparedSessionCreate::new(
            input,
            self.config(),
            !write_database,
        )?;
        if !self
            .before_runtime_session_optional_in_tx(&mut prepared, tx)
            .await?
        {
            return Ok(None);
        }
        let (original, fields) = prepared.into_parts();
        let mut session = if write_database {
            better_auth_core::store::database_hooks::await_adapter_lookup().await;
            self.write_session_create_fields(db, tx, fields.clone())
                .await?
        } else {
            None
        };
        let deferred = match writer {
            Some(writer) => {
                let final_fields = match &session {
                    Some(session) => session.clone().into(),
                    None => fields,
                };
                if session.is_none() {
                    session = Some(better_auth_core::store::session_from_create_fields(
                        final_fields.clone(),
                    )?);
                }
                let write = (writer.write)(original, final_fields);
                if writer.deferred {
                    Some(write)
                } else {
                    write.await?;
                    None
                }
            }
            None => None,
        };
        self.after_creation(
            tx,
            super::transaction_hooks::Effect::SessionCreated(session.clone().map(Box::new)),
            request,
        )
        .await?;
        if let Some(write) = deferred {
            super::transaction_hooks::after_write(tx, write).await?;
        }
        Ok(session)
    }

    async fn write_session_create_fields<C>(
        &self,
        db: &C,
        tx: Option<super::HookTransaction<'_, S>>,
        mut fields: better_auth_core::FieldMap,
    ) -> AuthResult<Option<better_auth_core::wire::SessionView>>
    where
        C: ConnectionTrait,
    {
        self.validate_session_fields()?;
        let readback_schema =
            better_auth_core::store::session_field_schema(&self.config().session, &fields);
        let schema = readback_schema.adapter_fields(&[]);
        let mut supplied_id = fields.remove("id");
        self.model_fields.begin_id_input(
            EntityRole::Session,
            AdapterIdInput {
                force_allow_id: supplied_id.is_some(),
                supports_native_uuid: db.get_database_backend() == sea_orm::DbBackend::Postgres,
            },
        )?;
        let fields = schema
            .storage_fields_with_bound_id(
                fields,
                true,
                || {
                    let supplied = supplied_id.take();
                    let Some(policy) = self.model_fields.id_input_policy(EntityRole::Session)?
                    else {
                        return Ok(supplied.filter(|value| !value.is_undefined()));
                    };
                    self.config()
                        .advanced
                        .database
                        .generate_id()
                        .adapter_create_id_input("session", supplied, policy)
                },
                |name, field, value| {
                    crate::reference_id::input_binding(
                        name,
                        field,
                        value,
                        self.config().advanced.database.generate_id(),
                        S::Session::field_column,
                        S::Session::native_json_field,
                        db.get_database_backend(),
                    )
                },
            )
            .await?;
        let mut initialized_columns = S::Session::extra_insert_columns();
        initialized_columns.extend(S::Session::active_column());
        let record = super::record_write::RecordWrite::from_initialized_fields(
            fields,
            S::Session::field_column,
            initialized_columns,
            |fields| S::Session::new_active(None, fields),
        )?;
        let session = database_operation::<<S::Session as SeaOrmSessionModel>::Entity, _>(
            self.config(),
            "create",
            async {
                record
                    .insert_raw(
                        db,
                        super::create_readback::CreateReadback {
                            schema: &readback_schema,
                            policy: self.config().advanced.database.generate_id(),
                            scope: self.readback_scope(tx),
                            column: S::Session::field_column,
                        },
                    )
                    .await
            },
        )
        .await?;
        match session {
            Some(session) => self
                .output_session_raw(&session, &schema, db)
                .await
                .map(Some),
            None => Ok(None),
        }
    }

    pub(crate) async fn create_session_in_tx(
        &self,
        tx: super::HookTransaction<'_, S>,
        create_session: CreateSession,
    ) -> AuthResult<better_auth_core::wire::SessionView> {
        self.create_session_with_connection(tx.0, Some(tx), create_session, None)
            .await?
            .ok_or_else(|| AuthError::forbidden("session creation returned no record"))
    }

    pub(super) async fn update_session_with_connection(
        &self,
        db: &impl ConnectionTrait,
        tx: Option<super::HookTransaction<'_, S>>,
        token: &str,
        update: SessionUpdate,
    ) -> AuthResult<Option<better_auth_core::wire::SessionView>> {
        self.update_session_with_writer_and_connection(db, tx, &token.into(), update, None)
            .await
    }

    pub(super) async fn update_session_with_writer_and_connection(
        &self,
        db: &impl ConnectionTrait,
        tx: Option<super::HookTransaction<'_, S>>,
        token: &better_auth_core::FieldValue,
        update: SessionUpdate,
        secondary: Option<better_auth_core::store::SessionUpdateWriter>,
    ) -> AuthResult<Option<better_auth_core::wire::SessionView>> {
        let context = self.hook_context(tx);
        let mut prepared = better_auth_core::store::database_hooks::PreparedRecordWrite::new(
            update.into_public_fields()?,
        );
        for hook in self.hooks() {
            let outcome = better_auth_core::observability::database::with_database_hook(
                context.config,
                hook.hook_metadata(),
                better_auth_core::observability::database::DatabaseHook::BeforeUpdateSession,
                hook.before_update_session(prepared.original_fields_mut(), &context),
            )
            .await?;
            if !prepared.apply(outcome) {
                return Ok(None);
            }
        }
        let update = prepared.into_fields();
        let (write_database, cached) = match secondary {
            Some(secondary) => {
                let result = (secondary.write)(update.clone()).await?;
                (secondary.write_database, result)
            }
            None => (true, None),
        };
        let session = if write_database {
            better_auth_core::store::database_hooks::await_adapter_lookup().await;
            self.write_session_update(db, token, update).await?
        } else {
            cached
        };
        let store = self.clone();
        let updated = session.clone();
        let request = context.request.clone();
        let after = Box::pin(async move {
            let mut context = store.hook_context(None);
            context.request = request;
            for hook in store.hooks() {
                better_auth_core::observability::database::with_database_hook(
                    context.config,
                    hook.hook_metadata(),
                    better_auth_core::observability::database::DatabaseHook::AfterUpdateSession,
                    hook.after_update_session(updated.as_ref(), &context),
                )
                .await?;
            }
            Ok(())
        });
        match tx {
            Some((_, transaction)) => transaction.queue_after_commit(after)?,
            None => after.await?,
        }
        Ok(session)
    }

    pub(super) async fn prepare_session_update(
        &self,
        db: &impl ConnectionTrait,
        mut input: better_auth_core::FieldMap,
    ) -> AuthResult<(
        super::record_write::RecordWrite<<S::Session as SeaOrmSessionModel>::Entity>,
        better_auth_core::user_fields::UserConfig,
    )> {
        let backend = db.get_database_backend();
        self.validate_session_fields()?;
        self.model_fields.begin_id_input(
            EntityRole::Session,
            AdapterIdInput {
                force_allow_id: false,
                supports_native_uuid: backend == sea_orm::DbBackend::Postgres,
            },
        )?;
        let schema = better_auth_core::store::session_create_schema(&self.config().session, &input);
        let mut supplied_id = input.remove("id");
        let fields = schema
            .update_adapter_storage_fields(
                input,
                || {
                    let Some(value) = supplied_id.take() else {
                        return Ok(None);
                    };
                    let Some(policy) = self.model_fields.id_input_policy(EntityRole::Session)?
                    else {
                        return Ok(Some(value));
                    };
                    self.config()
                        .advanced
                        .database
                        .generate_id()
                        .adapter_id_input(value, policy)
                },
                |name, field, value| {
                    crate::reference_id::input_binding(
                        name,
                        field,
                        value,
                        self.config().advanced.database.generate_id(),
                        S::Session::field_column,
                        S::Session::native_json_field,
                        backend,
                    )
                },
            )
            .await?;
        let mut active = super::record_write::RecordWrite::<
            <S::Session as SeaOrmSessionModel>::Entity,
        >::default();
        active.apply_fields(fields, S::Session::field_column)?;
        Ok((active, schema))
    }

    pub(super) async fn write_session_update(
        &self,
        db: &impl ConnectionTrait,
        token: &better_auth_core::FieldValue,
        update: better_auth_core::FieldMap,
    ) -> AuthResult<Option<better_auth_core::wire::SessionView>> {
        let backend = db.get_database_backend();
        let (active, schema) = self.prepare_session_update(db, update).await?;
        let filter = self.session_token_filter(token)?;
        let session = database_operation::<<S::Session as SeaOrmSessionModel>::Entity, _>(
            self.config(),
            "update",
            super::updates::execute_update_returning_raw(
                db,
                active.update_returning(backend)?.filter(filter.clone()),
                filter,
            ),
        )
        .await?;
        match session.as_ref() {
            Some(row) => self.output_session_raw(row, &schema, db).await.map(Some),
            None => Ok(None),
        }
    }
}
