use super::instrumentation::database_operation;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, EntityTrait, QueryFilter,
    QuerySelect, sea_query::ExprTrait,
};

use better_auth_core::id::AdapterIdInput;
use better_auth_core::session::SessionData;
use better_auth_core::store::schema::EntityRole;
use better_auth_core::store::{SessionStore, SessionUpdateWriter};

use crate::error::{AuthError, AuthResult};
use crate::hooks::{DatabaseHookUpdate, SessionUpdate};
use crate::schema::{AuthSchema, SeaOrmSessionModel, SeaOrmUserModel};
use crate::types::CreateSession;

use super::{SeaOrmStore, cancelled_by_hook, map_db_err, session_output::SessionSnapshot};

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

    pub(super) async fn apply_session_field_updates(
        &self,
        active: <S::Session as SeaOrmSessionModel>::ActiveModel,
    ) -> AuthResult<super::record_write::RecordWrite<<S::Session as SeaOrmSessionModel>::Entity>>
    {
        self.validate_session_fields()?;
        let schema = self.config().session.adapter_schema();
        self.model_fields.begin_id_input(
            EntityRole::Session,
            AdapterIdInput {
                force_allow_id: false,
                supports_native_uuid: self.connection().get_database_backend()
                    == sea_orm::DbBackend::Postgres,
            },
        )?;
        let fields = schema
            .storage_fields_with_binding(Default::default(), false, |name, field, value| {
                crate::reference_id::input_binding(
                    name,
                    field,
                    value,
                    self.config().advanced.database.generate_id(),
                    S::Session::field_column,
                    S::Session::native_json_field,
                    self.connection().get_database_backend(),
                )
            })
            .await?;
        let mut active = super::record_write::RecordWrite::from_active(active);
        active.apply_fields(fields, S::Session::field_column)?;
        Ok(active)
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

    async fn after_runtime_session(
        &self,
        session: &better_auth_core::wire::SessionView,
        request: Option<better_auth_core::hooks::RequestHookContext>,
    ) -> AuthResult<()> {
        let mut context = self.hook_context(None);
        context.request = request;
        for hook in self.hooks() {
            better_auth_core::observability::database::with_database_hook(
                context.config,
                hook.hook_metadata(),
                better_auth_core::observability::database::DatabaseHook::AfterCreateSession,
                hook.after_create_session(session, &context),
            )
            .await?;
        }
        Ok(())
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
        let secondary_fields = (!write_database).then(|| fields.clone());
        let session = if write_database {
            better_auth_core::store::database_hooks::await_adapter_lookup().await;
            self.write_session_create_fields(db, fields).await?
        } else {
            better_auth_core::store::session_from_create_fields(fields)?
        };
        let deferred = match writer {
            Some(writer) => {
                let write = (writer.write)(
                    original,
                    secondary_fields.unwrap_or_else(|| session.clone().into()),
                );
                if writer.deferred {
                    Some(write)
                } else {
                    write.await?;
                    None
                }
            }
            None => None,
        };
        let store = self.clone();
        let created = session.clone();
        super::transaction_hooks::after_write(
            tx,
            Box::pin(async move { store.after_runtime_session(&created, request).await }),
        )
        .await?;
        if let Some(write) = deferred {
            super::transaction_hooks::after_write(tx, write).await?;
        }
        Ok(Some(session))
    }

    async fn write_session_create_fields<C>(
        &self,
        db: &C,
        mut fields: better_auth_core::FieldMap,
    ) -> AuthResult<better_auth_core::wire::SessionView>
    where
        C: ConnectionTrait,
    {
        self.validate_session_fields()?;
        let schema =
            better_auth_core::store::session_create_schema(&self.config().session, &fields);
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
        let native = better_auth_core::store::session_create_native_fields(&schema, &fields);
        let prepared = better_auth_core::store::session_from_create_fields(native)?;
        let created_at = prepared.created_at.to_datetime()?.ok_or_else(|| {
            AuthError::config("The Session constructor requires a valid createdAt Date")
        })?;
        if let Some(user_id) = prepared.user_id.as_str() {
            let _ = S::Session::parse_user_id(user_id)?;
        }
        let input = CreateSession {
            user_id: prepared.user_id,
            expires_at: prepared.expires_at,
            ip_address: prepared.ip_address,
            user_agent: prepared.user_agent,
            impersonated_by: prepared.impersonated_by,
            active_organization_id: prepared.active_organization_id,
            additional_fields: Default::default(),
        };
        let mut active = S::Session::new_active(None, prepared.token, input, created_at)?;
        active.not_set(S::Session::id_column());
        let mut record = super::record_write::RecordWrite::from_active(active);
        record.apply_fields(fields, S::Session::field_column)?;
        let session = database_operation::<<S::Session as SeaOrmSessionModel>::Entity, _>(
            self.config(),
            "create",
            async { record.insert(db).await },
        )
        .await?;
        self.output_session(&session, db).await
    }

    pub(crate) async fn create_session_in_tx(
        &self,
        tx: super::HookTransaction<'_, S>,
        create_session: CreateSession,
    ) -> AuthResult<better_auth_core::wire::SessionView> {
        self.create_session_with_connection(tx.0, Some(tx), create_session, None)
            .await?
            .ok_or_else(|| cancelled_by_hook("session creation"))
    }

    pub(super) async fn update_session_with_connection(
        &self,
        db: &impl ConnectionTrait,
        tx: Option<super::HookTransaction<'_, S>>,
        token: &str,
        update: SessionUpdate,
    ) -> AuthResult<Option<better_auth_core::wire::SessionView>> {
        self.update_session_with_writer_and_connection(db, tx, token, update, None)
            .await
    }

    pub(super) async fn update_session_with_writer_and_connection(
        &self,
        db: &impl ConnectionTrait,
        tx: Option<super::HookTransaction<'_, S>>,
        token: &str,
        mut update: SessionUpdate,
        secondary: Option<better_auth_core::store::SessionUpdateWriter>,
    ) -> AuthResult<Option<better_auth_core::wire::SessionView>> {
        let context = self.hook_context(tx);
        let original = update.clone();
        for hook in self.hooks() {
            match better_auth_core::observability::database::with_database_hook(
                context.config,
                hook.hook_metadata(),
                better_auth_core::observability::database::DatabaseHook::BeforeUpdateSession,
                hook.before_update_session(token, &original, &context),
            )
            .await?
            {
                DatabaseHookUpdate::Continue => {}
                DatabaseHookUpdate::Cancel => return Ok(None),
                DatabaseHookUpdate::Patch(patch) => update.merge(patch),
            }
        }
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

    async fn write_session_update(
        &self,
        db: &impl ConnectionTrait,
        token: &str,
        mut update: SessionUpdate,
    ) -> AuthResult<Option<better_auth_core::wire::SessionView>> {
        let backend = db.get_database_backend();
        let mut active = <S::Session as SeaOrmSessionModel>::ActiveModel::default();
        self.validate_session_fields()?;
        self.model_fields.begin_id_input(
            EntityRole::Session,
            AdapterIdInput {
                force_allow_id: false,
                supports_native_uuid: backend == sea_orm::DbBackend::Postgres,
            },
        )?;
        let mut input = std::mem::take(&mut update.additional_fields);
        let typed_id = update.id.take().map(better_auth_core::FieldValue::from);
        let mut supplied_id = input.remove("id").or(typed_id);
        let fields = self
            .config()
            .session
            .adapter_schema()
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
        let _ = update.updated_at.get_or_insert_with(|| Utc::now().into());
        let dates = [
            ("expiresAt", update.expires_at.take()),
            ("createdAt", update.created_at.take()),
            ("updatedAt", update.updated_at.take()),
        ];
        S::Session::apply_update(&mut active, update)?;
        let mut active = super::record_write::RecordWrite::from_active(active);
        for (name, value) in dates {
            if let Some(date) = value {
                active.native_field(
                    S::Session::field_column(name)?,
                    better_auth_core::FieldValue::Date(date),
                );
            }
        }
        active.apply_fields(fields, S::Session::field_column)?;
        let reselect = match (
            active.expression(S::Session::id_column(), backend)?,
            active.expression(S::Session::token_column(), backend)?,
        ) {
            (Some(value), _) => S::Session::id_column()
                .into_expr()
                .eq(S::Session::id_column().save_as(value)),
            (_, Some(value)) => S::Session::token_column()
                .into_expr()
                .eq(S::Session::token_column().save_as(value)),
            _ => S::Session::token_column().eq(token),
        };
        let session = database_operation::<<S::Session as SeaOrmSessionModel>::Entity, _>(
            self.config(),
            "update",
            super::updates::update_record_returning_one::<
                <S::Session as SeaOrmSessionModel>::Entity,
                _,
            >(db, active, S::Session::token_column().eq(token), reselect),
        )
        .await?;
        match session.as_ref() {
            Some(row) => self.output_session(row, db).await.map(Some),
            None => Ok(None),
        }
    }
}

#[async_trait]
impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SessionStore<S>
    for SeaOrmStore<S, O, P>
where
    S: AuthSchema + Send + Sync,
    S::Session: SeaOrmSessionModel,
    S::User: SeaOrmUserModel,
    S::Account: crate::schema::SeaOrmAccountModel,
    S::Verification: crate::schema::SeaOrmVerificationModel,
{
    async fn update_session_with_writer(
        &self,
        token: &str,
        update: SessionUpdate,
        secondary: Option<SessionUpdateWriter>,
    ) -> AuthResult<Option<better_auth_core::wire::SessionView>> {
        self.update_session_with_writer_and_connection(
            self.connection(),
            None,
            token,
            update,
            secondary,
        )
        .await
    }

    async fn create_session_optional(
        &self,
        input: CreateSession,
    ) -> AuthResult<Option<better_auth_core::wire::SessionView>> {
        self.create_session_with_connection(self.connection(), None, input, None)
            .await
    }
    async fn create_session_with_writer(
        &self,
        input: CreateSession,
        writer: Option<better_auth_core::store::SessionCreateWriter>,
    ) -> AuthResult<Option<better_auth_core::wire::SessionView>> {
        self.create_session_with_connection(self.connection(), None, input, writer)
            .await
    }

    async fn before_create_runtime_session_optional(
        &self,
        input: &mut better_auth_core::store::PreparedSessionCreate,
    ) -> AuthResult<bool> {
        self.before_runtime_session_optional_in_tx(input, None)
            .await
    }
    async fn before_create_runtime_session(
        &self,
        session: &mut better_auth_core::store::PreparedSessionCreate,
    ) -> AuthResult<()> {
        self.before_runtime_session_in_tx(session, None).await
    }

    async fn after_create_runtime_session(
        &self,
        session: &better_auth_core::wire::SessionView,
        request: Option<better_auth_core::hooks::RequestHookContext>,
    ) -> AuthResult<()> {
        self.after_runtime_session(session, request).await
    }

    async fn end_session(&self, token: &str) -> AuthResult<()> {
        let condition = Condition::all().add(S::Session::token_column().eq(token));
        self.delete_sessions_with_connection(self.connection(), None, condition, true)
            .await
            .map(|_| ())
    }

    async fn create_session(
        &self,
        create_session: CreateSession,
    ) -> AuthResult<better_auth_core::wire::SessionView> {
        self.create_session_optional(create_session)
            .await?
            .ok_or_else(|| cancelled_by_hook("session creation"))
    }

    async fn get_session(
        &self,
        token: &str,
    ) -> AuthResult<Option<better_auth_core::wire::SessionView>> {
        self.model_fields.begin_id_query(EntityRole::Session)?;
        match database_operation::<<S::Session as SeaOrmSessionModel>::Entity, _>(
            self.config(),
            "findOne",
            async {
                <S::Session as SeaOrmSessionModel>::Entity::find()
                    .filter(<S::Session as SeaOrmSessionModel>::token_column().eq(token))
                    .filter(
                        Condition::all()
                            .add_option(S::Session::active_column().map(|column| column.eq(true))),
                    )
                    .one(self.connection())
                    .await
                    .map_err(map_db_err)
            },
        )
        .await?
        .as_ref()
        {
            Some(row) => self.output_session(row, self.connection()).await.map(Some),
            None => Ok(None),
        }
    }

    async fn get_session_snapshot(&self, token: &str) -> AuthResult<Option<SessionSnapshot>> {
        let relation = SessionData::resolve_schema(
            self.config(),
            &self.model_fields,
            super::model_names::table_matches::<S, O, P>,
        )?;
        self.model_fields.begin_id_query(EntityRole::Session)?;
        let parent = <S::Session as SeaOrmSessionModel>::Entity::find()
            .filter(S::Session::token_column().eq(token))
            .filter(
                Condition::all()
                    .add_option(S::Session::active_column().map(|column| column.eq(true))),
            )
            .limit(1);
        if self.config().advanced.database.joins != Some(true) {
            let rows = database_operation::<<S::Session as SeaOrmSessionModel>::Entity, _>(
                self.config(),
                "findOne",
                async { parent.all(self.connection()).await.map_err(map_db_err) },
            )
            .await?;
            return Ok(self
                .fallback_session_snapshots(&rows, &relation)
                .await?
                .into_iter()
                .next());
        }
        self.model_fields.canonicalize_id(EntityRole::User)?;
        let query = super::joins::joined_query::<
            <S::Session as SeaOrmSessionModel>::Entity,
            <S::User as SeaOrmUserModel>::Entity,
        >(
            parent,
            (
                S::Session::field_column(&relation.from)?,
                S::User::field_column(&relation.to)?,
            ),
            S::User::id_column(),
        );
        let rows = database_operation::<<S::Session as SeaOrmSessionModel>::Entity, _>(
            self.config(),
            "findOne",
            super::joins::joined_rows::<
                <S::Session as SeaOrmSessionModel>::Entity,
                <S::User as SeaOrmUserModel>::Entity,
            >(self.connection(), &query),
        )
        .await?;
        let (rows, users): (Vec<_>, Vec<_>) = super::joins::grouped_rows::<
            <S::Session as SeaOrmSessionModel>::Entity,
            <S::User as SeaOrmUserModel>::Entity,
        >(rows, S::Session::id_column())
        .into_iter()
        .map(|(session, users)| {
            let users = super::joins::selected_children::<<S::User as SeaOrmUserModel>::Entity>(
                users.into_iter(),
                S::User::id_column(),
                relation.many,
                self.config().advanced.database.find_many_limit(),
            );
            (session, users)
        })
        .unzip();
        Ok(self
            .native_session_snapshots(&rows, &users, relation.many)
            .await?
            .into_iter()
            .next())
    }

    async fn get_session_snapshots(
        &self,
        tokens: &[String],
        only_active: bool,
    ) -> AuthResult<Vec<SessionSnapshot>> {
        let relation = SessionData::resolve_schema(
            self.config(),
            &self.model_fields,
            super::model_names::table_matches::<S, O, P>,
        )?;
        self.model_fields.begin_id_query(EntityRole::Session)?;
        let mut condition = Condition::all()
            .add(S::Session::token_column().is_in(tokens.iter().cloned()))
            .add_option(S::Session::active_column().map(|column| column.eq(true)));
        if only_active {
            let now = super::record_bindings::Binding::Date(Utc::now().into())
                .bind(self.connection().get_database_backend())?;
            let expires_at = S::Session::expires_at_column();
            condition = condition.add(expires_at.into_expr().gt(expires_at.save_as(now)));
        }
        let (rows, native_users) = database_operation::<
            <S::Session as SeaOrmSessionModel>::Entity,
            _,
        >(self.config(), "findMany", async {
            let parent = <S::Session as SeaOrmSessionModel>::Entity::find()
                .filter(condition)
                .limit(super::pagination::default_limit(
                    self.config(),
                    self.connection().get_database_backend(),
                )?);
            if self.config().advanced.database.joins == Some(true) {
                self.model_fields
                    .canonicalize_id(better_auth_core::store::schema::EntityRole::User)?;
                let query = super::joins::joined_query::<
                    <S::Session as SeaOrmSessionModel>::Entity,
                    <S::User as SeaOrmUserModel>::Entity,
                >(
                    parent,
                    (
                        S::Session::field_column(&relation.from)?,
                        S::User::field_column(&relation.to)?,
                    ),
                    S::User::id_column(),
                );
                let rows = super::joins::joined_rows::<
                    <S::Session as SeaOrmSessionModel>::Entity,
                    <S::User as SeaOrmUserModel>::Entity,
                >(self.connection(), &query)
                .await?;
                let (rows, users): (Vec<_>, Vec<_>) = super::joins::grouped_rows::<
                    <S::Session as SeaOrmSessionModel>::Entity,
                    <S::User as SeaOrmUserModel>::Entity,
                >(
                    rows, S::Session::id_column()
                )
                .into_iter()
                .map(|(session, users)| {
                    let users =
                        super::joins::selected_children::<<S::User as SeaOrmUserModel>::Entity>(
                            users.into_iter(),
                            S::User::id_column(),
                            relation.many,
                            self.config().advanced.database.find_many_limit(),
                        );
                    (session, users)
                })
                .unzip();
                Ok((rows, Some(users)))
            } else {
                parent
                    .all(self.connection())
                    .await
                    .map(|rows| (rows, None))
                    .map_err(map_db_err)
            }
        })
        .await?;
        if let Some(users) = native_users {
            self.native_session_snapshots(&rows, &users, relation.many)
                .await
        } else {
            self.fallback_session_snapshots(&rows, &relation).await
        }
    }

    async fn get_user_sessions(
        &self,
        user_id: &str,
    ) -> AuthResult<Vec<better_auth_core::wire::SessionView>> {
        self.model_fields.begin_id_query(EntityRole::Session)?;
        let user_id = self.parse_id(user_id, <S::Session as SeaOrmSessionModel>::parse_user_id)?;
        match database_operation::<<S::Session as SeaOrmSessionModel>::Entity, _>(
            self.config(),
            "findMany",
            async {
                <S::Session as SeaOrmSessionModel>::Entity::find()
                    .filter(<S::Session as SeaOrmSessionModel>::user_id_column().eq(user_id))
                    .filter(
                        Condition::all()
                            .add_option(S::Session::active_column().map(|column| column.eq(true))),
                    )
                    .limit(super::pagination::default_limit(
                        self.config(),
                        self.connection().get_database_backend(),
                    )?)
                    .all(self.connection())
                    .await
                    .map_err(map_db_err)
            },
        )
        .await
        {
            Ok(rows) => self.output_sessions(&rows, self.connection()).await,
            Err(error) => Err(error),
        }
    }

    async fn update_session_fields(
        &self,
        token: &str,
        fields: better_auth_core::FieldMap,
    ) -> AuthResult<Option<better_auth_core::wire::SessionView>> {
        self.update_session_with_connection(
            self.connection(),
            None,
            token,
            SessionUpdate {
                additional_fields: fields,
                ..Default::default()
            },
        )
        .await
    }

    async fn update_session_expiry(
        &self,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> AuthResult<better_auth_core::wire::SessionView> {
        self.update_session_with_connection(
            self.connection(),
            None,
            token,
            SessionUpdate {
                expires_at: Some(expires_at.into()),
                updated_at: Some(Utc::now().into()),
                ..Default::default()
            },
        )
        .await?
        .ok_or(AuthError::SessionNotFound)
    }

    async fn delete_session(&self, token: &str) -> AuthResult<()> {
        self.model_fields.begin_id_query(EntityRole::Session)?;
        let snapshot = database_operation::<<S::Session as SeaOrmSessionModel>::Entity, _>(
            self.config(),
            "findOne",
            async {
                <S::Session as SeaOrmSessionModel>::Entity::find()
                    .filter(S::Session::token_column().eq(token))
                    .one(self.connection())
                    .await
                    .map_err(map_db_err)
            },
        )
        .await;
        // Upstream deleteWithHooks treats only snapshot-read errors as a missing record.
        let session = match snapshot.ok().flatten() {
            Some(session) => self.session_delete_snapshot(session).await.ok(),
            None => None,
        };
        let Some(session) = session else {
            return Ok(());
        };
        let context = self.hook_context(None);
        for hook in self.hooks() {
            if better_auth_core::observability::database::with_database_hook(
                context.config,
                hook.hook_metadata(),
                better_auth_core::observability::database::DatabaseHook::BeforeDeleteSession,
                hook.before_delete_session(&session, &context),
            )
            .await?
            .is_cancelled()
            {
                return Ok(());
            }
        }
        self.model_fields.begin_id_query(EntityRole::Session)?;
        let _ = database_operation::<<S::Session as SeaOrmSessionModel>::Entity, _>(
            self.config(),
            "delete",
            async {
                <S::Session as SeaOrmSessionModel>::Entity::delete_many()
                    .filter(S::Session::token_column().eq(token))
                    .exec(self.connection())
                    .await
                    .map_err(map_db_err)
            },
        )
        .await?;
        for hook in self.hooks() {
            better_auth_core::observability::database::with_database_hook(
                context.config,
                hook.hook_metadata(),
                better_auth_core::observability::database::DatabaseHook::AfterDeleteSession,
                hook.after_delete_session(&session, &context),
            )
            .await?;
        }
        Ok(())
    }

    async fn delete_sessions(&self, tokens: &[String]) -> AuthResult<()> {
        let condition =
            Condition::all().add(S::Session::token_column().is_in(tokens.iter().cloned()));
        self.delete_sessions_with_connection(self.connection(), None, condition, false)
            .await
            .map(|_| ())
    }

    async fn end_sessions(&self, tokens: &[String]) -> AuthResult<()> {
        let condition =
            Condition::all().add(S::Session::token_column().is_in(tokens.iter().cloned()));
        self.delete_sessions_with_connection(self.connection(), None, condition, true)
            .await
            .map(|_| ())
    }

    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
        self.delete_user_sessions_optional(user_id, false)
            .await
            .map(|_| ())
    }

    async fn delete_user_sessions_optional(
        &self,
        user_id: &str,
        preserve: bool,
    ) -> AuthResult<Option<usize>> {
        let user_id = self.parse_id(user_id, S::Session::parse_user_id)?;
        let condition = Condition::all().add(S::Session::user_id_column().eq(user_id));
        self.delete_sessions_with_connection(self.connection(), None, condition, preserve)
            .await
    }

    async fn delete_expired_sessions(&self) -> AuthResult<usize> {
        let now = super::record_bindings::Binding::Date(Utc::now().into())
            .bind(self.connection().get_database_backend())?;
        let expires_at = S::Session::expires_at_column();
        let condition = Condition::any()
            .add(expires_at.into_expr().lt(expires_at.save_as(now)))
            .add_option(S::Session::active_column().map(|column| column.eq(false)));
        self.delete_sessions_with_connection(self.connection(), None, condition, false)
            .await
            .map(Option::unwrap_or_default)
    }

    async fn update_session_active_organization(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<better_auth_core::wire::SessionView> {
        self.update_session_with_connection(
            self.connection(),
            None,
            token,
            SessionUpdate {
                active_organization_id: Some(organization_id.map(str::to_owned)),
                ..Default::default()
            },
        )
        .await?
        .ok_or(AuthError::SessionNotFound)
    }
    async fn accept_invitation_with_teams(
        &self,
        invitation_id: &str,
        user_id: &str,
        session_token: Option<&str>,
        teams_enabled: bool,
        maximum: better_auth_core::store::TeamMemberLimits<'_>,
    ) -> AuthResult<(
        better_auth_core::Member,
        better_auth_core::Invitation,
        Option<better_auth_core::wire::SessionView>,
    )> {
        self.accept_team_invitation(
            invitation_id,
            user_id,
            session_token,
            teams_enabled,
            maximum,
        )
        .await
    }
    async fn update_session_active_team(
        &self,
        token: &str,
        team_id: Option<&str>,
    ) -> AuthResult<better_auth_core::wire::SessionView> {
        self.update_session_with_connection(
            self.connection(),
            None,
            token,
            SessionUpdate {
                active_team_id: Some(team_id.map(str::to_owned)),
                ..Default::default()
            },
        )
        .await?
        .ok_or(AuthError::SessionNotFound)
    }
}
