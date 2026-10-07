use super::instrumentation::database_operation;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, EntityTrait, IntoActiveModel,
    QueryFilter, QuerySelect,
};

use better_auth_core::store::schema::EntityRole;
use better_auth_core::store::{SessionStore, SessionUpdateWriter};

use crate::error::{AuthError, AuthResult};
use crate::hooks::{DatabaseHookUpdate, SessionUpdate};
use crate::schema::{AuthSchema, SeaOrmSessionModel, SeaOrmUserModel};
use crate::types::CreateSession;

use super::{SeaOrmStore, cancelled_by_hook, map_db_err};

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

    pub(super) async fn output_sessions(
        &self,
        rows: &[S::Session],
        db: &impl ConnectionTrait,
    ) -> AuthResult<Vec<better_auth_core::wire::SessionView>> {
        self.validate_session_fields()?;
        if !rows.is_empty() {
            self.model_fields.begin_id_output(EntityRole::Session)?;
        }
        better_auth_core::wire::SessionView::with_internal_fields_many_for_adapter(
            rows,
            &self.config().session,
            db.get_database_backend() == sea_orm::DbBackend::Postgres,
        )
        .await
    }

    pub(super) async fn output_session(
        &self,
        row: &S::Session,
        db: &impl ConnectionTrait,
    ) -> AuthResult<better_auth_core::wire::SessionView> {
        self.validate_session_fields()?;
        self.model_fields.begin_id_output(EntityRole::Session)?;
        better_auth_core::wire::SessionView::with_internal_fields_for_adapter(
            row,
            &self.config().session,
            db.get_database_backend() == sea_orm::DbBackend::Postgres,
        )
        .await
    }

    async fn native_session_snapshots(
        &self,
        rows: &[S::Session],
        users: &[Option<S::User>],
    ) -> AuthResult<
        Vec<(
            better_auth_core::wire::SessionView,
            Option<better_auth_core::session::SessionData>,
        )>,
    >
    where
        S::User: SeaOrmUserModel,
    {
        self.validate_session_fields()?;
        if !rows.is_empty() {
            self.model_fields.begin_id_output(EntityRole::Session)?;
        }
        better_auth_core::wire::SessionView::with_internal_fields_many_for_adapter_batches_then(
            rows,
            &self.config().session,
            self.connection().get_database_backend() == sea_orm::DbBackend::Postgres,
            |ready| async move {
                let indices: Vec<_> = ready.iter().map(|(index, _)| *index).collect();
                let projected = self.output_joined_users(users, &indices).await?;
                Ok(ready
                    .into_iter()
                    .zip(projected)
                    .map(|((index, session), user)| {
                        let data = user.map(|user| better_auth_core::session::SessionData {
                            session: session.clone(),
                            user,
                        });
                        (index, (session, data))
                    })
                    .collect())
            },
        )
        .await
    }

    fn normalize_session_client_field(value: Option<String>) -> Option<String> {
        match value {
            Some(value) => Some(value),
            None => Some(String::new()),
        }
    }

    pub(super) async fn apply_session_field_updates(
        &self,
        active: <S::Session as SeaOrmSessionModel>::ActiveModel,
    ) -> AuthResult<super::record_write::RecordWrite<<S::Session as SeaOrmSessionModel>::Entity>>
    {
        self.validate_session_fields()?;
        let schema = self.config().session.adapter_schema();
        self.model_fields.begin_id_input(EntityRole::Session)?;
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
        session: &mut CreateSession,
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
        session: &mut CreateSession,
        tx: Option<super::HookTransaction<'_, S>>,
    ) -> AuthResult<bool> {
        let context = self.hook_context(tx);
        for hook in self.hooks() {
            if better_auth_core::observability::database::with_database_hook(
                context.config,
                hook.hook_metadata(),
                better_auth_core::observability::database::DatabaseHook::BeforeCreateSession,
                hook.before_create_session(session, &context),
            )
            .await?
            .is_cancelled()
            {
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
        mut create_session: CreateSession,
    ) -> AuthResult<Option<better_auth_core::wire::SessionView>>
    where
        C: ConnectionTrait,
    {
        if !self
            .before_runtime_session_optional_in_tx(&mut create_session, tx)
            .await?
        {
            return Ok(None);
        }
        if let Some(id) = create_session.user_id.as_str() {
            let id = self
                .config()
                .advanced
                .database
                .generate_id()
                .coerce_id(id)?
                .into_owned();
            let _ = S::Session::parse_user_id(&id)?;
            create_session.user_id = id.into();
        }
        let now = Utc::now();
        create_session.ip_address = Self::normalize_session_client_field(create_session.ip_address);
        create_session.user_agent = Self::normalize_session_client_field(create_session.user_agent);
        let mut fields = self.config().session.default_fields();
        fields.extend(std::mem::take(&mut create_session.additional_fields));
        let mut plugin_fields = better_auth_core::FieldMap::new();
        for name in ["impersonatedBy", "activeOrganizationId", "activeTeamId"] {
            if let Some(value) = fields.remove(name) {
                let _ = plugin_fields.insert(name.into(), value);
            }
        }
        self.validate_session_fields()?;
        let schema = self.config().session.adapter_schema();
        self.model_fields.begin_id_input(EntityRole::Session)?;
        let (fields, id) = schema
            .create_adapter_storage_fields(
                fields,
                || {
                    if !self.model_fields.id_input_active(EntityRole::Session)? {
                        return Ok(None);
                    }
                    self.generated_id("session", None)?
                        .as_deref()
                        .map(S::Session::parse_id)
                        .transpose()
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
        let database_generated_id = id.is_none();
        let expires_at = create_session.expires_at.clone();
        let mut active = S::Session::new_active(
            id,
            better_auth_core::id::random_id(None),
            create_session,
            now,
        )?;
        if database_generated_id {
            active.not_set(S::Session::id_column());
        }
        let mut active = super::record_write::RecordWrite::from_active(active);
        active.native_field(
            S::Session::expires_at_column(),
            better_auth_core::FieldValue::Date(expires_at),
        );
        active.apply_fields(fields, S::Session::field_column)?;
        active.apply_fields(plugin_fields, S::Session::field_column)?;
        let session = database_operation::<<S::Session as SeaOrmSessionModel>::Entity, _>(
            self.config(),
            "create",
            async { active.insert(db).await },
        )
        .await?;
        let session = self.output_session(&session, db).await?;
        if tx.is_none() {
            self.after_runtime_session(&session, crate::hooks::current_request_hook_context())
                .await?;
        }
        Ok(Some(session))
    }

    pub(crate) async fn create_session_in_tx(
        &self,
        tx: super::HookTransaction<'_, S>,
        create_session: CreateSession,
    ) -> AuthResult<better_auth_core::wire::SessionView> {
        self.create_session_with_connection(tx.0, Some(tx), create_session)
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
        let reselect = match update.id.as_deref() {
            Some(id) => S::Session::id_column().eq(self.parse_id(id, S::Session::parse_id)?),
            None => S::Session::token_column().eq(update.token.as_deref().unwrap_or(token)),
        };
        let mut active = <S::Session as SeaOrmSessionModel>::ActiveModel::default();
        self.validate_session_fields()?;
        self.model_fields.begin_id_input(EntityRole::Session)?;
        let fields = self
            .config()
            .session
            .adapter_schema()
            .storage_fields_with_binding(
                std::mem::take(&mut update.additional_fields),
                false,
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
        self.create_session_with_connection(self.connection(), None, input)
            .await
    }
    async fn before_create_runtime_session_optional(
        &self,
        input: &mut CreateSession,
    ) -> AuthResult<bool> {
        self.before_runtime_session_optional_in_tx(input, None)
            .await
    }
    async fn before_create_runtime_session(&self, session: &mut CreateSession) -> AuthResult<()> {
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
        self.model_fields.begin_id_input(EntityRole::Session)?;
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

    async fn get_session_snapshot(
        &self,
        token: &str,
    ) -> AuthResult<
        Option<(
            better_auth_core::wire::SessionView,
            Option<better_auth_core::session::SessionData>,
        )>,
    > {
        if self.config().advanced.database.joins != Some(true) {
            return Ok(self
                .get_session(token)
                .await?
                .map(|session| (session, None)));
        }
        self.model_fields.begin_id_input(EntityRole::Session)?;
        self.model_fields
            .canonicalize_id(better_auth_core::store::schema::EntityRole::User)?;
        let query = super::joins::joined_query::<
            <S::Session as SeaOrmSessionModel>::Entity,
            <S::User as SeaOrmUserModel>::Entity,
        >(
            <S::Session as SeaOrmSessionModel>::Entity::find()
                .filter(S::Session::token_column().eq(token))
                .filter(
                    Condition::all()
                        .add_option(S::Session::active_column().map(|column| column.eq(true))),
                )
                .limit(1),
            (S::Session::user_id_column(), S::User::id_column()),
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
        let Some((row, user)) = rows.into_iter().next() else {
            return Ok(None);
        };
        let session = self.output_session(&row, self.connection()).await?;
        let Some(user) = user else {
            return Ok(None);
        };
        let data = better_auth_core::session::SessionData {
            session: session.clone(),
            user: self.output_user(&user, self.connection()).await?,
        };
        Ok(Some((session, Some(data))))
    }

    async fn get_session_snapshots(
        &self,
        tokens: &[String],
        only_active: bool,
    ) -> AuthResult<
        Vec<(
            better_auth_core::wire::SessionView,
            Option<better_auth_core::session::SessionData>,
        )>,
    > {
        self.model_fields.begin_id_input(EntityRole::Session)?;
        let mut condition = Condition::all()
            .add(S::Session::token_column().is_in(tokens.iter().cloned()))
            .add_option(S::Session::active_column().map(|column| column.eq(true)));
        if only_active {
            condition = condition.add(S::Session::expires_at_column().gt(Utc::now()));
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
                    (S::Session::user_id_column(), S::User::id_column()),
                    S::User::id_column(),
                );
                let rows = super::joins::joined_rows::<
                    <S::Session as SeaOrmSessionModel>::Entity,
                    <S::User as SeaOrmUserModel>::Entity,
                >(self.connection(), &query)
                .await?;
                let (rows, users): (Vec<_>, Vec<_>) = rows.into_iter().unzip();
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
        let snapshots = if let Some(users) = native_users {
            self.native_session_snapshots(&rows, &users).await?
        } else {
            self.validate_session_fields()?;
            if !rows.is_empty() {
                self.model_fields.begin_id_output(EntityRole::Session)?;
            }
            better_auth_core::wire::SessionView::with_internal_fields_many_for_adapter_then(
                &rows,
                &self.config().session,
                self.connection().get_database_backend() == sea_orm::DbBackend::Postgres,
                |index, session| {
                    let rows = &rows;
                    async move {
                        let row = rows.get(index).ok_or_else(|| {
                            AuthError::internal("Session projection lost its stored join index")
                        })?;
                        let owner_id = row
                            .clone()
                            .into_active_model()
                            .get(S::Session::user_id_column())
                            .into_value();
                        let user = match owner_id {
                            Some(owner_id) => {
                                self.model_fields.begin_id_input(
                                    better_auth_core::store::schema::EntityRole::User,
                                )?;
                                database_operation::<<S::User as SeaOrmUserModel>::Entity, _>(
                                    self.config(),
                                    "findOne",
                                    async {
                                        <S::User as SeaOrmUserModel>::Entity::find()
                                            .filter(S::User::id_column().eq(owner_id))
                                            .one(self.connection())
                                            .await
                                            .map_err(map_db_err)
                                    },
                                )
                                .await?
                            }
                            None => None,
                        };
                        let data = match user.as_ref() {
                            Some(user) => Some(better_auth_core::session::SessionData {
                                session: session.clone(),
                                user: self.output_user(user, self.connection()).await?,
                            }),
                            None => None,
                        };
                        Ok((session, data))
                    }
                },
            )
            .await?
        };
        // Complete started output callbacks before applying the joined batch's missing-user rule.
        if snapshots.iter().any(|(_, user)| user.is_none()) {
            return Ok(Vec::new());
        }
        Ok(snapshots)
    }

    async fn get_user_sessions(
        &self,
        user_id: &str,
    ) -> AuthResult<Vec<better_auth_core::wire::SessionView>> {
        self.model_fields.begin_id_input(EntityRole::Session)?;
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
        self.model_fields.begin_id_input(EntityRole::Session)?;
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
        self.model_fields.begin_id_input(EntityRole::Session)?;
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
        let condition = Condition::any()
            .add(S::Session::expires_at_column().lt(Utc::now()))
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
