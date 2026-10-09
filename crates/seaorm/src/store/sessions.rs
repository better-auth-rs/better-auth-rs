use super::instrumentation::database_operation;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::{
    ColumnTrait, Condition, ConnectionTrait, EntityTrait, QueryFilter, QuerySelect, QueryTrait,
    sea_query::ExprTrait,
};

use better_auth_core::session::SessionData;
use better_auth_core::store::schema::EntityRole;
use better_auth_core::store::{SessionStore, SessionUpdateWriter};

use crate::error::{AuthError, AuthResult};
use crate::hooks::SessionUpdate;
use crate::schema::{AuthSchema, SeaOrmSessionModel, SeaOrmUserModel};
use crate::types::CreateSession;

use super::{SeaOrmStore, map_db_err, session_output::SessionSnapshot};

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
        self.update_session_with_writer_by_token_value(&token.into(), update, secondary)
            .await
    }

    async fn update_session_with_writer_by_token_value(
        &self,
        token: &better_auth_core::FieldValue,
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
        session: Option<&better_auth_core::wire::SessionView>,
        request: Option<better_auth_core::hooks::RequestHookContext>,
    ) -> AuthResult<()> {
        self.after_runtime_session(session, request).await
    }

    async fn end_session(&self, token: &str) -> AuthResult<()> {
        self.end_session_by_token_value(&token.into()).await
    }

    async fn end_session_by_token_value(
        &self,
        token: &better_auth_core::FieldValue,
    ) -> AuthResult<()> {
        self.model_fields.begin_id_query(EntityRole::Session)?;
        let condition = Condition::all().add(self.session_token_filter(token)?);
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
            .ok_or_else(|| AuthError::internal("Session creation returned no record"))
    }

    async fn get_session(
        &self,
        token: &str,
    ) -> AuthResult<Option<better_auth_core::wire::SessionView>> {
        self.get_session_by_token_value(&token.into()).await
    }

    async fn get_session_by_token_value(
        &self,
        token: &better_auth_core::FieldValue,
    ) -> AuthResult<Option<better_auth_core::wire::SessionView>> {
        self.model_fields.begin_id_query(EntityRole::Session)?;
        let db = self.connection();
        let query = <S::Session as SeaOrmSessionModel>::Entity::find()
            .filter(self.session_token_filter(token)?)
            .filter(
                Condition::all()
                    .add_option(S::Session::active_column().map(|column| column.eq(true))),
            )
            .build(db.get_database_backend());
        let row = database_operation::<<S::Session as SeaOrmSessionModel>::Entity, _>(
            self.config(),
            "findOne",
            async { db.query_one_raw(query).await.map_err(map_db_err) },
        )
        .await?;
        let schema = better_auth_core::store::session_create_schema(
            &self.config().session,
            &Default::default(),
        );
        match row {
            Some(row) => self.output_session_raw(&row, &schema, db).await.map(Some),
            None => Ok(None),
        }
    }

    async fn get_session_snapshot(&self, token: &str) -> AuthResult<Option<SessionSnapshot>> {
        self.get_session_snapshot_value(&token.into()).await
    }

    async fn get_session_snapshot_value(
        &self,
        token: &better_auth_core::FieldValue,
    ) -> AuthResult<Option<SessionSnapshot>> {
        let relation = SessionData::resolve_schema(
            self.config(),
            &self.model_fields,
            super::model_names::table_matches::<S, O, P>,
        )?;
        self.model_fields.begin_id_query(EntityRole::Session)?;
        let parent = <S::Session as SeaOrmSessionModel>::Entity::find()
            .filter(self.session_token_filter(token)?)
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
            super::joins::joined_raw_rows(self.connection(), &query),
        )
        .await?;
        let (rows, users): (Vec<_>, Vec<_>) =
            super::joins::grouped_raw_rows(rows, S::Session::id_column())?
                .into_iter()
                .map(|(session, users)| {
                    let users = super::joins::selected_raw_children(
                        users.into_iter(),
                        S::User::id_column(),
                        relation.many,
                        self.config().advanced.database.find_many_limit(),
                    )?;
                    Ok((session.model::<S::Session>()?, users))
                })
                .collect::<AuthResult<Vec<_>>>()?
                .into_iter()
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
                let rows = super::joins::joined_raw_rows(self.connection(), &query).await?;
                let (rows, users): (Vec<_>, Vec<_>) =
                    super::joins::grouped_raw_rows(rows, S::Session::id_column())?
                        .into_iter()
                        .map(|(session, users)| {
                            let users = super::joins::selected_raw_children(
                                users.into_iter(),
                                S::User::id_column(),
                                relation.many,
                                self.config().advanced.database.find_many_limit(),
                            )?;
                            Ok((session.model::<S::Session>()?, users))
                        })
                        .collect::<AuthResult<Vec<_>>>()?
                        .into_iter()
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
        self.get_user_sessions_value(&user_id.into()).await
    }

    async fn get_user_sessions_value(
        &self,
        user_id: &better_auth_core::FieldValue,
    ) -> AuthResult<Vec<better_auth_core::wire::SessionView>> {
        self.model_fields.begin_id_query(EntityRole::Session)?;
        let condition = self.session_user_filter(user_id)?;
        match database_operation::<<S::Session as SeaOrmSessionModel>::Entity, _>(
            self.config(),
            "findMany",
            async {
                <S::Session as SeaOrmSessionModel>::Entity::find()
                    .filter(condition)
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
        self.update_session_fields_by_token_value(&token.into(), fields)
            .await
    }

    async fn update_session_fields_by_token_value(
        &self,
        token: &better_auth_core::FieldValue,
        fields: better_auth_core::FieldMap,
    ) -> AuthResult<Option<better_auth_core::wire::SessionView>> {
        self.update_session_with_writer_by_token_value(
            token,
            SessionUpdate {
                additional_fields: fields,
                ..Default::default()
            },
            None,
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
        self.delete_session_by_token_value(&token.into()).await
    }

    async fn delete_session_by_token_value(
        &self,
        token: &better_auth_core::FieldValue,
    ) -> AuthResult<()> {
        self.model_fields.begin_id_query(EntityRole::Session)?;
        let snapshot = database_operation::<<S::Session as SeaOrmSessionModel>::Entity, _>(
            self.config(),
            "findOne",
            async {
                <S::Session as SeaOrmSessionModel>::Entity::find()
                    .filter(self.session_token_filter(token)?)
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
                    .filter(self.session_token_filter(token)?)
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
        self.delete_user_sessions_by_user_value(&user_id.into())
            .await
    }

    async fn delete_user_sessions_by_user_value(
        &self,
        user_id: &better_auth_core::FieldValue,
    ) -> AuthResult<()> {
        self.delete_user_sessions_optional_value(user_id, false)
            .await
            .map(|_| ())
    }

    async fn delete_user_sessions_optional(
        &self,
        user_id: &str,
        preserve: bool,
    ) -> AuthResult<Option<usize>> {
        self.delete_user_sessions_optional_value(&user_id.into(), preserve)
            .await
    }

    async fn delete_user_sessions_optional_value(
        &self,
        user_id: &better_auth_core::FieldValue,
        preserve: bool,
    ) -> AuthResult<Option<usize>> {
        let condition = Condition::all().add(self.session_user_filter(user_id)?);
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
        self.update_session_active_organization_by_token_value(
            &token.into(),
            organization_id
                .map(better_auth_core::FieldValue::from)
                .as_ref(),
        )
        .await
    }

    async fn update_session_active_organization_by_token_value(
        &self,
        token: &better_auth_core::FieldValue,
        organization_id: Option<&better_auth_core::FieldValue>,
    ) -> AuthResult<better_auth_core::wire::SessionView> {
        self.update_session_fields_by_token_value(
            token,
            [(
                "activeOrganizationId".into(),
                organization_id
                    .cloned()
                    .unwrap_or(better_auth_core::FieldValue::Null),
            )]
            .into(),
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
        self.accept_invitation_with_teams_by_token_value(
            invitation_id,
            user_id,
            session_token
                .map(better_auth_core::FieldValue::from)
                .as_ref(),
            teams_enabled,
            maximum,
        )
        .await
    }

    async fn accept_invitation_with_teams_by_token_value(
        &self,
        invitation_id: &str,
        user_id: &str,
        session_token: Option<&better_auth_core::FieldValue>,
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
        self.update_session_active_team_by_token_value(
            &token.into(),
            team_id.map(better_auth_core::FieldValue::from).as_ref(),
        )
        .await
    }

    async fn update_session_active_team_by_token_value(
        &self,
        token: &better_auth_core::FieldValue,
        team_id: Option<&better_auth_core::FieldValue>,
    ) -> AuthResult<better_auth_core::wire::SessionView> {
        self.update_session_fields_by_token_value(
            token,
            [(
                "activeTeamId".into(),
                team_id
                    .cloned()
                    .unwrap_or(better_auth_core::FieldValue::Null),
            )]
            .into(),
        )
        .await?
        .ok_or(AuthError::SessionNotFound)
    }
}

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S: AuthSchema,
    S::Session: SeaOrmSessionModel,
{
    pub(super) fn session_user_filter(
        &self,
        user_id: &better_auth_core::FieldValue,
    ) -> AuthResult<sea_orm::sea_query::SimpleExpr> {
        let schema = better_auth_core::store::session_create_schema(
            &self.config().session,
            &Default::default(),
        );
        let field = &schema.fields()["userId"];
        let backend = self.connection().get_database_backend();
        let value = if field.references_id() {
            self.config()
                .advanced
                .database
                .generate_id()
                .adapter_id_query(user_id.clone())?
        } else {
            user_id.clone()
        };
        let value = better_auth_core::user_query::bind_filter(field, &value)?;
        let value = super::value_filter::adapter_query_value(value, user_id, field, backend)?;
        let name = better_auth_core::store::schema::resolve_field_name(
            field.field_name.as_deref(),
            "userId",
        );
        super::value_filter::equals(S::Session::field_column(name)?, &value, backend)
    }
}
