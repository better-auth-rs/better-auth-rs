use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, ExprTrait, IntoActiveModel,
    QueryFilter,
};

use better_auth_core::store::SessionStore;

use crate::error::{AuthError, AuthResult};
use crate::hooks::{DatabaseHookUpdate, SessionUpdate};
use crate::schema::{AuthSchema, SeaOrmSessionModel};
use crate::types::CreateSession;

use super::{SeaOrmStore, cancelled_by_hook, map_db_err};

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S: AuthSchema,
    S::Session: SeaOrmSessionModel,
{
    fn normalize_session_client_field(value: Option<String>) -> Option<String> {
        match value {
            Some(value) => Some(value),
            None => Some(String::new()),
        }
    }

    pub(crate) fn apply_session_field_updates(
        &self,
        active: &mut <S::Session as SeaOrmSessionModel>::ActiveModel,
    ) -> AuthResult<()> {
        S::Session::apply_fields(
            active,
            self.config()
                .session
                .field_schema()
                .storage_fields_for_adapter(
                    Default::default(),
                    false,
                    self.connection().get_database_backend() == sea_orm::DbBackend::Postgres,
                    S::Session::native_json_field,
                )?,
        )?;
        crate::reference_id::apply_bindings(
            active,
            &self.config().session.field_schema(),
            self.connection().get_database_backend(),
            S::Session::field_column,
        )
    }

    pub(crate) async fn before_runtime_session_in_tx(
        &self,
        session: &mut CreateSession,
        tx: Option<super::HookTransaction<'_, S>>,
    ) -> AuthResult<()> {
        let context = self.hook_context(tx);
        for hook in self.hooks() {
            if hook
                .before_create_session(session, &context)
                .await?
                .is_cancelled()
            {
                return Err(cancelled_by_hook("session creation"));
            }
        }
        Ok(())
    }

    async fn after_runtime_session_in_tx(
        &self,
        session: &S::Session,
        tx: Option<super::HookTransaction<'_, S>>,
    ) -> AuthResult<()> {
        let context = self.hook_context(tx);
        for hook in self.hooks() {
            hook.after_create_session(session, &context).await?;
        }
        Ok(())
    }

    async fn create_session_with_connection<C>(
        &self,
        db: &C,
        tx: Option<super::HookTransaction<'_, S>>,
        mut create_session: CreateSession,
    ) -> AuthResult<S::Session>
    where
        C: ConnectionTrait,
    {
        self.before_runtime_session_in_tx(&mut create_session, tx)
            .await?;
        let now = Utc::now();
        create_session.ip_address = Self::normalize_session_client_field(create_session.ip_address);
        create_session.user_agent = Self::normalize_session_client_field(create_session.user_agent);
        let mut active = S::Session::new_active(
            None,
            format!("session_{}", uuid::Uuid::new_v4()),
            create_session,
            now,
        );
        S::Session::apply_fields(
            &mut active,
            self.config()
                .session
                .field_schema()
                .storage_fields_for_adapter(
                    self.config().session.default_fields(),
                    true,
                    db.get_database_backend() == sea_orm::DbBackend::Postgres,
                    S::Session::native_json_field,
                )?,
        )?;
        crate::reference_id::apply_bindings(
            &mut active,
            &self.config().session.field_schema(),
            db.get_database_backend(),
            S::Session::field_column,
        )?;
        let session = active.insert(db).await.map_err(map_db_err)?;
        if tx.is_none() {
            self.after_runtime_session_in_tx(&session, None).await?;
        }
        Ok(session)
    }

    pub(crate) async fn create_session_in_tx(
        &self,
        tx: super::HookTransaction<'_, S>,
        create_session: CreateSession,
    ) -> AuthResult<S::Session> {
        self.create_session_with_connection(tx.0, Some(tx), create_session)
            .await
    }

    pub(super) async fn update_session_with_connection(
        &self,
        db: &impl ConnectionTrait,
        tx: Option<super::HookTransaction<'_, S>>,
        token: &str,
        mut update: SessionUpdate,
    ) -> AuthResult<Option<S::Session>> {
        let context = self.hook_context(tx);
        let original = update.clone();
        for hook in self.hooks() {
            match hook
                .before_update_session(token, &original, &context)
                .await?
            {
                DatabaseHookUpdate::Continue => {}
                DatabaseHookUpdate::Cancel => return Ok(None),
                DatabaseHookUpdate::Patch(patch) => update.merge(patch),
            }
        }
        let reselect = match update.id.as_deref() {
            Some(id) => S::Session::id_column().eq(S::Session::parse_id(id)?),
            None => S::Session::token_column().eq(update.token.as_deref().unwrap_or(token)),
        };
        let mut active = <S::Session as SeaOrmSessionModel>::ActiveModel::default();
        let fields = self
            .config()
            .session
            .field_schema()
            .storage_fields_for_adapter(
                std::mem::take(&mut update.additional_fields),
                false,
                db.get_database_backend() == sea_orm::DbBackend::Postgres,
                S::Session::native_json_field,
            )?;
        let _ = update.updated_at.get_or_insert_with(Utc::now);
        S::Session::apply_update(&mut active, update)?;
        S::Session::apply_fields(&mut active, fields)?;
        crate::reference_id::apply_bindings(
            &mut active,
            &self.config().session.field_schema(),
            db.get_database_backend(),
            S::Session::field_column,
        )?;
        let session = super::updates::update_returning_one::<
            <S::Session as SeaOrmSessionModel>::Entity,
            _,
        >(db, active, S::Session::token_column().eq(token), reselect)
        .await?;
        for hook in self.hooks() {
            hook.after_update_session(session.as_ref(), &context)
                .await?;
        }
        Ok(session)
    }
}

#[async_trait]
impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SessionStore<S>
    for SeaOrmStore<S, O, P>
where
    S: AuthSchema + Send + Sync,
    S::Session: SeaOrmSessionModel,
{
    async fn before_create_runtime_session(&self, session: &mut CreateSession) -> AuthResult<()> {
        self.before_runtime_session_in_tx(session, None).await
    }

    async fn after_create_runtime_session(&self, session: &S::Session) -> AuthResult<()> {
        self.after_runtime_session_in_tx(session, None).await
    }

    async fn end_session(&self, token: &str) -> AuthResult<()> {
        use better_auth_core::entity::AuthSession;
        let now = Utc::now();
        let Some(session) = self
            .get_session(token)
            .await?
            .filter(|session| session.expires_at() > now)
        else {
            return Ok(());
        };
        let context = self.hook_context(None);
        for hook in self.hooks() {
            if hook
                .before_delete_session(&session, &context)
                .await?
                .is_cancelled()
            {
                return Err(cancelled_by_hook("session deletion"));
            }
        }
        let mut active = session.clone().into_active_model();
        S::Session::set_expires_at(&mut active, now);
        self.apply_session_field_updates(&mut active)?;
        let _ = active.update(self.connection()).await.map_err(map_db_err)?;
        for hook in self.hooks() {
            hook.after_delete_session(&session, &context).await?;
        }
        Ok(())
    }

    async fn create_session(&self, create_session: CreateSession) -> AuthResult<S::Session> {
        self.create_session_with_connection(self.connection(), None, create_session)
            .await
    }

    async fn get_session(&self, token: &str) -> AuthResult<Option<S::Session>> {
        <S::Session as SeaOrmSessionModel>::Entity::find()
            .filter(<S::Session as SeaOrmSessionModel>::token_column().eq(token))
            .filter(<S::Session as SeaOrmSessionModel>::active_column().eq(true))
            .one(self.connection())
            .await
            .map_err(map_db_err)
    }

    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<S::Session>> {
        let user_id = <S::Session as SeaOrmSessionModel>::parse_user_id(user_id)?;
        <S::Session as SeaOrmSessionModel>::Entity::find()
            .filter(<S::Session as SeaOrmSessionModel>::user_id_column().eq(user_id))
            .filter(<S::Session as SeaOrmSessionModel>::active_column().eq(true))
            .all(self.connection())
            .await
            .map_err(map_db_err)
    }

    async fn update_session_fields(
        &self,
        token: &str,
        fields: serde_json::Map<String, serde_json::Value>,
    ) -> AuthResult<Option<S::Session>> {
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
    ) -> AuthResult<S::Session> {
        self.update_session_with_connection(
            self.connection(),
            None,
            token,
            SessionUpdate {
                expires_at: Some(expires_at),
                updated_at: Some(Utc::now()),
                ..Default::default()
            },
        )
        .await?
        .ok_or(AuthError::SessionNotFound)
    }

    async fn delete_session(&self, token: &str) -> AuthResult<()> {
        let session = self.get_session(token).await?;
        let hook_context = self.hook_context(None);
        if let Some(session) = &session {
            for hook in self.hooks() {
                if hook
                    .before_delete_session(session, &hook_context)
                    .await?
                    .is_cancelled()
                {
                    return Err(cancelled_by_hook("session deletion"));
                }
            }
        }
        let _ = <S::Session as SeaOrmSessionModel>::Entity::delete_many()
            .filter(<S::Session as SeaOrmSessionModel>::token_column().eq(token))
            .exec(self.connection())
            .await
            .map_err(map_db_err)?;
        if let Some(session) = &session {
            for hook in self.hooks() {
                hook.after_delete_session(session, &hook_context).await?;
            }
        }
        Ok(())
    }

    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
        let user_id = <S::Session as SeaOrmSessionModel>::parse_user_id(user_id)?;
        <S::Session as SeaOrmSessionModel>::Entity::delete_many()
            .filter(<S::Session as SeaOrmSessionModel>::user_id_column().eq(user_id))
            .exec(self.connection())
            .await
            .map(|_| ())
            .map_err(map_db_err)
    }

    async fn delete_expired_sessions(&self) -> AuthResult<usize> {
        <S::Session as SeaOrmSessionModel>::Entity::delete_many()
            .filter(
                <S::Session as SeaOrmSessionModel>::expires_at_column()
                    .lt(Utc::now())
                    .or(<S::Session as SeaOrmSessionModel>::active_column().eq(false)),
            )
            .exec(self.connection())
            .await
            .map(|result| result.rows_affected as usize)
            .map_err(map_db_err)
    }

    async fn update_session_active_organization(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<S::Session> {
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
        Option<S::Session>,
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
    ) -> AuthResult<S::Session> {
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
