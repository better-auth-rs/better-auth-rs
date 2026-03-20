use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait, ExprTrait,
    IntoActiveModel, QueryFilter, QueryOrder,
};

use better_auth_core::store::SessionStore;

use crate::error::{AuthError, AuthResult};
use crate::schema::{AuthSchema, SeaOrmSessionModel};
use crate::types::CreateSession;

use super::{SeaOrmStore, cancelled_by_hook, map_db_err};

impl<S> SeaOrmStore<S>
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

    async fn create_session_with_connection<C>(
        &self,
        db: &C,
        tx: Option<&DatabaseTransaction>,
        mut create_session: CreateSession,
    ) -> AuthResult<S::Session>
    where
        C: ConnectionTrait,
    {
        let hook_context = self.hook_context(tx);
        for hook in self.hooks() {
            if hook
                .before_create_session(&mut create_session, &hook_context)
                .await?
                .is_cancelled()
            {
                return Err(cancelled_by_hook("session creation"));
            }
        }
        let now = Utc::now();
        create_session.ip_address = Self::normalize_session_client_field(create_session.ip_address);
        create_session.user_agent = Self::normalize_session_client_field(create_session.user_agent);
        let session = S::Session::new_active(
            None,
            format!("session_{}", uuid::Uuid::new_v4()),
            create_session,
            now,
        )
        .insert(db)
        .await
        .map_err(map_db_err)?;
        for hook in self.hooks() {
            hook.after_create_session(&session, &hook_context).await?;
        }
        Ok(session)
    }

    pub(crate) async fn create_session_in_tx(
        &self,
        tx: &DatabaseTransaction,
        create_session: CreateSession,
    ) -> AuthResult<S::Session> {
        self.create_session_with_connection(tx, Some(tx), create_session)
            .await
    }
}

#[async_trait]
impl<S> SessionStore<S> for SeaOrmStore<S>
where
    S: AuthSchema + Send + Sync,
    S::Session: SeaOrmSessionModel,
{
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
            .order_by_desc(<S::Session as SeaOrmSessionModel>::created_at_column())
            .all(self.connection())
            .await
            .map_err(map_db_err)
    }

    async fn update_session_expiry(
        &self,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> AuthResult<()> {
        let Some(model) = <S::Session as SeaOrmSessionModel>::Entity::find()
            .filter(<S::Session as SeaOrmSessionModel>::token_column().eq(token))
            .filter(<S::Session as SeaOrmSessionModel>::active_column().eq(true))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(AuthError::SessionNotFound);
        };

        let mut active = model.into_active_model();
        S::Session::set_expires_at(&mut active, expires_at);
        S::Session::set_updated_at(&mut active, Utc::now());
        active
            .update(self.connection())
            .await
            .map(|_| ())
            .map_err(map_db_err)
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
        let Some(model) = <S::Session as SeaOrmSessionModel>::Entity::find()
            .filter(<S::Session as SeaOrmSessionModel>::token_column().eq(token))
            .filter(<S::Session as SeaOrmSessionModel>::active_column().eq(true))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(AuthError::SessionNotFound);
        };

        let mut active = model.into_active_model();
        S::Session::set_active_organization_id(&mut active, organization_id.map(str::to_owned));
        S::Session::set_updated_at(&mut active, Utc::now());
        active.update(self.connection()).await.map_err(map_db_err)
    }
}
