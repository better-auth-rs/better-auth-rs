use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait, ExprTrait,
    IntoActiveModel, QueryFilter, QueryOrder, Set,
};
use uuid::Uuid;

use crate::error::{AuthError, AuthResult};
use crate::types::{CreateSession, Session};

use super::entities::session::{Column, Entity};
use super::{AuthStore, cancelled_by_hook, map_db_err};

impl AuthStore {
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
    ) -> AuthResult<Session>
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
        let session = super::entities::session::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            user_id: Set(create_session.user_id),
            token: Set(format!("session_{}", Uuid::new_v4())),
            expires_at: Set(create_session.expires_at),
            created_at: Set(now),
            updated_at: Set(now),
            ip_address: Set(Self::normalize_session_client_field(
                create_session.ip_address,
            )),
            user_agent: Set(Self::normalize_session_client_field(
                create_session.user_agent,
            )),
            impersonated_by: Set(create_session.impersonated_by),
            active_organization_id: Set(create_session.active_organization_id),
            active: Set(true),
        }
        .insert(db)
        .await
        .map(Session::from)
        .map_err(map_db_err)?;
        for hook in self.hooks() {
            hook.after_create_session(&session, &hook_context).await?;
        }
        Ok(session)
    }

    pub async fn create_session(&self, create_session: CreateSession) -> AuthResult<Session> {
        self.create_session_with_connection(self.connection(), None, create_session)
            .await
    }

    /// Create a session inside an existing transaction.
    #[doc(hidden)]
    pub async fn create_session_in_tx(
        &self,
        tx: &DatabaseTransaction,
        create_session: CreateSession,
    ) -> AuthResult<Session> {
        self.create_session_with_connection(tx, Some(tx), create_session)
            .await
    }

    pub async fn get_session(&self, token: &str) -> AuthResult<Option<Session>> {
        Entity::find()
            .filter(Column::Token.eq(token))
            .filter(Column::Active.eq(true))
            .one(self.connection())
            .await
            .map(|model| model.map(Session::from))
            .map_err(map_db_err)
    }

    pub async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<Session>> {
        Entity::find()
            .filter(Column::UserId.eq(user_id))
            .filter(Column::Active.eq(true))
            .order_by_desc(Column::CreatedAt)
            .all(self.connection())
            .await
            .map(|models| models.into_iter().map(Session::from).collect())
            .map_err(map_db_err)
    }

    pub async fn update_session_expiry(
        &self,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> AuthResult<()> {
        let Some(model) = Entity::find()
            .filter(Column::Token.eq(token))
            .filter(Column::Active.eq(true))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(AuthError::SessionNotFound);
        };

        let mut active = model.into_active_model();
        active.expires_at = Set(expires_at);
        active.updated_at = Set(Utc::now());
        active
            .update(self.connection())
            .await
            .map(|_| ())
            .map_err(map_db_err)
    }

    pub async fn delete_session(&self, token: &str) -> AuthResult<()> {
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
        let _ = Entity::delete_many()
            .filter(Column::Token.eq(token))
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

    pub async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
        Entity::delete_many()
            .filter(Column::UserId.eq(user_id))
            .exec(self.connection())
            .await
            .map(|_| ())
            .map_err(map_db_err)
    }

    pub async fn delete_expired_sessions(&self) -> AuthResult<usize> {
        Entity::delete_many()
            .filter(
                Column::ExpiresAt
                    .lt(Utc::now())
                    .or(Column::Active.eq(false)),
            )
            .exec(self.connection())
            .await
            .map(|result| result.rows_affected as usize)
            .map_err(map_db_err)
    }

    pub async fn update_session_active_organization(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<Session> {
        let Some(model) = Entity::find()
            .filter(Column::Token.eq(token))
            .filter(Column::Active.eq(true))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(AuthError::SessionNotFound);
        };

        let mut active = model.into_active_model();
        active.active_organization_id = Set(organization_id.map(str::to_owned));
        active.updated_at = Set(Utc::now());
        active
            .update(self.connection())
            .await
            .map(Session::from)
            .map_err(map_db_err)
    }
}
