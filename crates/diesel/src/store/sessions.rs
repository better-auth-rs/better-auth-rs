use async_trait::async_trait;
use better_auth_core::store::SessionStore;
use better_auth_core::types::CreateSession;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;

use crate::error::{AuthError, AuthResult};
use crate::hooks::HookConnection;
use crate::models::Session;
use crate::schema::sessions;
use crate::sql_types::UtcTimestampValue;

use super::{DieselAuthSchema, DieselStore, cancelled_by_hook, new_id};

impl DieselStore {
    pub(crate) async fn insert_session<'a>(
        &'a self,
        connection: &'a HookConnection<'a>,
        mut create_session: CreateSession,
    ) -> AuthResult<Session> {
        let hook_context = self.hook_context(connection);
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
        let row = Session {
            id: new_id(),
            expires_at: create_session.expires_at,
            token: format!("session_{}", uuid::Uuid::new_v4()),
            created_at: now,
            updated_at: now,
            ip_address: Some(create_session.ip_address.unwrap_or_default()),
            user_agent: Some(create_session.user_agent.unwrap_or_default()),
            user_id: create_session.user_id,
            impersonated_by: create_session.impersonated_by,
            active_organization_id: create_session.active_organization_id,
            active: true,
        };

        let session = run_query!(lock connection, |c| {
            diesel::insert_into(sessions::table)
                .values(row)
                .returning(Session::as_returning())
                .get_result(c)
                .await
        })?;

        for hook in self.hooks() {
            hook.after_create_session(&session, &hook_context).await?;
        }
        Ok(session)
    }
}

#[async_trait]
impl SessionStore<DieselAuthSchema> for DieselStore {
    async fn create_session(&self, create_session: CreateSession) -> AuthResult<Session> {
        self.insert_session(&HookConnection::pooled(&self.pool), create_session)
            .await
    }

    async fn get_session(&self, token: &str) -> AuthResult<Option<Session>> {
        run_query!(self, |c| {
            sessions::table
                .filter(sessions::token.eq(token))
                .filter(sessions::active.eq(true))
                .select(Session::as_select())
                .first(c)
                .await
                .optional()
        })
    }

    async fn update_session_fields(
        &self,
        token: &str,
        fields: serde_json::Map<String, serde_json::Value>,
    ) -> AuthResult<Option<Session>> {
        // The Diesel schema has no application session fields to write.
        if !fields.is_empty() {
            return Err(AuthError::Config(
                "The session model does not implement additional field updates".into(),
            ));
        }
        run_query!(self, |c| {
            diesel::update(
                sessions::table
                    .filter(sessions::token.eq(token))
                    .filter(sessions::active.eq(true)),
            )
            .set(sessions::updated_at.eq(UtcTimestampValue(Utc::now())))
            .returning(Session::as_returning())
            .get_result(c)
            .await
            .optional()
        })
    }

    async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<Session>> {
        run_query!(self, |c| {
            sessions::table
                .filter(sessions::user_id.eq(user_id))
                .filter(sessions::active.eq(true))
                .select(Session::as_select())
                .load(c)
                .await
        })
    }

    async fn update_session_expiry(
        &self,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> AuthResult<()> {
        let updated = run_query!(self, |c| {
            diesel::update(
                sessions::table
                    .filter(sessions::token.eq(token))
                    .filter(sessions::active.eq(true)),
            )
            .set((
                sessions::expires_at.eq(UtcTimestampValue(expires_at)),
                sessions::updated_at.eq(UtcTimestampValue(Utc::now())),
            ))
            .execute(c)
            .await
        })?;

        if updated == 0 {
            return Err(AuthError::SessionNotFound);
        }
        Ok(())
    }

    async fn delete_session(&self, token: &str) -> AuthResult<()> {
        let connection = HookConnection::pooled(&self.pool);
        let session = run_query!(lock connection, |c| {
            sessions::table
                .filter(sessions::token.eq(token))
                .filter(sessions::active.eq(true))
                .select(Session::as_select())
                .first(c)
                .await
                .optional()
        })?;
        let hook_context = self.hook_context(&connection);
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

        let _ = run_query!(lock connection, |c| {
            diesel::delete(sessions::table.filter(sessions::token.eq(token)))
                .execute(c)
                .await
        })?;

        if let Some(session) = &session {
            for hook in self.hooks() {
                hook.after_delete_session(session, &hook_context).await?;
            }
        }
        Ok(())
    }

    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
        let _ = run_query!(self, |c| {
            diesel::delete(sessions::table.filter(sessions::user_id.eq(user_id)))
                .execute(c)
                .await
        })?;
        Ok(())
    }

    async fn delete_expired_sessions(&self) -> AuthResult<usize> {
        run_query!(self, |c| {
            diesel::delete(
                sessions::table.filter(
                    sessions::expires_at
                        .lt(UtcTimestampValue(Utc::now()))
                        .or(sessions::active.eq(false)),
                ),
            )
            .execute(c)
            .await
        })
    }

    async fn update_session_active_organization(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> AuthResult<Session> {
        run_query!(self, |c| {
            diesel::update(
                sessions::table
                    .filter(sessions::token.eq(token))
                    .filter(sessions::active.eq(true)),
            )
            .set((
                sessions::active_organization_id.eq(organization_id),
                sessions::updated_at.eq(UtcTimestampValue(Utc::now())),
            ))
            .returning(Session::as_returning())
            .get_result(c)
            .await
            .optional()
        })?
        .ok_or(AuthError::SessionNotFound)
    }
}
