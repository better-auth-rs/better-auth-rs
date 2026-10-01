use super::hooks::CommittedWrite;
use super::*;
use crate::store::database_hooks::{DatabaseHookControl, DatabaseHookUpdate, SessionUpdate};

impl SessionUpdate {
    fn apply(self, session: &mut SessionView) {
        macro_rules! fields {
            ($($field:ident),* $(,)?) => {$(if let Some(value) = self.$field { session.$field = value; })*};
        }
        fields!(
            id,
            token,
            user_id,
            expires_at,
            created_at,
            ip_address,
            user_agent,
            impersonated_by,
            active_organization_id,
            active_team_id
        );
        session.updated_at = self.updated_at.unwrap_or_else(Utc::now);
        session.additional_fields.extend(self.additional_fields);
    }
}

impl EphemeralStore {
    pub(super) async fn update_session_with_hooks(
        &self,
        token: &str,
        mut update: SessionUpdate,
    ) -> AuthResult<Option<SessionView>> {
        let original = update.clone();
        let transaction = EphemeralTransaction { store: self };
        let context = self.hook_context(&transaction);
        for hook in &self.hooks {
            match hook.before_update_session(&original, &context).await? {
                DatabaseHookUpdate::Continue => {}
                DatabaseHookUpdate::Cancel => return Ok(None),
                DatabaseHookUpdate::Patch(patch) => update.merge(patch),
            }
        }
        update.additional_fields = self
            .session_config
            .field_schema()
            .storage_fields(update.additional_fields, false)?;
        let session = (|| -> AuthResult<Option<SessionView>> {
            let mut state = self.lock()?;
            let Some((position, _, mut session)) = state.sessions.shift_remove_full(token) else {
                return Ok(None);
            };
            update.apply(&mut session);
            let _ = state
                .sessions
                .shift_insert(position, session.token.clone(), session.clone());
            Ok(Some(session))
        })()?;
        let session = session.map(|row| self.output_session(row)).transpose()?;
        self.after(CommittedWrite::SessionUpdated(session.clone()))
            .await?;
        Ok(session)
    }

    pub(super) async fn delete_sessions_with_hooks(
        &self,
        predicate: impl Fn(&SessionView) -> bool + Send + Sync,
    ) -> AuthResult<usize> {
        let sessions: Vec<_> = self
            .lock()?
            .sessions
            .values()
            .filter(|row| predicate(row))
            .cloned()
            .collect();
        let sessions: Vec<_> = sessions
            .into_iter()
            .map(|row| self.output_session(row))
            .collect::<AuthResult<_>>()?;
        let transaction = EphemeralTransaction { store: self };
        let context = self.hook_context(&transaction);
        for session in &sessions {
            for hook in &self.hooks {
                if hook.before_delete_session(session, &context).await?
                    == DatabaseHookControl::Cancel
                {
                    return Ok(0);
                }
            }
        }
        let count = {
            let mut state = self.lock()?;
            let before = state.sessions.len();
            state.sessions.retain(|_, row| !predicate(row));
            before - state.sessions.len()
        };
        for session in sessions {
            self.after(CommittedWrite::SessionDeleted(session)).await?;
        }
        Ok(count)
    }
}
