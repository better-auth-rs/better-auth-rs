use super::hooks::CommittedWrite;
use super::*;
use crate::store::database_hooks::{DatabaseHookControl, DatabaseHookUpdate, VerificationUpdate};

impl VerificationUpdate {
    fn apply(self, row: &mut VerificationView) {
        macro_rules! fields {
            ($($field:ident),* $(,)?) => {$(if let Some(value) = self.$field { row.$field = value; })*};
        }
        fields!(id, identifier, value, expires_at, created_at);
        row.updated_at = self.updated_at.unwrap_or_else(Utc::now);
    }
}

impl EphemeralStore {
    pub(super) async fn update_verification_with_hooks(
        &self,
        identifier: &str,
        mut update: VerificationUpdate,
    ) -> AuthResult<()> {
        let original = update.clone();
        let transaction = EphemeralTransaction { store: self };
        let context = self.hook_context(&transaction);
        for hook in &self.hooks {
            match hook.before_update_verification(&original, &context).await? {
                DatabaseHookUpdate::Continue => {}
                DatabaseHookUpdate::Cancel => return Ok(()),
                DatabaseHookUpdate::Patch(patch) => update.merge(patch),
            }
        }
        let row = (|| -> AuthResult<Option<VerificationView>> {
            let mut state = self.lock()?;
            let Some(position) = state
                .verifications
                .values()
                .position(|row| row.identifier == identifier)
            else {
                return Ok(None);
            };
            let (_, mut row) = state
                .verifications
                .shift_remove_index(position)
                .ok_or_else(|| {
                    AuthError::internal("Ephemeral verification position changed while locked")
                })?;
            update.apply(&mut row);
            let _ = state
                .verifications
                .shift_insert(position, row.id.clone(), row.clone());
            Ok(Some(row))
        })()?;
        self.after(CommittedWrite::VerificationUpdated(row)).await
    }

    pub(super) async fn delete_verifications_with_hooks(
        &self,
        predicate: impl Fn(&VerificationView) -> bool + Send + Sync,
        many: bool,
    ) -> AuthResult<usize> {
        let rows: Vec<_> = self
            .lock()?
            .verifications
            .values()
            .filter(|row| predicate(row))
            .take(if many { usize::MAX } else { 1 })
            .cloned()
            .collect();
        let transaction = EphemeralTransaction { store: self };
        let context = self.hook_context(&transaction);
        for row in &rows {
            for hook in &self.hooks {
                if hook.before_delete_verification(row, &context).await?
                    == DatabaseHookControl::Cancel
                {
                    return Ok(0);
                }
            }
        }
        let count = {
            let mut state = self.lock()?;
            let count = state.verifications.len();
            state.verifications.retain(|_, row| !predicate(row));
            count - state.verifications.len()
        };
        for row in rows {
            self.after(CommittedWrite::VerificationDeleted(row)).await?;
        }
        Ok(count)
    }

    async fn consume_verification_inner(
        &self,
        identifier: &str,
        value: Option<&str>,
    ) -> AuthResult<Option<VerificationView>> {
        let Some(snapshot) = self.get_verification_including_expired(identifier).await? else {
            return Ok(None);
        };
        if value.is_some_and(|value| snapshot.value != value) {
            return Ok(None);
        }
        let transaction = EphemeralTransaction { store: self };
        let context = self.hook_context(&transaction);
        for hook in &self.hooks {
            if hook.before_delete_verification(&snapshot, &context).await?
                == DatabaseHookControl::Cancel
            {
                return Ok(None);
            }
        }
        let consumed = {
            let mut state = self.lock()?;
            let Some(consumed) = state.verifications.shift_remove(&snapshot.id) else {
                return Ok(None);
            };
            state
                .verifications
                .retain(|_, row| row.identifier != identifier);
            consumed
        };
        self.after(CommittedWrite::VerificationDeleted(consumed.clone()))
            .await?;
        Ok(Some(consumed))
    }

    pub(super) async fn consume_verification_with_hooks(
        &self,
        identifier: &str,
        value: Option<&str>,
    ) -> AuthResult<Option<VerificationView>> {
        let lock = self.verification_lock(format!("verification:{identifier}"))?;
        let _guard = lock.lock().await;
        if self.pending_hooks.is_some() {
            return self.consume_verification_inner(identifier, value).await;
        }
        let (base, isolated) = self.begin_transaction()?;
        let result = isolated
            .consume_verification_inner(identifier, value)
            .await?;
        self.commit_transaction(base, isolated).await?;
        Ok(result)
    }
}
