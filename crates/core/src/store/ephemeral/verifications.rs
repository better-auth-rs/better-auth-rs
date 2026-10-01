use super::hooks::CommittedWrite;
use super::*;
use crate::store::database_hooks::{DatabaseHookControl, VerificationUpdate};

#[async_trait]
impl VerificationStore<StatelessSchema> for EphemeralStore {
    async fn before_create_runtime_verification(
        &self,
        input: &mut CreateVerification,
    ) -> AuthResult<()> {
        let transaction = EphemeralTransaction { store: self };
        let context = self.hook_context(&transaction);
        for hook in &self.hooks {
            if hook.before_create_verification(input, &context).await?
                == DatabaseHookControl::Cancel
            {
                return Err(AuthError::forbidden(
                    "verification creation cancelled by database hook",
                ));
            }
        }
        Ok(())
    }

    async fn after_create_runtime_verification(
        &self,
        verification: &VerificationView,
    ) -> AuthResult<()> {
        self.after(CommittedWrite::VerificationCreated(verification.clone()))
            .await
    }

    async fn reserve_verification(
        &self,
        id: &str,
        verification: CreateVerification,
    ) -> AuthResult<bool> {
        let mut state = self.lock()?;
        if state.verifications.contains_key(id) {
            return Ok(false);
        }
        let now = Utc::now();
        let _ = state.verifications.insert(
            id.to_owned(),
            VerificationView {
                id: id.to_owned(),
                identifier: verification.identifier,
                value: verification.value,
                expires_at: verification.expires_at,
                created_at: now,
                updated_at: now,
            },
        );
        Ok(true)
    }

    async fn get_verification_including_expired(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        Ok(self
            .lock()?
            .verifications
            .values()
            .filter(|row| row.identifier == identifier)
            .min_by_key(|row| std::cmp::Reverse(row.created_at.timestamp_millis()))
            .cloned())
    }
    async fn update_verification_by_identifier(
        &self,
        identifier: &str,
        value: Option<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> AuthResult<()> {
        self.update_verification_with_hooks(
            identifier,
            VerificationUpdate {
                value,
                expires_at,
                ..Default::default()
            },
        )
        .await
    }
    async fn delete_verification_by_identifier(&self, identifier: &str) -> AuthResult<()> {
        let _ = self
            .delete_verifications_with_hooks(|row| row.identifier == identifier, false)
            .await?;
        Ok(())
    }
    async fn create_verification(
        &self,
        mut verification: CreateVerification,
    ) -> AuthResult<VerificationView> {
        self.before_create_runtime_verification(&mut verification)
            .await?;
        let now = Utc::now();
        let verification = VerificationView {
            id: uuid::Uuid::new_v4().to_string(),
            identifier: verification.identifier,
            value: verification.value,
            expires_at: verification.expires_at,
            created_at: now,
            updated_at: now,
        };
        let _ = self
            .lock()?
            .verifications
            .insert(verification.id.clone(), verification.clone());
        self.after_create_runtime_verification(&verification)
            .await?;
        Ok(verification)
    }

    async fn get_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<VerificationView>> {
        Ok(self
            .lock()?
            .verifications
            .values()
            .find(|verification| {
                verification.identifier == identifier && verification.value == value
            })
            .cloned())
    }

    async fn get_verification_by_value(&self, value: &str) -> AuthResult<Option<VerificationView>> {
        Ok(self
            .lock()?
            .verifications
            .values()
            .find(|verification| verification.value == value)
            .cloned())
    }

    async fn get_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        Ok(self
            .lock()?
            .verifications
            .values()
            .find(|verification| verification.identifier == identifier)
            .cloned())
    }

    async fn consume_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<VerificationView>> {
        let found = self
            .consume_verification_with_hooks(identifier, Some(value))
            .await?;
        Ok(found.filter(|verification| verification.expires_at >= Utc::now()))
    }

    async fn consume_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        Ok(self
            .consume_verification_including_expired(identifier)
            .await?
            .filter(|value| value.expires_at >= Utc::now()))
    }

    async fn consume_verification_including_expired(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        self.consume_verification_with_hooks(identifier, None).await
    }

    async fn delete_verification(&self, id: &str) -> AuthResult<()> {
        let _ = self
            .delete_verifications_with_hooks(|row| row.id == id, false)
            .await?;
        Ok(())
    }

    async fn delete_expired_verifications(&self) -> AuthResult<usize> {
        let now = Utc::now();
        self.delete_verifications_with_hooks(|row| row.expires_at < now, true)
            .await
    }
}
