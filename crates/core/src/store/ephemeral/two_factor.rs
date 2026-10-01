use super::*;

#[async_trait]
impl TwoFactorStore for EphemeralStore {
    async fn update_two_factor(
        &self,
        id: &str,
        update: crate::types::UpdateTwoFactor,
    ) -> AuthResult<TwoFactor> {
        let mut state = self.lock()?;
        let factor = state
            .two_factors
            .get_mut(id)
            .ok_or_else(|| AuthError::not_found("Two-factor settings not found"))?;
        if let Some(secret) = update.secret {
            factor.secret = secret;
        }
        if let Some(codes) = update.backup_codes {
            factor.backup_codes = codes;
        }
        if let Some(verified) = update.verified {
            factor.verified = verified;
        }
        factor.updated_at = Utc::now();
        Ok(factor.clone())
    }
    async fn compare_exchange_two_factor_backup_codes(
        &self,
        id: &str,
        previous: &str,
        replacement: &str,
    ) -> AuthResult<bool> {
        let mut state = self.lock()?;
        let Some(factor) = state
            .two_factors
            .get_mut(id)
            .filter(|factor| factor.backup_codes == previous)
        else {
            return Ok(false);
        };
        factor.backup_codes = replacement.to_owned();
        factor.updated_at = Utc::now();
        Ok(true)
    }
    async fn record_two_factor_failure(
        &self,
        id: &str,
        max_attempts: i64,
        locked_until: chrono::DateTime<Utc>,
    ) -> AuthResult<()> {
        if let Some(factor) = self.lock()?.two_factors.get_mut(id) {
            factor.failed_verification_count += 1;
            if factor.failed_verification_count >= max_attempts {
                factor.locked_until = Some(locked_until);
            }
        }
        Ok(())
    }
    async fn reset_two_factor_failures(
        &self,
        id: &str,
        locked_before: Option<chrono::DateTime<Utc>>,
    ) -> AuthResult<()> {
        if let Some(factor) = self.lock()?.two_factors.get_mut(id).filter(|factor| {
            locked_before
                .is_none_or(|before| factor.locked_until.is_some_and(|until| until <= before))
        }) {
            factor.failed_verification_count = 0;
            factor.locked_until = None;
        }
        Ok(())
    }
    async fn create_two_factor(&self, input: CreateTwoFactor) -> AuthResult<TwoFactor> {
        let factor = TwoFactor {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: input.user_id,
            secret: input.secret,
            backup_codes: input.backup_codes,
            verified: input.verified,
            failed_verification_count: 0,
            locked_until: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let _ = self
            .lock()?
            .two_factors
            .insert(factor.id.clone(), factor.clone());
        Ok(factor)
    }
    async fn get_two_factor_by_user_id(&self, user_id: &str) -> AuthResult<Option<TwoFactor>> {
        Ok(self
            .lock()?
            .two_factors
            .values()
            .find(|factor| factor.user_id == user_id)
            .cloned())
    }
    async fn update_two_factor_backup_codes(
        &self,
        user_id: &str,
        backup_codes: &str,
    ) -> AuthResult<TwoFactor> {
        let mut state = self.lock()?;
        let factor = state
            .two_factors
            .values_mut()
            .find(|factor| factor.user_id == user_id)
            .ok_or_else(|| AuthError::not_found("Two-factor settings not found"))?;
        factor.backup_codes = backup_codes.to_owned();
        factor.updated_at = Utc::now();
        Ok(factor.clone())
    }
    async fn delete_two_factor(&self, user_id: &str) -> AuthResult<()> {
        self.lock()?
            .two_factors
            .retain(|_, factor| factor.user_id != user_id);
        Ok(())
    }
}
