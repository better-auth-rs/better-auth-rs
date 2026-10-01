use super::*;

#[async_trait]
impl TwoFactorStore for EphemeralStore {
    async fn update_two_factor(
        &self,
        id: &crate::SchemaValue<String>,
        update: crate::types::UpdateTwoFactor,
    ) -> AuthResult<TwoFactor> {
        self.raw("twoFactor", "update", |state| {
            let Some(factor) = state.two_factors.get_mut(id) else {
                return Ok(None);
            };
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
            Ok(Some(factor.clone()))
        })
        .await?
        .ok_or_else(|| AuthError::not_found("Two-factor settings not found"))
    }
    async fn compare_exchange_two_factor_backup_codes(
        &self,
        id: &crate::SchemaValue<String>,
        previous: &str,
        replacement: &str,
    ) -> AuthResult<bool> {
        self.raw("twoFactor", "incrementOne", |state| {
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
        })
        .await
    }
    async fn record_two_factor_failure(
        &self,
        id: &crate::SchemaValue<String>,
        max_attempts: i64,
        locked_until: chrono::DateTime<Utc>,
    ) -> AuthResult<()> {
        let failures = self
            .raw("twoFactor", "incrementOne", |state| {
                Ok(state.two_factors.get_mut(id).map_or(0, |factor| {
                    factor.failed_verification_count += 1;
                    factor.failed_verification_count
                }))
            })
            .await?;
        if failures >= max_attempts {
            self.raw("twoFactor", "incrementOne", |state| {
                if let Some(factor) = state
                    .two_factors
                    .get_mut(id)
                    .filter(|factor| factor.failed_verification_count >= max_attempts)
                {
                    factor.locked_until = Some(locked_until);
                }
                Ok(())
            })
            .await?;
        }
        Ok(())
    }
    async fn reset_two_factor_failures(
        &self,
        id: &crate::SchemaValue<String>,
        locked_before: Option<chrono::DateTime<Utc>>,
    ) -> AuthResult<()> {
        self.raw(
            "twoFactor",
            if locked_before.is_some() {
                "incrementOne"
            } else {
                "update"
            },
            |state| {
                if let Some(factor) = state.two_factors.get_mut(id).filter(|factor| {
                    locked_before.is_none_or(|before| {
                        factor.locked_until.is_some_and(|until| until <= before)
                    })
                }) {
                    factor.failed_verification_count = 0;
                    factor.locked_until = None;
                }
                Ok(())
            },
        )
        .await
    }
    async fn create_two_factor(&self, input: CreateTwoFactor) -> AuthResult<TwoFactor> {
        let factor = TwoFactor {
            id: self
                .generated_id("twoFactor", None, self.lock()?.two_factors.len())?
                .map(crate::SchemaValue::Typed)
                .unwrap_or_default(),
            user_id: input.user_id,
            secret: input.secret,
            backup_codes: input.backup_codes,
            verified: input.verified,
            failed_verification_count: 0,
            locked_until: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        self.raw("twoFactor", "create", |state| {
            let _ = state.two_factors.push(factor.clone());
            Ok(factor)
        })
        .await
    }
    async fn get_two_factor_by_user_id(&self, user_id: &str) -> AuthResult<Option<TwoFactor>> {
        self.raw("twoFactor", "findOne", |state| {
            Ok(state
                .two_factors
                .iter()
                .find(|factor| factor.user_id == user_id)
                .cloned())
        })
        .await
    }
    async fn update_two_factor_backup_codes(
        &self,
        user_id: &str,
        backup_codes: &str,
    ) -> AuthResult<TwoFactor> {
        self.raw("twoFactor", "update", |state| {
            let Some(factor) = state
                .two_factors
                .iter_mut()
                .find(|factor| factor.user_id == user_id)
            else {
                return Ok(None);
            };
            factor.backup_codes = backup_codes.to_owned();
            factor.updated_at = Utc::now();
            Ok(Some(factor.clone()))
        })
        .await?
        .ok_or_else(|| AuthError::not_found("Two-factor settings not found"))
    }
    async fn delete_two_factor(&self, user_id: &str) -> AuthResult<()> {
        self.raw("twoFactor", "delete", |state| {
            state.two_factors.retain(|factor| factor.user_id != user_id);
            Ok(())
        })
        .await
    }
}
