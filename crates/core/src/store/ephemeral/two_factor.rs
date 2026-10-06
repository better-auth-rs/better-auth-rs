use super::*;

#[async_trait]
impl TwoFactorStore for EphemeralStore {
    async fn update_two_factor(
        &self,
        id: &crate::SchemaValue<String>,
        update: crate::types::UpdateTwoFactor,
    ) -> AuthResult<TwoFactor> {
        self.raw("twoFactor", "update", |state| {
            let Some(mut factor) = state.two_factors.get_mut(id)? else {
                return Ok(None);
            };
            if let Some(secret) = update.secret {
                factor.secret = secret;
            }
            if let Some(codes) = update.backup_codes {
                factor.backup_codes = codes;
            }
            if let Some(verified) = update.verified {
                factor.verified = Some(verified);
            }
            factor.updated_at = Utc::now().into();
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
            let Some(mut factor) = state
                .two_factors
                .get_mut(id)?
                .filter(|factor| factor.backup_codes == previous)
            else {
                return Ok(false);
            };
            factor.backup_codes = replacement.to_owned();
            factor.updated_at = Utc::now().into();
            Ok(true)
        })
        .await
    }
    async fn record_two_factor_failure(
        &self,
        id: &crate::SchemaValue<String>,
        max_attempts: i64,
        locked_until: &(dyn Fn() -> AuthResult<chrono::DateTime<Utc>> + Send + Sync),
    ) -> AuthResult<()> {
        let failures = self
            .raw("twoFactor", "incrementOne", |state| {
                Ok(state.two_factors.get_mut(id)?.map_or(0, |mut factor| {
                    let failures = factor.failed_verification_count.unwrap_or(0) + 1;
                    factor.failed_verification_count = Some(failures);
                    failures
                }))
            })
            .await?;
        if failures >= max_attempts {
            let locked_until = locked_until()?;
            self.raw("twoFactor", "incrementOne", |state| {
                if let Some(mut factor) = state.two_factors.get_mut(id)?.filter(|factor| {
                    factor
                        .failed_verification_count
                        .is_some_and(|failures| failures >= max_attempts)
                }) {
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
                if let Some(mut factor) = state.two_factors.get_mut(id)?.filter(|factor| {
                    locked_before.is_none_or(|before| {
                        factor.locked_until.is_some_and(|until| until <= before)
                    })
                }) {
                    factor.failed_verification_count = Some(0);
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
            verified: Some(input.verified),
            failed_verification_count: Some(0),
            locked_until: None,
            created_at: Utc::now().into(),
            updated_at: Utc::now().into(),
        };
        self.raw("twoFactor", "create", |state| {
            state.two_factors.push(factor.clone());
            Ok(factor)
        })
        .await
    }
    async fn get_two_factor_by_user_id(&self, user_id: &str) -> AuthResult<Option<TwoFactor>> {
        self.raw("twoFactor", "findOne", |state| {
            Ok(state
                .two_factors
                .snapshot()?
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
            let Some(mut factor) = state
                .two_factors
                .find_mut(|factor| factor.user_id == user_id)?
            else {
                return Ok(None);
            };
            factor.backup_codes = backup_codes.to_owned();
            factor.updated_at = Utc::now().into();
            Ok(Some(factor.clone()))
        })
        .await?
        .ok_or_else(|| AuthError::not_found("Two-factor settings not found"))
    }
    async fn delete_two_factor(&self, user_id: &str) -> AuthResult<()> {
        self.raw("twoFactor", "delete", |state| {
            state
                .two_factors
                .retain(|factor| factor.user_id != user_id)?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn nullable_memory_counter_starts_at_zero_and_keeps_account_lockout() {
        let store = EphemeralStore::default();
        let factor = store
            .create_two_factor(CreateTwoFactor {
                user_id: "owner".to_owned(),
                secret: "encrypted-secret".to_owned(),
                backup_codes: "encrypted-codes".to_owned(),
                verified: true,
            })
            .await
            .expect("create two-factor record");
        store
            .raw("twoFactor", "update", |state| {
                state
                    .two_factors
                    .get_mut(&factor.id)?
                    .expect("created record")
                    .failed_verification_count = None;
                Ok(())
            })
            .await
            .expect("store a nullable counter");
        let lock = Utc::now() + chrono::Duration::minutes(15);
        for expected in [1, 2] {
            store
                .record_two_factor_failure(&factor.id, 2, &|| Ok(lock))
                .await
                .expect("increment counter");
            let stored = store
                .get_two_factor_by_user_id("owner")
                .await
                .expect("read record")
                .expect("existing record");
            assert_eq!(stored.failed_verification_count, Some(expected));
            assert_eq!(stored.locked_until, (expected == 2).then_some(lock));
            assert_eq!(stored.verified, Some(true));
            assert_eq!(stored.secret, factor.secret);
            assert_eq!(stored.backup_codes, factor.backup_codes);
        }
    }
}
