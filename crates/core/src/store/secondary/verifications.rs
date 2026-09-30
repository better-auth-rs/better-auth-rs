use super::{SecondaryStore, decode, object, ttl};
use crate::entity::AuthVerification;
use crate::store::VerificationStore;
use crate::types::CreateVerification;
use crate::wire::VerificationView;
use crate::{AuthError, AuthResult, AuthSchema};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

impl<S: AuthSchema> SecondaryStore<S> {
    async fn cache_verification(
        &self,
        identifier: &str,
        verification: &S::Verification,
    ) -> AuthResult<()> {
        let seconds = ttl(verification.expires_at());
        if let Some(storage) = &self.storage
            && seconds > 0
        {
            storage
                .set(
                    &format!("verification:{identifier}"),
                    &serde_json::to_string(&VerificationView::from(verification))?,
                    Some(seconds),
                )
                .await?;
        }
        Ok(())
    }

    async fn cached_verification(&self, identifier: &str) -> AuthResult<Option<S::Verification>> {
        let Some(storage) = &self.storage else {
            return Ok(None);
        };
        decode(storage.get(&format!("verification:{identifier}")).await?)
            .map(|value| S::Verification::from_runtime_fields(object(value)?))
            .transpose()
    }

    async fn verification_identifiers(&self, identifier: &str) -> AuthResult<Vec<String>> {
        let (stored, migrate) = self
            .config
            .verification
            .store_identifier
            .process(identifier)
            .await?;
        Ok(if migrate {
            vec![stored, identifier.to_owned()]
        } else {
            vec![stored]
        })
    }

    async fn delete_cached_verifications(&self, identifiers: &[String]) -> AuthResult<()> {
        if let Some(storage) = &self.storage {
            for identifier in identifiers {
                storage
                    .delete(&format!("verification:{identifier}"))
                    .await?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl<S: AuthSchema> VerificationStore<S> for SecondaryStore<S> {
    async fn reserve_verification(
        &self,
        id: &str,
        mut input: CreateVerification,
    ) -> AuthResult<bool> {
        if !self.database_verifications() {
            return Err(AuthError::config(
                "reserveVerificationValue requires database-backed verification storage. Set verification.storeInDatabase to true for flows that reserve verification values.",
            ));
        }
        input.identifier = self
            .config
            .verification
            .store_identifier
            .process(&input.identifier)
            .await?
            .0;
        let identifier = input.identifier.clone();
        let inserted = self.inner.reserve_verification(id, input).await?;
        if inserted
            && let Some(record) = self
                .inner
                .get_verification_including_expired(&identifier)
                .await?
        {
            self.cache_verification(&identifier, &record).await?;
        }
        Ok(inserted)
    }

    async fn create_verification(
        &self,
        mut input: CreateVerification,
    ) -> AuthResult<S::Verification> {
        input.identifier = self
            .config
            .verification
            .store_identifier
            .process(&input.identifier)
            .await?
            .0;
        let identifier = input.identifier.clone();
        let verification = if self.database_verifications() {
            self.inner.create_verification(input).await?
        } else {
            self.inner
                .before_create_runtime_verification(&mut input)
                .await?;
            let now = Utc::now();
            S::Verification::from_runtime_fields(object(serde_json::to_value(
                VerificationView {
                    id: uuid::Uuid::new_v4().to_string(),
                    identifier: input.identifier,
                    value: input.value,
                    expires_at: input.expires_at,
                    created_at: now,
                    updated_at: now,
                },
            )?)?)?
        };
        self.cache_verification(&identifier, &verification).await?;
        if !self.database_verifications() {
            self.inner
                .after_create_runtime_verification(&verification)
                .await?;
        }
        Ok(verification)
    }

    async fn get_verification_including_expired(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        let identifiers = self.verification_identifiers(identifier).await?;
        for candidate in &identifiers {
            if let Some(cached) = self.cached_verification(candidate).await? {
                return Ok(Some(cached));
            }
        }
        if !self.database_verifications() {
            return Ok(None);
        }
        let mut found = None;
        for candidate in &identifiers {
            found = self
                .inner
                .get_verification_including_expired(candidate)
                .await?;
            if found.is_some() {
                break;
            }
        }
        if !self.config.verification.disable_cleanup {
            let _ = self.inner.delete_expired_verifications().await?;
        }
        Ok(found)
    }

    async fn get_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        Ok(self
            .get_verification_including_expired(identifier)
            .await?
            .filter(|value| value.expires_at() > Utc::now()))
    }

    async fn get_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<S::Verification>> {
        Ok(self
            .get_verification_by_identifier(identifier)
            .await?
            .filter(|record| record.value() == value))
    }

    async fn get_verification_by_value(&self, value: &str) -> AuthResult<Option<S::Verification>> {
        if self.database_verifications() {
            self.inner.get_verification_by_value(value).await
        } else {
            Err(AuthError::config(
                "Secondary verification storage supports lookup by identifier, not by value",
            ))
        }
    }

    async fn update_verification_by_identifier(
        &self,
        identifier: &str,
        value: Option<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> AuthResult<()> {
        let identifier = self
            .config
            .verification
            .store_identifier
            .process(identifier)
            .await?
            .0;
        if let Some(cached) = self.cached_verification(&identifier).await? {
            let mut record = VerificationView::from(&cached);
            if let Some(value) = &value {
                record.value.clone_from(value);
            }
            if let Some(expires_at) = expires_at {
                record.expires_at = expires_at;
            }
            let record =
                S::Verification::from_runtime_fields(object(serde_json::to_value(record)?)?)?;
            self.cache_verification(&identifier, &record).await?;
        }
        if self.database_verifications() {
            self.inner
                .update_verification_by_identifier(&identifier, value, expires_at)
                .await?;
        }
        Ok(())
    }

    async fn delete_verification_by_identifier(&self, identifier: &str) -> AuthResult<()> {
        let identifier = self
            .config
            .verification
            .store_identifier
            .process(identifier)
            .await?
            .0;
        if let Some(storage) = &self.storage {
            storage
                .delete(&format!("verification:{identifier}"))
                .await?;
        }
        if self.database_verifications() {
            self.inner
                .delete_verification_by_identifier(&identifier)
                .await?;
        }
        Ok(())
    }

    async fn consume_verification_including_expired(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        let identifiers = self.verification_identifiers(identifier).await?;
        if self.database_verifications() {
            for identifier in &identifiers {
                if let Some(consumed) = self
                    .inner
                    .consume_verification_including_expired(identifier)
                    .await?
                {
                    self.delete_cached_verifications(&identifiers).await?;
                    return Ok(Some(consumed));
                }
            }
            return Ok(None);
        }
        for identifier in &identifiers {
            let Some(value) = decode(
                self.secondary()?
                    .get_and_delete(&format!("verification:{identifier}"))
                    .await?,
            ) else {
                continue;
            };
            let valid_expiry = value
                .get("expiresAt")
                .cloned()
                .and_then(|value| serde_json::from_value::<DateTime<Utc>>(value).ok());
            if valid_expiry.is_none() {
                continue;
            }
            for other in identifiers.iter().filter(|other| *other != identifier) {
                self.secondary()?
                    .delete(&format!("verification:{other}"))
                    .await?;
            }
            return Ok(Some(S::Verification::from_runtime_fields(object(value)?)?));
        }
        Ok(None)
    }

    async fn consume_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<S::Verification>> {
        Ok(self
            .consume_verification_including_expired(identifier)
            .await?
            .filter(|value| value.expires_at() >= Utc::now()))
    }

    async fn consume_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<S::Verification>> {
        if self.database_verifications() {
            for candidate in self.verification_identifiers(identifier).await? {
                if let Some(consumed) = self.inner.consume_verification(&candidate, value).await? {
                    self.delete_cached_verifications(
                        &self.verification_identifiers(identifier).await?,
                    )
                    .await?;
                    return Ok(Some(consumed));
                }
            }
            return Ok(None);
        }
        if self.get_verification(identifier, value).await?.is_none() {
            return Ok(None);
        }
        Ok(self
            .consume_verification_by_identifier(identifier)
            .await?
            .filter(|record| record.value() == value))
    }

    async fn delete_verification(&self, id: &str) -> AuthResult<()> {
        if self.database_verifications() {
            self.inner.delete_verification(id).await
        } else {
            Err(AuthError::config(
                "Secondary verification storage requires deletion by identifier",
            ))
        }
    }

    async fn delete_expired_verifications(&self) -> AuthResult<usize> {
        if self.database_verifications() {
            self.inner.delete_expired_verifications().await
        } else {
            Ok(0)
        }
    }
}
