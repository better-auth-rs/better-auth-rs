use super::{SecondaryStore, cache};
use crate::store::VerificationStore;
use crate::store::{VerificationCreateWriter, database_hooks::VerificationUpdate};
use crate::types::CreateVerification;
use crate::wire::VerificationView;
use crate::{AuthError, AuthResult, AuthSchema, FieldValue};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

impl<S: AuthSchema> SecondaryStore<S> {
    pub(super) async fn consume_verification_in_transaction(
        &self,
        identifier: &str,
        transaction: Option<&dyn crate::store::AuthTransaction<S>>,
    ) -> AuthResult<Option<VerificationView>> {
        let identifiers = self.verification_identifiers(identifier).await?;
        if self.database_verifications() {
            for identifier in &identifiers {
                let consumed = match transaction {
                    Some(transaction) => {
                        transaction
                            .consume_verification_including_expired(identifier)
                            .await?
                    }
                    None => {
                        self.inner
                            .consume_verification_including_expired(identifier)
                            .await?
                    }
                };
                if let Some(consumed) = consumed {
                    self.delete_cached_verifications(&identifiers).await?;
                    return Ok(Some(consumed));
                }
            }
            return Ok(None);
        }
        for identifier in &identifiers {
            let raw = self
                .secondary()?
                .get_and_delete(&format!("verification:{identifier}"))
                .await?
                .map(FieldValue::from_json)
                .transpose()?;
            let Some(value) = cache::decode(raw) else {
                continue;
            };
            let mut record = cache::verification(&value)?;
            record.expires_at = record.expires_at.converted_date()?;
            if record.expires_at.date_milliseconds()?.is_nan() {
                continue;
            }
            for other in identifiers.iter().filter(|other| *other != identifier) {
                self.secondary()?
                    .delete(&format!("verification:{other}"))
                    .await?;
            }
            return Ok(Some(record));
        }
        Ok(None)
    }

    pub(super) async fn delete_verification_in_transaction(
        &self,
        identifier: &str,
        transaction: Option<&dyn crate::store::AuthTransaction<S>>,
    ) -> AuthResult<()> {
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
            match transaction {
                Some(transaction) => {
                    transaction
                        .delete_verification_by_identifier(&identifier)
                        .await?
                }
                None => {
                    self.inner
                        .delete_verification_by_identifier(&identifier)
                        .await?
                }
            }
        }
        Ok(())
    }
    pub(super) async fn create_verification_in_transaction(
        &self,
        mut input: CreateVerification,
        transaction: Option<&dyn crate::store::AuthTransaction<S>>,
    ) -> AuthResult<Option<VerificationView>> {
        let request = crate::hooks::current_request_hook_context();
        input = input.with_timestamps(self.now().into());
        input.identifier = self
            .config
            .verification
            .store_identifier
            .process(input.identifier.typed()?)
            .await?
            .0
            .into();
        let identifier = input.identifier.typed()?.clone();
        if self.database_verifications() {
            let writer = self.verification_writer(identifier);
            return match transaction {
                Some(transaction) => {
                    transaction
                        .create_verification_with_writer(input, writer)
                        .await
                }
                None => {
                    self.inner
                        .create_verification_with_writer(input, writer)
                        .await
                }
            };
        }
        let proceed = match transaction {
            Some(transaction) => {
                transaction
                    .before_create_runtime_verification_optional(&mut input)
                    .await?
            }
            None => {
                self.inner
                    .before_create_runtime_verification_optional(&mut input)
                    .await?
            }
        };
        if !proceed {
            return Ok(None);
        }
        // Secondary-only creation keeps the hook input: no generated ID or adapter field policies.
        let verification = VerificationView::from_fields(input.fields()?)?;
        self.cache_verification(&identifier, &verification).await?;
        if transaction.is_none() {
            self.inner
                .after_create_runtime_verification(Some(&verification), request)
                .await?;
        }

        Ok(Some(verification))
    }

    pub(super) async fn find_verification_in_transaction(
        &self,
        identifier: &str,
        transaction: Option<&dyn crate::store::AuthTransaction<S>>,
    ) -> AuthResult<Option<VerificationView>> {
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
            found = match transaction {
                Some(transaction) => {
                    transaction
                        .get_verification_including_expired(candidate)
                        .await?
                }
                None => {
                    self.inner
                        .get_verification_including_expired(candidate)
                        .await?
                }
            };
            if found.is_some() {
                break;
            }
        }
        if !self.config.verification.disable_cleanup() {
            let _ = match transaction {
                Some(transaction) => transaction.delete_expired_verifications().await?,
                None => self.inner.delete_expired_verifications().await?,
            };
        }
        Ok(found)
    }

    fn verification_writer(&self, identifier: String) -> Option<VerificationCreateWriter> {
        let _ = self.storage.as_ref()?;
        let runtime = self.clone();
        Some(Box::new(move |record| {
            Box::pin(async move { runtime.cache_verification_fields(&identifier, record).await })
        }))
    }

    pub(super) async fn update_verification_in_transaction(
        &self,
        identifier: &str,
        update: VerificationUpdate,
        transaction: Option<&dyn crate::store::AuthTransaction<S>>,
    ) -> AuthResult<Option<VerificationView>> {
        let identifier = self
            .config
            .verification
            .store_identifier
            .process(identifier)
            .await?
            .0;
        if let Some(cached) = self.cached_verification(&identifier).await? {
            let old_expiry = cached.expires_at.clone();
            let mut fields = cached.fields()?;
            fields.extend(update.fields()?);
            let record = VerificationView::from_fields(fields)?;
            // Upstream uses a nullish fallback for TTL while preserving the null in the cached JSON.
            let expiry =
                if record.expires_at.is_undefined() || record.expires_at.field_value().is_null() {
                    &old_expiry
                } else {
                    &record.expires_at
                };
            let seconds = expiry.converted_cache_ttl(self.now())?;
            if seconds > 0.0 {
                self.secondary()?
                    .set_native(
                        &format!("verification:{identifier}").into(),
                        &cache::stringify(&record.fields()?.into())?,
                        Some(seconds),
                    )
                    .await?;
            }
            if !self.database_verifications() {
                return Ok(Some(record));
            }
        }
        if self.database_verifications() {
            match transaction {
                Some(transaction) => transaction.update_verification(&identifier, update).await,
                None => self.inner.update_verification(&identifier, update).await,
            }
        } else {
            Ok(Some(VerificationView::from_fields(update.fields()?)?))
        }
    }

    async fn cache_verification(
        &self,
        identifier: &str,
        verification: &VerificationView,
    ) -> AuthResult<()> {
        self.cache_verification_fields(identifier, verification.fields()?)
            .await
    }

    async fn cache_verification_fields(
        &self,
        identifier: &str,
        fields: crate::FieldMap,
    ) -> AuthResult<()> {
        let Some(storage) = &self.storage else {
            return Ok(());
        };
        let seconds = crate::SchemaValue::<crate::FieldDate>::from_field(
            fields.get("expiresAt").cloned().unwrap_or_default(),
        )
        .cache_ttl(self.now())?;
        if seconds > 0.0 {
            storage
                .set_native(
                    &format!("verification:{identifier}").into(),
                    &cache::stringify(&fields.into())?,
                    Some(seconds),
                )
                .await?;
        }
        Ok(())
    }

    async fn cached_verification(&self, identifier: &str) -> AuthResult<Option<VerificationView>> {
        let Some(storage) = &self.storage else {
            return Ok(None);
        };
        cache::decode(
            storage
                .get_native(&format!("verification:{identifier}").into())
                .await?,
        )
        .map(|value| cache::verification(&value))
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
            .process(input.identifier.typed()?)
            .await?
            .0
            .into();
        let identifier = input.identifier.typed()?.clone();
        // Reservation caches the original four fields; the adapter result is not reused here.
        let cache = VerificationView::from_fields(crate::FieldMap::from_iter([
            ("id".into(), crate::FieldValue::String(id.to_owned())),
            (
                "identifier".into(),
                crate::FieldValue::String(identifier.clone()),
            ),
            ("value".into(), input.value.field_value()),
            ("expiresAt".into(), input.expires_at.field_value()),
        ]))?;
        let inserted = self.inner.reserve_verification(id, input).await?;
        if inserted {
            self.cache_verification(&identifier, &cache).await?;
        }
        Ok(inserted)
    }

    async fn create_verification(&self, input: CreateVerification) -> AuthResult<VerificationView> {
        self.create_verification_optional(input)
            .await?
            .ok_or_else(|| AuthError::internal("Verification creation returned no record"))
    }

    async fn create_verification_optional(
        &self,
        input: CreateVerification,
    ) -> AuthResult<Option<VerificationView>> {
        self.create_verification_in_transaction(input, None).await
    }

    async fn create_verification_with_writer(
        &self,
        input: CreateVerification,
        writer: Option<VerificationCreateWriter>,
    ) -> AuthResult<Option<VerificationView>> {
        self.inner
            .create_verification_with_writer(input, writer)
            .await
    }

    async fn get_verification_including_expired(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        self.find_verification_in_transaction(identifier, None)
            .await
    }

    async fn get_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        let record = self.get_verification_including_expired(identifier).await?;
        match record {
            Some(record) if record.expires_at.is_after(self.now())? => Ok(Some(record)),
            _ => Ok(None),
        }
    }

    async fn get_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<VerificationView>> {
        Ok(self
            .get_verification_by_identifier(identifier)
            .await?
            .filter(|record| record.value == value))
    }

    async fn get_verification_by_value(&self, value: &str) -> AuthResult<Option<VerificationView>> {
        if self.database_verifications() {
            self.inner.get_verification_by_value(value).await
        } else {
            Err(AuthError::config(
                "Secondary verification storage supports lookup by identifier, not by value",
            ))
        }
    }

    async fn update_verification(
        &self,
        identifier: &str,
        update: VerificationUpdate,
    ) -> AuthResult<Option<VerificationView>> {
        self.update_verification_in_transaction(identifier, update, None)
            .await
    }

    async fn update_verification_by_identifier(
        &self,
        identifier: &str,
        value: Option<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> AuthResult<()> {
        let _ = self
            .update_verification(
                identifier,
                VerificationUpdate {
                    value: value.map(Into::into).unwrap_or_default(),
                    expires_at: expires_at.map(Into::into).unwrap_or_default(),
                    ..Default::default()
                },
            )
            .await?;
        Ok(())
    }

    async fn delete_verification_by_identifier(&self, identifier: &str) -> AuthResult<()> {
        self.delete_verification_in_transaction(identifier, None)
            .await
    }

    async fn consume_verification_including_expired(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        self.consume_verification_in_transaction(identifier, None)
            .await
    }

    async fn consume_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        let record = self
            .consume_verification_including_expired(identifier)
            .await?;
        match record {
            Some(record) if !record.expires_at.is_before(self.now())? => Ok(Some(record)),
            _ => Ok(None),
        }
    }

    async fn consume_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<VerificationView>> {
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
            .filter(|record| record.value == value))
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
