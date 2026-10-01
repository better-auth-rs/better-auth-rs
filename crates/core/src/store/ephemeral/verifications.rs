use super::hooks::CommittedWrite;
use super::*;
use crate::store::{
    VerificationCreateWriter,
    database_hooks::{DatabaseHookControl, VerificationUpdate},
};

impl EphemeralStore {
    pub(super) async fn output_verifications(
        &self,
        records: &[Map<String, Value>],
    ) -> AuthResult<Vec<VerificationView>> {
        Ok(self
            .config
            .verification
            .field_schema()
            .project_records(records, true, true)
            .await?
            .into_iter()
            .map(VerificationView::from_adapter_fields)
            .collect())
    }

    pub(super) async fn output_verification(
        &self,
        record: &Map<String, Value>,
    ) -> AuthResult<VerificationView> {
        Ok(VerificationView::from_adapter_fields(
            self.config
                .verification
                .field_schema()
                .project_record(record, true, true)
                .await?,
        ))
    }
    pub(super) fn verification_field<'a>(
        &self,
        record: &'a Map<String, Value>,
        name: &str,
    ) -> Option<&'a Value> {
        record.get(
            self.config
                .verification
                .field_schema()
                .record_storage_key(name),
        )
    }
}

#[async_trait]
impl VerificationStore<StatelessSchema> for EphemeralStore {
    async fn before_create_runtime_verification(
        &self,
        input: &mut CreateVerification,
    ) -> AuthResult<()> {
        let transaction = EphemeralTransaction {
            store: self.clone(),
        };
        let context = self.hook_context(&transaction);
        for hook in &self.hooks {
            if crate::observability::database::with_database_hook(
                context.config,
                hook.hook_metadata(),
                crate::observability::database::DatabaseHook::BeforeCreateVerification,
                hook.before_create_verification(input, &context),
            )
            .await?
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
        record: &VerificationView,
        request: Option<crate::hooks::RequestHookContext>,
    ) -> AuthResult<()> {
        self.after_with_request(CommittedWrite::VerificationCreated(record.clone()), request)
            .await
    }

    async fn reserve_verification(&self, id: &str, input: CreateVerification) -> AuthResult<bool> {
        let mut record = self
            .config
            .verification
            .field_schema()
            .record_storage_fields_for_adapter(
                input.with_timestamps(Utc::now()).fields()?,
                true,
                true,
                |_| true,
            )
            .await?;
        let _ = record.insert("id".into(), Value::String(id.to_owned()));
        let inserted = self
            .raw("verification", "create", |state| {
                if state
                    .verifications
                    .snapshot()?
                    .iter()
                    .any(|row| row.get("id").and_then(Value::as_str) == Some(id))
                {
                    return Ok(false);
                }
                state.verifications.push(record.clone());
                Ok(true)
            })
            .await?;
        if !inserted {
            return Ok(false);
        }
        // Reservation catches create errors and then reads the existing row through the adapter again.
        if self.output_verification(&record).await.is_err() {
            let _ = self.output_verification(&record).await?;
            return Ok(false);
        }
        Ok(true)
    }

    async fn create_verification(&self, input: CreateVerification) -> AuthResult<VerificationView> {
        self.create_verification_with_writer(input, None).await
    }
    async fn create_verification_with_writer(
        &self,
        input: CreateVerification,
        writer: Option<VerificationCreateWriter>,
    ) -> AuthResult<VerificationView> {
        let mut input = input.with_timestamps(Utc::now());
        self.before_create_runtime_verification(&mut input).await?;
        let mut record = self
            .config
            .verification
            .field_schema()
            .record_storage_fields_for_adapter(input.fields()?, true, true, |_| true)
            .await?;
        let supplied = record
            .remove("id")
            .and_then(|id| id.as_str().map(str::to_owned));
        let id = self.generated_id("verification", supplied, self.lock()?.verifications.len())?;
        if let Some(id) = id {
            let _ = record.insert("id".into(), Value::String(id));
        }
        self.raw("verification", "create", |state| {
            state.verifications.push(record.clone());
            Ok(())
        })
        .await?;
        let projected = self.output_verification(&record).await?;
        if let Some(writer) = writer {
            writer(projected.clone()).await?;
        }
        self.after_create_runtime_verification(
            &projected,
            crate::hooks::current_request_hook_context(),
        )
        .await?;
        Ok(projected)
    }

    async fn get_verification_including_expired(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        let records: Vec<_> = self
            .raw("verification", "findMany", |state| {
                Ok(state
                    .verifications
                    .snapshot()?
                    .iter()
                    .filter(|row| {
                        self.verification_field(row, "identifier")
                            == Some(&Value::String(identifier.to_owned()))
                    })
                    .cloned()
                    .collect())
            })
            .await?;
        let latest = records.iter().min_by_key(|row| {
            std::cmp::Reverse(
                self.verification_field(row, "createdAt")
                    .and_then(Value::as_str),
            )
        });
        futures_util::future::OptionFuture::from(latest.map(|row| self.output_verification(row)))
            .await
            .transpose()
    }
    async fn get_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<VerificationView>> {
        let record = self
            .raw("verification", "findOne", |state| {
                Ok(state
                    .verifications
                    .snapshot()?
                    .iter()
                    .find(|row| {
                        self.verification_field(row, "identifier")
                            == Some(&Value::String(identifier.to_owned()))
                            && self.verification_field(row, "value")
                                == Some(&Value::String(value.to_owned()))
                    })
                    .cloned())
            })
            .await?;
        futures_util::future::OptionFuture::from(
            record
                .as_ref()
                .map(|record| self.output_verification(record)),
        )
        .await
        .transpose()
    }
    async fn get_verification_by_value(&self, value: &str) -> AuthResult<Option<VerificationView>> {
        let record = self
            .raw("verification", "findOne", |state| {
                Ok(state
                    .verifications
                    .snapshot()?
                    .iter()
                    .find(|row| {
                        self.verification_field(row, "value")
                            == Some(&Value::String(value.to_owned()))
                    })
                    .cloned())
            })
            .await?;
        futures_util::future::OptionFuture::from(
            record
                .as_ref()
                .map(|record| self.output_verification(record)),
        )
        .await
        .transpose()
    }
    async fn get_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        let record = self
            .raw("verification", "findOne", |state| {
                Ok(state
                    .verifications
                    .snapshot()?
                    .iter()
                    .find(|row| {
                        self.verification_field(row, "identifier")
                            == Some(&Value::String(identifier.to_owned()))
                    })
                    .cloned())
            })
            .await?;
        futures_util::future::OptionFuture::from(
            record
                .as_ref()
                .map(|record| self.output_verification(record)),
        )
        .await
        .transpose()
    }

    async fn update_verification(
        &self,
        identifier: &str,
        update: VerificationUpdate,
    ) -> AuthResult<Option<VerificationView>> {
        self.update_verification_with_hooks(identifier, update)
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
        let _ = self
            .delete_verifications_with_hooks(
                |row| {
                    self.verification_field(row, "identifier")
                        == Some(&Value::String(identifier.to_owned()))
                },
                false,
            )
            .await?;
        Ok(())
    }
    async fn delete_verification(&self, id: &str) -> AuthResult<()> {
        let _ = self
            .delete_verifications_with_hooks(
                |row| row.get("id") == Some(&Value::String(id.to_owned())),
                false,
            )
            .await?;
        Ok(())
    }
    async fn delete_expired_verifications(&self) -> AuthResult<usize> {
        let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.delete_verifications_with_hooks(
            |row| {
                self.verification_field(row, "expiresAt")
                    .and_then(Value::as_str)
                    .is_some_and(|value| value < now.as_str())
            },
            true,
        )
        .await
    }
    async fn consume_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<VerificationView>> {
        let record = self
            .consume_verification_with_hooks(identifier, Some(value))
            .await?;
        match record {
            Some(record) if !record.expires_at.is_before(Utc::now()) => Ok(Some(record)),
            _ => Ok(None),
        }
    }
    async fn consume_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        let record = self
            .consume_verification_including_expired(identifier)
            .await?;
        match record {
            Some(record) if !record.expires_at.is_before(Utc::now()) => Ok(Some(record)),
            _ => Ok(None),
        }
    }
    async fn consume_verification_including_expired(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        self.consume_verification_with_hooks(identifier, None).await
    }
}
