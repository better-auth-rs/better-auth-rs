use super::hooks::CommittedWrite;
use super::rows::{RecordSource, RowRef};
use super::*;
use crate::store::schema::EntityRole;
use crate::store::{
    VerificationCreateWriter,
    database_hooks::{DatabaseHookControl, VerificationUpdate},
};

impl EphemeralStore {
    pub(super) async fn output_verifications(
        &self,
        records: Vec<RecordSource>,
    ) -> AuthResult<Vec<VerificationView>> {
        let schema = self.field_policy().verification();
        let order = schema
            .adapter_fields(&[])
            .fields()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        Ok(self
            .project_record_sources(EntityRole::Verification, &schema, records)
            .await?
            .into_iter()
            .map(|fields| VerificationView::from_adapter_fields(fields.in_field_order(&order)))
            .collect())
    }

    pub(super) async fn output_verification(
        &self,
        record: RecordSource,
    ) -> AuthResult<VerificationView> {
        Ok(self.output_verifications(vec![record]).await?.remove(0))
    }

    pub(super) async fn verification_storage_fields(
        &self,
        input: FieldMap,
        create: bool,
    ) -> AuthResult<FieldMap> {
        let force_allow_id = create && input.contains_key("id");
        super::raw_records::MemoryRecordModel::new(
            self,
            EntityRole::Verification,
            self.field_policy().verification(),
        )
        .prepare(input.into(), create, force_allow_id)
        .await
    }

    async fn create_verification_record(&self, input: FieldMap) -> AuthResult<VerificationView> {
        let force_allow_id = input.contains_key("id");
        let source = super::raw_records::MemoryRecordModel::new(
            self,
            EntityRole::Verification,
            self.field_policy().verification(),
        )
        .create_ref(input.into(), FieldMap::new(), force_allow_id)
        .await?;
        self.output_verification(RecordSource::Live(source)).await
    }

    pub(super) fn verification_field(
        &self,
        record: &RowRef<FieldMap>,
        name: &str,
    ) -> AuthResult<Option<Value>> {
        record.field(self.field_policy().verification().record_storage_key(name))
    }

    pub(super) async fn latest_verification_record(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<RowRef<FieldMap>>> {
        let (identifier_column, bound_identifier) = self.memory_query_field(
            EntityRole::Verification,
            &self.field_policy().verification(),
            "identifier",
            identifier.into(),
        )?;
        let records = self
            .raw("verification", "findMany", |op| {
                let mut records =
                    op.capture_table(EntityRole::Verification)?
                        .select_refs(|row| {
                            Ok(row
                                .field(&identifier_column)?
                                .unwrap_or_default()
                                .strict_equals(&bound_identifier))
                        })?;
                crate::memory_sort::sort(&mut records, true, |row| {
                    Ok(self
                        .verification_field(row, "createdAt")?
                        .unwrap_or_default())
                })?;
                Ok(records)
            })
            .await?;
        Ok(records.into_iter().next())
    }
}

#[async_trait]
impl VerificationStore<StatelessSchema> for EphemeralStore {
    async fn before_create_runtime_verification(
        &self,
        input: &mut CreateVerification,
    ) -> AuthResult<()> {
        if self
            .before_create_runtime_verification_optional(input)
            .await?
        {
            Ok(())
        } else {
            Err(AuthError::forbidden(
                "verification creation cancelled by database hook",
            ))
        }
    }

    async fn before_create_runtime_verification_optional(
        &self,
        input: &mut CreateVerification,
    ) -> AuthResult<bool> {
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
                return Ok(false);
            }
        }
        Ok(true)
    }
    async fn after_create_runtime_verification(
        &self,
        record: Option<&VerificationView>,
        request: Option<crate::hooks::RequestHookContext>,
    ) -> AuthResult<()> {
        self.after_with_request(
            CommittedWrite::VerificationCreated(record.cloned()),
            request,
        )
        .await
    }

    async fn reserve_verification(&self, id: &str, input: CreateVerification) -> AuthResult<bool> {
        let result = async {
            self.create_verification_record(input.into_reservation(id).fields()?)
                .await
        }
        .await;
        // The fallback observes rows left by input, persistence, or output failures.
        if let Err(error) = result {
            let (column, bound) = self.memory_query_field(
                EntityRole::Verification,
                &self.field_policy().verification(),
                "id",
                id.into(),
            )?;
            let found = self
                .raw("verification", "findOne", |op| {
                    Ok(op
                        .capture_table(EntityRole::Verification)?
                        .select_refs(|record| {
                            Ok(record
                                .field(&column)?
                                .unwrap_or_default()
                                .strict_equals(&bound))
                        })?
                        .into_iter()
                        .next())
                })
                .await?;
            let Some(found) = found else {
                return Err(error);
            };
            let _ = self.output_verification(RecordSource::Live(found)).await?;
            return Ok(false);
        }
        Ok(true)
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
        self.create_verification_with_writer(input, None).await
    }
    async fn create_verification_with_writer(
        &self,
        input: CreateVerification,
        writer: Option<VerificationCreateWriter>,
    ) -> AuthResult<Option<VerificationView>> {
        let mut input = input.with_timestamps(Utc::now().into());
        if !self
            .before_create_runtime_verification_optional(&mut input)
            .await?
        {
            return Ok(None);
        }
        let projected = self.create_verification_record(input.fields()?).await?;
        if let Some(writer) = writer {
            writer(projected.fields()?).await?;
        }
        self.after_create_runtime_verification(
            Some(&projected),
            crate::hooks::current_request_hook_context(),
        )
        .await?;
        Ok(Some(projected))
    }

    async fn get_verification_including_expired(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        let record = self.latest_verification_record(identifier).await?;
        futures_util::future::OptionFuture::from(
            record.map(|row| self.output_verification(RecordSource::Live(row))),
        )
        .await
        .transpose()
    }
    async fn get_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<VerificationView>> {
        let (identifier_column, bound_identifier) = self.memory_query_field(
            EntityRole::Verification,
            &self.field_policy().verification(),
            "identifier",
            identifier.into(),
        )?;
        let (value_column, bound_value) = self.memory_query_field(
            EntityRole::Verification,
            &self.field_policy().verification(),
            "value",
            value.into(),
        )?;
        let record = self
            .raw("verification", "findOne", |op| {
                Ok(op
                    .capture_table(EntityRole::Verification)?
                    .select_refs(|row| {
                        crate::memory_query::matches_all(
                            [
                                (&identifier_column, &bound_identifier),
                                (&value_column, &bound_value),
                            ],
                            |(name, value)| {
                                Ok(row.field(name)?.unwrap_or_default().strict_equals(value))
                            },
                        )
                    })?
                    .into_iter()
                    .next())
            })
            .await?;
        futures_util::future::OptionFuture::from(
            record.map(|record| self.output_verification(RecordSource::Live(record))),
        )
        .await
        .transpose()
    }
    async fn get_verification_by_value(&self, value: &str) -> AuthResult<Option<VerificationView>> {
        let (value_column, bound_value) = self.memory_query_field(
            EntityRole::Verification,
            &self.field_policy().verification(),
            "value",
            value.into(),
        )?;
        let record = self
            .raw("verification", "findOne", |op| {
                Ok(op
                    .capture_table(EntityRole::Verification)?
                    .select_refs(|row| {
                        Ok(row
                            .field(&value_column)?
                            .unwrap_or_default()
                            .strict_equals(&bound_value))
                    })?
                    .into_iter()
                    .next())
            })
            .await?;
        futures_util::future::OptionFuture::from(
            record.map(|record| self.output_verification(RecordSource::Live(record))),
        )
        .await
        .transpose()
    }
    async fn get_verification_by_identifier(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        let (identifier_column, bound_identifier) = self.memory_query_field(
            EntityRole::Verification,
            &self.field_policy().verification(),
            "identifier",
            identifier.into(),
        )?;
        let record = self
            .raw("verification", "findOne", |op| {
                Ok(op
                    .capture_table(EntityRole::Verification)?
                    .select_refs(|row| {
                        Ok(row
                            .field(&identifier_column)?
                            .unwrap_or_default()
                            .strict_equals(&bound_identifier))
                    })?
                    .into_iter()
                    .next())
            })
            .await?;
        futures_util::future::OptionFuture::from(
            record.map(|record| self.output_verification(RecordSource::Live(record))),
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
                || {
                    let (column, value) = self.memory_query_field(
                        EntityRole::Verification,
                        &self.field_policy().verification(),
                        "identifier",
                        identifier.into(),
                    )?;
                    Ok(move |row: &RowRef<FieldMap>| {
                        Ok(row
                            .field(&column)?
                            .unwrap_or_default()
                            .strict_equals(&value))
                    })
                },
                false,
            )
            .await?;
        Ok(())
    }
    async fn delete_verification(&self, id: &str) -> AuthResult<()> {
        let bind = || {
            let (column, value) = self.memory_query_field(
                EntityRole::Verification,
                &self.field_policy().verification(),
                "id",
                id.into(),
            )?;
            Ok(move |row: &RowRef<FieldMap>| {
                Ok(row
                    .field(&column)?
                    .unwrap_or_default()
                    .strict_equals(&value))
            })
        };
        let predicate = bind()?;
        let rows = self
            .raw("verification", "findOne", |op| {
                Ok(op
                    .capture_table(EntityRole::Verification)?
                    .select_refs(predicate)?
                    .into_iter()
                    .next()
                    .into_iter()
                    .collect())
            })
            .await?;
        let _ = self.finish_verification_delete(rows, bind, false).await?;
        Ok(())
    }
    async fn delete_expired_verifications(&self) -> AuthResult<usize> {
        let now = Value::Date(Utc::now().into());
        self.delete_verifications_with_hooks(
            || {
                let (column, now) = self.memory_query_field(
                    EntityRole::Verification,
                    &self.field_policy().verification(),
                    "expiresAt",
                    now.clone(),
                )?;
                Ok(move |row: &RowRef<FieldMap>| {
                    crate::memory_query::matches(
                        row.field(&column)?.as_ref(),
                        &now,
                        crate::WhereOperator::Lt,
                        crate::WhereMode::Sensitive,
                    )
                })
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
            Some(record) if !record.expires_at.is_before(Utc::now())? => Ok(Some(record)),
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
            Some(record) if !record.expires_at.is_before(Utc::now())? => Ok(Some(record)),
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
