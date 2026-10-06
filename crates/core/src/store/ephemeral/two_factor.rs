use super::rows::RowRef;
use super::*;
use crate::store::schema::{EntityRole, resolve_field_name};
use crate::user_fields::project_adapter_value;

impl EphemeralStore {
    async fn prepare_two_factor_fields(
        &self,
        fields: Map<String, Value>,
        create: bool,
    ) -> AuthResult<Map<String, Value>> {
        self.model_fields
            .fields(EntityRole::TwoFactor)
            .storage_fields_with_binding(fields, create, |_, field, value| {
                self.memory_plugin_field_input(field, value)
            })
            .await
    }

    async fn project_two_factor(
        &self,
        mut snapshot: TwoFactor,
        source: RowRef<TwoFactor>,
    ) -> AuthResult<TwoFactor> {
        let mut output = Map::new();
        for (name, field) in self.model_fields.fields(EntityRole::TwoFactor).fields() {
            let value = source.read(|row| {
                Ok(row
                    .additional_fields
                    .get(resolve_field_name(field.field_name.as_deref(), name))
                    .cloned())
            })?;
            if let Some(value) = project_adapter_value(value, field, field.references_id(), true)
                .await?
                .json()?
            {
                let _ = output.insert(name.to_owned(), value);
            }
        }
        snapshot.additional_fields = output;
        Ok(snapshot)
    }

    async fn write_two_factor_row(
        &self,
        operation: &str,
        predicate: impl Fn(&TwoFactor) -> bool + Send,
        write: impl FnOnce(&mut TwoFactor) + Send,
    ) -> AuthResult<Option<TwoFactor>> {
        let selected = self
            .raw("twoFactor", operation, |state| {
                state
                    .two_factors
                    .first_ref(predicate)?
                    .map(|source| {
                        let snapshot = source.write(|factor| {
                            write(factor);
                            Ok(factor.clone())
                        })?;
                        Ok((snapshot, source))
                    })
                    .transpose()
            })
            .await?;
        match selected {
            Some((snapshot, source)) => self.project_two_factor(snapshot, source).await.map(Some),
            None => Ok(None),
        }
    }
}

#[async_trait]
impl TwoFactorStore for EphemeralStore {
    async fn update_two_factor(
        &self,
        id: &crate::SchemaValue<String>,
        update: crate::types::UpdateTwoFactor,
    ) -> AuthResult<TwoFactor> {
        let fields = self
            .prepare_two_factor_fields(update.additional_fields, false)
            .await?;
        self.write_two_factor_row(
            "update",
            |factor| factor.id == *id,
            |factor| {
                if let Some(secret) = update.secret {
                    factor.secret = secret;
                }
                if let Some(codes) = update.backup_codes {
                    factor.backup_codes = codes;
                }
                if let Some(verified) = update.verified {
                    factor.verified = Some(verified);
                }
                factor.additional_fields.extend(fields);
            },
        )
        .await?
        .ok_or_else(|| AuthError::not_found("Two-factor settings not found"))
    }
    async fn compare_exchange_two_factor_backup_codes(
        &self,
        id: &crate::SchemaValue<String>,
        previous: &str,
        replacement: &str,
    ) -> AuthResult<bool> {
        let fields = self.prepare_two_factor_fields(Map::new(), false).await?;
        self.write_two_factor_row(
            "incrementOne",
            |factor| factor.id == *id && factor.backup_codes == previous,
            |factor| {
                factor.backup_codes = replacement.to_owned();
                factor.additional_fields.extend(fields);
            },
        )
        .await
        .map(|row| row.is_some())
    }
    async fn record_two_factor_failure(
        &self,
        id: &crate::SchemaValue<String>,
        max_attempts: i64,
        locked_until: &(dyn Fn() -> AuthResult<chrono::DateTime<Utc>> + Send + Sync),
    ) -> AuthResult<()> {
        let failures = self
            .write_two_factor_row(
                "incrementOne",
                |factor| factor.id == *id,
                |factor| {
                    let failures = factor.failed_verification_count.unwrap_or(0) + 1;
                    factor.failed_verification_count = Some(failures);
                },
            )
            .await?
            .and_then(|factor| factor.failed_verification_count)
            .unwrap_or(0);
        if failures >= max_attempts {
            let locked_until = locked_until()?;
            let fields = self.prepare_two_factor_fields(Map::new(), false).await?;
            let _ = self
                .write_two_factor_row(
                    "incrementOne",
                    |factor| {
                        factor.id == *id
                            && factor
                                .failed_verification_count
                                .is_some_and(|failures| failures >= max_attempts)
                    },
                    |factor| {
                        factor.locked_until = Some(locked_until);
                        factor.additional_fields.extend(fields);
                    },
                )
                .await?;
        }
        Ok(())
    }
    async fn reset_two_factor_failures(
        &self,
        id: &crate::SchemaValue<String>,
        locked_before: Option<chrono::DateTime<Utc>>,
    ) -> AuthResult<()> {
        let fields = self.prepare_two_factor_fields(Map::new(), false).await?;
        let _ = self
            .write_two_factor_row(
                if locked_before.is_some() {
                    "incrementOne"
                } else {
                    "update"
                },
                |factor| {
                    factor.id == *id
                        && locked_before.is_none_or(|before| {
                            // The upstream Memory adapter compares a null lock as epoch zero.
                            factor
                                .locked_until
                                .map_or(before.timestamp_millis() >= 0, |until| until <= before)
                        })
                },
                |factor| {
                    factor.failed_verification_count = Some(0);
                    factor.locked_until = None;
                    factor.additional_fields.extend(fields);
                },
            )
            .await?;
        Ok(())
    }
    async fn create_two_factor(&self, input: CreateTwoFactor) -> AuthResult<TwoFactor> {
        let additional_fields = self
            .prepare_two_factor_fields(input.additional_fields, true)
            .await?;
        let factor = TwoFactor {
            additional_fields,
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
            created_at: crate::SchemaValue::Undefined,
            updated_at: crate::SchemaValue::Undefined,
        };
        let (snapshot, source) = self
            .raw("twoFactor", "create", |state| {
                let source = state.two_factors.push_ref(factor.clone());
                Ok((factor, source))
            })
            .await?;
        self.project_two_factor(snapshot, source).await
    }
    async fn get_two_factor_by_user_id(&self, user_id: &str) -> AuthResult<Option<TwoFactor>> {
        let selected = self
            .raw("twoFactor", "findOne", |state| {
                state
                    .two_factors
                    .first_ref(|factor| factor.user_id == user_id)?
                    .map(|source| {
                        let snapshot = source.read(|factor| Ok(factor.clone()))?;
                        Ok((snapshot, source))
                    })
                    .transpose()
            })
            .await?;
        match selected {
            Some((snapshot, source)) => self.project_two_factor(snapshot, source).await.map(Some),
            None => Ok(None),
        }
    }
    async fn update_two_factor_backup_codes(
        &self,
        user_id: &str,
        backup_codes: &str,
    ) -> AuthResult<TwoFactor> {
        let fields = self.prepare_two_factor_fields(Map::new(), false).await?;
        self.write_two_factor_row(
            "update",
            |factor| factor.user_id == user_id,
            |factor| {
                factor.backup_codes = backup_codes.to_owned();
                factor.additional_fields.extend(fields);
            },
        )
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
                additional_fields: Default::default(),
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
