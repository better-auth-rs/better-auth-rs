use super::rows::RowRef;
use super::*;
use crate::query::{field_compare, field_matches_equality};
use crate::store::schema::EntityRole;
use crate::{FieldDate, FieldValue, FromFieldMap, SchemaValue};

impl EphemeralStore {
    async fn project_two_factor_refs(
        &self,
        rows: Vec<RowRef<FieldMap>>,
    ) -> AuthResult<Vec<TwoFactor>> {
        self.project_plugin_refs(EntityRole::TwoFactor, rows)
            .await?
            .into_iter()
            .map(TwoFactor::from_field_values)
            .collect()
    }

    async fn write_two_factor_row(
        &self,
        operation: &str,
        predicate: impl Fn(&FieldMap) -> AuthResult<bool> + Send,
        write: impl Fn(&mut FieldMap) + Send,
    ) -> AuthResult<Option<TwoFactor>> {
        let selected = self
            .raw("twoFactor", operation, |state| {
                let matches = state.two_factors.try_select_refs(predicate)?;
                let writes = if operation == "incrementOne" {
                    1
                } else {
                    matches.len()
                };
                for source in matches.iter().take(writes) {
                    source.write(|row| {
                        write(row);
                        Ok(())
                    })?;
                }
                Ok(matches.into_iter().next())
            })
            .await?;
        Ok(self
            .project_two_factor_refs(selected.into_iter().collect())
            .await?
            .pop())
    }
}

#[async_trait]
impl TwoFactorStore for EphemeralStore {
    async fn create_two_factor_record(&self, input: FieldMap) -> AuthResult<FieldMap> {
        self.create_plugin_record(EntityRole::TwoFactor, input, Default::default())
            .await
    }

    async fn get_two_factor_record(
        &self,
        id: &SchemaValue<String>,
    ) -> AuthResult<Option<FieldMap>> {
        self.get_plugin_record(EntityRole::TwoFactor, id).await
    }

    async fn update_two_factor_record(
        &self,
        id: &SchemaValue<String>,
        input: FieldMap,
    ) -> AuthResult<Option<FieldMap>> {
        self.update_plugin_record(EntityRole::TwoFactor, id, input, Default::default())
            .await
    }

    async fn create_two_factor(&self, input: CreateTwoFactor) -> AuthResult<TwoFactor> {
        TwoFactor::from_field_values(
            self.create_two_factor_record(input.into_adapter_fields()?)
                .await?,
        )
    }

    async fn update_two_factor(
        &self,
        id: &SchemaValue<String>,
        update: crate::UpdateTwoFactor,
    ) -> AuthResult<TwoFactor> {
        self.update_two_factor_record(id, update.into_adapter_fields()?)
            .await?
            .map(TwoFactor::from_field_values)
            .transpose()?
            .ok_or_else(|| AuthError::not_found("Two-factor settings not found"))
    }

    async fn get_two_factor_by_user_id_value(
        &self,
        user_id: &SchemaValue<String>,
    ) -> AuthResult<Option<TwoFactor>> {
        let value =
            self.plugin_query_value(EntityRole::TwoFactor, "userId", user_id.field_value())?;
        let schema = self.model_fields.plugin_fields(EntityRole::TwoFactor);
        let column = schema.record_storage_key("userId");
        let selected = self
            .raw("twoFactor", "findOne", |state| {
                state.two_factors.first_ref(|row| {
                    field_matches_equality(
                        row.get(column).unwrap_or(&FieldValue::Undefined),
                        &value,
                    )
                })
            })
            .await?;
        Ok(self
            .project_two_factor_refs(selected.into_iter().collect())
            .await?
            .pop())
    }

    async fn update_two_factor_backup_codes(
        &self,
        user_id: &str,
        backup_codes: &str,
    ) -> AuthResult<TwoFactor> {
        let owner = self.plugin_query_value(EntityRole::TwoFactor, "userId", user_id.into())?;
        let patch = self
            .prepare_plugin_fields(
                EntityRole::TwoFactor,
                [("backupCodes".into(), backup_codes.into())].into(),
                false,
            )
            .await?;
        let schema = self.model_fields.plugin_fields(EntityRole::TwoFactor);
        let column = schema.record_storage_key("userId");
        self.write_two_factor_row(
            "update",
            |row| {
                Ok(field_matches_equality(
                    row.get(column).unwrap_or(&FieldValue::Undefined),
                    &owner,
                ))
            },
            |row| row.extend(patch.clone()),
        )
        .await?
        .ok_or_else(|| AuthError::not_found("Two-factor settings not found"))
    }

    async fn compare_exchange_two_factor_backup_codes(
        &self,
        id: &SchemaValue<String>,
        previous: &FieldValue,
        replacement: FieldValue,
    ) -> AuthResult<bool> {
        let id = self.plugin_query_value(EntityRole::TwoFactor, "id", id.field_value())?;
        let previous =
            self.plugin_query_value(EntityRole::TwoFactor, "backupCodes", previous.clone())?;
        let patch = self
            .prepare_plugin_fields(
                EntityRole::TwoFactor,
                [("backupCodes".into(), replacement)].into(),
                false,
            )
            .await?;
        let schema = self.model_fields.plugin_fields(EntityRole::TwoFactor);
        let column = schema.record_storage_key("backupCodes");
        self.write_two_factor_row(
            "incrementOne",
            |row| {
                Ok(
                    field_matches_equality(row.get("id").unwrap_or(&FieldValue::Undefined), &id)
                        && field_matches_equality(
                            row.get(column).unwrap_or(&FieldValue::Undefined),
                            &previous,
                        ),
                )
            },
            |row| row.extend(patch.clone()),
        )
        .await
        .map(|row| row.is_some())
    }

    async fn record_two_factor_failure(
        &self,
        id: &SchemaValue<String>,
        max_attempts: i64,
        locked_until: &(dyn Fn() -> AuthResult<FieldDate> + Send + Sync),
    ) -> AuthResult<()> {
        let schema = self.model_fields.plugin_fields(EntityRole::TwoFactor);
        let column = schema.record_storage_key("failedVerificationCount");
        let queried_id = self.plugin_query_value(EntityRole::TwoFactor, "id", id.field_value())?;
        let row = self
            .write_two_factor_row(
                "incrementOne",
                |row| {
                    Ok(field_matches_equality(
                        row.get("id").unwrap_or(&FieldValue::Undefined),
                        &queried_id,
                    ))
                },
                |row| {
                    let count = row.get(column).and_then(FieldValue::as_f64).unwrap_or(0.0) + 1.0;
                    let _ = row.insert(column.to_owned(), count.into());
                },
            )
            .await?;
        let count = row
            .map(|row| row.failed_verification_count.into_field_value())
            .unwrap_or_default();
        let count = if count.is_undefined() || count.is_null() {
            0.into()
        } else {
            count
        };
        if field_compare(&count, &FieldValue::from(max_attempts))?
            .is_some_and(|order| order.is_ge())
        {
            let deadline = locked_until()?;
            let queried_id =
                self.plugin_query_value(EntityRole::TwoFactor, "id", id.field_value())?;
            let maximum = self.plugin_query_value(
                EntityRole::TwoFactor,
                "failedVerificationCount",
                max_attempts.into(),
            )?;
            let patch = self
                .prepare_plugin_fields(
                    EntityRole::TwoFactor,
                    [("lockedUntil".into(), deadline.into())].into(),
                    false,
                )
                .await?;
            let _ = self
                .write_two_factor_row(
                    "incrementOne",
                    |row| {
                        Ok(field_matches_equality(
                            row.get("id").unwrap_or(&FieldValue::Undefined),
                            &queried_id,
                        ) && field_compare(
                            row.get(column).unwrap_or(&FieldValue::Undefined),
                            &maximum,
                        )?
                        .is_some_and(|order| order.is_ge()))
                    },
                    |row| row.extend(patch.clone()),
                )
                .await?;
        }
        Ok(())
    }

    async fn reset_two_factor_failures(
        &self,
        id: &SchemaValue<String>,
        locked_before: Option<FieldDate>,
    ) -> AuthResult<()> {
        let id = self.plugin_query_value(EntityRole::TwoFactor, "id", id.field_value())?;
        let cutoff = locked_before
            .map(|date| self.plugin_query_value(EntityRole::TwoFactor, "lockedUntil", date.into()))
            .transpose()?;
        let schema = self.model_fields.plugin_fields(EntityRole::TwoFactor);
        let column = schema.record_storage_key("lockedUntil");
        let patch = self
            .prepare_plugin_fields(
                EntityRole::TwoFactor,
                [
                    ("failedVerificationCount".into(), 0.into()),
                    ("lockedUntil".into(), FieldValue::Null),
                ]
                .into(),
                false,
            )
            .await?;
        let _ = self
            .write_two_factor_row(
                if cutoff.is_some() {
                    "incrementOne"
                } else {
                    "update"
                },
                |row| {
                    if !field_matches_equality(row.get("id").unwrap_or(&FieldValue::Undefined), &id)
                    {
                        return Ok(false);
                    }
                    match &cutoff {
                        Some(cutoff) => Ok(field_compare(
                            row.get(column).unwrap_or(&FieldValue::Undefined),
                            cutoff,
                        )?
                        .is_some_and(|order| order.is_le())),
                        None => Ok(true),
                    }
                },
                |row| row.extend(patch.clone()),
            )
            .await?;
        Ok(())
    }

    async fn delete_two_factor_by_user_id_value(
        &self,
        user_id: &SchemaValue<String>,
    ) -> AuthResult<()> {
        let owner =
            self.plugin_query_value(EntityRole::TwoFactor, "userId", user_id.field_value())?;
        let schema = self.model_fields.plugin_fields(EntityRole::TwoFactor);
        let column = schema.record_storage_key("userId");
        self.raw("twoFactor", "delete", |state| {
            state.two_factors.retain(|row| {
                !field_matches_equality(row.get(column).unwrap_or(&FieldValue::Undefined), &owner)
            })?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests;
