use async_trait::async_trait;
use better_auth_core::store::DeviceCodeStore;
use better_auth_core::{CreateDeviceCode, DeviceCode, UpdateDeviceCode};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;

use crate::error::{AuthError, AuthResult};
use crate::models::{DeviceCodeChanges, DeviceCodeRow};
use crate::schema::device_codes;
use crate::sql_types::NullableUtcTimestampValue;

use super::{DieselStore, new_id};

fn device_code_changes(update: UpdateDeviceCode) -> DeviceCodeChanges {
    DeviceCodeChanges {
        status: update.status,
        user_id: update.user_id,
        last_polled_at: update.last_polled_at.map(NullableUtcTimestampValue),
    }
}

#[async_trait]
impl DeviceCodeStore for DieselStore {
    async fn create_device_code(&self, input: CreateDeviceCode) -> AuthResult<DeviceCode> {
        let row = DeviceCodeRow {
            id: new_id(),
            device_code: input.device_code,
            user_code: input.user_code,
            user_id: input.user_id,
            expires_at: input.expires_at,
            status: input.status,
            last_polled_at: input.last_polled_at,
            polling_interval: input.polling_interval,
            client_id: input.client_id,
            scope: input.scope,
        };

        run_query!(self, |c| {
            diesel::insert_into(device_codes::table)
                .values(row)
                .returning(DeviceCodeRow::as_returning())
                .get_result(c)
                .await
        })
        .map(DeviceCode::from)
    }

    async fn get_device_code_by_device_code(
        &self,
        device_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        run_query!(self, |c| {
            device_codes::table
                .filter(device_codes::device_code.eq(device_code))
                .select(DeviceCodeRow::as_select())
                .first(c)
                .await
                .optional()
        })
        .map(|row| row.map(DeviceCode::from))
    }

    async fn get_device_code_by_user_code(
        &self,
        user_code: &str,
    ) -> AuthResult<Option<DeviceCode>> {
        run_query!(self, |c| {
            device_codes::table
                .filter(device_codes::user_code.eq(user_code))
                .select(DeviceCodeRow::as_select())
                .first(c)
                .await
                .optional()
        })
        .map(|row| row.map(DeviceCode::from))
    }

    async fn update_device_code(
        &self,
        id: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<DeviceCode> {
        let changes = device_code_changes(update);
        let row = if changes.is_empty() {
            run_query!(self, |c| {
                device_codes::table
                    .find(id)
                    .select(DeviceCodeRow::as_select())
                    .first(c)
                    .await
                    .optional()
            })?
        } else {
            run_query!(self, |c| {
                diesel::update(device_codes::table.find(id))
                    .set(changes)
                    .returning(DeviceCodeRow::as_returning())
                    .get_result(c)
                    .await
                    .optional()
            })?
        };

        row.map(DeviceCode::from)
            .ok_or_else(|| AuthError::not_found("Device code not found"))
    }

    async fn update_device_code_if_status(
        &self,
        id: &str,
        current_status: &str,
        update: UpdateDeviceCode,
    ) -> AuthResult<bool> {
        let changes = device_code_changes(update);
        let matched = if changes.is_empty() {
            run_query!(self, |c| {
                device_codes::table
                    .find(id)
                    .filter(device_codes::status.eq(current_status))
                    .count()
                    .get_result::<i64>(c)
                    .await
                    .map(|count| count == 1)
            })?
        } else {
            run_query!(self, |c| {
                diesel::update(
                    device_codes::table
                        .find(id)
                        .filter(device_codes::status.eq(current_status)),
                )
                .set(changes)
                .execute(c)
                .await
                .map(|rows| rows == 1)
            })?
        };
        Ok(matched)
    }

    async fn claim_device_code(&self, id: &str, user_id: &str) -> AuthResult<bool> {
        run_query!(self, |c| {
            diesel::update(
                device_codes::table
                    .find(id)
                    .filter(device_codes::status.eq("pending"))
                    .filter(device_codes::user_id.is_null()),
            )
            .set(device_codes::user_id.eq(user_id))
            .execute(c)
            .await
        })
        .map(|rows| rows == 1)
    }

    async fn delete_device_code(&self, id: &str) -> AuthResult<()> {
        let _ = run_query!(self, |c| {
            diesel::delete(device_codes::table.find(id))
                .execute(c)
                .await
        })?;
        Ok(())
    }

    async fn delete_device_code_if_status(&self, id: &str, status: &str) -> AuthResult<bool> {
        run_query!(self, |c| {
            diesel::delete(
                device_codes::table
                    .find(id)
                    .filter(device_codes::status.eq(status)),
            )
            .execute(c)
            .await
        })
        .map(|rows| rows == 1)
    }
}
