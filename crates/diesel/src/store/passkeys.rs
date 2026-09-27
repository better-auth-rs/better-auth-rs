use async_trait::async_trait;
use better_auth_core::store::PasskeyStore;
use better_auth_core::types::UpdatePasskeyAuthentication;
use better_auth_core::{CreatePasskey, Passkey};
use chrono::Utc;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;

use crate::error::{AuthError, AuthResult};
use crate::models::PasskeyRow;
use crate::schema::passkeys;
use crate::sql_types::UtcTimestampValue;

use super::{DieselStore, new_id};

fn counter_to_i64(counter: u64) -> AuthResult<i64> {
    i64::try_from(counter).map_err(|_| AuthError::bad_request("Passkey counter exceeds i64 range"))
}

#[async_trait]
impl PasskeyStore for DieselStore {
    async fn create_passkey(&self, input: CreatePasskey) -> AuthResult<Passkey> {
        let now = Utc::now();
        let row = PasskeyRow {
            id: new_id(),
            name: input.name,
            public_key: input.public_key,
            user_id: input.user_id,
            credential_id: input.credential_id,
            counter: counter_to_i64(input.counter)?,
            device_type: input.device_type,
            backed_up: input.backed_up,
            transports: input.transports,
            credential: input.credential,
            aaguid: input.aaguid,
            created_at: now,
            updated_at: now,
        };

        run_query!(self, |c| {
            diesel::insert_into(passkeys::table)
                .values(row)
                .returning(PasskeyRow::as_returning())
                .get_result(c)
                .await
        })
        .map(Passkey::from)
    }

    async fn get_passkey_by_id(&self, id: &str) -> AuthResult<Option<Passkey>> {
        run_query!(self, |c| {
            passkeys::table
                .find(id)
                .select(PasskeyRow::as_select())
                .first(c)
                .await
                .optional()
        })
        .map(|row| row.map(Passkey::from))
    }

    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> AuthResult<Option<Passkey>> {
        run_query!(self, |c| {
            passkeys::table
                .filter(passkeys::credential_id.eq(credential_id))
                .select(PasskeyRow::as_select())
                .first(c)
                .await
                .optional()
        })
        .map(|row| row.map(Passkey::from))
    }

    async fn list_passkeys_by_user(&self, user_id: &str) -> AuthResult<Vec<Passkey>> {
        run_query!(self, |c| {
            passkeys::table
                .filter(passkeys::user_id.eq(user_id))
                .order(passkeys::created_at.desc())
                .select(PasskeyRow::as_select())
                .load(c)
                .await
        })
        .map(|rows| rows.into_iter().map(Passkey::from).collect())
    }

    async fn update_passkey_authentication(
        &self,
        id: &str,
        update: UpdatePasskeyAuthentication,
    ) -> AuthResult<Passkey> {
        let counter = counter_to_i64(update.counter)?;
        run_query!(self, |c| {
            diesel::update(passkeys::table.find(id))
                .set((
                    passkeys::counter.eq(counter),
                    passkeys::backed_up.eq(update.backed_up),
                    passkeys::device_type.eq(&update.device_type),
                    passkeys::credential.eq(&update.credential),
                    passkeys::updated_at.eq(UtcTimestampValue(Utc::now())),
                ))
                .returning(PasskeyRow::as_returning())
                .get_result(c)
                .await
                .optional()
        })?
        .map(Passkey::from)
        .ok_or_else(|| AuthError::not_found("Passkey not found"))
    }

    async fn update_passkey_name(&self, id: &str, name: &str) -> AuthResult<Passkey> {
        run_query!(self, |c| {
            diesel::update(passkeys::table.find(id))
                .set((
                    passkeys::name.eq(name),
                    passkeys::updated_at.eq(UtcTimestampValue(Utc::now())),
                ))
                .returning(PasskeyRow::as_returning())
                .get_result(c)
                .await
                .optional()
        })?
        .map(Passkey::from)
        .ok_or_else(|| AuthError::not_found("Passkey not found"))
    }

    async fn delete_passkey(&self, id: &str) -> AuthResult<()> {
        let _ = run_query!(self, |c| {
            diesel::delete(passkeys::table.find(id)).execute(c).await
        })?;
        Ok(())
    }
}
