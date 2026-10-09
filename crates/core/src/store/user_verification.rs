use super::AuthStore;
use crate::{
    AuthError, AuthResult, AuthSchema, CreateVerification, FieldValue, SchemaValue, UpdateUser,
    UserView,
};
use chrono::{Duration, Utc};

#[cfg(test)]
mod tests;

/// Revoke unproven access in upstream order without adding an enclosing transaction.
#[doc(hidden)]
pub async fn revoke_unproven_account_access<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    user_id: &FieldValue,
) -> AuthResult<Option<UserView>> {
    let identifier = format!(
        "revoke-unproven-account-access:{}",
        SchemaValue::<String>::from_field(user_id.clone()).display_string()?,
    );
    let reserved = match store
        .reserve_verification_value(CreateVerification {
            identifier: identifier.clone().into(),
            value: SchemaValue::from_field(user_id.clone()),
            expires_at: (Utc::now() + Duration::seconds(5)).into(),
            ..Default::default()
        })
        .await
    {
        Err(AuthError::Config(message))
            if message.contains("requires database-backed verification storage") =>
        {
            true
        }
        result => result?,
    };
    if !reserved {
        let deadline = Utc::now() + Duration::seconds(2);
        while Utc::now() < deadline {
            let Some(lock) = store
                .get_verification_including_expired(&identifier)
                .await?
            else {
                break;
            };
            if lock.expires_at.is_before_or_equal(Utc::now())? {
                store.delete_verification_by_identifier(&identifier).await?;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        return find_user(store, user_id).await;
    }
    let result = async {
        let Some(user) = find_user(store, user_id).await? else {
            return Ok(None);
        };
        if user.email_verified.is_truthy()? {
            return Ok(Some(user));
        }
        for account in store.get_user_accounts_value(user_id).await? {
            store
                .delete_account_value(&account.id.field_value())
                .await?;
        }
        store.delete_user_sessions_by_user_value(user_id).await?;
        store
            .update_user_by_id_value(
                user_id,
                UpdateUser {
                    email_verified: Some(true),
                    ..Default::default()
                },
            )
            .await
    }
    .await;
    // Upstream preserves the operation result when releasing the cleanup lock fails.
    let _ = store.delete_verification_by_identifier(&identifier).await;
    result
}

async fn find_user<S: AuthSchema>(
    store: &dyn AuthStore<S>,
    user_id: &FieldValue,
) -> AuthResult<Option<UserView>> {
    if user_id.is_truthy() {
        store.get_user_by_id_value(user_id).await
    } else {
        Ok(None)
    }
}
