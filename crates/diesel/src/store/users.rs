use async_trait::async_trait;
use better_auth_core::store::UserStore;
use better_auth_core::types::{CreateUser, ListUsersParams, UpdateUser};
use chrono::Utc;
use diesel::prelude::*;
use diesel_async::{AsyncConnection, RunQueryDsl};

use crate::error::{AuthError, AuthResult};
use crate::hooks::HookConnection;
use crate::models::{User, UserChanges};
use crate::schema::{api_keys, users};
use crate::sql_types::{JsonDocumentValue, NullableUtcTimestampValue, UtcTimestampValue};

use super::{
    DieselAuthSchema, DieselStore, cancelled_by_hook, new_id, normalize_email,
    normalize_optional_email,
};

impl DieselStore {
    pub(crate) async fn insert_user<'a>(
        &'a self,
        connection: &'a HookConnection<'a>,
        mut create_user: CreateUser,
    ) -> AuthResult<User> {
        create_user.email = normalize_optional_email(create_user.email);
        let hook_context = self.hook_context(connection);
        for hook in self.hooks() {
            if hook
                .before_create_user(&mut create_user, &hook_context)
                .await?
                .is_cancelled()
            {
                return Err(cancelled_by_hook("user creation"));
            }
        }

        let now = Utc::now();
        let row = User {
            id: create_user.id.unwrap_or_else(new_id),
            name: create_user.name,
            email: create_user.email,
            email_verified: create_user.email_verified.unwrap_or(false),
            image: create_user.image,
            username: create_user.username.map(|username| username.to_lowercase()),
            display_username: create_user.display_username,
            two_factor_enabled: false,
            role: create_user.role,
            banned: false,
            ban_reason: None,
            ban_expires: None,
            metadata: create_user
                .metadata
                .unwrap_or_else(|| serde_json::json!({})),
            created_at: now,
            updated_at: now,
        };

        let user = run_query!(lock connection, |c| {
            diesel::insert_into(users::table)
                .values(row)
                .returning(User::as_returning())
                .get_result(c)
                .await
        })?;

        for hook in self.hooks() {
            hook.after_create_user(&user, &hook_context).await?;
        }
        Ok(user)
    }
}

/// Translate an `UpdateUser` into column changes.
///
/// Unbanning clears the ban reason and expiry; a ban reason or expiry sent
/// with `banned: false` is ignored.
fn user_changes(update: UpdateUser, now: chrono::DateTime<Utc>) -> UserChanges {
    let mut changes = UserChanges {
        email: update.email,
        name: update.name,
        image: update.image,
        email_verified: update.email_verified,
        username: update.username,
        display_username: update.display_username,
        role: update.role,
        two_factor_enabled: update.two_factor_enabled,
        metadata: update.metadata.map(JsonDocumentValue),
        updated_at: Some(UtcTimestampValue(now)),
        ..UserChanges::default()
    };

    if let Some(banned) = update.banned {
        changes.banned = Some(banned);
        if !banned {
            changes.ban_reason = Some(None);
            changes.ban_expires = Some(NullableUtcTimestampValue(None));
        }
    }
    if update.banned != Some(false) {
        if let Some(ban_reason) = update.ban_reason {
            changes.ban_reason = Some(Some(ban_reason));
        }
        if let Some(ban_expires) = update.ban_expires {
            changes.ban_expires = Some(NullableUtcTimestampValue(Some(ban_expires)));
        }
    }
    changes
}

#[async_trait]
impl UserStore<DieselAuthSchema> for DieselStore {
    async fn create_user(&self, create_user: CreateUser) -> AuthResult<User> {
        self.insert_user(&HookConnection::pooled(&self.pool), create_user)
            .await
    }

    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<User>> {
        run_query!(self, |c| {
            users::table
                .find(id)
                .select(User::as_select())
                .first(c)
                .await
                .optional()
        })
    }

    async fn list_users_by_ids(&self, ids: &[String]) -> AuthResult<Vec<User>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }

        run_query!(self, |c| {
            users::table
                .filter(users::id.eq_any(ids))
                .select(User::as_select())
                .load(c)
                .await
        })
    }

    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<User>> {
        let email = normalize_email(email);
        run_query!(self, |c| {
            users::table
                .filter(users::email.eq(&email))
                .select(User::as_select())
                .first(c)
                .await
                .optional()
        })
    }

    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<User>> {
        let username = username.to_lowercase();
        run_query!(self, |c| {
            users::table
                .filter(users::username.eq(&username))
                .select(User::as_select())
                .first(c)
                .await
                .optional()
        })
    }

    async fn update_user(&self, id: &str, mut update: UpdateUser) -> AuthResult<User> {
        update.email = normalize_optional_email(update.email);
        let connection = HookConnection::pooled(&self.pool);
        let hook_context = self.hook_context(&connection);
        for hook in self.hooks() {
            if hook
                .before_update_user(id, &mut update, &hook_context)
                .await?
                .is_cancelled()
            {
                return Err(cancelled_by_hook("user update"));
            }
        }
        if let Some(username) = update.username.as_mut() {
            *username = username.to_lowercase();
        }

        let changes = user_changes(update, Utc::now());
        let user = run_query!(lock connection, |c| {
            diesel::update(users::table.find(id))
                .set(changes)
                .returning(User::as_returning())
                .get_result(c)
                .await
                .optional()
        })?
        .ok_or(AuthError::UserNotFound)?;

        for hook in self.hooks() {
            hook.after_update_user(&user, &hook_context).await?;
        }
        Ok(user)
    }

    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        let connection = HookConnection::pooled(&self.pool);
        let Some(user) = run_query!(lock connection, |c| {
            users::table
                .find(id)
                .select(User::as_select())
                .first(c)
                .await
                .optional()
        })?
        else {
            return Err(AuthError::UserNotFound);
        };
        let hook_context = self.hook_context(&connection);
        for hook in self.hooks() {
            if hook
                .before_delete_user(&user, &hook_context)
                .await?
                .is_cancelled()
            {
                return Err(cancelled_by_hook("user deletion"));
            }
        }

        // One transaction, so that a user who cannot be deleted keeps their keys.
        let _ = run_query!(lock connection, |c| {
            c.transaction(async |c| {
                // API keys reference their owner polymorphically, so they carry
                // no foreign key to cascade from. Without this, a deleted user's
                // keys would outlive them and start working again if the id were
                // reused.
                let _ = diesel::delete(api_keys::table.filter(api_keys::reference_id.eq(id)))
                    .execute(c)
                    .await?;
                diesel::delete(users::table.find(id)).execute(c).await
            })
            .await
        })?;

        for hook in self.hooks() {
            hook.after_delete_user(&user, &hook_context).await?;
        }
        Ok(())
    }

    async fn list_users(&self, params: ListUsersParams) -> AuthResult<(Vec<User>, usize)> {
        let users = run_query!(self, |c| {
            users::table.select(User::as_select()).load(c).await
        })?;

        Ok(better_auth_core::user_query::apply_list_users(
            users, &params,
        ))
    }
}
