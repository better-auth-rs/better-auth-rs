use super::hooks::CommittedWrite;
use super::*;
use crate::store::database_hooks::{DatabaseHookControl, DatabaseHookUpdate};

impl EphemeralStore {
    fn output_user(&self, mut user: UserView) -> AuthResult<UserView> {
        user.additional_fields = self.config.user.output_fields(&user.additional_fields)?;
        Ok(user)
    }
    pub(super) async fn prepare_user_update(
        &self,
        mut update: UpdateUser,
    ) -> AuthResult<UpdateUser> {
        update.prepare_user_fields(&self.config.user)?;
        let original = update.clone();
        let transaction = EphemeralTransaction { store: self };
        let context = self.hook_context(&transaction);
        for hook in &self.hooks {
            match hook.before_update_user(&original, &context).await? {
                DatabaseHookUpdate::Continue => {}
                DatabaseHookUpdate::Cancel => {
                    return Err(AuthError::forbidden(
                        "user update cancelled by database hook",
                    ));
                }
                DatabaseHookUpdate::Patch(mut patch) => {
                    patch.prepare_user_fields(&self.config.user)?;
                    update.merge(patch);
                }
            }
        }
        let fields = update.take_user_field_input(&self.config.user);
        update.additional_fields = self.config.user.storage_fields(fields, false)?;
        update.username = self
            .config
            .user
            .stored_username_field(&update.additional_fields, "username")?
            .or(update.username);
        update.display_username = self
            .config
            .user
            .stored_username_field(&update.additional_fields, "displayUsername")?
            .or(update.display_username);
        Ok(update)
    }

    pub(super) fn update_user_record(
        &self,
        id: &str,
        mut update: UpdateUser,
    ) -> AuthResult<UserView> {
        let user = {
            let mut state = self.lock()?;
            let user = state.users.get_mut(id).ok_or(AuthError::UserNotFound)?;
            if update.phone_number == Some(None) {
                update.phone_number_verified = Some(false);
            }
            if let Some(email) = update.email {
                if let Some(fields) = &mut user.visible_fields {
                    let _ = fields.insert("email".into());
                }
                user.email = Some(email.to_lowercase());
            }
            if let Some(name) = update.name {
                if let Some(fields) = &mut user.visible_fields {
                    let _ = fields.insert("name".into());
                }
                user.name = Some(name);
            }
            if let Some(image) = update.image {
                if let Some(fields) = &mut user.visible_fields {
                    let _ = fields.insert("image".into());
                }
                user.image = Some(image);
            }
            if let Some(email_verified) = update.email_verified {
                user.email_verified = email_verified;
            }
            if let Some(value) = update.is_anonymous {
                user.is_anonymous = Some(value);
            }
            if let Some(value) = update.phone_number {
                user.phone_number = value;
            }
            if let Some(value) = update.phone_number_verified {
                user.phone_number_verified = Some(value);
            }
            if let Some(username) = update.username {
                user.username = username;
            }
            if let Some(display_username) = update.display_username {
                user.display_username = display_username;
            }
            if let Some(role) = update.role {
                user.role = Some(role);
            }
            if let Some(banned) = update.banned {
                user.banned = banned;
            }
            if let Some(ban_reason) = update.ban_reason {
                user.ban_reason = ban_reason;
            }
            if let Some(ban_expires) = update.ban_expires {
                user.ban_expires = ban_expires;
            }
            if let Some(two_factor_enabled) = update.two_factor_enabled {
                user.two_factor_enabled = two_factor_enabled;
            }
            if let Some(metadata) = update.metadata {
                user.metadata = metadata;
            }
            user.updated_at = Utc::now();
            user.additional_fields.extend(update.additional_fields);
            user.clone()
        };
        self.output_user(user)
    }
}

#[async_trait]
impl UserStore<StatelessSchema> for EphemeralStore {
    async fn verify_user_with_cleanup(
        &self,
        user_id: &str,
        cleanup: crate::store::VerificationCleanup,
        sessions: Option<&dyn crate::store::VerificationSessionCleanup>,
    ) -> AuthResult<Option<UserView>> {
        self.verify_unproven_user(
            user_id,
            matches!(
                cleanup,
                crate::store::VerificationCleanup::AccountsAndSessions
            ),
            sessions,
        )
        .await
    }

    async fn verify_user_and_revoke_unproven_access(
        &self,
        user_id: &str,
    ) -> AuthResult<Option<UserView>> {
        self.verify_unproven_user(user_id, true, None).await
    }
    async fn create_user(&self, mut create_user: CreateUser) -> AuthResult<UserView> {
        create_user.prepare_user_fields(&self.config.user)?;
        create_user.email = create_user
            .email
            .map(|value| crate::utils::email::normalize_user_email(&value));
        let transaction = EphemeralTransaction { store: self };
        let context = self.hook_context(&transaction);
        for hook in &self.hooks {
            if hook.before_create_user(&mut create_user, &context).await?
                == DatabaseHookControl::Cancel
            {
                return Err(AuthError::forbidden(
                    "user creation cancelled by database hook",
                ));
            }
            create_user.prepare_user_fields(&self.config.user)?;
        }
        let fields = create_user.take_user_field_input(&self.config.user);
        let fields = self.config.user.storage_fields(fields, true)?;
        let username = self
            .config
            .user
            .stored_username_field(&fields, "username")?
            .or(create_user.username.take())
            .flatten();
        let display_username = self
            .config
            .user
            .stored_username_field(&fields, "displayUsername")?
            .or(create_user.display_username.take())
            .flatten();
        let now = Utc::now();
        let id = create_user
            .id
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let user = UserView {
            additional_fields: fields,
            visible_fields: Some(
                [
                    ("name", create_user.name.is_some()),
                    ("email", create_user.email.is_some()),
                    ("image", create_user.image.is_some()),
                ]
                .into_iter()
                .filter(|(_, present)| *present)
                .map(|(name, _)| name.to_owned())
                .chain(
                    [
                        "isAnonymous",
                        "phoneNumber",
                        "phoneNumberVerified",
                        "username",
                        "displayUsername",
                        "twoFactorEnabled",
                        "role",
                        "banned",
                        "banReason",
                        "banExpires",
                    ]
                    .into_iter()
                    .map(str::to_owned),
                )
                .collect(),
            ),
            id: id.clone(),
            name: create_user.name,
            email: create_user.email,
            email_verified: create_user.email_verified.unwrap_or(false),
            image: create_user.image,
            created_at: now,
            updated_at: now,
            is_anonymous: create_user.is_anonymous,
            phone_number: create_user.phone_number,
            phone_number_verified: create_user.phone_number_verified,
            username,
            display_username,
            two_factor_enabled: false,
            role: create_user.role,
            banned: create_user.banned.unwrap_or(false),
            ban_reason: create_user.ban_reason,
            ban_expires: create_user.ban_expires,
            metadata: create_user
                .metadata
                .unwrap_or_else(|| serde_json::json!({})),
        };
        let _ = self.lock()?.users.insert(id, user.clone());
        let user = self.output_user(user)?;
        self.after(CommittedWrite::UserCreated(user.clone()))
            .await?;
        Ok(user)
    }

    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<UserView>> {
        self.lock()?
            .users
            .get(id)
            .cloned()
            .map(|user| self.output_user(user))
            .transpose()
    }
    async fn get_user_by_id_value(&self, id: &serde_json::Value) -> AuthResult<Option<UserView>> {
        self.lock()?
            .users
            .values()
            .find(|user| serde_json::json!(user.id) == *id)
            .cloned()
            .map(|user| self.output_user(user))
            .transpose()
    }

    async fn list_users_by_ids(&self, ids: &[String]) -> AuthResult<Vec<UserView>> {
        let state = self.lock()?;
        ids.iter()
            .filter_map(|id| state.users.get(id).cloned())
            .map(|user| self.output_user(user))
            .collect()
    }

    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<UserView>> {
        self.lock()?
            .users
            .values()
            .find(|user| user.email.as_deref() == Some(&email.to_lowercase()))
            .cloned()
            .map(|user| self.output_user(user))
            .transpose()
    }

    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<UserView>> {
        self.lock()?
            .users
            .values()
            .find(|user| user.username.as_deref() == Some(username))
            .cloned()
            .map(|user| self.output_user(user))
            .transpose()
    }

    async fn get_user_by_phone_number(&self, phone_number: &str) -> AuthResult<Option<UserView>> {
        self.lock()?
            .users
            .values()
            .find(|user| user.phone_number.as_deref() == Some(phone_number))
            .cloned()
            .map(|user| self.output_user(user))
            .transpose()
    }

    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<UserView> {
        let update = self.prepare_user_update(update).await?;
        let user = match self.update_user_record(id, update) {
            Err(AuthError::UserNotFound) => {
                self.after(CommittedWrite::UserUpdated(None)).await?;
                return Err(AuthError::UserNotFound);
            }
            result => result?,
        };
        self.after(CommittedWrite::UserUpdated(Some(user.clone())))
            .await?;
        Ok(user)
    }

    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        self.delete_user_optional(id, true).await.map(|_| ())
    }

    async fn delete_user_optional(
        &self,
        id: &str,
        delete_database_sessions: bool,
    ) -> AuthResult<Option<UserView>> {
        if delete_database_sessions {
            self.delete_user_sessions(id).await?;
        }
        self.delete_user_accounts_with_hooks(id).await?;
        let user = self.lock()?.users.get(id).cloned();
        // Upstream deleteWithHooks treats snapshot projection failures as a missing row.
        let Some(user) = user.and_then(|user| self.output_user(user).ok()) else {
            return Ok(None);
        };
        let transaction = EphemeralTransaction { store: self };
        let context = self.hook_context(&transaction);
        for hook in &self.hooks {
            if hook.before_delete_user(&user, &context).await? == DatabaseHookControl::Cancel {
                return Ok(None);
            }
        }
        let _ = self.lock()?.users.shift_remove(id);
        self.after(CommittedWrite::UserDeleted(user.clone()))
            .await?;
        Ok(Some(user))
    }

    async fn list_users(&self, _params: ListUsersParams) -> AuthResult<(Vec<UserView>, usize)> {
        let users: Vec<_> = self.lock()?.users.values().cloned().collect();
        let (users, total) = crate::user_query::apply_list_users(users, &_params);
        Ok((
            users
                .into_iter()
                .map(|user| self.output_user(user))
                .collect::<AuthResult<_>>()?,
            total,
        ))
    }
}
