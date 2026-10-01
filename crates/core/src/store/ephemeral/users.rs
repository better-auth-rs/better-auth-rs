use super::hooks::CommittedWrite;
use super::*;
use crate::store::database_hooks::{DatabaseHookControl, DatabaseHookUpdate};

impl EphemeralStore {
    async fn finish_user_update(
        &self,
        id: &str,
        update: UpdateUser,
    ) -> AuthResult<Option<UserView>> {
        let user = self.update_user_record_optional(id, update).await?;
        self.after(CommittedWrite::UserUpdated(user.clone()))
            .await?;
        Ok(user)
    }

    fn output_user(&self, mut user: UserView) -> AuthResult<UserView> {
        user.additional_fields = self.config.user.output_fields(&user.additional_fields)?;
        Ok(user)
    }
    pub(super) async fn prepare_user_update(&self, update: UpdateUser) -> AuthResult<UpdateUser> {
        self.prepare_user_update_optional(update)
            .await?
            .ok_or_else(|| AuthError::forbidden("user update cancelled by database hook"))
    }
    async fn prepare_user_update_optional(
        &self,
        mut update: UpdateUser,
    ) -> AuthResult<Option<UpdateUser>> {
        update.prepare_user_fields(&self.config.user)?;
        let original = update.clone();
        let transaction = EphemeralTransaction {
            store: self.clone(),
        };
        let context = self.hook_context(&transaction);
        for hook in &self.hooks {
            match crate::observability::database::with_database_hook(
                context.config,
                hook.hook_metadata(),
                crate::observability::database::DatabaseHook::BeforeUpdateUser,
                hook.before_update_user(&original, &context),
            )
            .await?
            {
                DatabaseHookUpdate::Continue => {}
                DatabaseHookUpdate::Cancel => return Ok(None),
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
        Ok(Some(update))
    }

    pub(super) async fn update_user_record(
        &self,
        id: &str,
        update: UpdateUser,
    ) -> AuthResult<UserView> {
        self.update_user_record_optional(id, update)
            .await?
            .ok_or(AuthError::UserNotFound)
    }

    async fn update_user_record_optional(
        &self,
        id: &str,
        mut update: UpdateUser,
    ) -> AuthResult<Option<UserView>> {
        let user = self
            .raw("user", "update", |state| {
                Ok({
                    let Some(mut user) = state.users.get_mut(id)? else {
                        return Ok(None);
                    };
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
                        user.image = image;
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
                        if let Some(fields) = &mut user.visible_fields {
                            let _ = fields.insert("banReason".into());
                        }
                        user.ban_reason = ban_reason;
                    }
                    if let Some(ban_expires) = update.ban_expires {
                        if let Some(fields) = &mut user.visible_fields {
                            let _ = fields.insert("banExpires".into());
                        }
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
                    Some(user.clone())
                })
            })
            .await?;
        user.map(|user| self.output_user(user)).transpose()
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
    async fn create_user(&self, input: CreateUser) -> AuthResult<UserView> {
        self.create_user_optional(input)
            .await?
            .ok_or_else(|| AuthError::forbidden("user creation cancelled by database hook"))
    }
    async fn create_user_optional(
        &self,
        mut create_user: CreateUser,
    ) -> AuthResult<Option<UserView>> {
        create_user.prepare_user_fields(&self.config.user)?;
        create_user.email = create_user
            .email
            .map(|value| crate::utils::email::normalize_user_email(&value));
        let transaction = EphemeralTransaction {
            store: self.clone(),
        };
        let context = self.hook_context(&transaction);
        for hook in &self.hooks {
            if crate::observability::database::with_database_hook(
                context.config,
                hook.hook_metadata(),
                crate::observability::database::DatabaseHook::BeforeCreateUser,
                hook.before_create_user(&mut create_user, &context),
            )
            .await?
                == DatabaseHookControl::Cancel
            {
                return Ok(None);
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
        let id = self
            .generated_id("user", create_user.id, self.lock()?.users.len())?
            .map(crate::SchemaValue::Typed)
            .unwrap_or_default();
        let user = UserView {
            additional_fields: fields,
            visible_fields: Some(
                [
                    ("name", create_user.name.is_some()),
                    ("email", create_user.email.is_some()),
                    ("image", create_user.image.is_some()),
                    ("banReason", create_user.ban_reason.is_some()),
                    ("banExpires", create_user.ban_expires.is_some()),
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
            image: create_user.image.flatten(),
            created_at: create_user.created_at.unwrap_or(now),
            updated_at: create_user.updated_at.unwrap_or(now),
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
        crate::observability::database::with_database_operation(
            &self.config,
            "user",
            "create",
            async {
                self.lock()?.users.push(user.clone());
                Ok(())
            },
        )
        .await?;
        let user = self.output_user(user)?;
        self.after(CommittedWrite::UserCreated(user.clone()))
            .await?;
        Ok(Some(user))
    }

    async fn get_user_by_id_field(
        &self,
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<Option<UserView>> {
        let user = self
            .raw("user", "findOne", |state| state.users.get(id))
            .await?;
        user.map(|user| self.output_user(user)).transpose()
    }
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<UserView>> {
        let user = self
            .raw("user", "findOne", |state| state.users.get(id))
            .await?;
        user.map(|user| self.output_user(user)).transpose()
    }
    async fn get_user_by_id_value(&self, id: &serde_json::Value) -> AuthResult<Option<UserView>> {
        let user = self
            .raw("user", "findOne", |state| {
                Ok(state
                    .users
                    .snapshot()?
                    .iter()
                    .find(|user| serde_json::json!(user.id) == *id)
                    .cloned())
            })
            .await?;
        user.map(|user| self.output_user(user)).transpose()
    }

    async fn list_users_by_ids(&self, ids: &[String], limit: f64) -> AuthResult<Vec<UserView>> {
        let users: Vec<_> = self
            .raw("user", "findMany", |state| {
                Ok(crate::query::paginate_memory(
                    state
                        .users
                        .snapshot()?
                        .iter()
                        .filter(|user| ids.iter().any(|id| user.id.as_str() == Some(id.as_str())))
                        .cloned()
                        .collect(),
                    Some(limit),
                    None,
                ))
            })
            .await?;
        users
            .into_iter()
            .map(|user| self.output_user(user))
            .collect()
    }

    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<UserView>> {
        let user = self
            .raw("user", "findOne", |state| {
                Ok(state
                    .users
                    .snapshot()?
                    .iter()
                    .find(|user| user.email.as_deref() == Some(&email.to_lowercase()))
                    .cloned())
            })
            .await?;
        user.map(|user| self.output_user(user)).transpose()
    }

    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<UserView>> {
        let user = self
            .raw("user", "findOne", |state| {
                Ok(state
                    .users
                    .snapshot()?
                    .iter()
                    .find(|user| user.username.as_deref() == Some(username))
                    .cloned())
            })
            .await?;
        user.map(|user| self.output_user(user)).transpose()
    }

    async fn get_user_by_phone_number(&self, phone_number: &str) -> AuthResult<Option<UserView>> {
        let user = self
            .raw("user", "findOne", |state| {
                Ok(state
                    .users
                    .snapshot()?
                    .iter()
                    .find(|user| user.phone_number.as_deref() == Some(phone_number))
                    .cloned())
            })
            .await?;
        user.map(|user| self.output_user(user)).transpose()
    }

    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<UserView> {
        let update = self.prepare_user_update(update).await?;
        self.finish_user_update(id, update)
            .await?
            .ok_or(AuthError::UserNotFound)
    }
    async fn update_user_optional(
        &self,
        id: &str,
        update: UpdateUser,
    ) -> AuthResult<Option<UserView>> {
        let Some(update) = self.prepare_user_update_optional(update).await? else {
            return Ok(None);
        };
        self.finish_user_update(id, update).await
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
        let user = self
            .raw("user", "findOne", |state| state.users.get(id))
            .await?;
        // Upstream deleteWithHooks treats snapshot projection failures as a missing row.
        let Some(user) = user.and_then(|user| self.output_user(user).ok()) else {
            return Ok(None);
        };
        let transaction = EphemeralTransaction {
            store: self.clone(),
        };
        let context = self.hook_context(&transaction);
        for hook in &self.hooks {
            if crate::observability::database::with_database_hook(
                context.config,
                hook.hook_metadata(),
                crate::observability::database::DatabaseHook::BeforeDeleteUser,
                hook.before_delete_user(&user, &context),
            )
            .await?
                == DatabaseHookControl::Cancel
            {
                return Ok(None);
            }
        }
        self.raw("user", "delete", |state| {
            let _ = state.users.remove(id)?;
            Ok(())
        })
        .await?;
        self.after(CommittedWrite::UserDeleted(user.clone()))
            .await?;
        Ok(Some(user))
    }

    async fn list_users(&self, mut params: ListUsersParams) -> AuthResult<(Vec<UserView>, usize)> {
        let _ = params
            .limit
            .get_or_insert(self.config.advanced.database.find_many_limit());
        let users: Vec<_> = self
            .raw("user", "findMany", |state| state.users.snapshot())
            .await?;
        let (users, _) = crate::user_query::apply_list_users(users, &params);
        let users = users
            .into_iter()
            .map(|user| self.output_user(user))
            .collect::<AuthResult<Vec<_>>>()?;
        let total = self
            .raw("user", "count", |state| {
                Ok(crate::user_query::count_users(
                    state.users.snapshot()?.iter(),
                    &params,
                ))
            })
            .await?;
        Ok((users, total))
    }
}
