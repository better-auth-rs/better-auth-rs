use super::hooks::CommittedWrite;
use super::rows::RowRef;
use super::*;
use crate::store::database_hooks::{DatabaseHookControl, DatabaseHookUpdate};
use crate::store::schema::resolve_field_name;

impl EphemeralStore {
    async fn user_ref_by_email(&self, email: &str) -> AuthResult<Option<RowRef<UserView>>> {
        self.user_ref(|user| user.email.as_deref() == Some(&email.to_lowercase()))
            .await
    }

    pub(super) async fn user_ref(
        &self,
        predicate: impl Fn(&UserView) -> bool + Send,
    ) -> AuthResult<Option<RowRef<UserView>>> {
        self.raw("user", "findOne", move |state| {
            state.users.first_ref(predicate)
        })
        .await
    }

    pub(super) async fn user_ref_by_id_value(
        &self,
        id: &serde_json::Value,
    ) -> AuthResult<Option<RowRef<UserView>>> {
        let id = self.memory_user_id_query(id)?;
        self.user_ref(|user| serde_json::json!(user.id) == id).await
    }

    async fn output_optional_user_ref(
        &self,
        user: Option<RowRef<UserView>>,
    ) -> AuthResult<Option<UserView>> {
        Ok(self
            .output_user_refs(user.into_iter().collect())
            .await?
            .into_iter()
            .next())
    }

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

    pub(super) async fn output_user(&self, user: UserView) -> AuthResult<UserView> {
        // Projection preserves the one input row.
        Ok(self.output_users(vec![user]).await?.remove(0))
    }

    pub(super) async fn output_users(&self, mut users: Vec<UserView>) -> AuthResult<Vec<UserView>> {
        let storage = users
            .iter_mut()
            .map(|user| {
                let mut input = std::mem::take(&mut user.additional_fields);
                for (name, value) in [("name", &user.name), ("image", &user.image)] {
                    if let Some(config) = self.config.user.fields().get(name)
                        && let Some(raw) = value.json()?
                    {
                        let _ = input.insert(
                            resolve_field_name(config.field_name.as_deref(), name).into(),
                            raw,
                        );
                    }
                }
                Ok(input)
            })
            .collect::<AuthResult<Vec<_>>>()?;
        let fields = self.config.user.output_memory_fields_many(&storage).await?;
        for (user, fields) in users.iter_mut().zip(fields) {
            self.assign_user_output(user, fields);
        }
        Ok(users)
    }

    pub(super) fn assign_user_output(&self, user: &mut UserView, mut fields: Map<String, Value>) {
        if self.config.user.fields().contains_key("name") {
            user.name = crate::SchemaValue::from_json(fields.remove("name"));
        }
        if self.config.user.fields().contains_key("image") {
            user.image = crate::SchemaValue::from_json(fields.remove("image"));
        }
        user.additional_fields = fields;
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
        let fields = update.take_user_field_input(&self.config.user)?;
        update.additional_fields = self
            .config
            .user
            .storage_fields_with_binding(fields, false, |_, field, value| {
                self.memory_plugin_field_input(field, value)
            })
            .await?;
        for (name, target) in [("name", &mut update.name), ("image", &mut update.image)] {
            if let Some(field) = self.config.user.fields().get(name) {
                *target = crate::SchemaValue::from_json(
                    update
                        .additional_fields
                        .remove(resolve_field_name(field.field_name.as_deref(), name)),
                );
            }
        }
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
                    if !update.name.is_undefined() {
                        if let Some(fields) = &mut user.visible_fields {
                            let _ = fields.insert("name".into());
                        }
                        user.name = update.name;
                    }
                    if !update.image.is_undefined() {
                        if let Some(fields) = &mut user.visible_fields {
                            let _ = fields.insert("image".into());
                        }
                        user.image = update.image;
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
                        user.two_factor_enabled = Some(two_factor_enabled);
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
        futures_util::future::OptionFuture::from(user.map(|user| self.output_user(user)))
            .await
            .transpose()
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
        let fields = create_user.take_user_field_input(&self.config.user)?;
        let mut fields = self
            .config
            .user
            .storage_fields_with_binding(fields, true, |_, field, value| {
                self.memory_plugin_field_input(field, value)
            })
            .await?;
        for (name, target) in [
            ("name", &mut create_user.name),
            ("image", &mut create_user.image),
        ] {
            if let Some(field) = self.config.user.fields().get(name) {
                *target = crate::SchemaValue::from_json(
                    fields.remove(resolve_field_name(field.field_name.as_deref(), name)),
                );
            }
        }
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
                    ("name", !create_user.name.is_undefined()),
                    ("email", create_user.email.is_some()),
                    ("image", !create_user.image.is_undefined()),
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
            image: create_user.image,
            created_at: create_user.created_at.unwrap_or(now),
            updated_at: create_user.updated_at.unwrap_or(now),
            is_anonymous: create_user.is_anonymous,
            phone_number: create_user.phone_number,
            phone_number_verified: create_user.phone_number_verified,
            username,
            display_username,
            two_factor_enabled: Some(false),
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
        let user = self.output_user(user).await?;
        self.after(CommittedWrite::UserCreated(user.clone()))
            .await?;
        Ok(Some(user))
    }

    async fn get_user_by_id_field(
        &self,
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<Option<UserView>> {
        self.output_optional_user_ref(self.user_ref(|user| user.id == *id).await?)
            .await
    }
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<UserView>> {
        self.output_optional_user_ref(self.user_ref(|user| user.id == id).await?)
            .await
    }
    async fn get_user_by_id_value(&self, id: &serde_json::Value) -> AuthResult<Option<UserView>> {
        self.output_optional_user_ref(self.user_ref_by_id_value(id).await?)
            .await
    }

    async fn list_users_by_ids(&self, ids: &[String], limit: f64) -> AuthResult<Vec<UserView>> {
        let users: Vec<_> = self
            .raw("user", "findMany", |state| {
                Ok(crate::query::paginate_memory(
                    state.users.select_refs(|user| {
                        ids.iter().any(|id| user.id.as_str() == Some(id.as_str()))
                    })?,
                    Some(limit),
                    None,
                ))
            })
            .await?;
        self.output_user_refs(users).await
    }

    async fn get_user_with_accounts(
        &self,
        email: &str,
    ) -> AuthResult<Option<crate::store::UserAccounts>> {
        crate::store::UserAccounts::validate_schema(&self.config, &self.model_fields, |_, _| {
            false
        })?;
        if self.config.advanced.database.joins == Some(true) {
            return self.joined_user_accounts(email).await;
        }
        let Some(record) = self.user_ref_by_email(email).await? else {
            return Ok(None);
        };
        let stored_user_id = record.read(|user| Ok(user.id.clone()))?;
        let user = self.output_user_refs(vec![record]).await?.remove(0);
        let mut accounts = Vec::new();
        if let Some(id) = stored_user_id.as_str() {
            for record in self.user_account_refs(id).await? {
                accounts.push(self.output_account_ref(&record).await?);
            }
        }
        crate::store::UserAccounts::new(user, accounts, &stored_user_id).map(Some)
    }

    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<UserView>> {
        let user = self.user_ref_by_email(email).await?;
        self.output_optional_user_ref(user).await
    }

    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<UserView>> {
        let user = self
            .user_ref(|user| user.username.as_deref() == Some(username))
            .await?;
        self.output_optional_user_ref(user).await
    }

    async fn get_user_by_phone_number(&self, phone_number: &str) -> AuthResult<Option<UserView>> {
        let user = self
            .user_ref(|user| user.phone_number.as_deref() == Some(phone_number))
            .await?;
        self.output_optional_user_ref(user).await
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
        let Some(user) = (match user {
            Some(user) => self.output_user(user).await.ok(),
            None => None,
        }) else {
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
        let query = crate::user_query::PreparedUserQuery::new(&params, &self.config.user)?;
        let users: Vec<_> = self
            .raw("user", "findMany", |state| {
                state
                    .users
                    .select_refs(|_| true)?
                    .into_iter()
                    .map(|source| {
                        let snapshot = source.read(|user| Ok(user.clone()))?;
                        Ok((snapshot, source))
                    })
                    .collect::<AuthResult<Vec<_>>>()
            })
            .await?;
        let (users, _) = query.select(users, |(snapshot, _)| {
            (snapshot, &snapshot.additional_fields)
        })?;
        let users = self
            .output_user_refs(users.into_iter().map(|(_, source)| source).collect())
            .await?;
        let total = self
            .raw("user", "count", |state| {
                Ok(query.count(state.users.snapshot()?.iter(), |snapshot| {
                    (snapshot, &snapshot.additional_fields)
                }))
            })
            .await?;
        Ok((users, total))
    }
}
