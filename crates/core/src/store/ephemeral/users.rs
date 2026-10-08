use super::hooks::CommittedWrite;
use super::rows::RowRef;
use super::*;
use crate::id::AdapterIdInput;
use crate::store::database_hooks::{DatabaseHookControl, DatabaseHookUpdate};
use crate::store::schema::EntityRole;
use crate::store::schema::resolve_field_name;

impl EphemeralStore {
    pub(super) async fn user_ref_by_email(
        &self,
        email: &str,
    ) -> AuthResult<Option<RowRef<UserView>>> {
        self.user_ref(|user| {
            user.email
                .field_value()
                .strict_equals(&Value::from(email.to_lowercase()))
        })
        .await
    }

    pub(super) async fn user_ref(
        &self,
        predicate: impl Fn(&UserView) -> bool + Send,
    ) -> AuthResult<Option<RowRef<UserView>>> {
        self.model_fields.begin_id_query(EntityRole::User)?;
        self.raw("user", "findOne", move |state| {
            state.users.first_ref(predicate)
        })
        .await
    }

    pub(super) async fn user_ref_by_id_value(
        &self,
        id: &Value,
    ) -> AuthResult<Option<RowRef<UserView>>> {
        let id = self.memory_primary_id_query(id)?;
        self.user_ref(|user| user.id.field_value().strict_equals(&id))
            .await
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
        id: &Value,
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
        if !users.is_empty() {
            self.model_fields.begin_id_output(EntityRole::User)?;
        }
        let storage = users
            .iter_mut()
            .map(|user| {
                let mut input = std::mem::take(&mut user.additional_fields);
                for (name, config) in self.config.user.fields() {
                    if UserView::NATIVE_FIELDS.contains(&name.as_str())
                        && let Some(value) = user.native_field_value(name)
                    {
                        let _ = input.insert(
                            resolve_field_name(config.field_name.as_deref(), name).into(),
                            value,
                        );
                    }
                }
                let _ = input.insert("id".into(), user.id.field_value());
                Ok(input)
            })
            .collect::<AuthResult<Vec<_>>>()?;
        let fields = self
            .config
            .user
            .user_adapter_fields()
            .output_memory_fields_many(&storage)
            .await?;
        for (user, fields) in users.iter_mut().zip(fields) {
            self.assign_user_output(user, fields)?;
        }
        Ok(users)
    }

    pub(super) fn project_id(
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<crate::SchemaValue<String>> {
        let value = id.field_value();
        if value.is_null() || value.is_undefined() {
            Ok(crate::SchemaValue::from_field(value))
        } else {
            Ok(crate::SchemaValue::from_field(
                value.display_utf16()?.into(),
            ))
        }
    }

    pub(super) fn assign_user_output(
        &self,
        user: &mut UserView,
        mut fields: FieldMap,
    ) -> AuthResult<()> {
        user.id = Self::project_id(&user.id)?;
        let _ = fields.remove("id");
        for name in self.config.user.fields().keys() {
            if name != "id" && UserView::NATIVE_FIELDS.contains(&name.as_str()) {
                user.set_field(name, fields.remove(name).unwrap_or_default());
            }
        }
        user.additional_fields.clear();
        for (name, value) in fields {
            user.set_field(&name, value);
        }
        Ok(())
    }

    fn assign_user_storage_fields(&self, user: &mut UserView) {
        for (name, field) in self.config.user.fields() {
            if name != "id"
                && UserView::NATIVE_FIELDS.contains(&name.as_str())
                && let Some(value) = user
                    .additional_fields
                    .remove(resolve_field_name(field.field_name.as_deref(), name))
            {
                user.set_field(name, value);
            }
        }
    }

    pub(super) async fn prepare_user_update(&self, update: UpdateUser) -> AuthResult<UpdateUser> {
        let update = self
            .prepare_user_update_optional(update)
            .await?
            .ok_or_else(|| AuthError::forbidden("user update cancelled by database hook"))?;
        self.prepare_user_update_fields(update).await
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
        Ok(Some(update))
    }

    async fn prepare_user_update_fields(&self, mut update: UpdateUser) -> AuthResult<UpdateUser> {
        let fields = update.take_user_field_input(&self.config.user)?;
        self.model_fields
            .begin_id_input(EntityRole::User, AdapterIdInput::default())?;
        update.additional_fields = self
            .config
            .user
            .user_adapter_fields()
            .storage_fields_with_binding(fields, false, |_, field, value| {
                self.memory_plugin_field_input(field, value)
            })
            .await?;
        for (name, target) in [("name", &mut update.name), ("image", &mut update.image)] {
            if let Some(field) = self.config.user.fields().get(name) {
                *target = crate::SchemaValue::from_field(
                    update
                        .additional_fields
                        .remove(resolve_field_name(field.field_name.as_deref(), name))
                        .unwrap_or_default(),
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
        Ok(update)
    }

    async fn update_user_outcome(
        &self,
        id: &Value,
        update: UpdateUser,
    ) -> AuthResult<std::ops::ControlFlow<(), Option<UserView>>> {
        let Some(update) = self.prepare_user_update_optional(update).await? else {
            return Ok(std::ops::ControlFlow::Break(()));
        };
        self.model_fields.canonicalize_id(EntityRole::User)?;
        let id = self.memory_primary_id_query(id)?;
        let update = self.prepare_user_update_fields(update).await?;
        self.finish_user_update(&id, update)
            .await
            .map(std::ops::ControlFlow::Continue)
    }

    pub(super) async fn update_user_record(
        &self,
        id: &str,
        update: UpdateUser,
    ) -> AuthResult<UserView> {
        self.model_fields.canonicalize_id(EntityRole::User)?;
        let id = self.memory_primary_id_query(&Value::from(id))?;
        self.update_user_record_optional(&id, update)
            .await?
            .ok_or(AuthError::UserNotFound)
    }

    async fn update_user_record_optional(
        &self,
        id: &Value,
        update: UpdateUser,
    ) -> AuthResult<Option<UserView>> {
        let updated_at = Utc::now();
        let user = self
            .raw("user", "update", |state| {
                let selected = state.users.select_refs(|user| {
                    let value = user.id.field_value();
                    value.strict_equals(id) || (id.is_null() && value.is_undefined())
                })?;
                for row in &selected {
                    let mut update = update.clone();
                    row.write(|user| {
                        if update.phone_number == Some(None) {
                            update.phone_number_verified = Some(false);
                        }
                        if let Some(email) = update.email {
                            if let Some(fields) = &mut user.visible_fields {
                                let _ = fields.insert("email".into());
                            }
                            user.email = Some(email.to_lowercase()).into();
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
                            user.email_verified = email_verified.into();
                        }
                        if let Some(value) = update.is_anonymous {
                            user.is_anonymous = Some(value).into();
                        }
                        if let Some(value) = update.phone_number {
                            user.phone_number = value.into();
                        }
                        if let Some(value) = update.phone_number_verified {
                            user.phone_number_verified = Some(value).into();
                        }
                        if let Some(username) = update.username {
                            user.username = username.into();
                        }
                        if let Some(display_username) = update.display_username {
                            user.display_username = display_username.into();
                        }
                        if let Some(role) = update.role {
                            user.role = Some(role).into();
                        }
                        if let Some(banned) = update.banned {
                            user.banned = banned.into();
                        }
                        if let Some(ban_reason) = update.ban_reason {
                            if let Some(fields) = &mut user.visible_fields {
                                let _ = fields.insert("banReason".into());
                            }
                            user.ban_reason = ban_reason.into();
                        }
                        if let Some(ban_expires) = update.ban_expires {
                            if let Some(fields) = &mut user.visible_fields {
                                let _ = fields.insert("banExpires".into());
                            }
                            user.ban_expires = ban_expires.into();
                        }
                        if let Some(two_factor_enabled) = update.two_factor_enabled {
                            user.two_factor_enabled = Some(two_factor_enabled).into();
                        }
                        if let Some(metadata) = update.metadata {
                            user.metadata = metadata;
                        }
                        user.updated_at = updated_at.into();
                        user.additional_fields.extend(update.additional_fields);
                        self.assign_user_storage_fields(user);
                        Ok(())
                    })?;
                }
                selected
                    .first()
                    .map(|row| row.read(|user| Ok(user.clone())))
                    .transpose()
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
            .ok_or_else(|| AuthError::forbidden("user creation returned no record"))
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
        self.model_fields.begin_id_input(
            EntityRole::User,
            AdapterIdInput {
                force_allow_id: create_user.id.is_some(),
                supports_native_uuid: false,
            },
        )?;
        let mut fields = self
            .config
            .user
            .user_adapter_fields()
            .storage_fields_with_bound_id(
                fields,
                true,
                || {
                    let Some(policy) = self.model_fields.id_input_policy(EntityRole::User)? else {
                        return Ok(create_user.id.take().map(Value::from));
                    };
                    let row_count = self.lock()?.users.len();
                    let id = self.generated_id_with_policy(
                        "user",
                        create_user.id.take(),
                        row_count,
                        policy,
                    )?;
                    Ok(self
                        .next_serial_id(row_count)
                        .or_else(|| id.map(Value::from)))
                },
                |name, field, value| {
                    let value = self.memory_plugin_field_input(field, value)?;
                    if name == "id"
                        && let Some(id) = self.next_serial_id(self.lock()?.users.len())
                    {
                        return Ok(id);
                    }
                    Ok(value)
                },
            )
            .await?;
        let id = crate::SchemaValue::from_field(fields.get("id").cloned().unwrap_or_default());
        for (name, target) in [
            ("name", &mut create_user.name),
            ("image", &mut create_user.image),
        ] {
            if let Some(field) = self.config.user.fields().get(name) {
                *target = crate::SchemaValue::from_field(
                    fields
                        .remove(resolve_field_name(field.field_name.as_deref(), name))
                        .unwrap_or_default(),
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
        let now = crate::FieldDate::from(Utc::now());
        let _ = fields.remove("id");
        let mut user = UserView {
            field_order: self
                .config
                .user
                .user_field_schema()
                .adapter_fields(&[])
                .fields()
                .keys()
                .cloned()
                .collect(),
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
                        "id",
                        "emailVerified",
                        "createdAt",
                        "updatedAt",
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
            email: create_user.email.into(),
            email_verified: create_user.email_verified.unwrap_or(false).into(),
            image: create_user.image,
            created_at: create_user.created_at.unwrap_or_else(|| now.clone()).into(),
            updated_at: create_user.updated_at.unwrap_or(now).into(),
            is_anonymous: Some(create_user.is_anonymous.unwrap_or(false)).into(),
            phone_number: create_user.phone_number.into(),
            phone_number_verified: create_user.phone_number_verified.into(),
            username: username.into(),
            display_username: display_username.into(),
            two_factor_enabled: Some(false).into(),
            role: create_user.role.into(),
            banned: create_user.banned.unwrap_or(false).into(),
            ban_reason: create_user.ban_reason.into(),
            ban_expires: create_user.ban_expires.into(),
            metadata: create_user
                .metadata
                .unwrap_or_else(|| FieldMap::new().into()),
        };
        self.assign_user_storage_fields(&mut user);
        crate::observability::database::with_database_operation(
            &self.config,
            "user",
            "create",
            async {
                let mut state = self.lock()?;
                if let Some(id) = self.next_serial_id(state.users.len()) {
                    user.id = crate::SchemaValue::from_field(id);
                }
                state.users.push(user.clone());
                Ok(())
            },
        )
        .await?;
        let user = self.output_user(user).await?;
        self.after(CommittedWrite::UserCreated(Some(user.clone())))
            .await?;
        Ok(Some(user))
    }

    async fn get_user_by_id_field(
        &self,
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<Option<UserView>> {
        self.get_user_by_id_value(&id.field_value()).await
    }
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<UserView>> {
        self.get_user_by_id_value(&Value::from(id)).await
    }
    async fn get_user_by_id_value(&self, id: &Value) -> AuthResult<Option<UserView>> {
        self.output_optional_user_ref(self.user_ref_by_id_value(id).await?)
            .await
    }

    async fn list_users_by_ids(&self, ids: &[String], limit: f64) -> AuthResult<Vec<UserView>> {
        self.model_fields.begin_id_query(EntityRole::User)?;
        let ids = ids
            .iter()
            .map(|id| self.memory_primary_id_query(&Value::from(id.clone())))
            .collect::<AuthResult<Vec<_>>>()?;
        let users: Vec<_> = self
            .raw("user", "findMany", |state| {
                Ok(crate::query::paginate_memory(
                    state.users.select_refs(|user| {
                        ids.iter()
                            .any(|id| user.id.field_value().same_value_zero(id))
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
        let relation = crate::store::UserAccounts::resolve_schema(
            &self.config,
            &self.model_fields,
            |_, _| false,
        )?;
        self.user_accounts_relation(email, &relation).await
    }

    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<UserView>> {
        let user = self.user_ref_by_email(email).await?;
        self.output_optional_user_ref(user).await
    }

    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<UserView>> {
        let user = self
            .user_ref(|user| {
                user.username
                    .field_value()
                    .strict_equals(&Value::from(username))
            })
            .await?;
        self.output_optional_user_ref(user).await
    }

    async fn get_user_by_phone_number(&self, phone_number: &str) -> AuthResult<Option<UserView>> {
        let user = self
            .user_ref(|user| {
                user.phone_number
                    .field_value()
                    .strict_equals(&Value::from(phone_number))
            })
            .await?;
        self.output_optional_user_ref(user).await
    }

    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<UserView> {
        match self.update_user_outcome(&Value::from(id), update).await? {
            std::ops::ControlFlow::Break(()) => Err(AuthError::forbidden(
                "user update cancelled by database hook",
            )),
            std::ops::ControlFlow::Continue(user) => user.ok_or(AuthError::UserNotFound),
        }
    }
    async fn update_user_optional(
        &self,
        id: &str,
        update: UpdateUser,
    ) -> AuthResult<Option<UserView>> {
        self.update_user_by_id_value(&Value::from(id), update).await
    }
    async fn update_user_by_id_value(
        &self,
        id: &Value,
        update: UpdateUser,
    ) -> AuthResult<Option<UserView>> {
        Ok(self
            .update_user_outcome(id, update)
            .await?
            .continue_value()
            .flatten())
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
        self.model_fields.begin_id_query(EntityRole::User)?;
        let stored_id = crate::SchemaValue::<String>::from_field(
            self.memory_primary_id_query(&Value::from(id))?,
        );
        let user = self
            .raw("user", "findOne", |state| state.users.get(&stored_id))
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
        self.model_fields.begin_id_query(EntityRole::User)?;
        self.raw("user", "delete", |state| {
            let _ = state.users.remove(&stored_id)?;
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
        let query = crate::user_query::PreparedUserQuery::for_adapter(
            &params,
            &self.config.user,
            &self.model_fields,
        )?
        .bind_memory_filter(|name, value| {
            if matches!(name, "id" | "_id") {
                return self.memory_primary_id_query(&value);
            }
            self.memory_field_query(&self.config.user, name, value)
        })?;
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
        let (users, _) = query.select_memory(users, |(snapshot, _)| {
            (snapshot, &snapshot.additional_fields)
        })?;
        let users = self
            .output_user_refs(users.into_iter().map(|(_, source)| source).collect())
            .await?;
        query.begin_adapter_count(&self.model_fields)?;
        let total = self
            .raw("user", "count", |state| {
                query.count_memory(state.users.snapshot()?.iter(), |snapshot| {
                    (snapshot, &snapshot.additional_fields)
                })
            })
            .await?;
        Ok((users, total))
    }
}
