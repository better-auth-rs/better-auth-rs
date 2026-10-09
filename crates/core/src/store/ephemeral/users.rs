use super::hooks::CommittedWrite;
use super::rows::RowRef;
use super::*;
use crate::id::AdapterIdInput;
use crate::store::database_hooks::{DatabaseHookControl, PreparedRecordWrite};
use crate::store::schema::EntityRole;
use crate::store::schema::resolve_field_name;

impl EphemeralStore {
    pub(super) async fn user_ref_by_email(
        &self,
        email: &str,
    ) -> AuthResult<Option<RowRef<UserView>>> {
        self.user_ref_by_field_value("email", &Value::from(email.to_lowercase()))
            .await
    }

    async fn user_ref_by_field_value(
        &self,
        name: &str,
        value: &Value,
    ) -> AuthResult<Option<RowRef<UserView>>> {
        self.model_fields.begin_id_query(EntityRole::User)?;
        let (physical, value) = self.user_field_selector(name, value)?;
        self.user_ref(|user| Self::user_matches_selector(user, &physical, &value))
            .await
    }

    fn user_field_selector(&self, name: &str, value: &Value) -> AuthResult<(String, Value)> {
        let schema = self.user_schema();
        let (logical, field) = schema
            .fields()
            .get_key_value(name)
            .or_else(|| {
                schema
                    .fields()
                    .iter()
                    .find(|(_, field)| field.field_name.as_deref() == Some(name))
            })
            .ok_or_else(|| AuthError::config(format!("User field {name} does not exist")))?;
        let value = if logical == "id" {
            self.memory_primary_id_query(value)?
        } else {
            crate::user_query::bind_filter(
                field,
                &self.memory_field_query(&schema, logical, value.clone())?,
            )?
        };
        let physical = resolve_field_name(field.field_name.as_deref(), logical);
        Ok((physical.to_owned(), value))
    }

    fn user_matches_selector(user: &UserView, field: &str, value: &Value) -> bool {
        let stored = FieldMap::from(user.clone())
            .get(field)
            .cloned()
            .unwrap_or_default();
        crate::query::field_matches_equality(&stored, value)
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
        field: &str,
        value: &Value,
        update: FieldMap,
    ) -> AuthResult<Option<UserView>> {
        let user = self
            .update_user_record_optional(field, value, update)
            .await?;
        self.after(CommittedWrite::UserUpdated(user.clone()))
            .await?;
        Ok(user)
    }

    pub(super) async fn output_user(&self, user: UserView) -> AuthResult<UserView> {
        // Projection preserves the one input row.
        Ok(self.output_users(vec![user]).await?.remove(0))
    }

    pub(super) fn user_schema(&self) -> crate::user_fields::UserConfig {
        self.config
            .user
            .user_field_schema_with_plugins(self.model_fields.user_plugin_fields())
            .adapter_fields(&[])
    }

    pub(super) fn user_storage_fields(&self, user: &UserView) -> FieldMap {
        FieldMap::from(user.clone())
    }

    pub(super) async fn output_users(&self, users: Vec<UserView>) -> AuthResult<Vec<UserView>> {
        if !users.is_empty() {
            self.model_fields.begin_id_output(EntityRole::User)?;
        }
        let storage = users
            .iter()
            .map(|user| self.user_storage_fields(user))
            .collect::<Vec<_>>();
        let mut schema = self.user_schema();
        if let Some(id) = schema.fields_mut().get_mut("id") {
            id.field_name = Some("id".into());
        }
        schema
            .output_memory_fields_many(&storage)
            .await?
            .into_iter()
            .map(UserView::try_from)
            .collect()
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

    fn assign_user_storage_fields(&self, user: &mut UserView, storage: &FieldMap) {
        for (name, value) in storage {
            user.set_field(name, value.clone());
        }
    }

    async fn prepare_user_update_optional(
        &self,
        update: UpdateUser,
    ) -> AuthResult<Option<FieldMap>> {
        let mut prepared = PreparedRecordWrite::new(update.into_user_fields()?);
        let transaction = EphemeralTransaction {
            store: self.clone(),
        };
        let context = self.hook_context(&transaction);
        for hook in &self.hooks {
            let outcome = crate::observability::database::with_database_hook(
                context.config,
                hook.hook_metadata(),
                crate::observability::database::DatabaseHook::BeforeUpdateUser,
                hook.before_update_user(prepared.original_fields_mut(), &context),
            )
            .await?;
            if !prepared.apply(outcome) {
                return Ok(None);
            }
        }
        Ok(Some(prepared.into_fields()))
    }

    async fn prepare_user_update_fields(&self, fields: FieldMap) -> AuthResult<FieldMap> {
        self.model_fields
            .begin_id_input(EntityRole::User, AdapterIdInput::default())?;
        self.user_schema()
            .storage_fields_with_bound_id(
                fields.clone(),
                false,
                || match (
                    self.model_fields.id_input_policy(EntityRole::User)?,
                    fields.get("id"),
                ) {
                    (Some(policy), Some(value)) => self
                        .config
                        .advanced
                        .database
                        .generate_id()
                        .adapter_id_input(value.clone(), policy),
                    (_, value) => Ok(value.cloned()),
                },
                |_, field, value| self.memory_plugin_field_input(field, value),
            )
            .await
    }

    async fn update_user_outcome(
        &self,
        field: &str,
        value: &Value,
        update: UpdateUser,
    ) -> AuthResult<std::ops::ControlFlow<(), Option<UserView>>> {
        let Some(update) = self.prepare_user_update_optional(update).await? else {
            return Ok(std::ops::ControlFlow::Break(()));
        };
        self.model_fields.canonicalize_id(EntityRole::User)?;
        let (physical, value) = self.user_field_selector(field, value)?;
        let update = self.prepare_user_update_fields(update).await?;
        self.finish_user_update(&physical, &value, update)
            .await
            .map(std::ops::ControlFlow::Continue)
    }

    async fn update_user_record_optional(
        &self,
        field: &str,
        value: &Value,
        update: FieldMap,
    ) -> AuthResult<Option<UserView>> {
        let user = self
            .raw("user", "update", |state| {
                let selected = state
                    .users
                    .select_refs(|user| Self::user_matches_selector(user, field, value))?;
                for row in &selected {
                    row.write(|user| {
                        self.assign_user_storage_fields(user, &update);
                        Ok(())
                    })?;
                }
                Ok(selected.into_iter().next())
            })
            .await?;
        self.output_optional_user_ref(user).await
    }
}

#[async_trait]
impl UserStore<StatelessSchema> for EphemeralStore {
    async fn verify_user_and_revoke_unproven_access(
        &self,
        user_id: &str,
    ) -> AuthResult<Option<UserView>> {
        self.verify_user_and_revoke_unproven_access_value(&user_id.into())
            .await
    }

    async fn verify_user_and_revoke_unproven_access_value(
        &self,
        user_id: &crate::FieldValue,
    ) -> AuthResult<Option<UserView>> {
        crate::store::revoke_unproven_account_access(self, user_id).await
    }
    async fn create_user(&self, input: CreateUser) -> AuthResult<UserView> {
        self.create_user_optional(input)
            .await?
            .ok_or_else(|| AuthError::forbidden("user creation returned no record"))
    }
    async fn create_user_fields_optional(&self, fields: FieldMap) -> AuthResult<Option<UserView>> {
        let mut prepared = PreparedRecordWrite::new(fields);
        let transaction = EphemeralTransaction {
            store: self.clone(),
        };
        let context = self.hook_context(&transaction);
        for hook in &self.hooks {
            let outcome = crate::observability::database::with_database_hook(
                context.config,
                hook.hook_metadata(),
                crate::observability::database::DatabaseHook::BeforeCreateUser,
                hook.before_create_user(prepared.fields_mut(), &context),
            )
            .await?;
            if !prepared.apply(outcome) {
                return Ok(None);
            }
        }
        let input = prepared.into_fields();
        self.model_fields.begin_id_input(
            EntityRole::User,
            AdapterIdInput {
                force_allow_id: true,
                supports_native_uuid: false,
            },
        )?;
        let fields = self
            .user_schema()
            .storage_fields_with_bound_id(
                input.clone(),
                true,
                || {
                    let supplied = input.get("id").cloned();
                    let Some(policy) = self.model_fields.id_input_policy(EntityRole::User)? else {
                        return Ok(supplied);
                    };
                    if let Some(serial) = self.next_serial_id(self.lock()?.users.len()) {
                        return Ok(Some(serial));
                    }
                    self.config
                        .advanced
                        .database
                        .generate_id()
                        .adapter_create_id_input("user", supplied, policy)
                },
                |_, field, value| self.memory_plugin_field_input(field, value),
            )
            .await?;
        let mut user = UserView::try_from(fields)?;
        let user = crate::observability::database::with_database_operation(
            &self.config,
            "user",
            "create",
            async {
                let mut state = self.lock()?;
                if let Some(id) = self.next_serial_id(state.users.len()) {
                    user.set_field("id", id);
                }
                Ok(state.users.push_ref(user))
            },
        )
        .await?;
        let user = self.output_user_refs(vec![user]).await?.remove(0);
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
        let ids = ids.iter().cloned().map(Value::from).collect::<Vec<_>>();
        self.list_users_by_id_values(&ids, limit).await
    }

    async fn list_users_by_id_values(
        &self,
        ids: &[Value],
        limit: f64,
    ) -> AuthResult<Vec<UserView>> {
        self.model_fields.begin_id_query(EntityRole::User)?;
        let bound = self.memory_primary_id_query(&ids.to_vec().into())?;
        let ids = bound
            .as_array()
            .ok_or_else(|| AuthError::internal("Native ID batch query lost its array shape"))?;
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
        self.get_user_by_field_value("username", &Value::from(username))
            .await
    }

    async fn get_user_by_phone_number(&self, phone_number: &str) -> AuthResult<Option<UserView>> {
        self.get_user_by_field_value("phoneNumber", &Value::from(phone_number))
            .await
    }

    async fn get_user_by_field_value(
        &self,
        name: &str,
        value: &Value,
    ) -> AuthResult<Option<UserView>> {
        let user = self.user_ref_by_field_value(name, value).await?;
        self.output_optional_user_ref(user).await
    }

    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<UserView> {
        match self
            .update_user_outcome("id", &Value::from(id), update)
            .await?
        {
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
    async fn update_user_by_field_value(
        &self,
        field: &str,
        value: &Value,
        update: UpdateUser,
    ) -> AuthResult<Option<UserView>> {
        Ok(self
            .update_user_outcome(field, value, update)
            .await?
            .continue_value()
            .flatten())
    }

    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        self.delete_user_value(&id.into()).await
    }

    async fn delete_user_value(&self, id: &Value) -> AuthResult<()> {
        self.delete_user_optional_value(id, true).await.map(|_| ())
    }

    async fn delete_user_optional(
        &self,
        id: &str,
        delete_database_sessions: bool,
    ) -> AuthResult<Option<UserView>> {
        self.delete_user_optional_value(&id.into(), delete_database_sessions)
            .await
    }

    async fn delete_user_optional_value(
        &self,
        id: &Value,
        delete_database_sessions: bool,
    ) -> AuthResult<Option<UserView>> {
        if delete_database_sessions {
            self.delete_user_sessions_by_user_value(id).await?;
        }
        self.delete_user_accounts_with_hooks(id).await?;
        let snapshot: AuthResult<Option<UserView>> = async {
            self.model_fields.begin_id_query(EntityRole::User)?;
            let stored_id = self.memory_primary_id_query(id)?;
            let user = self
                .raw("user", "findMany", |state| {
                    state
                        .users
                        .find(|user| Self::user_matches_selector(user, "id", &stored_id))
                })
                .await?;
            match user {
                Some(user) => self.output_user(user).await.map(Some),
                None => Ok(None),
            }
        }
        .await;
        // Upstream single-delete catches snapshot lookup and projection errors.
        let Ok(Some(user)) = snapshot else {
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
        crate::store::database_hooks::await_adapter_lookup().await;
        self.model_fields.begin_id_query(EntityRole::User)?;
        let stored_id = self.memory_primary_id_query(id)?;
        self.raw("user", "delete", |state| {
            state
                .users
                .retain(|user| !Self::user_matches_selector(user, "id", &stored_id))
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
                        Ok((
                            snapshot.clone(),
                            self.user_storage_fields(&snapshot),
                            source,
                        ))
                    })
                    .collect::<AuthResult<Vec<_>>>()
            })
            .await?;
        let (users, _) =
            query.select_memory(users, |(snapshot, storage, _)| (snapshot, storage))?;
        let users = self
            .output_user_refs(users.into_iter().map(|(_, _, source)| source).collect())
            .await?;
        query.begin_adapter_count(&self.model_fields)?;
        let total = self
            .raw("user", "count", |state| {
                let rows = state
                    .users
                    .snapshot()?
                    .into_iter()
                    .map(|user| {
                        let storage = self.user_storage_fields(&user);
                        (user, storage)
                    })
                    .collect::<Vec<_>>();
                query.count_memory(rows.iter(), |(user, storage)| (user, storage))
            })
            .await?;
        Ok((users, total))
    }
}
