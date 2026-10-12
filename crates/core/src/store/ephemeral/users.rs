use super::hooks::CommittedWrite;
use super::rows::RowRef;
use super::*;
use crate::store::database_hooks::{DatabaseHookControl, PreparedRecordWrite};
use crate::store::schema::EntityRole;

impl EphemeralStore {
    pub(super) async fn user_ref_by_email(
        &self,
        email: &str,
    ) -> AuthResult<Option<RowRef<FieldMap>>> {
        self.user_ref_by_field_value("email", &Value::from(email.to_lowercase()))
            .await
    }

    pub(super) async fn user_ref_by_field_value(
        &self,
        name: &str,
        value: &Value,
    ) -> AuthResult<Option<RowRef<FieldMap>>> {
        let (physical, value) = self.memory_query_field(
            EntityRole::User,
            &self.field_policy().user(),
            name,
            value.clone(),
        )?;
        self.user_ref(|user| {
            Ok(crate::query::field_matches_equality(
                &user.field(&physical)?.unwrap_or_default(),
                &value,
            ))
        })
        .await
    }

    pub(super) async fn user_ref(
        &self,
        predicate: impl Fn(&RowRef<FieldMap>) -> AuthResult<bool> + Send,
    ) -> AuthResult<Option<RowRef<FieldMap>>> {
        self.raw("user", "findOne", move |op| {
            Ok(op
                .capture_table(EntityRole::User)?
                .select_refs(predicate)?
                .into_iter()
                .next())
        })
        .await
    }

    pub(super) async fn user_ref_by_id_value(
        &self,
        id: &Value,
    ) -> AuthResult<Option<RowRef<FieldMap>>> {
        let (column, id) = self.memory_query_field(
            EntityRole::User,
            &self.field_policy().user(),
            "id",
            id.clone(),
        )?;
        self.user_ref(|user| Ok(user.field(&column)?.unwrap_or_default().strict_equals(&id)))
            .await
    }

    async fn output_optional_user_ref(
        &self,
        user: Option<RowRef<FieldMap>>,
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

    #[cfg(test)]
    pub(super) async fn output_users(&self, users: Vec<FieldMap>) -> AuthResult<Vec<UserView>> {
        let sources = users
            .into_iter()
            .map(|user| super::rows::RecordSource::Snapshot(Box::new(user)))
            .collect::<Vec<_>>();
        self.project_record_sources(EntityRole::User, &self.field_policy().user(), sources)
            .await?
            .into_iter()
            .map(UserView::try_from)
            .collect()
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
        super::raw_records::MemoryRecordModel::new(
            self,
            EntityRole::User,
            self.field_policy().user(),
        )
        .prepare(fields.into(), false, false)
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
        let (physical, value) = self.memory_query_field(
            EntityRole::User,
            &self.field_policy().user(),
            field,
            value.clone(),
        )?;
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
            .raw("user", "update", |op| {
                let selected = op.capture_table(EntityRole::User)?.select_refs(|user| {
                    Ok(crate::query::field_matches_equality(
                        &user.field(field)?.unwrap_or_default(),
                        value,
                    ))
                })?;
                for row in &selected {
                    row.apply_patch(update.clone())?;
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
        let user = super::raw_records::MemoryRecordModel::new(
            self,
            EntityRole::User,
            self.field_policy().user(),
        )
        .create_ref(input.into(), FieldMap::new(), true)
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
        let (column, bound) = self.memory_query_field(
            EntityRole::User,
            &self.field_policy().user(),
            "id",
            ids.to_vec().into(),
        )?;
        let ids = bound
            .as_array()
            .ok_or_else(|| AuthError::internal("Native ID batch query lost its array shape"))?;
        let users: Vec<_> = self
            .raw("user", "findMany", |op| {
                Ok(crate::query::paginate_memory(
                    op.capture_table(EntityRole::User)?.select_refs(|user| {
                        let actual = user.field(&column)?.unwrap_or_default();
                        ids.includes(&actual)
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
        self.get_user_with_accounts_value(&Value::from(email.to_lowercase()))
            .await
    }

    async fn get_user_with_accounts_value(
        &self,
        email: &Value,
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
            let (column, stored_id) = self.memory_query_field(
                EntityRole::User,
                &self.field_policy().user(),
                "id",
                id.clone(),
            )?;
            let user = self
                .raw("user", "findMany", |op| {
                    Ok(op
                        .capture_table(EntityRole::User)?
                        .select_refs(|user| {
                            Ok(crate::query::field_matches_equality(
                                &user.field(&column)?.unwrap_or_default(),
                                &stored_id,
                            ))
                        })?
                        .into_iter()
                        .next())
                })
                .await?;
            match user {
                Some(user) => self.output_optional_user_ref(Some(user)).await,
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
        let (column, stored_id) = self.memory_query_field(
            EntityRole::User,
            &self.field_policy().user(),
            "id",
            id.clone(),
        )?;
        self.raw("user", "delete", |op| {
            let table = op.capture_table(EntityRole::User)?;
            let selected = table.select_refs(|user| {
                Ok(crate::query::field_matches_equality(
                    &user.field(&column)?.unwrap_or_default(),
                    &stored_id,
                ))
            })?;
            op.replace_table(EntityRole::User, table.without_refs(&selected)?)
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
        let schema = self.field_policy().user();
        let bind =
            |name: &str, value| self.memory_query_field(EntityRole::User, &schema, name, value);
        let query = crate::user_query::PreparedUserQuery::for_memory_adapter(
            &params,
            &self.config.user,
            bind,
        )?;
        let users: Vec<_> = self
            .raw("user", "findMany", |op| {
                let selected = op.capture_table(EntityRole::User)?.select_refs(|user| {
                    query.matches_memory_fields(|name| Ok(user.field(name)?.unwrap_or_default()))
                })?;
                let sort_fields = self
                    .model_fields
                    .runtime_fields(EntityRole::User, &schema)?;
                query
                    .page_memory(selected, &sort_fields, |user, name| {
                        Ok(user.field(name)?.unwrap_or_default())
                    })
                    .map(|(users, _)| users)
            })
            .await?;
        let users = self.output_user_refs(users).await?;
        let count = crate::user_query::PreparedUserQuery::for_memory_adapter(
            &params,
            &self.config.user,
            bind,
        )?;
        let total = self
            .raw("user", "count", |op| {
                Ok(op
                    .capture_table(EntityRole::User)?
                    .select_refs(|user| {
                        count
                            .matches_memory_fields(|name| Ok(user.field(name)?.unwrap_or_default()))
                    })?
                    .len())
            })
            .await?;
        Ok((users, total))
    }
}
