use super::rows::RowRef;
use super::*;
use crate::store::schema::EntityRole;
use crate::store::{AccountOwner, JoinValue, ResolvedJoin, UserAccounts};

type UserRef = RowRef<UserView>;
type AccountRef = RowRef<FieldMap>;

pub(super) fn user_value(user: &UserView, logical: &str, physical: &str) -> Value {
    if physical == "id" {
        return user.id.field_value();
    }
    if matches!(logical, "name" | "image") {
        return user.native_field_value(logical).unwrap_or_default();
    }
    user.additional_fields
        .get(physical)
        .cloned()
        .or_else(|| {
            (physical == logical)
                .then(|| user.native_field_value(logical))
                .flatten()
        })
        .unwrap_or_default()
}

fn native_relation<T>(
    rows: Vec<RowRef<T>>,
    relation: &ResolvedJoin,
    limit: f64,
    id: impl Fn(&T) -> Value,
) -> AuthResult<JoinValue<RowRef<T>>> {
    if !relation.many {
        return Ok(JoinValue::One(rows.into_iter().next()));
    }
    let mut selected = Vec::new();
    let mut seen = Vec::new();
    for row in rows {
        if selected.len() as f64 >= limit {
            break;
        }
        let id = row.read(|row| Ok(id(row)))?;
        if !seen.iter().any(|seen: &Value| seen.same_value_zero(&id)) {
            seen.push(id);
            selected.push(row);
        }
    }
    Ok(JoinValue::Many(selected))
}

fn fallback_relation<T>(rows: Vec<T>, many: bool, limit: f64) -> JoinValue<T> {
    if many {
        JoinValue::Many(crate::query::paginate_memory(rows, Some(limit), None))
    } else {
        JoinValue::One(rows.into_iter().next())
    }
}

impl EphemeralStore {
    fn join_user_visibility(&self, user: &mut UserView) {
        user.visible_fields = Some(
            ["name", "email", "image"]
                .into_iter()
                .map(str::to_owned)
                .chain(self.config.user.fields().keys().cloned())
                .collect(),
        );
    }

    pub(super) async fn user_accounts_relation(
        &self,
        email: &str,
        relation: &ResolvedJoin,
    ) -> AuthResult<Option<UserAccounts>> {
        let native = self.config.advanced.database.joins == Some(true);
        let (mut user, accounts) = if native {
            let selected = self
                .raw("user", "findOne", |state| {
                    let Some(user) = state
                        .users
                        .find(|user| user.email.as_deref() == Some(&email.to_lowercase()))?
                    else {
                        return Ok(None);
                    };
                    let value = user_value(&user, &relation.logical_from, &relation.from);
                    let accounts = native_relation(
                        state.accounts.select_refs(|row| {
                            row.get(&relation.to)
                                .unwrap_or(&Value::Undefined)
                                .strict_equals(&value)
                        })?,
                        relation,
                        self.config.advanced.database.find_many_limit(),
                        |row| row.get("id").cloned().unwrap_or_default(),
                    )?;
                    Ok(Some((user, accounts)))
                })
                .await?;
            let Some((user, accounts)) = selected else {
                return Ok(None);
            };
            (self.output_user(user).await?, Some(accounts))
        } else {
            let Some(user) = self.user_ref_by_email(email).await? else {
                return Ok(None);
            };
            (self.output_user_refs(vec![user]).await?.remove(0), None)
        };
        let accounts = match accounts {
            Some(accounts) => accounts,
            None => self.fallback_join_accounts(relation, &user).await?,
        };
        let accounts = match accounts {
            JoinValue::One(account) => JoinValue::One(match account {
                Some(account) => Some(self.output_account_ref(&account).await?),
                None => None,
            }),
            JoinValue::Many(accounts) => {
                let mut projected = Vec::with_capacity(accounts.len());
                for account in accounts {
                    projected.push(self.output_account_ref(&account).await?);
                }
                JoinValue::Many(projected)
            }
        };
        self.join_user_visibility(&mut user);
        Ok(Some(UserAccounts::new(user, accounts)))
    }

    async fn fallback_join_accounts(
        &self,
        relation: &ResolvedJoin,
        user: &UserView,
    ) -> AuthResult<JoinValue<AccountRef>> {
        let from = relation.fallback_from(
            (EntityRole::User, "user", &self.config.user),
            &self.model_fields,
        )?;
        let value = user.field_values()?.remove(&from).unwrap_or_default();
        if value.is_null() || value.is_undefined() {
            return Ok(fallback_relation(Vec::new(), relation.many, 0.0));
        }
        let fields = self.config.account.field_schema();
        let (logical, physical) = relation.fallback_target(
            (EntityRole::Account, "account", &fields),
            &self.model_fields,
        )?;
        let value = if logical == "id" {
            self.memory_primary_id_query(&value)?
        } else {
            let value = self.memory_field_query(&fields, &logical, value)?;
            let field = fields.fields().get(&logical).cloned().unwrap_or_default();
            crate::user_query::bind_filter(&field, &value)?
        };
        self.raw(
            "account",
            if relation.many { "findMany" } else { "findOne" },
            |state| {
                Ok(fallback_relation(
                    state.accounts.select_refs(|row| {
                        row.get(&physical)
                            .unwrap_or(&Value::Undefined)
                            .strict_equals(&value)
                    })?,
                    relation.many,
                    self.config.advanced.database.find_many_limit(),
                ))
            },
        )
        .await
    }

    pub(super) async fn account_owner_relation(
        &self,
        provider: &str,
        account_id: &str,
        relation: &ResolvedJoin,
    ) -> AuthResult<Option<AccountOwner>> {
        let fields = self.config.account.field_schema();
        let native = self.config.advanced.database.joins == Some(true);
        let (records, users) = if native {
            let provider = self.memory_field_query(&fields, "providerId", Value::from(provider))?;
            let account_id =
                self.memory_field_query(&fields, "accountId", Value::from(account_id))?;
            let rows = self
                .raw("account", "findMany", |state| {
                    let mut selected = Vec::new();
                    let mut parent_ids = Vec::new();
                    for account in state.accounts.snapshot()?.into_iter().filter(|row| {
                        row.get(fields.record_storage_key("providerId"))
                            .unwrap_or(&Value::Undefined)
                            .strict_equals(&provider)
                            && row
                                .get(fields.record_storage_key("accountId"))
                                .unwrap_or(&Value::Undefined)
                                .strict_equals(&account_id)
                    }) {
                        let id = account.get("id").cloned().unwrap_or_default();
                        if parent_ids
                            .iter()
                            .any(|seen: &Value| seen.same_value_zero(&id))
                        {
                            continue;
                        }
                        parent_ids.push(id);
                        let value = account.get(&relation.from).cloned().unwrap_or_default();
                        let users = native_relation(
                            state.users.select_refs(|user| {
                                user_value(user, &relation.logical_to, &relation.to)
                                    .strict_equals(&value)
                            })?,
                            relation,
                            self.config.advanced.database.find_many_limit(),
                            |user| user.id.field_value(),
                        )?;
                        selected.push((account, users));
                        if selected.len() == 2 {
                            break;
                        }
                    }
                    Ok(selected)
                })
                .await?;
            let (records, users): (Vec<_>, Vec<_>) = rows.into_iter().unzip();
            (records, Some(users))
        } else {
            (self.account_records(provider, account_id).await?, None)
        };
        let owners = fields
            .project_memory_records_batches_then(&records, |ready| {
                let users = &users;
                let fields = &fields;
                async move {
                    let mut selected = Vec::with_capacity(ready.len());
                    for (index, account) in &ready {
                        selected.push(match users {
                            Some(users) => users.get(*index).cloned().ok_or_else(|| {
                                AuthError::internal("Account projection lost its joined User index")
                            })?,
                            None => self.fallback_join_users(relation, fields, account).await?,
                        });
                    }
                    let projected = self.output_user_relations(selected).await?;
                    Ok(ready
                        .into_iter()
                        .zip(projected)
                        .map(|((index, account), user)| {
                            (
                                index,
                                AccountOwner {
                                    account: AccountView::from_adapter_fields(account),
                                    user,
                                },
                            )
                        })
                        .collect())
                }
            })
            .await?;
        if owners.len() > 1 {
            return Err(AuthError::internal(format!(
                "Multiple accounts match the same accountId for provider {}. Resolve duplicate account identities before continuing.",
                serde_json::to_string(provider)?
            )));
        }
        Ok(owners.into_iter().next())
    }

    async fn fallback_join_users(
        &self,
        relation: &ResolvedJoin,
        fields: &crate::user_fields::UserConfig,
        account: &FieldMap,
    ) -> AuthResult<JoinValue<UserRef>> {
        let from =
            relation.fallback_from((EntityRole::Account, "account", fields), &self.model_fields)?;
        let value = account.get(&from).cloned().unwrap_or_default();
        if value.is_null() || value.is_undefined() {
            return Ok(fallback_relation(Vec::new(), relation.many, 0.0));
        }
        let (logical, physical) = relation.fallback_target(
            (EntityRole::User, "user", &self.config.user),
            &self.model_fields,
        )?;
        let value = if logical == "id" {
            self.memory_primary_id_query(&value)?
        } else {
            let value = self.memory_field_query(&self.config.user, &logical, value)?;
            let field = ResolvedJoin::user_field(&self.config, &logical);
            crate::user_query::bind_filter(&field, &value)?
        };
        self.raw(
            "user",
            if relation.many { "findMany" } else { "findOne" },
            |state| {
                Ok(fallback_relation(
                    state.users.select_refs(|user| {
                        user_value(user, &logical, &physical).strict_equals(&value)
                    })?,
                    relation.many,
                    self.config.advanced.database.find_many_limit(),
                ))
            },
        )
        .await
    }

    async fn output_user_relations(
        &self,
        users: Vec<JoinValue<UserRef>>,
    ) -> AuthResult<Vec<JoinValue<UserView>>> {
        let (many, pages): (Vec<_>, Vec<_>) = users
            .into_iter()
            .map(|users| match users {
                JoinValue::One(user) => (false, user.into_iter().collect()),
                JoinValue::Many(users) => (true, users),
            })
            .unzip();
        let projected = self.output_user_pages(pages).await?;
        Ok(many
            .into_iter()
            .zip(projected)
            .map(|(many, mut users)| {
                for user in &mut users {
                    self.join_user_visibility(user);
                }
                if many {
                    JoinValue::Many(users)
                } else {
                    JoinValue::One(users.into_iter().next())
                }
            })
            .collect())
    }

    fn output_user_pages(
        &self,
        pages: Vec<Vec<UserRef>>,
    ) -> futures_util::future::BoxFuture<'_, AuthResult<Vec<Vec<UserView>>>> {
        Box::pin(async move {
            let mut output = vec![Vec::new(); pages.len()];
            let mut pending = Vec::new();
            let mut first = Vec::new();
            for (index, page) in pages.into_iter().enumerate() {
                let mut page = page.into_iter();
                if let Some(user) = page.next() {
                    first.push(user);
                    pending.push((index, page.collect::<Vec<_>>()));
                }
            }
            let projected = self
                .output_user_refs_batches_then(first, |ready| {
                    let pending = &pending;
                    async move {
                        let tails = ready
                            .iter()
                            .map(|(index, _)| pending[*index].1.clone())
                            .collect();
                        // Ready parents advance independently; each page awaits its preceding child.
                        let tails = self.output_user_pages(tails).await?;
                        Ok(ready
                            .into_iter()
                            .zip(tails)
                            .map(|((index, user), tail)| {
                                (index, std::iter::once(user).chain(tail).collect())
                            })
                            .collect())
                    }
                })
                .await?;
            for ((index, _), users) in pending.into_iter().zip(projected) {
                output[index] = users;
            }
            Ok(output)
        })
    }
}
