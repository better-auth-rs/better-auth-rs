use super::native_joins::native_relationships;
use super::rows::{RecordSource, RowRef};
use super::*;
use crate::store::schema::EntityRole;
use crate::store::{AccountOwner, JoinValue, ResolvedJoin, UserAccounts};

type UserRef = RowRef<FieldMap>;
type UserPage = (Arc<[UserRef]>, usize);
type AccountRef = RowRef<FieldMap>;

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
            [
                "id",
                "name",
                "email",
                "emailVerified",
                "image",
                "createdAt",
                "updatedAt",
            ]
            .into_iter()
            .map(str::to_owned)
            .chain(
                self.model_fields
                    .user_plugin_fields()
                    .iter()
                    .map(|name| (*name).to_owned()),
            )
            .filter(|name| {
                user.visible_fields
                    .as_ref()
                    .is_none_or(|fields| fields.contains(name))
            })
            .chain(self.config.user.fields().keys().cloned())
            .collect(),
        );
    }

    pub(super) async fn user_accounts_relation(
        &self,
        email: &Value,
        relation: &ResolvedJoin,
    ) -> AuthResult<Option<UserAccounts>> {
        let native = self.config.advanced.database.joins == Some(true);
        let (mut user, accounts) = if native {
            let (email_field, email) = self.memory_query_field(
                EntityRole::User,
                &self.field_policy().user(),
                "email",
                email.clone(),
            )?;
            let selected = self
                .raw("user", "findOne", |op| {
                    let users = op
                        .capture_table(EntityRole::User)?
                        .select_refs(|user| {
                            Ok(user
                                .field(&email_field)?
                                .unwrap_or_default()
                                .strict_equals(&email))
                        })?
                        .into_iter()
                        .map(RecordSource::Live)
                        .collect();
                    let Some(mut group) = native_relationships(
                        users,
                        &[(
                            EntityRole::Account,
                            relation,
                            self.config.advanced.database.find_many_limit(),
                        )],
                        |role| op.capture_join_table(role),
                    )?
                    .into_iter()
                    .next() else {
                        return Ok(None);
                    };
                    let accounts = group.children.remove(0);
                    let accounts = if relation.many {
                        JoinValue::Many(accounts)
                    } else {
                        JoinValue::One(accounts.into_iter().next())
                    };
                    let source = RecordSource::joined(
                        group.parent,
                        [(
                            self.model_fields
                                .storage_model_name(EntityRole::Account, "account")
                                .to_owned(),
                            accounts.raw_value(),
                        )],
                    );
                    Ok(Some((source, accounts)))
                })
                .await?;
            let Some((source, accounts)) = selected else {
                return Ok(None);
            };
            let mut projected = self
                .project_record_sources(EntityRole::User, &self.field_policy().user(), vec![source])
                .await?;
            (
                UserView::from_field_values(projected.remove(0))?,
                Some(accounts),
            )
        } else {
            let Some(user) = self.user_ref_by_field_value("email", email).await? else {
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
                Some(account) => Some(self.output_account(RecordSource::Live(account)).await?),
                None => None,
            }),
            JoinValue::Many(accounts) => {
                let mut projected = Vec::with_capacity(accounts.len());
                for account in accounts {
                    projected.push(self.output_account(RecordSource::Live(account)).await?);
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
        let fields = self.field_policy().account();
        let (logical, physical) = relation.fallback_target(
            (EntityRole::Account, "account", &fields),
            &self.model_fields,
        )?;
        let value = self.memory_field_query(&fields, &logical, value)?;
        self.raw(
            "account",
            if relation.many { "findMany" } else { "findOne" },
            |op| {
                Ok(fallback_relation(
                    op.capture_table(EntityRole::Account)?.select_refs(|row| {
                        Ok(row
                            .field(&physical)?
                            .unwrap_or_default()
                            .strict_equals(&value))
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
        provider: &Value,
        account_id: &Value,
        relation: &ResolvedJoin,
    ) -> AuthResult<Option<AccountOwner>> {
        let fields = self.field_policy().account();
        let native = self.config.advanced.database.joins == Some(true);
        let (records, users) = if native {
            let selectors = self.account_identity_selectors(provider, account_id)?;
            let rows = self
                .raw("account", "findMany", |op| {
                    let accounts = op
                        .capture_table(EntityRole::Account)?
                        .select_refs(|row| Self::account_matches_selectors(row, &selectors))?
                        .into_iter()
                        .map(RecordSource::Live)
                        .collect();
                    let groups = native_relationships(
                        accounts,
                        &[(
                            EntityRole::User,
                            relation,
                            self.config.advanced.database.find_many_limit(),
                        )],
                        |role| op.capture_join_table(role),
                    )?;
                    Ok(groups
                        .into_iter()
                        .take(2)
                        .map(|mut group| {
                            let users = group.children.remove(0);
                            let users = if relation.many {
                                JoinValue::Many(users)
                            } else {
                                JoinValue::One(users.into_iter().next())
                            };
                            let source = RecordSource::joined(
                                group.parent,
                                [(
                                    self.model_fields
                                        .storage_model_name(EntityRole::User, "user")
                                        .to_owned(),
                                    users.raw_value(),
                                )],
                            );
                            (source, users)
                        })
                        .collect::<Vec<_>>())
                })
                .await?;
            let (records, users): (Vec<_>, Vec<_>) = rows.into_iter().unzip();
            (records, Some(users))
        } else {
            (self.account_records(provider, account_id).await?, None)
        };
        let continuation = Arc::new((users, fields.clone(), relation.clone()));
        let store = self.clone();
        let owners = self
            .project_record_sources_owned_batches_then(
                EntityRole::Account,
                &fields,
                records,
                |_, fields| Ok(fields),
                move |ready| {
                    let continuation = continuation.clone();
                    let store = store.clone();
                    async move {
                        let (users, fields, relation) = continuation.as_ref();
                        let mut selected = Vec::with_capacity(ready.len());
                        for (index, account) in &ready {
                            selected.push(match users {
                                Some(users) => users.get(*index).cloned().ok_or_else(|| {
                                    AuthError::internal(
                                        "Account projection lost its joined User index",
                                    )
                                })?,
                                None => {
                                    store
                                        .fallback_join_users(
                                            relation,
                                            (EntityRole::Account, "account", fields),
                                            account,
                                        )
                                        .await?
                                }
                            });
                        }
                        let projected = store.output_user_relations(selected).await?;
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
                },
            )
            .await?;
        if owners.len() > 1 {
            return Err(AuthError::internal(format!(
                "Multiple accounts match the same accountId for provider {}. Resolve duplicate account identities before continuing.",
                provider.stringify()?.unwrap_or_else(|| "undefined".into())
            )));
        }
        Ok(owners.into_iter().next())
    }

    pub(super) async fn fallback_join_users(
        &self,
        relation: &ResolvedJoin,
        parent: (EntityRole, &str, &crate::user_fields::UserConfig),
        fields: &FieldMap,
    ) -> AuthResult<JoinValue<UserRef>> {
        let from = relation.fallback_from(parent, &self.model_fields)?;
        let value = fields.get(&from).cloned().unwrap_or_default();
        if value.is_null() || value.is_undefined() {
            return Ok(fallback_relation(Vec::new(), relation.many, 0.0));
        }
        let (logical, physical) = relation.fallback_target(
            (EntityRole::User, "user", &self.config.user),
            &self.model_fields,
        )?;
        let value = self.memory_field_query(&self.field_policy().user(), &logical, value)?;
        self.raw(
            "user",
            if relation.many { "findMany" } else { "findOne" },
            |op| {
                Ok(fallback_relation(
                    op.capture_table(EntityRole::User)?.select_refs(|user| {
                        Ok(user
                            .field(&physical)?
                            .unwrap_or_default()
                            .strict_equals(&value))
                    })?,
                    relation.many,
                    self.config.advanced.database.find_many_limit(),
                ))
            },
        )
        .await
    }

    pub(super) async fn output_user_relations(
        &self,
        users: Vec<JoinValue<UserRef>>,
    ) -> AuthResult<Vec<JoinValue<UserView>>> {
        let (many, pages): (Vec<_>, Vec<_>) = users
            .into_iter()
            .map(|users| {
                let (many, users) = match users {
                    JoinValue::One(user) => (false, user.into_iter().collect()),
                    JoinValue::Many(users) => (true, users),
                };
                (many, (Arc::from(users), 0))
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
        pages: Vec<UserPage>,
    ) -> futures_util::future::BoxFuture<'static, AuthResult<Vec<Vec<UserView>>>> {
        let store = self.clone();
        Box::pin(async move {
            let mut output = vec![Vec::new(); pages.len()];
            let mut pending = Vec::new();
            let mut first = Vec::new();
            for (index, (page, position)) in pages.into_iter().enumerate() {
                if let Some(user) = page.get(position) {
                    first.push(user.clone());
                    pending.push((index, (page, position + 1)));
                }
            }
            if first.is_empty() {
                return Ok(output);
            }
            let pending = Arc::new(pending);
            let continuation = (pending.clone(), store.clone());
            let projected = store
                .output_user_refs_batches_then(first, move |ready| {
                    let (pending, store) = continuation.clone();
                    async move {
                        let tails = ready
                            .iter()
                            .map(|(index, _)| {
                                pending
                                    .get(*index)
                                    .map(|(_, tail)| tail.clone())
                                    .ok_or_else(|| {
                                        AuthError::internal(
                                            "User projection lost its pending page index",
                                        )
                                    })
                            })
                            .collect::<AuthResult<Vec<_>>>()?;
                        // Ready parents advance independently; each page awaits its preceding child.
                        let tails = store.output_user_pages(tails).await?;
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
            for ((index, _), users) in pending.iter().zip(projected) {
                *output.get_mut(*index).ok_or_else(|| {
                    AuthError::internal("User projection lost its output page index")
                })? = users;
            }
            Ok(output)
        })
    }
}
