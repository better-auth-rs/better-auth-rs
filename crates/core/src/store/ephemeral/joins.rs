//! Native joins retain child row references selected by the original raw query.

use super::rows::RowRef;
use super::*;
use crate::session::SessionData;
use crate::store::schema::resolve_field_name;
use crate::store::{AccountOwner, UserAccounts};
use crate::user_fields::{UserFieldConfig, project_adapter_value, project_source_fields_then};

type UserRef = RowRef<UserView>;
type AccountRef = RowRef<FieldMap>;
type SessionSnapshot = (SessionView, Option<SessionData>);

impl EphemeralStore {
    pub(super) async fn output_user_refs(&self, users: Vec<UserRef>) -> AuthResult<Vec<UserView>> {
        if !users.is_empty() {
            self.model_fields
                .canonicalize_id(crate::store::schema::EntityRole::User)?;
        }
        // Core fields keep their schema positions even when an application replaces a policy.
        let mut fields: IndexMap<String, UserFieldConfig> = [
            "name",
            "email",
            "emailVerified",
            "image",
            "createdAt",
            "updatedAt",
        ]
        .into_iter()
        .map(|name| (name.to_owned(), UserFieldConfig::default()))
        .collect();
        fields.extend(self.config.user.fields().clone());
        for name in UserView::NATIVE_FIELDS {
            let _ = fields.entry((*name).into()).or_default();
        }
        let _ = fields.shift_remove("id");
        let _ = fields.insert("id".into(), UserFieldConfig::default());
        let mut rows = users
            .into_iter()
            .map(|user| (user, FieldMap::new(), FieldMap::new()))
            .collect::<Vec<_>>();
        project_source_fields_then(
            &mut rows,
            &fields,
            |(source, native, _), name, field| {
                source.read(|user| {
                    let value = user.native_field_value(name);
                    if let Some(value) = &value {
                        let _ = native.insert(name.to_owned(), value.clone());
                    }
                    Ok(if matches!(name, "name" | "image") {
                        value
                    } else {
                        let key = resolve_field_name(field.field_name.as_deref(), name);
                        user.additional_fields
                            .get(key)
                            .cloned()
                            .or_else(|| (key == name).then_some(value).flatten())
                    })
                })
            },
            |(_, _, output), name, field, value| {
                let configured = name != "id" && self.config.user.fields().contains_key(name);
                Box::pin(async move {
                    if configured {
                        let value = project_adapter_value(
                            value.unwrap_or_default(),
                            field,
                            field.references_id(),
                            true,
                        )
                        .await?;
                        crate::user_fields::assign_output(output, name, field, value)?;
                    }
                    Ok(())
                })
            },
            |_, (source, native, output)| {
                let mut user = UserView::from_field_values(std::mem::take(native))?;
                user.metadata = source.read(|user| Ok(user.metadata.clone()))?;
                self.assign_user_output(&mut user, std::mem::take(output))?;
                Ok(user)
            },
        )
        .await
    }

    pub(super) async fn output_account_ref(&self, source: &AccountRef) -> AuthResult<AccountView> {
        self.model_fields
            .canonicalize_id(crate::store::schema::EntityRole::Account)?;
        let schema = self.config.account.field_schema();
        let mut fields = FieldMap::new();
        for (name, field) in schema.fields() {
            if name == "id" {
                continue;
            }
            let value = source.read(|row| Ok(row.get(schema.record_storage_key(name)).cloned()))?;
            let value = project_adapter_value(
                value.unwrap_or_default(),
                field,
                field.references_id(),
                true,
            )
            .await?;
            let _ = fields.insert(name.clone(), value);
        }
        if let Some(id) = source.read(|row| Ok(row.get("id").cloned()))? {
            let _ = fields.insert("id".into(), id);
        }
        Ok(AccountView::from_adapter_fields(fields))
    }

    pub(super) async fn user_account_refs(&self, user_id: &str) -> AuthResult<Vec<AccountRef>> {
        self.model_fields
            .canonicalize_id(crate::store::schema::EntityRole::Account)?;
        let fields = self.config.account.field_schema();
        let user_id =
            self.memory_field_query(&fields, "userId", Value::String(user_id.to_owned()))?;
        self.raw("account", "findMany", |state| {
            Ok(crate::query::paginate_memory(
                state.accounts.select_refs(|record| {
                    record
                        .get(fields.record_storage_key("userId"))
                        .unwrap_or(&Value::Undefined)
                        .strict_equals(&user_id)
                })?,
                Some(self.config.advanced.database.find_many_limit()),
                None,
            ))
        })
        .await
    }

    pub(super) async fn joined_user_accounts(
        &self,
        email: &str,
    ) -> AuthResult<Option<UserAccounts>> {
        let fields = self.config.account.field_schema();
        let records = self
            .raw("user", "findOne", |state| {
                let Some(user) = state
                    .users
                    .find(|user| user.email.as_deref() == Some(&email.to_lowercase()))?
                else {
                    return Ok(None);
                };
                let stored_id = Self::project_id(&user.id)?;
                let mut accounts = Vec::new();
                let id = user.id.field_value();
                let matching = state.accounts.select_refs(|row| {
                    row.get(fields.record_storage_key("userId"))
                        .unwrap_or(&Value::Undefined)
                        .strict_equals(&id)
                })?;
                let mut seen = Vec::new();
                for row in matching {
                    if accounts.len() as f64 >= self.config.advanced.database.find_many_limit() {
                        break;
                    }
                    let id = row.read(|row| Ok(row.get("id").cloned().unwrap_or_default()))?;
                    if !seen.iter().any(|seen: &Value| seen.same_value_zero(&id)) {
                        seen.push(id);
                        accounts.push(row);
                    }
                }
                Ok(Some((user, stored_id, accounts)))
            })
            .await?;
        let Some((user, stored_id, accounts)) = records else {
            return Ok(None);
        };
        let user = self.output_user(user).await?;
        let mut projected = Vec::with_capacity(accounts.len());
        for account in accounts {
            projected.push(self.output_account_ref(&account).await?);
        }
        UserAccounts::new(user, projected, &stored_id).map(Some)
    }

    pub(super) async fn joined_account_owner(
        &self,
        provider: &str,
        account_id: &str,
    ) -> AuthResult<Option<AccountOwner>> {
        let fields = self.config.account.field_schema();
        let bound_provider =
            self.memory_field_query(&fields, "providerId", Value::String(provider.to_owned()))?;
        let account_id =
            self.memory_field_query(&fields, "accountId", Value::String(account_id.to_owned()))?;
        let rows = self
            .raw("account", "findMany", |state| {
                let mut rows = Vec::new();
                for account in state
                    .accounts
                    .snapshot()?
                    .into_iter()
                    .filter(|record| {
                        record
                            .get(fields.record_storage_key("providerId"))
                            .unwrap_or(&Value::Undefined)
                            .strict_equals(&bound_provider)
                            && record
                                .get(fields.record_storage_key("accountId"))
                                .unwrap_or(&Value::Undefined)
                                .strict_equals(&account_id)
                    })
                    .take(2)
                {
                    let owner = account.get(fields.record_storage_key("userId")).cloned();
                    let user = state.users.first_ref(|user| {
                        user.id
                            .field_value()
                            .strict_equals(owner.as_ref().unwrap_or(&Value::Undefined))
                    })?;
                    rows.push((account, self.stored_account_owner_id(owner)?, user));
                }
                Ok(rows)
            })
            .await?;
        let storage: Vec<_> = rows.iter().map(|(account, _, _)| account.clone()).collect();
        let owners = fields
            .project_memory_records_batches_then(&storage, |ready| {
                let rows = &rows;
                async move {
                    let mut pending = Vec::new();
                    let mut users = Vec::new();
                    for (index, account) in ready {
                        let (_, owner_id, user) = rows.get(index).ok_or_else(|| {
                            AuthError::internal("Account projection lost its stored owner index")
                        })?;
                        users.extend(user.clone());
                        pending.push((index, account, owner_id, user.is_some()));
                    }
                    let mut users = self.output_user_refs(users).await?.into_iter();
                    pending
                        .into_iter()
                        .map(|(index, account, owner, has_user)| {
                            AccountOwner::new(
                                AccountView::from_adapter_fields(account),
                                if has_user { users.next() } else { None },
                                owner,
                            )
                            .map(|owner| (index, owner))
                        })
                        .collect()
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

    pub(super) async fn joined_session_snapshot(
        &self,
        token: &str,
    ) -> AuthResult<Option<SessionSnapshot>> {
        let rows = self
            .raw("session", "findOne", |state| {
                match state.sessions.find(|row| row.token == token)? {
                    Some(session) => {
                        let owner = session.user_id.field_value();
                        let user = state
                            .users
                            .first_ref(|user| user.id.field_value().strict_equals(&owner))?;
                        Ok(vec![(session, user)])
                    }
                    None => Ok(Vec::new()),
                }
            })
            .await?;
        Ok(self
            .project_joined_sessions(rows)
            .await?
            .into_iter()
            .next()
            .filter(|(_, user)| user.is_some()))
    }

    pub(super) async fn joined_session_snapshots(
        &self,
        tokens: &[String],
        only_active: bool,
    ) -> AuthResult<Vec<SessionSnapshot>> {
        let now = Utc::now();
        let rows = self
            .raw("session", "findMany", |state| {
                let sessions = crate::query::paginate_memory(
                    state
                        .sessions
                        .snapshot()?
                        .into_iter()
                        .filter(|session| {
                            tokens.contains(&session.token)
                                && (!only_active
                                    || session.expires_at.milliseconds()
                                        > now.timestamp_millis() as f64)
                        })
                        .collect(),
                    Some(self.config.advanced.database.find_many_limit()),
                    None,
                );
                sessions
                    .into_iter()
                    .map(|session| {
                        let owner = session.user_id.field_value();
                        let user = state
                            .users
                            .first_ref(|user| user.id.field_value().strict_equals(&owner))?;
                        Ok((session, user))
                    })
                    .collect()
            })
            .await?;
        let snapshots = self.project_joined_sessions(rows).await?;
        if snapshots.iter().any(|(_, user)| user.is_none()) {
            return Ok(Vec::new());
        }
        Ok(snapshots)
    }

    async fn project_joined_sessions(
        &self,
        rows: Vec<(SessionView, Option<UserRef>)>,
    ) -> AuthResult<Vec<SessionSnapshot>> {
        let sessions = rows.iter().map(|(session, _)| session.clone()).collect();
        self.output_sessions_batches_then(sessions, |ready| {
            let rows = &rows;
            async move {
                let mut pending = Vec::new();
                let mut users = Vec::new();
                for (index, session) in ready {
                    let (_, user) = rows.get(index).ok_or_else(|| {
                        AuthError::internal("Session projection lost its stored join index")
                    })?;
                    users.extend(user.clone());
                    pending.push((index, session, user.is_some()));
                }
                let mut users = self.output_user_refs(users).await?.into_iter();
                Ok(pending
                    .into_iter()
                    .map(|(index, session, has_user)| {
                        let data =
                            if has_user { users.next() } else { None }.map(|user| SessionData {
                                session: session.clone(),
                                user,
                            });
                        (index, (session, data))
                    })
                    .collect())
            }
        })
        .await
    }
}
