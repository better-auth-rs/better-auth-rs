//! Native joins retain child row references selected by the original raw query.

use super::account_joins::{native_relation, user_value};
use super::rows::RowRef;
use super::sessions::{SessionSource, session_token_matches, session_tokens_match};
use super::*;
use crate::session::SessionData;
use crate::store::schema::resolve_field_name;
use crate::store::{JoinValue, ResolvedJoin};
use crate::user_fields::{project_adapter_value, project_source_fields_batches_then};

type UserRef = RowRef<UserView>;
type AccountRef = RowRef<FieldMap>;
type SessionSnapshot = (SessionView, Option<SessionData<JoinValue<UserView>>>);

impl EphemeralStore {
    pub(super) async fn output_user_refs(&self, users: Vec<UserRef>) -> AuthResult<Vec<UserView>> {
        self.output_user_refs_batches_then(users, |ready| std::future::ready(Ok(ready)))
            .await
    }

    pub(super) async fn output_user_refs_batches_then<R: Send, F>(
        &self,
        users: Vec<UserRef>,
        complete: impl Fn(Vec<(usize, UserView)>) -> F + Sync,
    ) -> AuthResult<Vec<R>>
    where
        F: std::future::Future<Output = AuthResult<Vec<(usize, R)>>> + Send,
    {
        if !users.is_empty() {
            self.model_fields
                .begin_id_output(crate::store::schema::EntityRole::User)?;
        }
        let fields = self.user_schema();
        let mut rows = users
            .into_iter()
            .map(|user| (user, (), FieldMap::new()))
            .collect::<Vec<_>>();
        project_source_fields_batches_then(
            &mut rows,
            fields.fields(),
            |(source, _, _), name, field| {
                let physical = resolve_field_name(field.field_name.as_deref(), name);
                source.read(|user| Ok(FieldMap::from(user.clone()).get(physical).cloned()))
            },
            |(_, _, output), name, field, value| {
                Box::pin(async move {
                    let value = if name == "id" {
                        Self::project_id(&crate::SchemaValue::from_field(
                            value.unwrap_or_default(),
                        ))?
                        .into_field_value()
                    } else {
                        project_adapter_value(
                            value.unwrap_or_default(),
                            field,
                            field.references_id(),
                            true,
                        )
                        .await?
                    };
                    let _ = output.insert(name.to_owned(), value);
                    Ok(())
                })
            },
            |_, (_, _, output)| UserView::from_field_values(std::mem::take(output)),
            complete,
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
            let id = Self::project_id(&crate::SchemaValue::from_field(id))?;
            let _ = fields.insert("id".into(), id.into_field_value());
        }
        Ok(AccountView::from_adapter_fields(fields))
    }

    pub(super) async fn session_user_relations(
        &self,
        token_query: Value,
        only_active: bool,
        single: bool,
        relation: &ResolvedJoin,
    ) -> AuthResult<Vec<SessionSnapshot>> {
        use crate::store::schema::EntityRole;
        self.model_fields.begin_id_query(EntityRole::Session)?;
        let (token_column, token_query) = self.memory_session_token_query(token_query)?;
        let native = self.config.advanced.database.joins == Some(true);
        let expiry = only_active
            .then(|| self.memory_session_field_query("expiresAt", Utc::now().into()))
            .transpose()?;
        let rows = self
            .raw(
                "session",
                if single { "findOne" } else { "findMany" },
                |state| {
                    let sessions = crate::query::paginate_memory(
                        state.sessions.try_select_refs(|session| {
                            let token_matches = if single {
                                session_token_matches(session, &token_column, &token_query)
                            } else {
                                session_tokens_match(session, &token_column, &token_query)?
                            };
                            Ok(token_matches
                                && match &expiry {
                                    Some((column, now)) => {
                                        crate::query::field_compare(
                                            session.get(column).unwrap_or(&Value::Undefined),
                                            now,
                                        )? == Some(std::cmp::Ordering::Greater)
                                    }
                                    None => true,
                                })
                        })?,
                        Some(if single {
                            1.0
                        } else {
                            self.config.advanced.database.find_many_limit()
                        }),
                        None,
                    );
                    sessions
                        .into_iter()
                        .map(|source| {
                            if !native {
                                return Ok((SessionSource::Live(source), None));
                            }
                            let session = source.read(|session| Ok(session.clone()))?;
                            let value = session.get(&relation.from).cloned().unwrap_or_default();
                            let users = native_relation(
                                state.users.select_refs(|user| {
                                    user_value(user, &relation.logical_to, &relation.to)
                                        .strict_equals(&value)
                                })?,
                                relation,
                                self.config.advanced.database.find_many_limit(),
                                |user| user.id.field_value(),
                            )?;
                            Ok((SessionSource::Snapshot(Box::new(session)), Some(users)))
                        })
                        .collect::<AuthResult<Vec<_>>>()
                },
            )
            .await?;
        let (sessions, users): (Vec<_>, Vec<_>) = rows.into_iter().unzip();
        let fields = super::super::session_create_schema(&self.config.session, &FieldMap::new());
        self.output_sessions_batches_then(sessions, |ready| {
            let users = &users;
            let fields = &fields;
            async move {
                let mut selected = Vec::with_capacity(ready.len());
                for (index, session) in &ready {
                    let user = users.get(*index).ok_or_else(|| {
                        AuthError::internal("Session projection lost its stored join index")
                    })?;
                    selected.push(match user {
                        Some(user) => user.clone(),
                        None => {
                            self.fallback_join_users(
                                relation,
                                (EntityRole::Session, "session", fields),
                                &session.field_values()?,
                            )
                            .await?
                        }
                    });
                }
                let projected = self.output_user_relations(selected).await?;
                Ok(ready
                    .into_iter()
                    .zip(projected)
                    .map(|((index, session), user)| {
                        let data = SessionData {
                            session: session.clone(),
                            user,
                        };
                        (index, (session, Some(data)))
                    })
                    .collect())
            }
        })
        .await
    }
}
