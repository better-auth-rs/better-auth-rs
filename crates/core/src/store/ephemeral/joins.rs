//! Native joins retain child row references selected by the original raw query.

use super::native_joins::native_relationships;
use super::rows::RecordSource;
use super::rows::RowRef;
use super::*;
use crate::session::SessionData;
use crate::store::{JoinValue, schema::EntityRole};

type UserRef = RowRef<FieldMap>;
type SessionSnapshot = (SessionView, Option<SessionData<JoinValue<UserView>>>);

impl EphemeralStore {
    pub(super) async fn output_user_refs(&self, users: Vec<UserRef>) -> AuthResult<Vec<UserView>> {
        self.output_user_refs_batches_then(users, |ready| std::future::ready(Ok(ready)))
            .await
    }

    pub(super) async fn output_user_refs_batches_then<R: Send + 'static, F>(
        &self,
        users: Vec<UserRef>,
        complete: impl Fn(Vec<(usize, UserView)>) -> F + Send + Sync + 'static,
    ) -> AuthResult<Vec<R>>
    where
        F: std::future::Future<Output = AuthResult<Vec<(usize, R)>>> + Send + 'static,
    {
        self.project_record_sources_owned_batches_then(
            EntityRole::User,
            &self.field_policy().user(),
            users.into_iter().map(RecordSource::Live).collect(),
            |_, fields| UserView::from_field_values(fields),
            complete,
        )
        .await
    }

    pub(super) async fn session_user_relations(
        &self,
        token_query: Value,
        only_active: bool,
        single: bool,
    ) -> AuthResult<Vec<SessionSnapshot>> {
        let (token_column, token_query) = self.memory_session_token_query(token_query)?;
        let native = self.config.advanced.database.joins == Some(true);
        let expiry = only_active
            .then(|| self.memory_session_field_query("expiresAt", Utc::now().into()))
            .transpose()?;
        let relation = SessionData::resolve_schema(&self.config, &self.model_fields, |_, _| false)?;
        let rows = self
            .raw(
                "session",
                if single { "findOne" } else { "findMany" },
                |op| {
                    let sessions =
                        op.capture_table(EntityRole::Session)?
                            .select_refs(|session| {
                                let clauses = std::iter::once((
                                    &token_column,
                                    &token_query,
                                    if single {
                                        crate::WhereOperator::Eq
                                    } else {
                                        crate::WhereOperator::In
                                    },
                                ))
                                .chain(expiry.as_ref().map(|(column, value)| {
                                    (column, value, crate::WhereOperator::Gt)
                                }));
                                crate::memory_query::matches_all(
                                    clauses,
                                    |(column, value, operator)| {
                                        crate::memory_query::matches(
                                            session.field(column)?.as_ref(),
                                            value,
                                            operator,
                                            crate::WhereMode::Sensitive,
                                        )
                                    },
                                )
                            })?
                            .into_iter()
                            .map(RecordSource::Live)
                            .collect();
                    let limit = Some(if single {
                        1.0
                    } else {
                        self.config.advanced.database.find_many_limit()
                    });
                    if !native {
                        return Ok(crate::query::paginate_memory(sessions, limit, None)
                            .into_iter()
                            .map(|source| (source, None))
                            .collect::<Vec<_>>());
                    }
                    let groups = native_relationships(
                        sessions,
                        &[(
                            EntityRole::User,
                            &relation,
                            self.config.advanced.database.find_many_limit(),
                        )],
                        |role| op.capture_join_table(role),
                    )?;
                    Ok(crate::query::paginate_memory(groups, limit, None)
                        .into_iter()
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
                            (source, Some(users))
                        })
                        .collect::<Vec<_>>())
                },
            )
            .await?;
        let (sessions, users): (Vec<_>, Vec<_>) = rows.into_iter().unzip();
        let fields = self
            .model_fields
            .bind(&self.config)
            .session(&FieldMap::new())
            .adapter_fields(&[]);
        let continuation = Arc::new((users, fields, relation));
        let store = self.clone();
        self.output_sessions_batches_then(sessions, move |ready| {
            let continuation = continuation.clone();
            let store = store.clone();
            async move {
                let (users, fields, relation) = continuation.as_ref();
                let mut selected = Vec::with_capacity(ready.len());
                for (index, session) in &ready {
                    let user = users.get(*index).ok_or_else(|| {
                        AuthError::internal("Session projection lost its stored join index")
                    })?;
                    selected.push(match user {
                        Some(user) => user.clone(),
                        None => {
                            store
                                .fallback_join_users(
                                    relation,
                                    (EntityRole::Session, "session", fields),
                                    &session.field_values()?,
                                )
                                .await?
                        }
                    });
                }
                let projected = store.output_user_relations(selected).await?;
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
