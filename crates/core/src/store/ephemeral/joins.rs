//! Native joins retain child row references selected by the original raw query.

use super::rows::RowRef;
use super::sessions::SessionSource;
use super::*;
use crate::session::SessionData;
use crate::store::schema::resolve_field_name;
use crate::user_fields::{
    UserFieldConfig, project_adapter_value, project_source_fields_batches_then,
};

type UserRef = RowRef<UserView>;
type AccountRef = RowRef<FieldMap>;
type SessionSnapshot = (SessionView, Option<SessionData>);

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
        let fields = crate::user_fields::UserConfig {
            additional_fields: Some(fields),
        }
        .adapter_fields(&[]);
        let mut rows = users
            .into_iter()
            .map(|user| (user, FieldMap::new(), FieldMap::new()))
            .collect::<Vec<_>>();
        project_source_fields_batches_then(
            &mut rows,
            fields.fields(),
            |(source, native, _), name, field| {
                source.read(|user| {
                    let value = user.native_field_value(name);
                    if let Some(value) = &value {
                        let _ = native.insert(name.to_owned(), value.clone());
                    }
                    let key = resolve_field_name(field.field_name.as_deref(), name);
                    Ok(if key == "id" {
                        Some(user.id.field_value())
                    } else if matches!(name, "name" | "image") {
                        value
                    } else {
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

    pub(super) async fn joined_session_snapshot(
        &self,
        token: &str,
    ) -> AuthResult<Option<SessionSnapshot>> {
        self.model_fields
            .begin_id_query(crate::store::schema::EntityRole::Session)?;
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
        self.model_fields
            .begin_id_query(crate::store::schema::EntityRole::Session)?;
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
        let sessions = rows
            .iter()
            .map(|(session, _)| SessionSource::Snapshot(Box::new(session.clone())))
            .collect();
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
