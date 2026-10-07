//! Native joins retain child row references selected by the original raw query.

use super::account_joins::{native_relation, user_value};
use super::rows::RowRef;
use super::sessions::SessionSource;
use super::*;
use crate::session::SessionData;
use crate::store::schema::resolve_field_name;
use crate::store::{JoinValue, ResolvedJoin};
use crate::user_fields::{
    UserFieldConfig, project_adapter_value, project_source_fields_batches_then,
};

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

    pub(super) async fn session_user_relations(
        &self,
        tokens: &[String],
        only_active: bool,
        single: bool,
        relation: &ResolvedJoin,
    ) -> AuthResult<Vec<SessionSnapshot>> {
        use crate::store::schema::EntityRole;
        self.model_fields.begin_id_query(EntityRole::Session)?;
        let native = self.config.advanced.database.joins == Some(true);
        let now = Utc::now();
        let rows = self
            .raw(
                "session",
                if single { "findOne" } else { "findMany" },
                |state| {
                    let sessions = crate::query::paginate_memory(
                        state.sessions.select_refs(|session| {
                            tokens.contains(&session.token)
                                && (!only_active
                                    || session.expires_at.milliseconds()
                                        > now.timestamp_millis() as f64)
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
                            let value = session
                                .field_values()?
                                .get(&relation.from)
                                .cloned()
                                .unwrap_or_default();
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
