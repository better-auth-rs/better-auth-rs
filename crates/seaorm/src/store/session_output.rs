//! Project persisted Sessions before joined snapshots or cookie caches consume the records.

use better_auth_core::store::schema::EntityRole;
use better_auth_core::store::{JoinValue, ResolvedJoin};
use better_auth_core::{
    FieldMap, FromFieldMap, UserView,
    session::SessionData,
    user_fields::{AdapterRecord, UserConfig},
    wire::SessionView,
};
use sea_orm::{ConnectionTrait, DbBackend, EntityName, IdenStatic};

use crate::error::{AuthError, AuthResult};
use crate::schema::{AuthSchema, SeaOrmSessionModel, SeaOrmUserModel};

use super::{SeaOrmStore, plugin_rows::SqlRow};

pub(super) type SessionSnapshot = (SessionView, Option<SessionData<JoinValue<UserView>>>);

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S: AuthSchema,
    S::Session: SeaOrmSessionModel,
{
    fn set_session_field_visibility(&self, session: &mut SessionView) {
        session.visible_fields = Some(
            self.model_fields
                .session_plugin_fields()
                .iter()
                .copied()
                .chain(self.config().session.fields().keys().map(String::as_str))
                .filter(|name| {
                    session
                        .visible_fields
                        .as_ref()
                        .is_none_or(|fields| fields.contains(*name))
                })
                .map(str::to_owned)
                .collect(),
        );
    }

    fn session_records(
        &self,
        rows: &[SqlRow],
        schema: &UserConfig,
        backend: DbBackend,
    ) -> AuthResult<Vec<AdapterRecord>> {
        self.validate_session_fields()?;
        rows.iter()
            .map(|row| {
                row.record::<<S::Session as SeaOrmSessionModel>::Entity>(
                    schema,
                    backend,
                    S::Session::id_column(),
                    S::Session::field_column,
                )
                .map(|record| record.with_id_output(&self.model_fields, EntityRole::Session))
            })
            .collect()
    }

    fn session_from_output(
        &self,
        rows: &[SqlRow],
        index: usize,
        schema: &UserConfig,
        output: FieldMap,
    ) -> AuthResult<SessionView> {
        let row = rows
            .get(index)
            .ok_or_else(|| AuthError::internal("Session projection lost its source row"))?;
        let mut output = super::plugin_rows::ordered_output(schema, output);
        let order = output.keys().cloned().collect();
        // The enumerable active field is independent of the model's private liveness state.
        let active = output.shift_remove("active");
        let mut session = SessionView::from_field_values(output)?;
        session.field_order = order;
        if let Some(active) = active {
            let _ = session.additional_fields.insert("active".into(), active);
        }
        session.active = match S::Session::active_column() {
            Some(column) => row.value(column.as_str())?.is_truthy(),
            None => true,
        };
        self.set_session_field_visibility(&mut session);
        Ok(session)
    }

    async fn output_sessions_with_schema(
        &self,
        rows: &[SqlRow],
        schema: &UserConfig,
        db: &impl ConnectionTrait,
    ) -> AuthResult<Vec<SessionView>> {
        let backend = db.get_database_backend();
        let records = self.session_records(rows, schema, backend)?;
        schema
            .project_adapter_records_then(
                records,
                backend == DbBackend::Postgres,
                backend != DbBackend::Sqlite,
                |index, output| {
                    std::future::ready(self.session_from_output(rows, index, schema, output))
                },
            )
            .await
    }

    pub(super) async fn output_sessions(
        &self,
        rows: &[SqlRow],
        db: &impl ConnectionTrait,
    ) -> AuthResult<Vec<SessionView>> {
        let schema = better_auth_core::store::session_create_schema(
            &self.config().session,
            &FieldMap::new(),
        );
        self.output_sessions_with_schema(rows, &schema, db).await
    }

    pub(super) async fn output_session_raw(
        &self,
        row: &SqlRow,
        schema: &UserConfig,
        db: &impl ConnectionTrait,
    ) -> AuthResult<SessionView> {
        // Projection preserves the one input row.
        Ok(self
            .output_sessions_with_schema(std::slice::from_ref(row), schema, db)
            .await?
            .remove(0))
    }

    pub(super) async fn native_session_snapshots(
        &self,
        rows: &[SqlRow],
        users: &[Vec<SqlRow>],
        many: bool,
    ) -> AuthResult<Vec<SessionSnapshot>>
    where
        S::User: SeaOrmUserModel,
    {
        let backend = self.connection().get_database_backend();
        let schema = better_auth_core::store::session_create_schema(
            &self.config().session,
            &FieldMap::new(),
        );
        let records = self.session_records(rows, &schema, backend)?;
        let user_fields = self.user_field_schema().adapter_fields(&[]);
        let entity = <S::User as SeaOrmUserModel>::Entity::default();
        let physical = self
            .model_fields
            .storage_model_name(EntityRole::User, entity.table_name());
        let records = records
            .into_iter()
            .zip(users)
            .map(|(record, users)| {
                Ok(record.with_storage_property(
                    physical,
                    super::joins::raw_relation_value(
                        users,
                        &user_fields,
                        many,
                        S::User::field_column,
                    )?,
                ))
            })
            .collect::<AuthResult<Vec<_>>>()?;
        schema
            .project_adapter_records_batches_then(
                records,
                backend == DbBackend::Postgres,
                backend != DbBackend::Sqlite,
                |ready| {
                    let schema = &schema;
                    async move {
                        let ready = ready
                            .into_iter()
                            .map(|(index, output)| {
                                self.session_from_output(rows, index, schema, output)
                                    .map(|session| (index, session))
                            })
                            .collect::<AuthResult<Vec<_>>>()?;
                        let pages = ready
                            .iter()
                            .map(|(index, _)| {
                                users.get(*index).map(Vec::as_slice).ok_or_else(|| {
                                    AuthError::internal(
                                        "Session projection lost its joined User page",
                                    )
                                })
                            })
                            .collect::<AuthResult<Vec<_>>>()?;
                        let projected = self.output_native_user_pages(pages).await?;
                        ready
                            .into_iter()
                            .zip(projected)
                            .map(|((index, session), users)| {
                                let users = users
                                    .into_iter()
                                    .map(UserView::try_from)
                                    .collect::<AuthResult<Vec<_>>>()?;
                                let data = SessionData {
                                    session: session.clone(),
                                    user: super::joins::relation_value(many, users),
                                };
                                Ok((index, (session, Some(data))))
                            })
                            .collect()
                    }
                },
            )
            .await
    }

    pub(super) async fn fallback_session_snapshots(
        &self,
        rows: &[SqlRow],
        relation: &ResolvedJoin,
    ) -> AuthResult<Vec<SessionSnapshot>>
    where
        S::User: SeaOrmUserModel,
    {
        let backend = self.connection().get_database_backend();
        let schema = better_auth_core::store::session_create_schema(
            &self.config().session,
            &FieldMap::new(),
        );
        let records = self.session_records(rows, &schema, backend)?;
        schema
            .project_adapter_records_then(
                records,
                backend == DbBackend::Postgres,
                backend != DbBackend::Sqlite,
                |index, output| {
                    let schema = &schema;
                    async move {
                        let source = relation.fallback_from(
                            (EntityRole::Session, "session", schema),
                            &self.model_fields,
                        )?;
                        let value = output.get(&source).cloned().unwrap_or_default();
                        let session = self.session_from_output(rows, index, schema, output)?;
                        let users = self
                            .selected_join_users(
                                relation,
                                value,
                                self.config().advanced.database.find_many_limit(),
                            )
                            .await?;
                        let mut projected = Vec::with_capacity(users.len());
                        for user in users {
                            let user = self.output_user(&user, self.connection()).await?;
                            projected.push(user);
                        }
                        let data = SessionData {
                            session: session.clone(),
                            user: super::joins::relation_value(relation.many, projected),
                        };
                        Ok((session, Some(data)))
                    }
                },
            )
            .await
    }
}
