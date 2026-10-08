//! Project persisted Sessions before joined snapshots or cookie caches consume the records.

use better_auth_core::store::schema::EntityRole;
use better_auth_core::store::{JoinValue, ResolvedJoin};
use better_auth_core::{FieldMap, UserView, session::SessionData, wire::SessionView};
use sea_orm::ConnectionTrait;

use crate::error::{AuthError, AuthResult};
use crate::schema::{AuthSchema, SeaOrmSessionModel, SeaOrmUserModel};

use super::SeaOrmStore;

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

    pub(super) async fn output_session_raw(
        &self,
        row: &sea_orm::QueryResult,
        schema: &better_auth_core::user_fields::UserConfig,
        db: &impl ConnectionTrait,
    ) -> AuthResult<SessionView> {
        use better_auth_core::FromFieldMap;
        let backend = db.get_database_backend();
        self.model_fields.begin_id_output(EntityRole::Session)?;
        let record =
            super::plugin_rows::record_from_columns::<<S::Session as SeaOrmSessionModel>::Entity>(
                row,
                schema,
                backend,
                S::Session::id_column(),
                S::Session::field_column,
            )?;
        let fields = schema
            .project_adapter_records_with_capabilities(
                vec![record],
                super::field_output::capabilities(backend),
                backend != sea_orm::DbBackend::Sqlite,
            )
            .await?
            .remove(0);
        let order = schema.fields().keys().cloned().collect::<Vec<_>>();
        let mut session = SessionView::from_field_values(fields.in_field_order(&order))?;
        session.active = match S::Session::active_column() {
            Some(column) => {
                use sea_orm::IdenStatic;
                super::plugin_rows::value(row, column.as_str())?.is_truthy()
            }
            None => true,
        };
        self.set_session_field_visibility(&mut session);
        Ok(session)
    }

    pub(super) async fn output_sessions(
        &self,
        rows: &[S::Session],
        db: &impl ConnectionTrait,
    ) -> AuthResult<Vec<SessionView>> {
        self.validate_session_fields()?;
        if !rows.is_empty() {
            self.model_fields.begin_id_output(EntityRole::Session)?;
        }
        SessionView::with_internal_fields_many_for_adapter_then(
            rows,
            &self.config().session,
            db.get_database_backend() == sea_orm::DbBackend::Postgres,
            |_, mut session| {
                self.set_session_field_visibility(&mut session);
                std::future::ready(Ok(session))
            },
        )
        .await
    }

    pub(super) async fn output_session(
        &self,
        row: &S::Session,
        db: &impl ConnectionTrait,
    ) -> AuthResult<SessionView> {
        // Projection preserves the one input row.
        Ok(self
            .output_sessions(std::slice::from_ref(row), db)
            .await?
            .remove(0))
    }

    pub(super) async fn native_session_snapshots(
        &self,
        rows: &[S::Session],
        users: &[Vec<S::User>],
        many: bool,
    ) -> AuthResult<Vec<SessionSnapshot>>
    where
        S::User: SeaOrmUserModel,
    {
        self.validate_session_fields()?;
        if !rows.is_empty() {
            self.model_fields.begin_id_output(EntityRole::Session)?;
        }
        SessionView::with_internal_fields_many_for_adapter_batches_then(
            rows,
            &self.config().session,
            self.connection().get_database_backend() == sea_orm::DbBackend::Postgres,
            |ready| async move {
                let pages = ready
                    .iter()
                    .map(|(index, _)| {
                        users.get(*index).map(Vec::as_slice).ok_or_else(|| {
                            AuthError::internal("Session projection lost its joined User page")
                        })
                    })
                    .collect::<AuthResult<Vec<_>>>()?;
                let projected = self.output_native_user_pages(pages).await?;
                ready
                    .into_iter()
                    .zip(projected)
                    .map(|((index, mut session), users)| {
                        self.set_session_field_visibility(&mut session);
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
            },
        )
        .await
    }

    pub(super) async fn fallback_session_snapshots(
        &self,
        rows: &[S::Session],
        relation: &ResolvedJoin,
    ) -> AuthResult<Vec<SessionSnapshot>>
    where
        S::User: SeaOrmUserModel,
    {
        self.validate_session_fields()?;
        if !rows.is_empty() {
            self.model_fields.begin_id_output(EntityRole::Session)?;
        }
        SessionView::with_internal_fields_many_for_adapter_then(
            rows,
            &self.config().session,
            self.connection().get_database_backend() == sea_orm::DbBackend::Postgres,
            |_, mut session| async move {
                self.set_session_field_visibility(&mut session);
                let fields = better_auth_core::store::session_create_schema(
                    &self.config().session,
                    &FieldMap::new(),
                );
                let source = relation.fallback_from(
                    (EntityRole::Session, "session", &fields),
                    &self.model_fields,
                )?;
                let value = FieldMap::from(session.clone())
                    .remove(&source)
                    .unwrap_or_default();
                let users = self
                    .selected_join_users(
                        relation,
                        value,
                        self.config().advanced.database.find_many_limit(),
                    )
                    .await?;
                let mut projected = Vec::with_capacity(users.len());
                for user in users {
                    let mut user = self.output_user(&user, self.connection()).await?;
                    self.set_join_user_visibility(&mut user);
                    projected.push(user);
                }
                let data = SessionData {
                    session: session.clone(),
                    user: super::joins::relation_value(relation.many, projected),
                };
                Ok((session, Some(data)))
            },
        )
        .await
    }
}
