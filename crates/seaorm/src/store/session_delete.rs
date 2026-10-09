use super::instrumentation::database_operation;
use better_auth_core::{FieldValue, store::schema::EntityRole};
use chrono::Utc;
use sea_orm::{
    ColumnTrait, Condition, ConnectionTrait, DbBackend, EntityTrait, QueryFilter, QuerySelect,
    sea_query::ExprTrait,
};

use crate::SeaOrmStore;
use crate::error::{AuthError, AuthResult};
use crate::schema::{AuthSchema, SeaOrmSessionModel};

use super::{HookTransaction, map_db_err};

use super::transaction_hooks::after_write;

#[cfg(test)]
#[path = "session_token_delete_tests.rs"]
mod token_tests;

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S: AuthSchema,
    S::Session: SeaOrmSessionModel,
{
    pub(super) fn session_token_filter(
        &self,
        token: &FieldValue,
        backend: DbBackend,
    ) -> AuthResult<sea_orm::sea_query::SimpleExpr> {
        let (column, value) = self.session_query_field("token", token, backend)?;
        super::value_filter::equals(column, &value, backend)
    }

    pub(super) fn session_tokens_filter(
        &self,
        tokens: &[String],
        backend: DbBackend,
    ) -> AuthResult<sea_orm::sea_query::SimpleExpr> {
        let tokens = tokens
            .iter()
            .cloned()
            .map(FieldValue::from)
            .collect::<Vec<_>>()
            .into();
        let (column, value) = self.session_query_field("token", &tokens, backend)?;
        super::value_filter::is_in(column, &value, backend)
    }

    pub(super) fn session_user_filter(
        &self,
        user_id: &FieldValue,
        backend: DbBackend,
    ) -> AuthResult<sea_orm::sea_query::SimpleExpr> {
        let (column, value) = self.session_query_field("userId", user_id, backend)?;
        super::value_filter::equals(column, &value, backend)
    }

    pub(super) fn session_live_filter(
        &self,
        now: &FieldValue,
        backend: DbBackend,
    ) -> AuthResult<sea_orm::sea_query::SimpleExpr> {
        let (column, value) = self.session_query_field("expiresAt", now, backend)?;
        let value = super::record_bindings::parameter(value, backend)?;
        Ok(column.into_expr().gt(column.save_as(value)))
    }

    pub(super) fn session_query_field(
        &self,
        name: &str,
        original: &FieldValue,
        backend: DbBackend,
    ) -> AuthResult<(<S::Session as SeaOrmSessionModel>::Column, FieldValue)> {
        self.model_fields.begin_id_query(EntityRole::Session)?;
        let schema = better_auth_core::store::session_create_schema(
            &self.config().session,
            &Default::default(),
        );
        let field = schema
            .fields()
            .get(name)
            .ok_or_else(|| AuthError::config(format!("Unknown session field: {name}")))?;
        let value = if name == "id" || field.references_id() {
            self.config()
                .advanced
                .database
                .generate_id()
                .adapter_id_query(original.clone())?
        } else {
            original.clone()
        };
        let value = better_auth_core::user_query::bind_filter(field, &value)?;
        let value = super::value_filter::adapter_query_value(value, original, field, backend)?;
        Ok((
            S::Session::field_column(schema.record_storage_key(name))?,
            value,
        ))
    }

    pub(super) async fn delete_sessions_with_connection(
        &self,
        db: &impl ConnectionTrait,
        transaction: Option<HookTransaction<'_, S>>,
        bind: impl Fn() -> AuthResult<Condition> + Send + Sync,
        preserve: bool,
    ) -> AuthResult<Option<usize>> {
        let backend = db.get_database_backend();
        let live_since = preserve.then(|| FieldValue::from(Utc::now()));
        let bind_condition = || -> AuthResult<Condition> {
            let mut condition = bind()?;
            if let Some(now) = &live_since {
                condition = condition.add(self.session_live_filter(now, backend)?);
            }
            Ok(condition)
        };
        // Upstream catches snapshot conversion, query and projection failures before the batch write.
        let sessions = async {
            let condition = bind_condition()?;
            let sessions = database_operation::<<S::Session as SeaOrmSessionModel>::Entity, _>(
                self.config(),
                "findMany",
                async {
                    super::plugin_rows::all(
                        db,
                        <S::Session as SeaOrmSessionModel>::Entity::find()
                            .filter(condition)
                            .limit(super::pagination::default_limit(self.config(), backend)?),
                    )
                    .await
                },
            )
            .await?;
            self.output_sessions(&sessions, db).await
        }
        .await
        .unwrap_or_default();
        let context = self.hook_context(transaction);
        for session in &sessions {
            for hook in self.hooks() {
                if better_auth_core::observability::database::with_database_hook(
                    context.config,
                    hook.hook_metadata(),
                    better_auth_core::observability::database::DatabaseHook::BeforeDeleteSession,
                    hook.before_delete_session(session, &context),
                )
                .await?
                .is_cancelled()
                {
                    return Ok(None);
                }
            }
        }

        // One statement preserves the all-before/all-write/all-after batch boundary.
        let update = preserve.then(|| [("expiresAt".into(), Utc::now().into())].into());
        let condition = bind_condition()?;
        let count = if let Some(update) = update {
            let (active, _) = self.prepare_session_update(db, update).await?;
            database_operation::<<S::Session as SeaOrmSessionModel>::Entity, _>(
                self.config(),
                "updateMany",
                async {
                    active
                        .update(backend)?
                        .filter(condition)
                        .exec(db)
                        .await
                        .map_err(map_db_err)
                },
            )
            .await?
            .rows_affected
        } else {
            database_operation::<<S::Session as SeaOrmSessionModel>::Entity, _>(
                self.config(),
                "deleteMany",
                async {
                    <S::Session as SeaOrmSessionModel>::Entity::delete_many()
                        .filter(condition)
                        .exec(db)
                        .await
                        .map_err(map_db_err)
                },
            )
            .await?
            .rows_affected
        };
        for session in sessions {
            let store = self.clone();
            let request = context.request.clone();
            after_write(
                transaction,
                Box::pin(async move {
                    let mut context = store.hook_context(None);
                    context.request = request;
                    for hook in store.hooks() {
                        better_auth_core::observability::database::with_database_hook(context.config, hook.hook_metadata(), better_auth_core::observability::database::DatabaseHook::AfterDeleteSession, hook.after_delete_session(&session, &context)).await?;
                    }
                    Ok(())
                }),
            )
            .await?;
        }
        Ok(Some(count as usize))
    }
}
