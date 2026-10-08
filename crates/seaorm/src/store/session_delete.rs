use super::instrumentation::database_operation;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, EntityTrait, QueryFilter,
    QuerySelect, sea_query::ExprTrait,
};

use crate::SeaOrmStore;
use crate::error::AuthResult;
use crate::hooks::SessionUpdate;
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
        token: &better_auth_core::FieldValue,
    ) -> AuthResult<sea_orm::sea_query::SimpleExpr> {
        let field = self
            .config()
            .session
            .fields()
            .get("token")
            .cloned()
            .unwrap_or_default();
        let backend = self.connection().get_database_backend();
        let value = if field.references_id() {
            self.config()
                .advanced
                .database
                .generate_id()
                .adapter_id_query(token.clone())?
        } else {
            token.clone()
        };
        let value = better_auth_core::user_query::bind_filter(&field, &value)?;
        let value = super::value_filter::adapter_query_value(value, token, &field, backend)?;
        let name = better_auth_core::store::schema::resolve_field_name(
            field.field_name.as_deref(),
            "token",
        );
        super::value_filter::equals(S::Session::field_column(name)?, &value, backend)
    }

    pub(super) async fn session_delete_snapshot(
        &self,
        session: S::Session,
    ) -> AuthResult<better_auth_core::wire::SessionView> {
        self.output_session(&session, self.connection()).await
    }

    pub(super) async fn delete_sessions_with_connection(
        &self,
        db: &impl ConnectionTrait,
        transaction: Option<HookTransaction<'_, S>>,
        mut condition: Condition,
        preserve: bool,
    ) -> AuthResult<Option<usize>> {
        self.model_fields
            .begin_id_query(better_auth_core::store::schema::EntityRole::Session)?;
        let now = Utc::now();
        if preserve {
            let now = super::record_bindings::Binding::Date(now.into())
                .bind(db.get_database_backend())?;
            let expires_at = S::Session::expires_at_column();
            condition = condition.add(expires_at.into_expr().gt(expires_at.save_as(now)));
        }
        let snapshot = database_operation::<<S::Session as SeaOrmSessionModel>::Entity, _>(
            self.config(),
            "findMany",
            async {
                <S::Session as SeaOrmSessionModel>::Entity::find()
                    .filter(condition.clone())
                    .limit(super::pagination::default_limit(
                        self.config(),
                        db.get_database_backend(),
                    )?)
                    .all(db)
                    .await
                    .map_err(map_db_err)
            },
        )
        .await;
        // Upstream deleteManyWithHooks ignores snapshot failures only. The batch write still runs.
        let sessions = match snapshot {
            Ok(sessions) => self.output_sessions(&sessions, db).await,
            Err(error) => Err(error),
        }
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
        let count = if preserve {
            let mut active = <S::Session as SeaOrmSessionModel>::ActiveModel::default();
            S::Session::apply_update(
                &mut active,
                SessionUpdate {
                    expires_at: Some(Utc::now().into()),
                    updated_at: Some(Utc::now().into()),
                    ..Default::default()
                },
            )?;
            let active = self.apply_session_field_updates(active).await?;
            database_operation::<<S::Session as SeaOrmSessionModel>::Entity, _>(
                self.config(),
                "updateMany",
                async {
                    active
                        .update(db.get_database_backend())?
                        .filter(condition)
                        .exec(db)
                        .await
                        .map_err(map_db_err)
                },
            )
            .await?
            .rows_affected
        } else {
            self.model_fields
                .begin_id_query(better_auth_core::store::schema::EntityRole::Session)?;
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
