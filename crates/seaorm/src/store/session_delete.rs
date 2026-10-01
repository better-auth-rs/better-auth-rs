use super::instrumentation::database_operation;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, EntityTrait, QueryFilter,
    QuerySelect,
};

use crate::SeaOrmStore;
use crate::error::AuthResult;
use crate::hooks::SessionUpdate;
use crate::schema::{AuthSchema, SeaOrmSessionModel};

use super::{HookTransaction, map_db_err};

use super::transaction_hooks::after_write;

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S: AuthSchema,
    S::Session: SeaOrmSessionModel,
{
    pub(super) fn session_delete_snapshot(
        &self,
        session: S::Session,
    ) -> AuthResult<better_auth_core::wire::SessionView> {
        self.output_session(&session, self.connection())
    }

    pub(super) async fn delete_sessions_with_connection(
        &self,
        db: &impl ConnectionTrait,
        transaction: Option<HookTransaction<'_, S>>,
        mut condition: Condition,
        preserve: bool,
    ) -> AuthResult<Option<usize>> {
        let now = Utc::now();
        if preserve {
            condition = condition.add(S::Session::expires_at_column().gt(now));
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
        let sessions = snapshot
            .and_then(|sessions| self.output_sessions(&sessions, db))
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
                    expires_at: Some(Utc::now()),
                    updated_at: Some(Utc::now()),
                    ..Default::default()
                },
            )?;
            self.apply_session_field_updates(&mut active)?;
            database_operation::<<S::Session as SeaOrmSessionModel>::Entity, _>(
                self.config(),
                "updateMany",
                async {
                    <S::Session as SeaOrmSessionModel>::Entity::update_many()
                        .set(active)
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
