use super::instrumentation::database_operation;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, EntityTrait, QueryFilter,
};

use crate::SeaOrmStore;
use crate::error::AuthResult;
use crate::hooks::SessionUpdate;
use crate::schema::{AuthSchema, SeaOrmSessionModel};
use better_auth_core::{AuthSession, user_fields::UserFieldType, wire::SessionView};
use serde_json::{Map, Value};

use super::{HookTransaction, map_db_err};

use super::transaction_hooks::after_write;

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S: AuthSchema,
    S::Session: SeaOrmSessionModel,
{
    fn session_delete_needs_projection(&self) -> bool {
        self.config()
            .session
            .additional_fields
            .values()
            .any(|field| {
                field.output_transform.is_some()
                    || field.references_id()
                    || matches!(field.field_type, UserFieldType::Date | UserFieldType::Json)
            })
    }

    pub(super) fn validate_session_delete_projection(&self) -> AuthResult<()> {
        if self.session_delete_needs_projection() && !S::Session::SUPPORTS_RUNTIME_HYDRATION {
            return Err(better_auth_core::AuthError::config(
                "Session delete hooks with configured fields require AuthSession runtime hydration; derive AuthEntity or implement from_runtime_fields",
            ));
        }
        Ok(())
    }

    pub(super) fn session_delete_snapshot(&self, session: S::Session) -> AuthResult<S::Session> {
        if !self.session_delete_needs_projection() {
            return Ok(session);
        }
        let view = SessionView::with_internal_fields_for_adapter(
            &session,
            &self.config().session,
            self.connection().get_database_backend() == sea_orm::DbBackend::Postgres,
        )?;
        // Preserve application columns that are not part of the configured public schema.
        let mut fields: Map<String, Value> =
            serde_json::from_value(serde_json::to_value(&session)?)?;
        let mut projected: Map<String, Value> = view.into();
        for (name, config) in &self.config().session.additional_fields {
            let storage = config.field_name.as_ref().unwrap_or(name);
            match projected.remove(name) {
                Some(value) => {
                    let _ = fields.insert(storage.clone(), value);
                }
                None => {
                    let _ = fields.remove(storage);
                }
            }
        }
        // Keep typed serialized IDs; the public view renders every ID as a string.
        for (name, value) in projected {
            let _ = fields.entry(name).or_insert(value);
        }
        S::Session::from_runtime_fields(fields)
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
                    .all(db)
                    .await
                    .map_err(map_db_err)
            },
        )
        .await;
        // Upstream deleteManyWithHooks ignores snapshot failures only. The batch write still runs.
        let sessions = snapshot
            .and_then(|sessions| {
                sessions
                    .into_iter()
                    .map(|session| self.session_delete_snapshot(session))
                    .collect::<AuthResult<Vec<_>>>()
            })
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
            after_write(
                transaction,
                Box::pin(async move {
                    let context = store.hook_context(None);
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
