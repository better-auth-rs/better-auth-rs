use super::instrumentation::database_operation;
use crate::store::query_compile::Execute;
use better_auth_core::{FieldValue, WhereMode, WhereOperator, store::schema::EntityRole};
use chrono::Utc;
use sea_orm::{
    Condition, ConnectionTrait, DbBackend, EntityTrait, QueryFilter, QuerySelect,
    sea_query::SimpleExpr,
};

use crate::SeaOrmStore;
use crate::error::AuthResult;
use crate::schema::{AuthSchema, SeaOrmSessionModel};

use super::HookTransaction;
#[cfg(test)]
use super::map_db_err;
use super::value_filter::{self, BoundQueryField, QueryPredicate};

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

    pub(super) fn bind_session_tokens(
        &self,
        tokens: &[String],
        backend: DbBackend,
    ) -> AuthResult<super::value_filter::BoundQueryField> {
        let tokens = tokens
            .iter()
            .cloned()
            .map(FieldValue::from)
            .collect::<Vec<_>>()
            .into();
        self.bind_session_query_field("token", &tokens, backend)
    }

    pub(super) fn resolve_session_predicates(
        &self,
        predicates: impl IntoIterator<Item = (BoundQueryField, WhereOperator)>,
        backend: DbBackend,
    ) -> AuthResult<Condition> {
        value_filter::all(self.session_query_predicates(predicates)?, backend)
    }

    fn session_query_predicates(
        &self,
        predicates: impl IntoIterator<Item = (BoundQueryField, WhereOperator)>,
    ) -> AuthResult<Vec<QueryPredicate<<S::Session as SeaOrmSessionModel>::Column>>> {
        predicates
            .into_iter()
            .map(|(bound, operator)| {
                let (column, value) = self.resolve_session_query_field(bound)?;
                Ok(
                    QueryPredicate::new(column, operator, WhereMode::Sensitive, value)
                        .with_save_as(),
                )
            })
            .collect()
    }

    pub(super) fn session_query_field(
        &self,
        name: &str,
        original: &FieldValue,
        backend: DbBackend,
    ) -> AuthResult<(<S::Session as SeaOrmSessionModel>::Column, FieldValue)> {
        let bound = self.bind_session_query_field(name, original, backend)?;
        self.resolve_session_query_field(bound)
    }

    pub(super) fn resolve_session_query_field(
        &self,
        bound: super::value_filter::BoundQueryField,
    ) -> AuthResult<(<S::Session as SeaOrmSessionModel>::Column, FieldValue)> {
        let schema = self.field_policy().session(&Default::default());
        let (column, value) = bound.resolve(EntityRole::Session, &schema)?;
        Ok((S::Session::field_column(&column)?, value))
    }

    pub(super) fn bind_session_query_field(
        &self,
        name: &str,
        original: &FieldValue,
        backend: DbBackend,
    ) -> AuthResult<super::value_filter::BoundQueryField> {
        let schema = self.field_policy().session(&Default::default());
        self.bind_query_field(EntityRole::Session, &schema, name, original, backend)
    }

    pub(super) async fn delete_sessions_with_connection(
        &self,
        db: &impl ConnectionTrait,
        transaction: Option<HookTransaction<'_, S>>,
        bind: impl Fn() -> AuthResult<super::value_filter::BoundQueryField> + Send + Sync,
        operator: WhereOperator,
        or_condition: Option<SimpleExpr>,
        preserve: bool,
    ) -> AuthResult<Option<usize>> {
        let backend = db.get_database_backend();
        let live_since = preserve.then(|| FieldValue::from(Utc::now()));
        let bind_condition = || -> AuthResult<_> {
            let bound = bind()?;
            let live = live_since
                .as_ref()
                .map(|now| self.bind_session_query_field("expiresAt", now, backend))
                .transpose()?;
            Ok((bound, live))
        };
        let resolve_condition = |(bound, live): (
            _,
            Option<super::value_filter::BoundQueryField>,
        )|
         -> AuthResult<Condition> {
            let condition = self.resolve_session_predicates(
                std::iter::once((bound, operator))
                    .chain(live.map(|live| (live, WhereOperator::Gt))),
                backend,
            )?;
            Ok(match &or_condition {
                Some(extra) => Condition::any().add(condition).add(extra.clone()),
                None => condition,
            })
        };
        // Upstream catches snapshot conversion, query and projection failures before the batch write.
        let sessions = async {
            let condition = resolve_condition(bind_condition()?)?;
            let sessions = database_operation::<<S::Session as SeaOrmSessionModel>::Entity, _>(
                self.config(),
                "findMany",
                async {
                    super::plugin_rows::all(
                            db,
                            super::plugin_rows::select_all::<
                                <S::Session as SeaOrmSessionModel>::Entity,
                            >()
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
                    let (bound, live) = condition;
                    let predicates = self.session_query_predicates(
                        std::iter::once((bound, operator))
                            .chain(live.map(|live| (live, WhereOperator::Gt))),
                    )?;
                    active
                        .update_where(backend, predicates)?
                        .query
                        .exec_native(db)
                        .await
                },
            )
            .await?
            .rows_affected
        } else {
            let condition = resolve_condition(condition)?;
            database_operation::<<S::Session as SeaOrmSessionModel>::Entity, _>(
                self.config(),
                "deleteMany",
                async {
                    <S::Session as SeaOrmSessionModel>::Entity::delete_many()
                        .filter(condition)
                        .exec_native(db)
                        .await
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
