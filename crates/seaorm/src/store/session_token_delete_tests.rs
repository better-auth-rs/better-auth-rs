#![expect(
    clippy::panic_in_result_fn,
    reason = "Tests intentionally panic when fixture setup or adapter contract assertions fail."
)]

use super::*;
use crate::hooks::{HookControl, SeaOrmHookContext, SeaOrmHooks};
use crate::store::{bundled_schema::BundledSchema, entities::session, migrator::run_migrations};
use better_auth_core::{
    AuthConfig, AuthError, CreateSession, CreateUser, FieldFunction, FieldValue,
    store::{SessionStore, UserStore},
    user_fields::{UserFieldConfig, UserFieldType},
    wire::SessionView,
};
use sea_orm::{ColumnTrait, Database, sea_query::Expr};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[tokio::test]
async fn session_queries_reject_unknown_names_before_query_callbacks() -> AuthResult<()> {
    for array in [false, true] {
        let database = Database::connect("sqlite::memory:")
            .await
            .map_err(map_db_err)?;
        run_migrations(&database).await.map_err(map_db_err)?;
        let store = SeaOrmStore::<BundledSchema>::new(AuthConfig::default(), database.clone());
        let owner = store
            .create_user(
                CreateUser::new()
                    .with_name("Session owner")
                    .with_email("session-query@example.test"),
            )
            .await?;
        let _ = store
            .create_session(CreateSession {
                inherited_fields: Default::default(),
                additional_fields: Default::default(),
                user_id: owner.id,
                expires_at: (Utc::now() + chrono::Duration::hours(1)).into(),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await?;
        let before = session::Entity::find()
            .all(&database)
            .await
            .map_err(map_db_err)?;
        let calls = Arc::new(AtomicUsize::new(0));
        let query_calls = calls.clone();
        let callback: FieldValue = FieldFunction::contextual(move |_, _| {
            let _ = query_calls.fetch_add(1, Ordering::SeqCst);
            Err(AuthError::internal("session-predicate-error"))
        })
        .into();
        let value = if array {
            vec![callback].into()
        } else {
            callback
        };
        let backend = database.get_database_backend();
        let result = (|| {
            let predicates = [
                ("userId", value, WhereOperator::Eq),
                ("unknownExpiry", Utc::now().into(), WhereOperator::Gt),
            ]
            .into_iter()
            .map(|(name, value, operator)| {
                Ok((
                    store.bind_session_query_field(name, &value, backend)?,
                    operator,
                ))
            })
            .collect::<AuthResult<Vec<_>>>()?;
            store.resolve_session_predicates(predicates, backend)
        })();
        let Err(AuthError::Config(message)) = result else {
            return Err(AuthError::internal(format!(
                "Expected the unknown Session field error for array={array}: {result:?}"
            )));
        };
        assert_eq!(message, "Field unknownExpiry not found in model session");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            session::Entity::find()
                .all(&database)
                .await
                .map_err(map_db_err)?,
            before
        );
    }
    Ok(())
}

struct ObserveDelete {
    calls: Arc<AtomicUsize>,
    preserve: bool,
}

#[better_auth_core::database_hooks()]
impl SeaOrmHooks<BundledSchema> for ObserveDelete {
    async fn before_delete_session(
        &self,
        session: &SessionView,
        ctx: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<HookControl> {
        assert_eq!(self.calls.fetch_add(1, Ordering::SeqCst), 0);
        assert_eq!(
            better_auth_core::FieldMap::from(session.clone())
                .get("token")
                .map(FieldValue::json)
                .transpose()?
                .flatten(),
            Some(serde_json::json!({"secret":7}))
        );
        assert!(
            session::Entity::find_by_id(session.id.typed()?.clone())
                .one(ctx.db)
                .await
                .map_err(map_db_err)?
                .is_some()
        );
        Ok(HookControl::Continue)
    }

    async fn after_delete_session(
        &self,
        session: &SessionView,
        ctx: &SeaOrmHookContext<'_, BundledSchema>,
    ) -> AuthResult<()> {
        assert_eq!(self.calls.fetch_add(1, Ordering::SeqCst), 1);
        let stored = session::Entity::find_by_id(session.id.typed()?.clone())
            .one(ctx.db)
            .await
            .map_err(map_db_err)?;
        if self.preserve {
            assert!(stored.is_some_and(|row| row.expires_at <= Utc::now()));
        } else {
            assert!(stored.is_none());
        }
        Ok(())
    }
}

#[tokio::test]
async fn dynamic_token_deletion_keeps_native_query_values_and_hook_order() -> AuthResult<()> {
    for preserve in [false, true] {
        let database = Database::connect("sqlite::memory:")
            .await
            .map_err(map_db_err)?;
        run_migrations(&database).await.map_err(map_db_err)?;
        let mut config = AuthConfig::new("a-secret-that-is-at-least-32-characters");
        let store = SeaOrmStore::<BundledSchema>::new(config.clone(), database.clone());
        let owner = store
            .create_user(
                CreateUser::new()
                    .with_name("Session owner")
                    .with_email("native-token@example.test"),
            )
            .await?;
        let created = store
            .create_session(CreateSession {
                inherited_fields: Default::default(),
                additional_fields: Default::default(),
                user_id: owner.id,
                expires_at: (Utc::now() + chrono::Duration::hours(1)).into(),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await?;
        let _ = session::Entity::update_many()
            .col_expr(session::Column::Token, Expr::value(r#"{"secret":7}"#))
            .filter(session::Column::Id.eq(created.id.typed()?.clone()))
            .exec(&database)
            .await
            .map_err(map_db_err)?;
        let _ = config.session.fields_mut().insert(
            "token".into(),
            UserFieldConfig {
                field_type: UserFieldType::Json,
                ..Default::default()
            },
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let store = SeaOrmStore::<BundledSchema>::new(config, database).hook(ObserveDelete {
            calls: calls.clone(),
            preserve,
        });
        let token = FieldValue::from_json(serde_json::json!({"secret":7}))?;
        for _ in 0..2 {
            if preserve {
                store.end_session_by_token_value(&token).await?;
            } else {
                store.delete_session_by_token_value(&token).await?;
            }
            assert_eq!(calls.load(Ordering::SeqCst), 2);
        }
    }
    Ok(())
}
