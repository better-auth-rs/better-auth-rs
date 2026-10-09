use super::*;
use crate::store::database_hooks::{DatabaseHookContext, DatabaseHookControl, DatabaseHooks};

type Events = Arc<Mutex<Vec<(&'static str, String)>>>;

struct Hooks {
    mode: &'static str,
    events: Events,
}

impl Hooks {
    fn record(&self, phase: &'static str, session: &SessionView) -> AuthResult<()> {
        self.events
            .lock()
            .map_err(|_| AuthError::internal("Native Session hook trace lock poisoned"))?
            .push((phase, session.token.typed()?.clone()));
        Ok(())
    }
}

#[crate::database_hooks()]
impl DatabaseHooks<StatelessSchema> for Hooks {
    async fn before_delete_session(
        &self,
        session: &SessionView,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookControl> {
        self.record("before", session)?;
        Ok(if self.mode == "cancel" && session.token == "target-b" {
            DatabaseHookControl::Cancel
        } else {
            DatabaseHookControl::Continue
        })
    }

    async fn after_delete_session(
        &self,
        session: &SessionView,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        self.record("after", session)?;
        if self.mode == "after-error" {
            return Err(AuthError::internal("native-session-after"));
        }
        Ok(())
    }
}

async fn seed(store: &EphemeralStore, token: &str, owner: Value) -> AuthResult<()> {
    let _ = store
        .create_session(CreateSession {
            inherited_fields: Default::default(),
            user_id: crate::SchemaValue::from_field(owner),
            expires_at: (Utc::now() + chrono::Duration::hours(1)).into(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            additional_fields: [("token".into(), token.into())].into(),
        })
        .await?;
    Ok(())
}

fn tokens(sessions: Vec<SessionView>) -> AuthResult<Vec<String>> {
    sessions
        .into_iter()
        .map(|session| session.token.typed().cloned())
        .collect()
}

#[tokio::test]
async fn native_user_session_batch_keeps_cancellation_and_committed_after_errors() -> AuthResult<()>
{
    for mode in ["complete", "cancel", "after-error"] {
        let events = Events::default();
        let store = EphemeralStore::default().with_hooks(vec![Arc::new(Hooks {
            mode,
            events: events.clone(),
        })]);
        seed(&store, "target-a", 7.into()).await?;
        seed(&store, "target-b", 7.into()).await?;
        seed(&store, "text-owner", "7".into()).await?;
        assert_eq!(
            tokens(store.get_user_sessions_value(&7.into()).await?)?,
            ["target-a", "target-b"]
        );
        assert_eq!(tokens(store.get_user_sessions("7").await?)?, ["text-owner"]);
        let result = store
            .delete_user_sessions_optional_value(&7.into(), false)
            .await;
        let mut expected = vec![("before", "target-a".into()), ("before", "target-b".into())];
        if mode == "cancel" {
            assert_eq!(result?, None);
            assert_eq!(store.get_user_sessions_value(&7.into()).await?.len(), 2);
        } else {
            expected.push(("after", "target-a".into()));
            if mode == "after-error" {
                assert!(
                    matches!(result, Err(AuthError::Internal(message)) if message == "native-session-after")
                );
            } else {
                assert_eq!(result?, Some(2));
                expected.push(("after", "target-b".into()));
            }
            assert!(store.get_user_sessions_value(&7.into()).await?.is_empty());
        }
        assert_eq!(
            *events
                .lock()
                .map_err(|_| AuthError::internal("Native Session hook trace lock poisoned"))?,
            expected
        );
        assert_eq!(tokens(store.get_user_sessions("7").await?)?, ["text-owner"]);
    }
    Ok(())
}

#[tokio::test]
async fn native_user_session_selectors_keep_nullish_and_boolean_memory_equality() -> AuthResult<()>
{
    let store = EphemeralStore::default();
    for (token, owner) in [
        ("null", Value::Null),
        ("missing", Value::Undefined),
        ("false", false.into()),
        ("text-null", "null".into()),
        ("text-missing", "undefined".into()),
        ("text-false", "false".into()),
    ] {
        seed(&store, token, owner).await?;
    }
    assert_eq!(
        tokens(store.get_user_sessions_value(&Value::Null).await?)?,
        ["null", "missing"]
    );
    assert_eq!(
        tokens(store.get_user_sessions_value(&Value::Undefined).await?)?,
        ["missing"]
    );
    assert_eq!(
        tokens(store.get_user_sessions_value(&false.into()).await?)?,
        ["false"]
    );
    store
        .delete_user_sessions_by_user_value(&Value::Null)
        .await?;
    store
        .delete_user_sessions_by_user_value(&false.into())
        .await?;
    assert!(
        store
            .get_user_sessions_value(&Value::Null)
            .await?
            .is_empty()
    );
    assert!(
        store
            .get_user_sessions_value(&false.into())
            .await?
            .is_empty()
    );
    for (owner, token) in [
        ("null", "text-null"),
        ("undefined", "text-missing"),
        ("false", "text-false"),
    ] {
        assert_eq!(tokens(store.get_user_sessions(owner).await?)?, [token]);
    }
    Ok(())
}
