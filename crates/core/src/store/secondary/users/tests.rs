use super::*;
use crate::observability::{LogArgument, LogLevel, LogSink};
use crate::store::{EphemeralStore, MemoryCacheAdapter, SecondaryStorage, transaction};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Semaphore, mpsc};

struct GatedStorage {
    values: MemoryCacheAdapter,
    started: mpsc::UnboundedSender<String>,
    completed: mpsc::UnboundedSender<String>,
    reject: Semaphore,
    release: Semaphore,
}

#[async_trait]
impl SecondaryStorage for GatedStorage {
    async fn get(&self, key: &str) -> AuthResult<Option<Value>> {
        if matches!(key, "rejected-session" | "pending-session") {
            self.started
                .send(key.into())
                .map_err(|error| AuthError::internal(error.to_string()))?;
            if key == "rejected-session" {
                self.reject
                    .acquire()
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?
                    .forget();
                return Err(AuthError::bad_request("refresh failure"));
            }
            self.release
                .acquire()
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?
                .forget();
        }
        self.values.get(key).await
    }

    async fn set(&self, key: &str, value: &str, seconds: Option<u64>) -> AuthResult<()> {
        self.values.set(key, value, seconds).await?;
        self.completed
            .send(key.into())
            .map_err(|error| AuthError::internal(error.to_string()))
    }

    async fn delete(&self, key: &str) -> AuthResult<()> {
        self.values.delete(key).await
    }

    async fn get_and_delete(&self, key: &str) -> AuthResult<Option<Value>> {
        self.values.get_and_delete(key).await
    }
}

struct Logs(mpsc::UnboundedSender<(LogLevel, String, bool)>);

impl LogSink for Logs {
    fn log(&self, level: LogLevel, message: LogArgument<'_>, arguments: &[LogArgument<'_>]) {
        let structured_error = matches!(arguments, [LogArgument::Error(error)] if error.to_string() == "refresh failure");
        let _ = self.0.send((level, message.to_string(), structured_error));
    }
}

#[tokio::test]
async fn refresh_logs_to_instance_and_keeps_pending_peer_after_return()
-> Result<(), Box<dyn std::error::Error>> {
    for committed in [false, true] {
        let (started, mut starts) = mpsc::unbounded_channel();
        let (completed, mut writes) = mpsc::unbounded_channel();
        let (logger, mut logs) = mpsc::unbounded_channel();
        let cache = Arc::new(GatedStorage {
            values: MemoryCacheAdapter::new(),
            started,
            completed,
            reject: Semaphore::new(0),
            release: Semaphore::new(0),
        });
        let mut config = crate::AuthConfig::default();
        config.logger.log = Some(Arc::new(Logs(logger)));
        let config = Arc::new(config);
        let inner = Arc::new(EphemeralStore::new(config.clone()));
        let user = inner
            .create_user(
                CreateUser::new()
                    .with_email("refresh@example.com")
                    .with_name("Original"),
            )
            .await?;
        let id = user.id.typed()?.clone();
        let expires = chrono::Utc::now() + chrono::Duration::hours(1);
        let references = ["rejected-session", "pending-session"]
            .map(|token| json!({"token": token, "expiresAt": expires.timestamp_millis()}));
        cache
            .values
            .set(
                &format!("active-sessions-{id}"),
                &serde_json::to_string(&references)?,
                None,
            )
            .await?;
        for token in ["rejected-session", "pending-session"] {
            cache
                .values
                .set(
                    token,
                    &json!({"session": {"token": token, "expiresAt": expires}, "user": user})
                        .to_string(),
                    None,
                )
                .await?;
        }
        let store = SecondaryStore::<crate::store::StatelessSchema>::new(
            inner.clone(),
            cache.clone(),
            config,
            Default::default(),
        )?;
        let update_id = id.clone();
        let update = tokio::spawn(async move {
            let patch = UpdateUser {
                name: Some("Updated".into()).into(),
                ..Default::default()
            };
            if committed {
                transaction(&store, move |tx| {
                    Box::pin(async move { tx.update_user(&update_id, patch).await })
                })
                .await
            } else {
                store.update_user(&update_id, patch).await
            }
        });

        for token in ["rejected-session", "pending-session"] {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(5), starts.recv())
                    .await?
                    .as_deref(),
                Some(token)
            );
        }
        cache.reject.add_permits(1);
        let returned = tokio::time::timeout(Duration::from_secs(5), update).await???;
        assert_eq!(returned.name.typed()?.as_deref(), Some("Updated"));
        assert_eq!(
            logs.try_recv()?,
            (
                LogLevel::Error,
                "Failed to refresh committed user sessions in secondary storage".into(),
                true
            )
        );
        assert!(logs.try_recv().is_err());
        assert!(writes.try_recv().is_err());
        let encoded = cache
            .values
            .get("pending-session")
            .await?
            .ok_or("Missing pending session")?;
        let before: Value =
            serde_json::from_str(encoded.as_str().ok_or("Cached session must be text")?)?;
        assert_eq!(before.pointer("/user/name"), Some(&json!("Original")));

        cache.release.add_permits(1);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), writes.recv())
                .await?
                .as_deref(),
            Some("pending-session")
        );
        let encoded = cache
            .values
            .get("pending-session")
            .await?
            .ok_or("Missing refreshed session")?;
        let after: Value =
            serde_json::from_str(encoded.as_str().ok_or("Cached session must be text")?)?;
        assert_eq!(after.pointer("/user/name"), Some(&json!("Updated")));
        assert_eq!(after.get("session"), before.get("session"));
        let stored = inner
            .get_user_by_id(&id)
            .await?
            .ok_or("Missing updated user")?;
        assert_eq!(stored.name.typed()?.as_deref(), Some("Updated"));
    }
    Ok(())
}
