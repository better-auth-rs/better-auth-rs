use std::sync::Arc;

use crate::store::SecondaryStorage;
use crate::{AuthError, AuthResult};

pub(super) async fn delete_cached_tokens(
    storage: Arc<dyn SecondaryStorage>,
    tokens: Vec<String>,
) -> AuthResult<()> {
    let count = tokens.len();
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
    // Promise.all rejects immediately but leaves every already-started peer running.
    let task = crate::request_runtime::spawn_with_request_context(async move {
        let _ = futures_util::future::join_all(tokens.into_iter().map(|token| {
            let storage = storage.clone();
            let sender = sender.clone();
            async move {
                let result = storage.delete(&token).await;
                let _ = sender.send(result);
            }
        }))
        .await;
    });
    for _ in 0..count {
        let Some(result) = receiver.recv().await else {
            break;
        };
        result?;
    }
    match task.await {
        Ok(()) => Ok(()),
        Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
        Err(error) => Err(AuthError::internal(format!(
            "Session deletion task: {error}"
        ))),
    }
}
