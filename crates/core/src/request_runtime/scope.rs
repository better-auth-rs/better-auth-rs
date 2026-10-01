use std::any::Any;
use std::future::Future;
use std::sync::Arc;

use crate::{AuthContext, AuthSchema};

/// Identity belongs to an auth instance, including all request-derived clones.
#[derive(Clone, Default)]
pub(crate) struct Identity(Arc<()>);

impl Identity {
    pub(crate) fn current<S: AuthSchema>(&self) -> Option<Arc<AuthContext<S>>> {
        current(self)
    }
}

#[derive(Clone)]
struct Binding {
    identity: Identity,
    context: Arc<dyn Any + Send + Sync>,
}

tokio::task_local! {
    static CONTEXTS: Vec<Binding>;
}

pub(super) fn current<S: AuthSchema>(identity: &Identity) -> Option<Arc<AuthContext<S>>> {
    CONTEXTS
        .try_with(|contexts| {
            contexts
                .iter()
                .rev()
                .find(|binding| Arc::ptr_eq(&binding.identity.0, &identity.0))
                .and_then(|binding| binding.context.clone().downcast().ok())
        })
        .ok()
        .flatten()
}

pub(super) fn run<S: AuthSchema, T>(
    context: Arc<AuthContext<S>>,
    future: impl Future<Output = T>,
) -> impl Future<Output = T> {
    let mut contexts = CONTEXTS.try_with(Clone::clone).unwrap_or_default();
    contexts.push(Binding {
        identity: context.request_runtime.identity.clone(),
        context,
    });
    // Keep large endpoint futures off each nested runtime scope's stack frame.
    CONTEXTS.scope(contexts, Box::pin(future))
}

/// Promise-all peers keep running after another resolver rejects.
pub(super) fn spawn<T: Send + 'static>(
    future: impl Future<Output = T> + Send + 'static,
) -> tokio::task::JoinHandle<T> {
    let contexts = CONTEXTS.try_with(Clone::clone).unwrap_or_default();
    let request = crate::hooks::current_request_hook_context();
    tokio::spawn(CONTEXTS.scope(contexts, async move {
        match request {
            Some(request) => crate::hooks::with_request_hook_context_value(request, future).await,
            None => future.await,
        }
    }))
}
