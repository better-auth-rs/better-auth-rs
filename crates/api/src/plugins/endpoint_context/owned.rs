use super::EndpointContext;
use better_auth_core::{AuthContext, AuthRequest, AuthResponse, AuthSchema};
use std::{collections::HashMap, sync::Arc};

/// Retained endpoint input and the same transaction adapter used by the original callback.
/// SQL transactions reject database operations after finalization. Memory transactions
/// retain their isolated rows, including row identities installed during commit.
pub struct OwnedEndpointContext<S: AuthSchema> {
    input_request: Option<AuthRequest>,
    request: Option<AuthRequest>,
    path: Option<String>,
    params: HashMap<String, String>,
    body: better_auth_core::FieldValue,
    auth: AuthContext<S>,
    transaction: Option<Arc<dyn better_auth_core::store::AuthTransaction<S>>>,
    session: Option<(
        better_auth_core::wire::UserView,
        better_auth_core::wire::SessionView,
    )>,
    response: Option<AuthResponse>,
}
impl<S: AuthSchema> OwnedEndpointContext<S> {
    /// Borrow the retained endpoint without resolving a new request or transaction.
    pub fn as_endpoint(&self) -> EndpointContext<'_, S> {
        EndpointContext {
            input_request: self.input_request.as_ref(),
            request: self.request.as_ref(),
            path: self.path.as_deref(),
            params: self.params.clone(),
            body: self.body.clone(),
            auth: &self.auth,
            transaction: self.transaction.as_deref(),
            session: self.session.clone(),
            response: self.response.as_ref(),
        }
    }
}
impl<S: AuthSchema> EndpointContext<'_, S> {
    /// Retain this endpoint for asynchronous work that may outlive its response.
    pub fn to_owned(&self) -> OwnedEndpointContext<S> {
        OwnedEndpointContext {
            input_request: self.input_request.cloned(),
            request: self.request.cloned(),
            path: self.path.map(str::to_owned),
            params: self.params.clone(),
            body: self.body.clone(),
            auth: self.auth.clone(),
            transaction: self.transaction.map(|tx| tx.clone_handle()),
            session: self.session.clone(),
            response: self.response.cloned(),
        }
    }
}
