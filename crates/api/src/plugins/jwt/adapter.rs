use super::{JwtCallbacks, JwtPlugin};
use crate::plugins::endpoint_context::EndpointContext;
use better_auth_core::{AuthResult, AuthSchema, CreateJwk, Jwk, store::JwksStore};
use std::sync::Arc;

pub(super) fn store<'a, S: AuthSchema>(endpoint: &'a EndpointContext<'_, S>) -> &'a dyn JwksStore {
    match endpoint.transaction {
        Some(transaction) => transaction,
        None => endpoint.auth.database.as_ref(),
    }
}

impl JwtPlugin {
    pub(super) async fn read_key<S: AuthSchema>(
        &self,
        id: &str,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<Option<Jwk>> {
        if let Some(callback) = endpoint
            .auth
            .extensions
            .get::<Arc<JwtCallbacks<S>>>()
            .and_then(|callbacks| callbacks.get.as_ref())
        {
            return Ok(callback(endpoint)
                .await?
                .and_then(|keys| keys.into_iter().find(|key| key.id == id)));
        }
        store(endpoint).get_jwk(id).await
    }

    pub(super) async fn read_keys<S: AuthSchema>(
        &self,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<Option<Vec<Jwk>>> {
        if let Some(callback) = endpoint
            .auth
            .extensions
            .get::<Arc<JwtCallbacks<S>>>()
            .and_then(|callbacks| callbacks.get.as_ref())
        {
            return callback(endpoint).await;
        }
        store(endpoint).list_jwks().await.map(Some)
    }

    pub(super) async fn persist_key<S: AuthSchema>(
        &self,
        data: CreateJwk,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<Jwk> {
        if let Some(callback) = endpoint
            .auth
            .extensions
            .get::<Arc<JwtCallbacks<S>>>()
            .and_then(|callbacks| callbacks.create.as_ref())
        {
            return callback(data, endpoint).await;
        }
        store(endpoint).create_jwk(data).await
    }
}
