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
            return Ok(callback(endpoint).await?.and_then(|keys| {
                keys.into_iter()
                    .find(|key| key.id.field_value().strict_equals(&id.into()))
            }));
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
        mut data: CreateJwk,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<Option<Jwk>> {
        if let Some(callback) = endpoint
            .auth
            .extensions
            .get::<Arc<JwtCallbacks<S>>>()
            .and_then(|callbacks| callbacks.create.as_ref())
        {
            return callback(data, endpoint).await;
        }
        data.created_at = chrono::Utc::now().into();
        let mut fields = better_auth_core::FieldMap::from([("alg".into(), data.alg.into())]);
        if let Some(curve) = data.crv {
            let _ = fields.insert("crv".into(), curve.into());
        }
        fields.extend([
            ("publicKey".into(), data.public_key.into()),
            ("privateKey".into(), data.private_key.into()),
            ("createdAt".into(), data.created_at.into()),
        ]);
        if let Some(expiry) = data.expires_at {
            let _ = fields.insert("expiresAt".into(), expiry.into());
        }
        fields.extend(data.additional_fields);
        use better_auth_core::FromFieldMap as _;
        store(endpoint)
            .create_jwk_record(fields)
            .await?
            .map(Jwk::from_field_values)
            .transpose()
    }
}
