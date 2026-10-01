use super::*;

#[async_trait]
impl crate::store::JwksStore for EphemeralStore {
    async fn get_jwk(&self, id: &str) -> AuthResult<Option<crate::Jwk>> {
        self.raw("jwks", "findOne", |state| {
            Ok(state
                .jwks
                .snapshot()?
                .iter()
                .find(|key| key.id == id)
                .cloned())
        })
        .await
    }
    async fn list_jwks(&self) -> AuthResult<Vec<crate::Jwk>> {
        self.raw("jwks", "findMany", |state| {
            Ok(crate::query::paginate_memory(
                state.jwks.snapshot()?,
                Some(self.config.advanced.database.find_many_limit()),
                None,
            ))
        })
        .await
    }

    async fn create_jwk(&self, input: crate::CreateJwk) -> AuthResult<crate::Jwk> {
        let key = crate::Jwk {
            id: self
                .generated_id("jwks", None, self.lock()?.jwks.len())?
                .map(crate::SchemaValue::Typed)
                .unwrap_or_default(),
            public_key: input.public_key,
            private_key: input.private_key,
            created_at: input.created_at,
            expires_at: input.expires_at,
            alg: Some(input.alg),
            crv: input.crv,
        };
        self.raw("jwks", "create", |state| {
            state.jwks.push(key.clone());
            Ok(key)
        })
        .await
    }
}
