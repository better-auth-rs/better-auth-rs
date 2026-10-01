use super::*;

#[async_trait]
impl crate::store::JwksStore for EphemeralStore {
    async fn get_jwk(&self, id: &str) -> AuthResult<Option<crate::Jwk>> {
        Ok(self.lock()?.jwks.iter().find(|key| key.id == id).cloned())
    }
    async fn list_jwks(&self) -> AuthResult<Vec<crate::Jwk>> {
        Ok(self.lock()?.jwks.clone())
    }

    async fn create_jwk(&self, input: crate::CreateJwk) -> AuthResult<crate::Jwk> {
        let key = crate::Jwk {
            id: uuid::Uuid::new_v4().to_string(),
            public_key: input.public_key,
            private_key: input.private_key,
            created_at: Utc::now(),
            expires_at: input.expires_at,
            alg: Some(input.alg),
            crv: input.crv,
        };
        self.lock()?.jwks.push(key.clone());
        Ok(key)
    }
}
