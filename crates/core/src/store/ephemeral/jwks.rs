use super::*;
use crate::store::schema::EntityRole;

#[cfg(test)]
mod id_slot_tests;

#[async_trait]
impl crate::store::JwksStore for EphemeralStore {
    async fn create_jwk_record(&self, input: FieldMap) -> AuthResult<FieldMap> {
        self.create_plugin_record(EntityRole::Jwk, input, Default::default())
            .await
    }

    async fn get_jwk_record(
        &self,
        id: &crate::SchemaValue<String>,
    ) -> AuthResult<Option<FieldMap>> {
        self.get_plugin_record(EntityRole::Jwk, id).await
    }

    async fn update_jwk_record(
        &self,
        id: &crate::SchemaValue<String>,
        input: FieldMap,
    ) -> AuthResult<Option<FieldMap>> {
        self.update_plugin_record(EntityRole::Jwk, id, input, Default::default())
            .await
    }

    async fn delete_jwk_record(&self, id: &crate::SchemaValue<String>) -> AuthResult<()> {
        self.delete_plugin_records(EntityRole::Jwk, id).await
    }

    async fn list_jwk_records(&self) -> AuthResult<Vec<FieldMap>> {
        let selected = self
            .raw("jwks", "findMany", |state| {
                Ok(crate::query::paginate_memory(
                    state.jwks.select_refs(|_| true)?,
                    Some(self.config.advanced.database.find_many_limit()),
                    None,
                ))
            })
            .await?;
        self.project_plugin_refs(EntityRole::Jwk, selected).await
    }
}
