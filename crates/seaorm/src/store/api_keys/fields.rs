use super::*;

impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    SeaOrmStore<S, O, P>
{
    pub(in crate::store) fn validate_api_key_fields(&self) -> AuthResult<()> {
        self.validate_plugin_fields::<P::ApiKey>(EntityRole::ApiKey)
    }

    pub(super) async fn project_api_key_models(
        &self,
        rows: Vec<sea_orm::QueryResult>,
    ) -> AuthResult<Vec<ApiKey>> {
        self.project_plugin_rows::<P::ApiKey, ApiKey>(EntityRole::ApiKey, rows)
            .await
    }
}
