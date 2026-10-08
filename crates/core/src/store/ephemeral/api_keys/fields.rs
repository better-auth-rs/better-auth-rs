use super::*;
use crate::FromFieldMap;

impl EphemeralStore {
    pub(super) async fn project_api_key_refs(
        &self,
        rows: Vec<(crate::FieldMap, RowRef<crate::FieldMap>)>,
    ) -> AuthResult<Vec<ApiKey>> {
        self.project_plugin_refs(
            EntityRole::ApiKey,
            rows.into_iter().map(|(_, source)| source).collect(),
        )
        .await?
        .into_iter()
        .map(ApiKey::from_field_values)
        .collect()
    }

    pub(super) async fn find_api_key(
        &self,
        predicate: impl Fn(&crate::FieldMap) -> bool + Send,
    ) -> AuthResult<Option<ApiKey>> {
        let selected = self
            .raw("apikey", "findOne", |state| {
                state
                    .api_keys
                    .first_ref(predicate)?
                    .map(|source| {
                        let snapshot = source.read(|row| Ok(row.clone()))?;
                        Ok((snapshot, source))
                    })
                    .transpose()
            })
            .await?;
        Ok(self
            .project_api_key_refs(selected.into_iter().collect())
            .await?
            .pop())
    }
}
