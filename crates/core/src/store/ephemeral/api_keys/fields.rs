use super::*;
use crate::store::schema::{EntityRole, resolve_field_name};
use crate::user_fields::{project_adapter_value, project_source_fields_then};

impl EphemeralStore {
    pub(super) async fn project_api_key_refs(
        &self,
        mut rows: Vec<(ApiKey, RowRef<ApiKey>)>,
    ) -> AuthResult<Vec<ApiKey>> {
        let configured = self.model_fields.fields(EntityRole::ApiKey).fields();
        let mut fields = indexmap::IndexMap::from_iter([(
            "name".to_owned(),
            configured.get("name").cloned().unwrap_or_default(),
        )]);
        fields.extend(configured.clone());
        project_source_fields_then(
            &mut rows,
            &fields,
            |(_, source), name, field| {
                source.read(|row| {
                    if name == "name" {
                        Ok(row.name.field_value())
                    } else {
                        Ok(row
                            .additional_fields
                            .get(resolve_field_name(field.field_name.as_deref(), name))
                            .cloned()
                            .unwrap_or_default())
                    }
                })
            },
            |(snapshot, source), name, field, value| {
                Box::pin(async move {
                    let value =
                        project_adapter_value(value, field, field.references_id(), true).await?;
                    if name == "name" {
                        let name = crate::SchemaValue::from_field(value);
                        // Native fields follow name and precede application fields in the upstream schema.
                        *snapshot = source.read(|row| Ok(row.clone()))?;
                        snapshot.additional_fields.clear();
                        snapshot.name = name;
                    } else {
                        let _ = snapshot.additional_fields.insert(name.to_owned(), value);
                    }
                    Ok(())
                })
            },
            |_, (snapshot, source)| {
                snapshot.id = source.read(|row| Self::project_id(&row.id))?;
                Ok(snapshot.clone())
            },
        )
        .await
    }

    pub(super) async fn find_api_key(
        &self,
        predicate: impl Fn(&ApiKey) -> bool + Send,
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
