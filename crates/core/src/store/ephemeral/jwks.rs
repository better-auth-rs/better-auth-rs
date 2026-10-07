use super::rows::RowRef;
use super::*;
use crate::store::schema::{EntityRole, resolve_field_name};
use crate::user_fields::{project_adapter_value, project_source_fields_then};

impl EphemeralStore {
    async fn project_jwk_refs(
        &self,
        selected: Vec<(crate::Jwk, RowRef<crate::Jwk>)>,
    ) -> AuthResult<Vec<crate::Jwk>> {
        let mut rows = selected
            .into_iter()
            .map(|(snapshot, source)| (snapshot, source, FieldMap::new()))
            .collect::<Vec<_>>();
        project_source_fields_then(
            &mut rows,
            self.model_fields.fields(EntityRole::Jwk).fields(),
            |(_, source, _), name, field| {
                source.read(|row| {
                    Ok(row
                        .additional_fields
                        .get(resolve_field_name(field.field_name.as_deref(), name))
                        .cloned())
                })
            },
            |(_, _, output), name, field, value| {
                Box::pin(async move {
                    // References bypass JSON decoding; Serial reference arrays must reach callbacks unchanged.
                    let value = project_adapter_value(
                        value.unwrap_or_default(),
                        field,
                        field.references_id(),
                        true,
                    )
                    .await?;
                    let _ = output.insert(name.to_owned(), value);
                    Ok(())
                })
            },
            |_, (snapshot, _, output)| {
                let mut row = snapshot.clone();
                row.id = Self::project_id(&row.id)?;
                row.additional_fields = std::mem::take(output);
                Ok(row)
            },
        )
        .await
    }
}

#[async_trait]
impl crate::store::JwksStore for EphemeralStore {
    async fn get_jwk(&self, id: &str) -> AuthResult<Option<crate::Jwk>> {
        let id = self.memory_primary_id_query(&Value::from(id))?;
        let selected = self
            .raw("jwks", "findOne", |state| {
                state
                    .jwks
                    .first_ref(|key| key.id.field_value().strict_equals(&id))?
                    .map(|source| {
                        let snapshot = source.read(|row| Ok(row.clone()))?;
                        Ok((snapshot, source))
                    })
                    .transpose()
            })
            .await?;
        Ok(self
            .project_jwk_refs(selected.into_iter().collect())
            .await?
            .pop())
    }

    async fn list_jwks(&self) -> AuthResult<Vec<crate::Jwk>> {
        let selected = self
            .raw("jwks", "findMany", |state| {
                crate::query::paginate_memory(
                    state.jwks.select_refs(|_| true)?,
                    Some(self.config.advanced.database.find_many_limit()),
                    None,
                )
                .into_iter()
                .map(|source| {
                    let snapshot = source.read(|row| Ok(row.clone()))?;
                    Ok((snapshot, source))
                })
                .collect()
            })
            .await?;
        self.project_jwk_refs(selected).await
    }

    async fn create_jwk(&self, input: crate::CreateJwk) -> AuthResult<crate::Jwk> {
        let additional_fields = self
            .model_fields
            .fields(EntityRole::Jwk)
            .storage_fields_with_binding(input.additional_fields, true, |_, field, value| {
                self.memory_plugin_field_input(field, value)
            })
            .await?;
        let mut key = crate::Jwk {
            additional_fields,
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
        let selected = self
            .raw("jwks", "create", |state| {
                if let Some(id) = self.next_serial_id(state.jwks.len()) {
                    key.id = crate::SchemaValue::from_field(id);
                }
                let source = state.jwks.push_ref(key.clone());
                Ok((key, source))
            })
            .await?;
        Ok(self.project_jwk_refs(vec![selected]).await?.remove(0))
    }
}
