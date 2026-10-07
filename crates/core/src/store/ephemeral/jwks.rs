use super::rows::RowRef;
use super::*;
use crate::store::schema::{EntityRole, resolve_field_name};
use crate::user_fields::{project_adapter_value, project_source_fields_then};

#[cfg(test)]
mod id_slot_tests;

impl EphemeralStore {
    async fn project_jwk_refs(
        &self,
        selected: Vec<(crate::Jwk, RowRef<crate::Jwk>)>,
    ) -> AuthResult<Vec<crate::Jwk>> {
        if !selected.is_empty() {
            self.model_fields.begin_id_output(EntityRole::Jwk)?;
        }
        let fields = self
            .model_fields
            .fields(EntityRole::Jwk)
            .adapter_fields(&[]);
        let mut rows = selected
            .into_iter()
            .map(|(snapshot, source)| (snapshot, source, FieldMap::new()))
            .collect::<Vec<_>>();
        project_source_fields_then(
            &mut rows,
            fields.fields(),
            |(_, source, _), name, field| {
                source.read(|row| {
                    if name == "id" {
                        return Ok(Some(row.id.field_value()));
                    }
                    Ok(row
                        .additional_fields
                        .get(resolve_field_name(field.field_name.as_deref(), name))
                        .cloned())
                })
            },
            |(snapshot, _, output), name, field, value| {
                Box::pin(async move {
                    if name == "id" {
                        snapshot.id = Self::project_id(&crate::SchemaValue::from_field(
                            value.unwrap_or_default(),
                        ))?;
                        return Ok(());
                    }
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
        self.model_fields.begin_id_input(EntityRole::Jwk)?;
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
        self.model_fields.begin_id_input(EntityRole::Jwk)?;
        let (additional_fields, id) = self
            .model_fields
            .fields(EntityRole::Jwk)
            .create_adapter_storage_fields(
                input.additional_fields,
                || {
                    if !self.model_fields.id_input_active(EntityRole::Jwk)? {
                        return Ok(None);
                    }
                    self.config
                        .advanced
                        .database
                        .generate_id()
                        .adapter_id("jwks", None, false)
                },
                |_, field, value| self.memory_plugin_field_input(field, value),
            )
            .await?;
        let mut key = crate::Jwk {
            additional_fields,
            id: id.map(crate::SchemaValue::Typed).unwrap_or_default(),
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
