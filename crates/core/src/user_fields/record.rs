use super::{UserConfig, UserFieldConfig, UserFieldReference, UserFieldType};
use crate::{AuthResult, SchemaValue};
use serde_json::{Map, Value};
use std::sync::Arc;

/// Raw logical fields and mapped storage fields, before adapter output policies run.
pub struct AdapterRecord {
    output: indexmap::IndexMap<String, SchemaValue<Value>>,
    storage: Map<String, Value>,
}

impl AdapterRecord {
    /// Preserve unmapped core fields and defer configured policies to the batch boundary.
    pub fn new(core: Map<String, Value>, storage: Map<String, Value>) -> Self {
        Self {
            output: core
                .into_iter()
                .map(|(name, value)| (name, SchemaValue::Typed(value)))
                .collect(),
            storage,
        }
    }
}

fn field(field_type: UserFieldType, required: bool) -> UserFieldConfig {
    UserFieldConfig {
        field_type,
        required: Some(required),
        ..Default::default()
    }
}

fn timestamp(default: bool, update: bool) -> UserFieldConfig {
    let now: Arc<dyn Fn() -> Value + Send + Sync> = Arc::new(|| {
        Value::String(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
    });
    UserFieldConfig {
        default_value_fn: default.then(|| now.clone()),
        on_update: update.then_some(now),
        ..field(UserFieldType::Date, true)
    }
}

impl crate::config::AccountConfig {
    /// Compose the adapter schema. A replacement field replaces all built-in attributes.
    pub fn field_schema(&self) -> UserConfig {
        let mut fields = [
            ("accountId".into(), field(UserFieldType::String, true)),
            ("providerId".into(), field(UserFieldType::String, true)),
            (
                "userId".into(),
                UserFieldConfig {
                    references: Some(UserFieldReference {
                        model: "user".into(),
                        field: "id".into(),
                    }),
                    ..field(UserFieldType::String, true)
                },
            ),
            (
                "accessToken".into(),
                UserFieldConfig {
                    returned: Some(false),
                    ..field(UserFieldType::String, false)
                },
            ),
            (
                "refreshToken".into(),
                UserFieldConfig {
                    returned: Some(false),
                    ..field(UserFieldType::String, false)
                },
            ),
            (
                "idToken".into(),
                UserFieldConfig {
                    returned: Some(false),
                    ..field(UserFieldType::String, false)
                },
            ),
            (
                "accessTokenExpiresAt".into(),
                UserFieldConfig {
                    returned: Some(false),
                    ..field(UserFieldType::Date, false)
                },
            ),
            (
                "refreshTokenExpiresAt".into(),
                UserFieldConfig {
                    returned: Some(false),
                    ..field(UserFieldType::Date, false)
                },
            ),
            ("scope".into(), field(UserFieldType::String, false)),
            (
                "password".into(),
                UserFieldConfig {
                    returned: Some(false),
                    ..field(UserFieldType::String, false)
                },
            ),
            ("createdAt".into(), timestamp(true, false)),
            ("updatedAt".into(), timestamp(false, true)),
        ]
        .into_iter()
        .collect::<indexmap::IndexMap<_, _>>();
        fields.extend(self.additional_fields.clone());
        UserConfig {
            additional_fields: Some(fields),
        }
    }
}

impl crate::config::VerificationConfig {
    /// Compose database field policies without applying them to secondary-only values.
    pub fn field_schema(&self) -> UserConfig {
        let mut fields = [
            ("identifier".into(), field(UserFieldType::String, true)),
            ("value".into(), field(UserFieldType::String, true)),
            ("expiresAt".into(), field(UserFieldType::Date, true)),
            ("createdAt".into(), timestamp(true, false)),
            ("updatedAt".into(), timestamp(true, true)),
        ]
        .into_iter()
        .collect::<indexmap::IndexMap<_, _>>();
        fields.extend(self.additional_fields.clone());
        UserConfig {
            additional_fields: Some(fields),
        }
    }
}

impl UserConfig {
    /// Project Organization rows in one batch while retaining adapter-owned IDs.
    pub async fn organization_output_records(
        &self,
        records: Vec<AdapterRecord>,
        supports_native_json: bool,
    ) -> AuthResult<Vec<Map<String, Value>>> {
        let mut rows = records
            .into_iter()
            .map(|record| {
                let mut core = Map::new();
                for (name, value) in record.output {
                    if let Some(value) = value.json()? {
                        let _ = core.insert(name, value);
                    }
                }
                core.retain(|name, _| name == "id" || !self.fields().contains_key(name));
                Ok((record.storage, core))
            })
            .collect::<AuthResult<Vec<_>>>()?;
        super::batch::project_fields(
            &mut rows,
            self.fields(),
            |(storage, output), name, field| {
                Box::pin(async move {
                    if name == "id" {
                        return Ok(());
                    }
                    let value = storage
                        .get(field.field_name.as_deref().unwrap_or(name))
                        .cloned();
                    super::organization::assign_output(
                        output,
                        name,
                        field,
                        field.adapter_output(value, supports_native_json).await?,
                    )
                })
            },
        )
        .await?;
        Ok(rows.into_iter().map(|(_, output)| output).collect())
    }

    /// Resolve a logical field in an adapter-owned record.
    pub fn record_storage_key<'a>(&'a self, name: &'a str) -> &'a str {
        if name == "id" {
            return name;
        }
        self.fields()
            .get(name)
            .and_then(|field| field.field_name.as_deref())
            .unwrap_or(name)
    }

    /// Project a raw adapter record without retaining unmapped storage field names.
    pub async fn project_record(
        &self,
        storage: &Map<String, Value>,
        supports_native_json: bool,
        supports_native_dates: bool,
    ) -> AuthResult<indexmap::IndexMap<String, SchemaValue<Value>>> {
        // Projection preserves the one input row.
        Ok(self
            .project_records(
                std::slice::from_ref(storage),
                supports_native_json,
                supports_native_dates,
            )
            .await?
            .remove(0))
    }

    /// Project raw adapter records together without retaining unmapped storage field names.
    pub async fn project_records(
        &self,
        storage: &[Map<String, Value>],
        supports_native_json: bool,
        supports_native_dates: bool,
    ) -> AuthResult<Vec<indexmap::IndexMap<String, SchemaValue<Value>>>> {
        self.project_records_then(
            storage,
            supports_native_json,
            supports_native_dates,
            |_, fields| std::future::ready(Ok(fields)),
        )
        .await
    }

    /// Complete each successfully projected row without cancelling other started rows.
    /// The original row index remains available for adapter-owned association data.
    pub async fn project_records_then<R: Send, F>(
        &self,
        storage: &[Map<String, Value>],
        supports_native_json: bool,
        supports_native_dates: bool,
        complete: impl Fn(usize, indexmap::IndexMap<String, SchemaValue<Value>>) -> F + Sync,
    ) -> AuthResult<Vec<R>>
    where
        F: std::future::Future<Output = AuthResult<R>> + Send,
    {
        let records = storage
            .iter()
            .map(|storage| {
                let mut core = Map::new();
                if let Some(id) = storage.get("id") {
                    let _ = core.insert(
                        "id".into(),
                        Value::String(
                            crate::SchemaValue::<String>::from_json(Some(id.clone()))
                                .display_string()?,
                        ),
                    );
                }
                Ok(AdapterRecord::new(core, storage.clone()))
            })
            .collect::<AuthResult<Vec<_>>>()?;
        self.project_adapter_records_then(
            records,
            supports_native_json,
            supports_native_dates,
            complete,
        )
        .await
    }

    /// Apply adapter input policies once to a complete logical record or update patch.
    /// Native adapter writes do not run HTTP input validation or remove `input: false` fields.
    pub async fn record_storage_fields_for_adapter(
        &self,
        input: Map<String, Value>,
        create: bool,
        supports_native_json: bool,
        native_json_field: impl Fn(&str) -> bool,
    ) -> AuthResult<Map<String, Value>> {
        self.record_storage_fields_with_binding(input, create, |name, field, value| {
            Ok(field.adapter_input(value, supports_native_json, native_json_field(name)))
        })
        .await
    }

    /// Bind a complete record after its storage policies, while retaining force-allowed IDs.
    pub async fn record_storage_fields_with_binding(
        &self,
        input: Map<String, Value>,
        create: bool,
        bind: impl Fn(&str, &super::UserFieldConfig, Value) -> AuthResult<Value>,
    ) -> AuthResult<Map<String, Value>> {
        let mut output = Map::new();
        if let Some(id) = input.get("id") {
            let _ = output.insert("id".into(), id.clone());
        }
        let transformed = self.storage_fields_async(input, create, true).await?;
        for (name, field) in self.fields() {
            if name == "id" {
                continue;
            }
            let storage = field.field_name.as_deref().unwrap_or(name);
            if let Some(value) = transformed.get(storage) {
                let _ = output.insert(storage.to_owned(), bind(storage, field, value.clone())?);
            }
        }
        Ok(output)
    }

    /// Project stored values without applying endpoint visibility or decoding replacement types.
    /// The caller must invoke this after the write and before cache writes or database after hooks.
    pub async fn record_output_fields(
        &self,
        core: Map<String, Value>,
        storage: &Map<String, Value>,
        supports_native_json: bool,
        supports_native_dates: bool,
    ) -> AuthResult<indexmap::IndexMap<String, SchemaValue<Value>>> {
        // Projection preserves the one input row.
        Ok(self
            .project_adapter_records(
                vec![AdapterRecord::new(core, storage.clone())],
                supports_native_json,
                supports_native_dates,
            )
            .await?
            .remove(0))
    }

    /// Project extracted records in row order, interleaving synchronous callbacks by field.
    pub async fn project_adapter_records(
        &self,
        records: Vec<AdapterRecord>,
        supports_native_json: bool,
        supports_native_dates: bool,
    ) -> AuthResult<Vec<indexmap::IndexMap<String, SchemaValue<Value>>>> {
        self.project_adapter_records_then(
            records,
            supports_native_json,
            supports_native_dates,
            |_, fields| std::future::ready(Ok(fields)),
        )
        .await
    }

    /// Complete each extracted row after its output policies, retaining the original row order.
    /// A failed projection skips its completion; other started rows still finish before an error returns.
    pub async fn project_adapter_records_then<R: Send, F>(
        &self,
        mut records: Vec<AdapterRecord>,
        supports_native_json: bool,
        supports_native_dates: bool,
        complete: impl Fn(usize, indexmap::IndexMap<String, SchemaValue<Value>>) -> F + Sync,
    ) -> AuthResult<Vec<R>>
    where
        F: std::future::Future<Output = AuthResult<R>> + Send,
    {
        super::batch::project_fields_then(
            &mut records,
            self.fields(),
            |record, name, field| {
                Box::pin(async move {
                    if name == "id" {
                        return Ok(());
                    }
                    let value = record
                        .storage
                        .get(field.field_name.as_deref().unwrap_or(name))
                        .cloned();
                    let value = field.adapter_output(value, supports_native_json).await?;
                    let value = if !supports_native_dates
                        && !field.references_id()
                        && matches!(field.field_type, UserFieldType::Date)
                    {
                        match value {
                            Some(Value::String(text)) => {
                                match crate::utils::date::parse_adapter_date(&text) {
                                    Some(date) => SchemaValue::Typed(Value::String(
                                        date.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                                    )),
                                    None => SchemaValue::InvalidDate,
                                }
                            }
                            value => SchemaValue::from_json(value),
                        }
                    } else {
                        SchemaValue::from_json(value)
                    };
                    if value.is_undefined() {
                        let _ = record.output.shift_remove(name);
                    } else {
                        let _ = record.output.insert(name.to_owned(), value);
                    }
                    Ok(())
                })
            },
            |index, record| complete(index, std::mem::take(&mut record.output)),
        )
        .await
    }
}
