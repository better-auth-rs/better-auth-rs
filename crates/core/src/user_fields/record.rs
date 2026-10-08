use super::{
    FieldOutputCapabilities, UserConfig, UserFieldConfig, UserFieldFactory, UserFieldReference,
    UserFieldType,
};
use crate::AuthResult;
use crate::store::schema::resolve_field_name;
use crate::{FieldMap, FieldValue as Value};
use std::sync::Arc;

/// Raw logical fields and mapped storage fields, before adapter output policies run.
pub struct AdapterRecord {
    output: FieldMap,
    storage: FieldMap,
    raw_storage: Option<FieldOutputCapabilities>,
}

impl AdapterRecord {
    /// Preserve unmapped core fields and defer configured policies to the batch boundary.
    pub fn new(core: FieldMap, storage: FieldMap) -> Self {
        Self {
            output: core,
            storage,
            raw_storage: None,
        }
    }

    /// Restore raw adapter values before output policies. `None` retains the extracted value.
    /// The restored values bypass the model's JSON conversion before callbacks.
    pub fn map_storage_fields(
        &mut self,
        fields: &UserConfig,
        capabilities: FieldOutputCapabilities,
        map: impl Fn(&str, &UserFieldConfig) -> AuthResult<Option<Value>>,
    ) -> AuthResult<()> {
        for (name, field) in fields.fields() {
            if name == "id" {
                continue;
            }
            let storage = resolve_field_name(field.field_name.as_deref(), name);
            if let Some(value) = map(storage, field)? {
                let _ = self.storage.insert(storage.to_owned(), value);
            }
        }
        self.raw_storage = Some(capabilities);
        Ok(())
    }

    /// Restore unconfigured core values without applying application field policies.
    pub fn map_native_fields(
        &mut self,
        fields: &UserConfig,
        map: impl Fn(&str) -> AuthResult<Option<Value>>,
    ) -> AuthResult<()> {
        for (name, value) in &mut self.output {
            if !fields.fields().contains_key(name)
                && let Some(raw) = map(name)?
            {
                *value = raw;
            }
        }
        Ok(())
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
    let now: UserFieldFactory = Arc::new(|| Ok(chrono::Utc::now().into()));
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
                        ..Default::default()
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
    ) -> AuthResult<Vec<FieldMap>> {
        self.organization_output_records_then(records, supports_native_json, |_, output| {
            std::future::ready(Ok(output))
        })
        .await
    }

    /// Continue each Organization row after projection without cancelling started peers.
    pub async fn organization_output_records_then<R: Send, F>(
        &self,
        records: Vec<AdapterRecord>,
        supports_native_json: bool,
        complete: impl Fn(usize, FieldMap) -> F + Sync,
    ) -> AuthResult<Vec<R>>
    where
        F: std::future::Future<Output = AuthResult<R>> + Send,
    {
        self.organization_output_records_with_json(records, |_| supports_native_json, complete)
            .await
    }

    pub(crate) async fn organization_output_memory_records(
        &self,
        records: Vec<AdapterRecord>,
    ) -> AuthResult<Vec<FieldMap>> {
        self.organization_output_records_with_json(
            records,
            UserFieldConfig::references_id,
            |_, output| std::future::ready(Ok(output)),
        )
        .await
    }

    async fn organization_output_records_with_json<R: Send, F>(
        &self,
        records: Vec<AdapterRecord>,
        supports_native_json: impl Fn(&UserFieldConfig) -> bool + Sync,
        complete: impl Fn(usize, FieldMap) -> F + Sync,
    ) -> AuthResult<Vec<R>>
    where
        F: std::future::Future<Output = AuthResult<R>> + Send,
    {
        let mut rows = self.organization_records(records)?;
        super::batch::project_fields_then(
            &mut rows,
            self.fields(),
            |row, name, field| {
                Box::pin(project_organization_field(
                    row,
                    name,
                    field,
                    supports_native_json(field),
                ))
            },
            |index, record| complete(index, std::mem::take(&mut record.output)),
        )
        .await
    }

    /// Decode ready Organization rows before continuing their synchronous adapter reads together.
    pub async fn organization_output_records_batches_then<V: Send, R: Send, F>(
        &self,
        records: Vec<AdapterRecord>,
        supports_native_json: bool,
        decode: impl Fn(usize, FieldMap) -> AuthResult<V> + Sync,
        complete: impl Fn(Vec<(usize, V)>) -> F + Sync,
    ) -> AuthResult<Vec<R>>
    where
        F: std::future::Future<Output = AuthResult<Vec<(usize, R)>>> + Send,
    {
        self.organization_output_records_batches_with_json(
            records,
            |_| supports_native_json,
            decode,
            complete,
        )
        .await
    }

    pub(crate) async fn organization_output_memory_records_batches_then<V: Send, R: Send, F>(
        &self,
        records: Vec<AdapterRecord>,
        decode: impl Fn(usize, FieldMap) -> AuthResult<V> + Sync,
        complete: impl Fn(Vec<(usize, V)>) -> F + Sync,
    ) -> AuthResult<Vec<R>>
    where
        F: std::future::Future<Output = AuthResult<Vec<(usize, R)>>> + Send,
    {
        self.organization_output_records_batches_with_json(
            records,
            UserFieldConfig::references_id,
            decode,
            complete,
        )
        .await
    }

    async fn organization_output_records_batches_with_json<V: Send, R: Send, F>(
        &self,
        records: Vec<AdapterRecord>,
        supports_native_json: impl Fn(&UserFieldConfig) -> bool + Sync,
        decode: impl Fn(usize, FieldMap) -> AuthResult<V> + Sync,
        complete: impl Fn(Vec<(usize, V)>) -> F + Sync,
    ) -> AuthResult<Vec<R>>
    where
        F: std::future::Future<Output = AuthResult<Vec<(usize, R)>>> + Send,
    {
        let mut rows = self.organization_records(records)?;
        super::batch::project_fields_batches_then(
            &mut rows,
            self.fields(),
            |row, name, field| {
                Box::pin(project_organization_field(
                    row,
                    name,
                    field,
                    supports_native_json(field),
                ))
            },
            |index, record| decode(index, std::mem::take(&mut record.output)),
            complete,
        )
        .await
    }

    fn organization_records(
        &self,
        records: Vec<AdapterRecord>,
    ) -> AuthResult<Vec<OrganizationRecord>> {
        records
            .into_iter()
            .map(|mut record| {
                record
                    .output
                    .retain(|name, _| name == "id" || !self.fields().contains_key(name));
                Ok(record)
            })
            .collect()
    }

    /// Resolve a logical field in an adapter-owned record.
    pub fn record_storage_key<'a>(&'a self, name: &'a str) -> &'a str {
        if name == "id" {
            return name;
        }
        resolve_field_name(
            self.fields()
                .get(name)
                .and_then(|field| field.field_name.as_deref()),
            name,
        )
    }

    /// Project a raw adapter record without retaining unmapped storage field names.
    pub async fn project_record(
        &self,
        storage: &FieldMap,
        supports_native_json: bool,
        supports_native_dates: bool,
    ) -> AuthResult<FieldMap> {
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
        storage: &[FieldMap],
        supports_native_json: bool,
        supports_native_dates: bool,
    ) -> AuthResult<Vec<FieldMap>> {
        self.project_records_then(
            storage,
            supports_native_json,
            supports_native_dates,
            |_, fields| std::future::ready(Ok(fields)),
        )
        .await
    }

    /// Keep raw Memory reference values and decode ordinary JSON after output callbacks.
    pub(crate) async fn project_memory_records(
        &self,
        storage: &[FieldMap],
    ) -> AuthResult<Vec<FieldMap>> {
        self.project_memory_adapter_records(adapter_records(storage)?)
            .await
    }

    /// Preserve Memory field conversion while continuing each ready batch with its original indices.
    pub(crate) async fn project_memory_records_batches_then<R: Send, F>(
        &self,
        storage: &[FieldMap],
        complete: impl Fn(Vec<(usize, FieldMap)>) -> F + Sync,
    ) -> AuthResult<Vec<R>>
    where
        F: std::future::Future<Output = AuthResult<Vec<(usize, R)>>> + Send,
    {
        let mut records = adapter_records(storage)?;
        super::batch::project_fields_batches_then(
            &mut records,
            self.fields(),
            |record, name, field| {
                Box::pin(project_adapter_field(
                    record,
                    name,
                    field,
                    field.references_id(),
                    true,
                ))
            },
            |_, record| Ok(std::mem::take(&mut record.output)),
            complete,
        )
        .await
    }

    /// Complete each successfully projected row without cancelling other started rows.
    /// The original row index remains available for adapter-owned association data.
    pub async fn project_records_then<R: Send, F>(
        &self,
        storage: &[FieldMap],
        supports_native_json: bool,
        supports_native_dates: bool,
        complete: impl Fn(usize, FieldMap) -> F + Sync,
    ) -> AuthResult<Vec<R>>
    where
        F: std::future::Future<Output = AuthResult<R>> + Send,
    {
        let records = adapter_records(storage)?;
        self.project_adapter_records_then(
            records,
            supports_native_json,
            supports_native_dates,
            complete,
        )
        .await
    }

    /// Continue ready raw records as a batch, retaining each original row index.
    pub async fn project_records_batches_then<R: Send, F>(
        &self,
        storage: &[FieldMap],
        supports_native_json: bool,
        supports_native_dates: bool,
        complete: impl Fn(Vec<(usize, FieldMap)>) -> F + Sync,
    ) -> AuthResult<Vec<R>>
    where
        F: std::future::Future<Output = AuthResult<Vec<(usize, R)>>> + Send,
    {
        self.project_adapter_records_batches_then(
            adapter_records(storage)?,
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
        input: FieldMap,
        create: bool,
        supports_native_json: bool,
        native_json_field: impl Fn(&str) -> bool,
    ) -> AuthResult<FieldMap> {
        self.record_storage_fields_with_binding(input, create, |name, field, value| {
            field.adapter_input(value, supports_native_json, native_json_field(name))
        })
        .await
    }

    /// Bind a complete record after its storage policies, while retaining force-allowed IDs.
    pub async fn record_storage_fields_with_binding(
        &self,
        input: FieldMap,
        create: bool,
        bind: impl Fn(&str, &super::UserFieldConfig, Value) -> AuthResult<Value>,
    ) -> AuthResult<FieldMap> {
        let mut output = FieldMap::new();
        if let Some(id) = input.get("id") {
            let _ = output.insert("id".into(), id.clone());
        }
        output.extend(self.storage_fields_async(input, create, true, bind).await?);
        Ok(output)
    }

    /// Project stored values without applying endpoint visibility or decoding replacement types.
    /// The caller must invoke this after the write and before cache writes or database after hooks.
    pub async fn record_output_fields(
        &self,
        core: FieldMap,
        storage: &FieldMap,
        supports_native_json: bool,
        supports_native_dates: bool,
    ) -> AuthResult<FieldMap> {
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
    ) -> AuthResult<Vec<FieldMap>> {
        self.project_adapter_records_then(
            records,
            supports_native_json,
            supports_native_dates,
            |_, fields| std::future::ready(Ok(fields)),
        )
        .await
    }

    /// Project adapter fields with the database's JSON, array, boolean, and date conversions.
    pub async fn project_adapter_records_with_capabilities(
        &self,
        mut records: Vec<AdapterRecord>,
        capabilities: FieldOutputCapabilities,
        supports_native_dates: bool,
    ) -> AuthResult<Vec<FieldMap>> {
        super::batch::project_fields(&mut records, self.fields(), |record, name, field| {
            Box::pin(project_adapter_field_with_capabilities(
                record,
                name,
                field,
                capabilities,
                supports_native_dates,
            ))
        })
        .await?;
        Ok(records.into_iter().map(|record| record.output).collect())
    }

    /// Preserve Memory reference values until callbacks run, then decode ordinary JSON text.
    pub(crate) async fn project_memory_adapter_records(
        &self,
        mut records: Vec<AdapterRecord>,
    ) -> AuthResult<Vec<FieldMap>> {
        super::batch::project_fields(&mut records, self.fields(), |record, name, field| {
            Box::pin(project_adapter_field(
                record,
                name,
                field,
                field.references_id(),
                true,
            ))
        })
        .await?;
        Ok(records.into_iter().map(|record| record.output).collect())
    }

    /// Complete each extracted row after its output policies, retaining the original row order.
    /// A failed projection skips its completion; other started rows still finish before an error returns.
    pub async fn project_adapter_records_then<R: Send, F>(
        &self,
        mut records: Vec<AdapterRecord>,
        supports_native_json: bool,
        supports_native_dates: bool,
        complete: impl Fn(usize, FieldMap) -> F + Sync,
    ) -> AuthResult<Vec<R>>
    where
        F: std::future::Future<Output = AuthResult<R>> + Send,
    {
        super::batch::project_fields_then(
            &mut records,
            self.fields(),
            |record, name, field| {
                Box::pin(project_adapter_field(
                    record,
                    name,
                    field,
                    supports_native_json,
                    supports_native_dates,
                ))
            },
            |index, record| complete(index, std::mem::take(&mut record.output)),
        )
        .await
    }

    /// Continue ready extracted records together, retaining their original row indices.
    pub async fn project_adapter_records_batches_then<R: Send, F>(
        &self,
        mut records: Vec<AdapterRecord>,
        supports_native_json: bool,
        supports_native_dates: bool,
        complete: impl Fn(Vec<(usize, FieldMap)>) -> F + Sync,
    ) -> AuthResult<Vec<R>>
    where
        F: std::future::Future<Output = AuthResult<Vec<(usize, R)>>> + Send,
    {
        super::batch::project_fields_batches_then(
            &mut records,
            self.fields(),
            |record, name, field| {
                Box::pin(project_adapter_field(
                    record,
                    name,
                    field,
                    supports_native_json,
                    supports_native_dates,
                ))
            },
            |_, record| Ok(std::mem::take(&mut record.output)),
            complete,
        )
        .await
    }
}

type OrganizationRecord = AdapterRecord;

async fn project_organization_field(
    record: &mut OrganizationRecord,
    name: &str,
    field: &UserFieldConfig,
    supports_native_json: bool,
) -> AuthResult<()> {
    if name == "id" {
        return Ok(());
    }
    let value = record
        .storage
        .get(resolve_field_name(field.field_name.as_deref(), name))
        .cloned()
        .unwrap_or_default();
    let value = if let Some(capabilities) = record.raw_storage {
        field.adapter_output_from_raw(value, capabilities).await?
    } else {
        field.adapter_output(value, supports_native_json).await?
    };
    super::organization::assign_output(&mut record.output, name, field, value)
}

fn adapter_records(storage: &[FieldMap]) -> AuthResult<Vec<AdapterRecord>> {
    storage
        .iter()
        .map(|storage| {
            let mut core = FieldMap::new();
            if let Some(id) = storage.get("id") {
                let _ = core.insert(
                    "id".into(),
                    if id.is_null() || id.is_undefined() {
                        id.clone()
                    } else {
                        Value::String(
                            crate::SchemaValue::<String>::from_field(id.clone())
                                .display_string()?,
                        )
                    },
                );
            }
            Ok(AdapterRecord::new(core, storage.clone()))
        })
        .collect()
}

async fn project_adapter_field(
    record: &mut AdapterRecord,
    name: &str,
    field: &UserFieldConfig,
    supports_native_json: bool,
    supports_native_dates: bool,
) -> AuthResult<()> {
    project_adapter_field_with_capabilities(
        record,
        name,
        field,
        FieldOutputCapabilities::json_only(supports_native_json),
        supports_native_dates,
    )
    .await
}

async fn project_adapter_field_with_capabilities(
    record: &mut AdapterRecord,
    name: &str,
    field: &UserFieldConfig,
    capabilities: FieldOutputCapabilities,
    supports_native_dates: bool,
) -> AuthResult<()> {
    if name == "id" {
        return Ok(());
    }
    let value = record
        .storage
        .get(resolve_field_name(field.field_name.as_deref(), name))
        .cloned()
        .unwrap_or_default();
    let value = if let Some(capabilities) = record.raw_storage {
        field.adapter_output_from_raw(value, capabilities).await?
    } else {
        field
            .adapter_output_with_capabilities(value, capabilities)
            .await?
    };
    let value = project_output_value(value, field, supports_native_dates);
    let _ = record.output.insert(name.to_owned(), value);
    Ok(())
}

pub(crate) async fn project_adapter_value(
    value: Value,
    field: &UserFieldConfig,
    supports_native_json: bool,
    supports_native_dates: bool,
) -> AuthResult<Value> {
    let value = field.adapter_output(value, supports_native_json).await?;
    Ok(project_output_value(value, field, supports_native_dates))
}

fn project_output_value(
    value: Value,
    field: &UserFieldConfig,
    supports_native_dates: bool,
) -> Value {
    if !supports_native_dates
        && !field.uses_id_output()
        && matches!(field.field_type, UserFieldType::Date)
    {
        match value {
            Value::String(text) => Value::Date(
                crate::utils::date::parse_date_constructor(&text)
                    .unwrap_or_else(crate::FieldDate::invalid),
            ),
            value => value,
        }
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user_fields::{FieldTransforms, UserFieldTransform};
    macro_rules! json {
        ($($token:tt)*) => { Value::from_json(serde_json::json!($($token)*)).expect("valid JSON field") };
    }

    #[tokio::test]
    async fn raw_adapter_json_reaches_callbacks_before_output_decoding() -> AuthResult<()> {
        for raw in [Value::Null, json!({"owner": "Alpha"}), json!(["Alpha"])] {
            let expected = raw.clone();
            let fields = UserConfig {
                additional_fields: Some(
                    [(
                        "payload".into(),
                        UserFieldConfig {
                            field_type: UserFieldType::Json,
                            transform: Some(FieldTransforms {
                                output: Some(UserFieldTransform::new(move |value| {
                                    assert_eq!(value, expected.clone());
                                    Ok(json!("[3,4]"))
                                })),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    )]
                    .into(),
                ),
            };
            let mut record = AdapterRecord::new(FieldMap::new(), FieldMap::new());
            record.map_storage_fields(
                &fields,
                FieldOutputCapabilities::json_only(false),
                |_, _| Ok(Some(raw.clone())),
            )?;
            let projected = fields
                .project_adapter_records_with_capabilities(
                    vec![record],
                    FieldOutputCapabilities::json_only(false),
                    true,
                )
                .await?;
            assert_eq!(
                projected.first().and_then(|row| row.get("payload")),
                Some(&json!([3, 4]))
            );
        }
        Ok(())
    }
}
