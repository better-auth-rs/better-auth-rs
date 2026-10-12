use super::{
    FieldOutputCapabilities, UserConfig, UserFieldConfig, UserFieldFactory, UserFieldReference,
    UserFieldType,
};
use crate::AuthResult;
use crate::store::schema::resolve_field_name;
use crate::{FieldMap, FieldObject, FieldValue as Value};

/// Raw logical fields and mapped storage fields, before adapter output policies run.
pub struct AdapterRecord {
    output: FieldMap,
    storage: FieldMap,
    storage_object: Option<FieldObject>,
    raw_storage: Option<FieldOutputCapabilities>,
    output_initializer: Option<Box<dyn FnOnce() -> AuthResult<()> + Send + Sync>>,
}

impl AdapterRecord {
    /// Preserve unmapped core fields and defer configured policies to the batch boundary.
    pub fn new(core: FieldMap, storage: FieldMap) -> Self {
        Self {
            output: core,
            storage,
            storage_object: None,
            raw_storage: None,
            output_initializer: None,
        }
    }

    /// Read raw physical properties from one shared snapshot at each field's output boundary.
    /// Object mutations become visible to later fields, including the adapter-owned ID.
    pub fn from_storage_object(
        storage: FieldObject,
        capabilities: FieldOutputCapabilities,
    ) -> Self {
        Self {
            output: FieldMap::new(),
            storage: FieldMap::new(),
            storage_object: Some(storage),
            raw_storage: Some(capabilities),
            output_initializer: None,
        }
    }

    /// Attach a raw physical property before configured output policies read the record.
    #[doc(hidden)]
    pub fn with_storage_property(mut self, name: &str, value: Value) -> Self {
        let _ = self.storage.insert(name.to_owned(), value);
        self
    }

    /// Replace the runtime ID policy when this row starts output conversion.
    #[doc(hidden)]
    pub fn with_id_output(
        mut self,
        runtime: &crate::plugin_runtime::ModelFields,
        model: impl Into<crate::plugin_runtime::ModelKey>,
    ) -> Self {
        self.output_initializer = Some(runtime.id_output_initializer(model));
        self
    }

    fn begin_output(&mut self) -> AuthResult<()> {
        if let Some(object) = &self.storage_object {
            for (name, value) in std::mem::take(&mut self.storage) {
                object.set(name, value)?;
            }
        }
        if let Some(initialize) = self.output_initializer.take() {
            initialize()?;
        }
        Ok(())
    }

    fn storage_value(&self, name: &str) -> AuthResult<Value> {
        match &self.storage_object {
            Some(object) => Ok(object.get(name)?.unwrap_or_default()),
            None => Ok(self.storage.get(name).cloned().unwrap_or_default()),
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
    let now: UserFieldFactory = UserFieldFactory::new(|| Ok(chrono::Utc::now().into()));
    UserFieldConfig {
        default_value_fn: default.then(|| now.clone()),
        on_update: update.then_some(now),
        ..field(UserFieldType::Date, true)
    }
}

impl UserConfig {
    /// Compose the complete User declaration before replacing adapter-owned ID policies.
    #[doc(hidden)]
    pub fn user_field_schema(&self) -> Self {
        self.user_field_schema_with_plugins(&[])
    }

    /// Compose core fields and registered declarations in schema order.
    /// Metadata supplies missing plugin declarations without moving explicitly declared fields.
    #[doc(hidden)]
    pub fn user_field_schema_with_plugins(&self, plugins: &[&str]) -> Self {
        let mut fields: indexmap::IndexMap<_, _> = [
            (
                "name".into(),
                UserFieldConfig {
                    sortable: Some(true),
                    ..field(UserFieldType::String, true)
                },
            ),
            (
                "email".into(),
                UserFieldConfig {
                    unique: Some(true),
                    sortable: Some(true),
                    ..field(UserFieldType::String, true)
                },
            ),
            (
                "emailVerified".into(),
                UserFieldConfig {
                    default_value: Some(false.into()),
                    input: Some(false),
                    ..field(UserFieldType::Boolean, true)
                },
            ),
            ("image".into(), field(UserFieldType::String, false)),
            ("createdAt".into(), timestamp(true, false)),
            ("updatedAt".into(), timestamp(true, true)),
        ]
        .into();
        for name in plugins {
            if self.fields().contains_key(*name) {
                continue;
            }
            let mut declaration = match *name {
                "isAnonymous" | "twoFactorEnabled" | "banned" => UserFieldConfig {
                    default_value: Some(false.into()),
                    input: Some(false),
                    ..field(UserFieldType::Boolean, false)
                },
                "phoneNumber" => UserFieldConfig {
                    unique: Some(true),
                    sortable: Some(true),
                    returned: Some(true),
                    ..field(UserFieldType::String, false)
                },
                "phoneNumberVerified" => UserFieldConfig {
                    returned: Some(true),
                    input: Some(false),
                    ..field(UserFieldType::Boolean, false)
                },
                "banExpires" => UserFieldConfig {
                    input: Some(false),
                    ..field(UserFieldType::Date, false)
                },
                "role" | "banReason" => UserFieldConfig {
                    input: Some(false),
                    ..field(UserFieldType::String, false)
                },
                _ => field(UserFieldType::String, false),
            };
            if *name == "username" {
                declaration.unique = Some(true);
                declaration.sortable = Some(true);
            }
            let _ = fields.insert((*name).into(), declaration);
        }
        fields.extend(self.fields().clone());
        Self {
            additional_fields: Some(fields),
        }
        .ordered_declarations(&[])
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
                    index: Some(true),
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
        .ordered_declarations(&[])
    }
}

impl crate::config::VerificationConfig {
    /// Compose database field policies without applying them to secondary-only values.
    pub fn field_schema(&self) -> UserConfig {
        let mut fields = [
            (
                "identifier".into(),
                UserFieldConfig {
                    index: Some(true),
                    ..field(UserFieldType::String, true)
                },
            ),
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
        .ordered_declarations(&[])
    }
}

impl UserConfig {
    /// Project Organization rows in one batch while retaining adapter-owned IDs.
    pub async fn organization_output_records(
        &self,
        records: Vec<AdapterRecord>,
        supports_native_json: bool,
    ) -> AuthResult<Vec<FieldMap>> {
        self.organization_output_records_owned_then(records, supports_native_json, |_, output| {
            std::future::ready(Ok(output))
        })
        .await
    }

    /// Retain owned row continuations after the first projection or continuation error.
    #[doc(hidden)]
    pub async fn organization_output_records_owned_then<R: Send + 'static, F>(
        &self,
        records: Vec<AdapterRecord>,
        supports_native_json: bool,
        complete: impl Fn(usize, FieldMap) -> F + Send + Sync + 'static,
    ) -> AuthResult<Vec<R>>
    where
        F: std::future::Future<Output = AuthResult<R>> + Send + 'static,
    {
        let schema = self.adapter_fields(&[]);
        super::batch::project_owned_fields_then(
            schema.organization_records(records),
            schema.fields().clone(),
            move |row, name, field| {
                Box::pin(project_organization_field(
                    row,
                    name,
                    field,
                    supports_native_json,
                ))
            },
            move |index, record| complete(index, std::mem::take(&mut record.output)),
        )
        .await
    }

    /// Retain ready row batches and their owned continuations after a peer fails.
    #[doc(hidden)]
    pub async fn organization_output_records_owned_batches_then<
        V: Send + 'static,
        R: Send + 'static,
        F,
    >(
        &self,
        records: Vec<AdapterRecord>,
        supports_native_json: bool,
        decode: impl Fn(usize, FieldMap) -> AuthResult<V> + Send + Sync + 'static,
        complete: impl Fn(Vec<(usize, V)>) -> F + Send + Sync + 'static,
    ) -> AuthResult<Vec<R>>
    where
        F: std::future::Future<Output = AuthResult<Vec<(usize, R)>>> + Send + 'static,
    {
        let schema = self.adapter_fields(&[]);
        super::batch::project_owned_source_fields_batches_then(
            schema.organization_records(records),
            schema.fields().clone(),
            |_, _, _| Ok(()),
            move |row, name, field, ()| {
                Box::pin(project_organization_field(
                    row,
                    name,
                    field,
                    supports_native_json,
                ))
            },
            move |index, record| decode(index, std::mem::take(&mut record.output)),
            complete,
        )
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

    async fn organization_output_records_with_json<R: Send, F>(
        &self,
        records: Vec<AdapterRecord>,
        supports_native_json: impl Fn(&UserFieldConfig) -> bool + Sync,
        complete: impl Fn(usize, FieldMap) -> F + Sync,
    ) -> AuthResult<Vec<R>>
    where
        F: std::future::Future<Output = AuthResult<R>> + Send,
    {
        let schema = self.adapter_fields(&[]);
        let mut rows = schema.organization_records(records);
        super::batch::project_fields_then(
            &mut rows,
            schema.fields(),
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
        let schema = self.adapter_fields(&[]);
        let mut rows = schema.organization_records(records);
        super::batch::project_fields_batches_then(
            &mut rows,
            schema.fields(),
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

    fn organization_records(&self, records: Vec<AdapterRecord>) -> Vec<OrganizationRecord> {
        records
            .into_iter()
            .map(|mut record| {
                if let Some(id) = record.output.shift_remove("id") {
                    let _ = record.storage.insert("id".into(), id);
                }
                record
                    .output
                    .retain(|name, _| !self.fields().contains_key(name));
                record
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
        let capabilities = FieldOutputCapabilities {
            supports_native_dates,
            ..FieldOutputCapabilities::json_only(supports_native_json)
        };
        self.adapter_fields(&[])
            .project_adapter_records_with_capabilities(
                adapter_records(storage, capabilities),
                capabilities,
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
        let capabilities = FieldOutputCapabilities {
            supports_native_dates,
            ..FieldOutputCapabilities::json_only(supports_native_json)
        };
        self.adapter_fields(&[])
            .project_adapter_records_then(
                adapter_records(storage, capabilities),
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
        let capabilities = FieldOutputCapabilities {
            supports_native_dates,
            ..FieldOutputCapabilities::json_only(supports_native_json)
        };
        self.adapter_fields(&[])
            .project_adapter_records_batches_then(
                adapter_records(storage, capabilities),
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

    /// Bind a complete record with force-allowed IDs in their declaration slot.
    pub async fn record_storage_fields_with_binding(
        &self,
        input: FieldMap,
        create: bool,
        bind: impl Fn(&str, &super::UserFieldConfig, Value) -> AuthResult<Value>,
    ) -> AuthResult<FieldMap> {
        let id = input.get("id").cloned();
        self.storage_fields_with_bound_id(input, create, || Ok(id.clone()), bind)
            .await
    }

    /// Project stored values without applying endpoint visibility or decoding replacement types.
    /// Retain already projected logical `core` fields; declared fields read physical `storage` values.
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
        self.project_adapter_records_owned_then(
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
        records: Vec<AdapterRecord>,
        capabilities: FieldOutputCapabilities,
    ) -> AuthResult<Vec<FieldMap>> {
        super::batch::project_owned_fields_then(
            records,
            self.fields().clone(),
            move |record, name, field| {
                Box::pin(project_adapter_field_with_capabilities(
                    record,
                    name,
                    field,
                    capabilities,
                ))
            },
            |_, record| std::future::ready(Ok(std::mem::take(&mut record.output))),
        )
        .await
    }

    /// Retain owned row continuations after the first projection or continuation error.
    #[doc(hidden)]
    pub async fn project_adapter_records_owned_then<R: Send + 'static, F>(
        &self,
        records: Vec<AdapterRecord>,
        supports_native_json: bool,
        supports_native_dates: bool,
        complete: impl Fn(usize, FieldMap) -> F + Send + Sync + 'static,
    ) -> AuthResult<Vec<R>>
    where
        F: std::future::Future<Output = AuthResult<R>> + Send + 'static,
    {
        super::batch::project_owned_fields_then(
            records,
            self.fields().clone(),
            move |record, name, field| {
                Box::pin(project_adapter_field(
                    record,
                    name,
                    field,
                    supports_native_json,
                    supports_native_dates,
                ))
            },
            move |index, record| complete(index, std::mem::take(&mut record.output)),
        )
        .await
    }

    /// Retain ready adapter row batches and their continuations after a peer fails.
    #[doc(hidden)]
    pub async fn project_adapter_records_owned_batches_then<R: Send + 'static, F>(
        &self,
        records: Vec<AdapterRecord>,
        supports_native_json: bool,
        supports_native_dates: bool,
        complete: impl Fn(Vec<(usize, FieldMap)>) -> F + Send + Sync + 'static,
    ) -> AuthResult<Vec<R>>
    where
        F: std::future::Future<Output = AuthResult<Vec<(usize, R)>>> + Send + 'static,
    {
        super::batch::project_owned_source_fields_batches_then(
            records,
            self.fields().clone(),
            |_, _, _| Ok(()),
            move |record, name, field, ()| {
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
    record.begin_output()?;
    let value = record.storage_value(resolve_field_name(field.field_name.as_deref(), name))?;
    let value = if name == "id" {
        if value.is_null() || value.is_undefined() {
            value
        } else {
            value.display_utf16()?.into()
        }
    } else if let Some(capabilities) = record.raw_storage {
        field.adapter_output_from_raw(value, capabilities).await?
    } else {
        field.adapter_output(value, supports_native_json).await?
    };
    let _ = record.output.insert(name.to_owned(), value);
    Ok(())
}

fn adapter_records(
    storage: &[FieldMap],
    capabilities: FieldOutputCapabilities,
) -> Vec<AdapterRecord> {
    storage
        .iter()
        .map(|storage| AdapterRecord::from_storage_object(storage.clone().into(), capabilities))
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
        FieldOutputCapabilities {
            supports_native_dates,
            ..FieldOutputCapabilities::json_only(supports_native_json)
        },
    )
    .await
}

async fn project_adapter_field_with_capabilities(
    record: &mut AdapterRecord,
    name: &str,
    field: &UserFieldConfig,
    capabilities: FieldOutputCapabilities,
) -> AuthResult<()> {
    record.begin_output()?;
    if name == "id" {
        if record.storage_object.is_some() {
            let value = record.storage_value("id")?;
            let value = if value.is_null() || value.is_undefined() {
                value
            } else {
                value.display_utf16()?.into()
            };
            let _ = record.output.insert(name.into(), value);
        }
        return Ok(());
    }
    let value = record.storage_value(resolve_field_name(field.field_name.as_deref(), name))?;
    let value = if let Some(capabilities) = record.raw_storage {
        field.adapter_output_from_raw(value, capabilities).await?
    } else {
        field
            .adapter_output_with_capabilities(value, capabilities)
            .await?
    };
    let _ = record.output.insert(name.to_owned(), value);
    Ok(())
}

pub(crate) async fn project_adapter_value(
    value: Value,
    field: &UserFieldConfig,
    supports_native_json: bool,
    supports_native_dates: bool,
) -> AuthResult<Value> {
    field
        .adapter_output_with_capabilities(
            value,
            FieldOutputCapabilities {
                supports_native_dates,
                ..FieldOutputCapabilities::json_only(supports_native_json)
            },
        )
        .await
}

#[cfg(test)]
mod object_tests;

#[cfg(test)]
mod projection_tests;

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]
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
