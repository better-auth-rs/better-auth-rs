use super::{UserConfig, UserFieldConfig, UserFieldType};
use crate::AuthResult;
use crate::store::schema::resolve_field_name;
use crate::{FieldMap, FieldValue as Value};

/// Adapter capabilities for decoding values after an application output callback.
#[derive(Clone, Copy, Debug)]
pub struct FieldOutputCapabilities {
    /// JSON values need no text decoding when the adapter supports native JSON.
    pub supports_native_json: bool,
    /// Array values need no text decoding when the adapter supports arrays.
    pub supports_arrays: bool,
    /// Boolean values need no numeric decoding when the adapter supports booleans.
    pub supports_booleans: bool,
}

impl FieldOutputCapabilities {
    pub(crate) const fn json_only(supports_native_json: bool) -> Self {
        Self {
            supports_native_json,
            supports_arrays: true,
            supports_booleans: true,
        }
    }
}

impl UserConfig {
    /// Resolve schema order and replace the adapter-owned ID policy in its existing slot.
    #[doc(hidden)]
    pub fn adapter_fields(&self, native: &[&str]) -> Self {
        let mut fields: indexmap::IndexMap<_, _> = self
            .ordered_fields(native)
            .into_iter()
            .map(|(name, field)| (name.to_owned(), field.clone()))
            .collect();
        let _ = fields.insert("id".into(), UserFieldConfig::default());
        Self {
            additional_fields: Some(fields),
        }
    }

    /// Apply creation policies and resolve the current ID policy at its schema slot.
    #[doc(hidden)]
    pub async fn create_adapter_storage_fields<I>(
        &self,
        input: FieldMap,
        generate_id: impl FnMut() -> AuthResult<Option<I>>,
        bind: impl Fn(&str, &UserFieldConfig, Value) -> AuthResult<Value>,
    ) -> AuthResult<(FieldMap, Option<I>)> {
        self.storage_fields_with_adapter_id(input, true, generate_id, bind)
            .await
    }

    /// Resolve the adapter-owned ID between field policies without applying application ID callbacks.
    #[doc(hidden)]
    pub async fn storage_fields_with_adapter_id<I>(
        &self,
        input: FieldMap,
        create: bool,
        mut resolve_id: impl FnMut() -> AuthResult<Option<I>>,
        bind: impl Fn(&str, &UserFieldConfig, Value) -> AuthResult<Value>,
    ) -> AuthResult<(FieldMap, Option<I>)> {
        let mut id = None;
        let output = self
            .storage_fields_with_bound_id(
                input,
                create,
                || {
                    id = resolve_id()?;
                    Ok(None)
                },
                bind,
            )
            .await?;
        Ok((output, id))
    }

    /// Apply update policies and preserve ID writes in schema order with aliased fields.
    #[doc(hidden)]
    pub async fn update_adapter_storage_fields(
        &self,
        input: FieldMap,
        resolve_id: impl FnMut() -> AuthResult<Option<Value>>,
        bind: impl Fn(&str, &UserFieldConfig, Value) -> AuthResult<Value>,
    ) -> AuthResult<FieldMap> {
        self.storage_fields_with_bound_id(input, false, resolve_id, bind)
            .await
    }

    /// Bind ID and application fields to the same storage keys in schema order.
    #[doc(hidden)]
    pub async fn storage_fields_with_bound_id(
        &self,
        input: FieldMap,
        create: bool,
        mut resolve_id: impl FnMut() -> AuthResult<Option<Value>>,
        bind: impl Fn(&str, &UserFieldConfig, Value) -> AuthResult<Value>,
    ) -> AuthResult<FieldMap> {
        let schema = self.adapter_fields(&[]);
        let mut output = FieldMap::new();
        for (name, field) in schema.fields() {
            let value = if name == "id" {
                resolve_id()?
            } else {
                field.storage_input(input.get(name), create).await?
            };
            if let Some(value) = value {
                let storage_name = resolve_field_name(field.field_name.as_deref(), name);
                let value = if name == "id" {
                    value
                } else {
                    bind(storage_name, field, value)?
                };
                if !value.is_undefined() {
                    let _ = output.insert(storage_name.to_owned(), value);
                }
            }
        }
        Ok(output)
    }

    pub(crate) fn ordered_fields(&self, native: &[&str]) -> Vec<(&str, &UserFieldConfig)> {
        let mut fields: Vec<_> = self
            .fields()
            .iter()
            .map(|(name, field)| (name.as_str(), field))
            .collect();
        // Native replacements retain schema positions. Integer keys use JavaScript property order.
        fields.sort_by_key(|(name, _)| {
            let native = native
                .iter()
                .position(|field| field == name)
                .unwrap_or(native.len());
            crate::utils::json::array_index(name)
                .map_or((true, 0, native), |index| (false, index, 0))
        });
        fields
    }

    /// Apply storage policies before converting JSON for the selected adapter.
    pub async fn storage_fields_for_adapter(
        &self,
        input: FieldMap,
        create: bool,
        supports_native_json: bool,
        native_json_field: impl Fn(&str) -> bool,
    ) -> AuthResult<FieldMap> {
        self.storage_fields_with_binding(input, create, |name, field, value| {
            field.adapter_input(value, supports_native_json, native_json_field(name))
        })
        .await
    }

    /// Bind transformed fields to an adapter without repeating defaults or application transforms.
    pub async fn storage_fields_with_binding(
        &self,
        input: FieldMap,
        create: bool,
        bind: impl Fn(&str, &UserFieldConfig, Value) -> AuthResult<Value>,
    ) -> AuthResult<FieldMap> {
        let mut fields = self.storage_fields(input, create).await?;
        for (name, field) in self.fields() {
            let storage_name = resolve_field_name(field.field_name.as_deref(), name);
            if let Some(value) = fields.get_mut(storage_name) {
                *value = bind(storage_name, field, value.take())?;
            }
        }
        Ok(fields)
    }
}

impl UserFieldConfig {
    /// Convert a transformed value to the selected adapter's database binding.
    /// JSON text uses JavaScript property ordering and number formatting.
    /// Serialization errors propagate before the adapter writes the value.
    pub fn adapter_input(
        &self,
        value: Value,
        supports_native_json: bool,
        native_json_field: bool,
    ) -> AuthResult<Value> {
        if self.references_id() {
            match (&self.field_type, &value) {
                (UserFieldType::Boolean, Value::Bool(value)) if !supports_native_json => {
                    return Ok(Value::from(i64::from(*value)));
                }
                (UserFieldType::StringArray | UserFieldType::NumberArray, Value::Array(_))
                | (UserFieldType::Json, Value::Object(_) | Value::Array(_) | Value::Date(_)) => {
                    return json_text(value);
                }
                _ => {}
            }
        }
        if !supports_native_json
            && matches!(self.field_type, UserFieldType::Json)
            && (value.is_null()
                || (!native_json_field
                    && (value.is_object() || value.is_array() || matches!(value, Value::Date(_)))))
        {
            json_text(value)
        } else {
            Ok(value)
        }
    }

    /// Whether this field uses the adapter's reference-to-ID conversion.
    pub fn references_id(&self) -> bool {
        self.references
            .as_ref()
            .is_some_and(|reference| reference.field == "id")
    }

    pub(crate) fn uses_id_output(&self) -> bool {
        self.references_id() || self.field_name.as_deref() == Some("id")
    }

    /// Await the output policy before decoding adapter storage values.
    pub async fn adapter_output(
        &self,
        value: Value,
        supports_native_json: bool,
    ) -> AuthResult<Value> {
        self.adapter_output_with_capabilities(
            value,
            FieldOutputCapabilities::json_only(supports_native_json),
        )
        .await
    }

    pub(crate) async fn adapter_output_with_capabilities(
        &self,
        value: Value,
        capabilities: FieldOutputCapabilities,
    ) -> AuthResult<Value> {
        let value = self.prepare_output(value, capabilities.supports_native_json)?;
        self.adapter_output_from_raw(value, capabilities).await
    }

    pub(crate) async fn adapter_output_from_raw(
        &self,
        mut value: Value,
        capabilities: FieldOutputCapabilities,
    ) -> AuthResult<Value> {
        if let Some(transform) = self.output_transform() {
            value = transform.call(value).await?;
        }
        self.finish_output(value, capabilities)
    }

    fn prepare_output(&self, value: Value, supports_native_json: bool) -> AuthResult<Value> {
        if !supports_native_json
            && self.field_name.as_deref() != Some("id")
            && matches!(self.field_type, UserFieldType::Json)
        {
            match value {
                Value::Object(_) | Value::Array(_) | Value::Date(_) => json_text(value),
                value => Ok(value),
            }
        } else {
            Ok(value)
        }
    }

    fn finish_output(
        &self,
        value: Value,
        capabilities: FieldOutputCapabilities,
    ) -> AuthResult<Value> {
        if self.uses_id_output() {
            return if value.is_null() || value.is_undefined() {
                Ok(value)
            } else {
                value.display_utf16().map(Value::from)
            };
        }
        match value {
            Value::String(text)
                if (!capabilities.supports_native_json
                    && matches!(self.field_type, UserFieldType::Json))
                    || (!capabilities.supports_arrays
                        && matches!(
                            self.field_type,
                            UserFieldType::StringArray | UserFieldType::NumberArray
                        )) =>
            {
                revive_json(crate::utils::json::safe_json_parse(&text))
            }
            Value::Number(number)
                if !capabilities.supports_booleans
                    && matches!(self.field_type, UserFieldType::Boolean) =>
            {
                Ok(Value::Bool(number == 1.0))
            }
            value => Ok(value),
        }
    }
}

fn json_text(value: Value) -> AuthResult<Value> {
    Ok(value.stringify()?.map(Value::String).unwrap_or_default())
}

fn revive_json(value: serde_json::Value) -> AuthResult<Value> {
    match value {
        serde_json::Value::String(text) => Ok(crate::utils::json::parse_json_date(&text)
            .map_or_else(|| Value::String(text), Value::from)),
        serde_json::Value::Array(values) => values
            .into_iter()
            .map(revive_json)
            .collect::<AuthResult<Vec<_>>>()
            .map(Value::from),
        serde_json::Value::Object(values) => values
            .into_iter()
            .map(|(name, value)| Ok((name, revive_json(value)?)))
            .collect::<AuthResult<FieldMap>>()
            .map(Value::from),
        value => Value::from_json(value),
    }
}
