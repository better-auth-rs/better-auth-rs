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
    /// Date strings need no constructor conversion when the adapter supports dates.
    pub supports_native_dates: bool,
}

impl FieldOutputCapabilities {
    pub(crate) const fn json_only(supports_native_json: bool) -> Self {
        Self {
            supports_native_json,
            supports_arrays: true,
            supports_booleans: true,
            supports_native_dates: true,
        }
    }
}

impl UserConfig {
    /// Resolve schema order and replace the adapter-owned ID policy in its existing slot.
    #[doc(hidden)]
    pub fn adapter_fields(&self, native: &[&str]) -> Self {
        let mut ordered = self.ordered_declarations(native);
        let _ = ordered
            .fields_mut()
            .insert("id".into(), UserFieldConfig::default());
        ordered
    }

    pub(crate) fn ordered_declarations(&self, native: &[&str]) -> Self {
        Self {
            additional_fields: Some(
                self.ordered_fields(native)
                    .into_iter()
                    .map(|(name, field)| (name.to_owned(), field.clone()))
                    .collect(),
            ),
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
        let result = async {
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
        .await;
        // The factory awaits transformInput before the backend can observe the prepared write.
        super::batch::await_boundary().await;
        result
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
        self.storage_fields_async(input, create, bind).await
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
            value = transform.call_adapter(value).await?;
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
            value @ (Value::String(_) | Value::Utf16String(_))
                if (!capabilities.supports_native_json
                    && matches!(self.field_type, UserFieldType::Json))
                    || (!capabilities.supports_arrays
                        && matches!(
                            self.field_type,
                            UserFieldType::StringArray | UserFieldType::NumberArray
                        )) =>
            {
                Ok(crate::utils::json::safe_parse_field(&value))
            }
            Value::Number(number)
                if !capabilities.supports_booleans
                    && matches!(self.field_type, UserFieldType::Boolean) =>
            {
                Ok(Value::Bool(number == 1.0))
            }
            value @ (Value::String(_) | Value::Utf16String(_))
                if !capabilities.supports_native_dates
                    && matches!(self.field_type, UserFieldType::Date) =>
            {
                crate::query::field_date(&value).map(Value::Date)
            }
            value => Ok(value),
        }
    }
}

fn json_text(value: Value) -> AuthResult<Value> {
    Ok(value.stringify()?.map(Value::String).unwrap_or_default())
}
