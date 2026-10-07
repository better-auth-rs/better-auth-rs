//! Model-aware IDs. Credentials use independent random values.

use crate::AuthResult;
use rand::distributions::{Alphanumeric, DistString};
use std::{borrow::Cow, fmt, sync::Arc};

/// The canonical model name is independent of the physical table name.
#[derive(Debug, Clone, Copy)]
pub struct IdGenerationRequest<'a> {
    pub model: &'a str,
    pub size: Option<usize>,
}

type Callback = dyn Fn(IdGenerationRequest<'_>) -> AuthResult<Option<String>> + Send + Sync;

#[derive(Clone)]
pub struct IdGenerator(Arc<Callback>);

impl IdGenerator {
    /// Return `None` for upstream `false`; database inserts omit the generated ID.
    /// Pure-secondary sessions use their random fallback for this result.
    pub fn new(
        callback: impl Fn(IdGenerationRequest<'_>) -> AuthResult<Option<String>> + Send + Sync + 'static,
    ) -> Self {
        Self(Arc::new(callback))
    }

    pub fn generate(&self, request: IdGenerationRequest<'_>) -> AuthResult<Option<String>> {
        (self.0)(request)
    }
}

impl fmt::Debug for IdGenerator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IdGenerator")
    }
}

#[derive(Debug, Clone, Default)]
pub enum IdGeneration {
    /// Generate an alphanumeric ID. The default length is 32.
    #[default]
    Random,
    Uuid,
    /// Use the database's numeric auto-increment column.
    Serial,
    /// Omit generated IDs, equivalent to upstream `generateId: false`.
    Database,
    Custom(IdGenerator),
}

/// Parameters retained by the adapter's current ID input field.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AdapterIdInput {
    /// Accept an explicitly supplied ID through the force-allowed create operation.
    pub force_allow_id: bool,
    /// Let the database generate UUIDs instead of installing a UUID default callback.
    pub supports_native_uuid: bool,
}

impl IdGeneration {
    /// Apply the serial adapter's Number conversion before a model parses an ID or reference.
    /// Other generation modes retain the caller's identifier exactly.
    pub fn coerce_id<'a>(&self, value: &'a str) -> AuthResult<Cow<'a, str>> {
        if matches!(self, Self::Serial) {
            let number = crate::query::number(&serde_json::Value::String(value.to_owned()))?;
            Ok(Cow::Owned(crate::schema_value::number_string(number)))
        } else {
            Ok(Cow::Borrowed(value))
        }
    }

    pub fn generate(&self, request: IdGenerationRequest<'_>) -> AuthResult<Option<String>> {
        match self {
            Self::Random => Ok(Some(random_id(request.size))),
            Self::Uuid => Ok(Some(uuid::Uuid::new_v4().to_string())),
            Self::Serial | Self::Database => Ok(None),
            Self::Custom(generator) => generator.generate(request),
        }
    }

    /// Explicit IDs represent the adapter's `forceAllowId` operation.
    pub fn adapter_id(
        &self,
        model: &str,
        supplied: Option<String>,
        supports_native_uuid: bool,
    ) -> AuthResult<Option<String>> {
        let policy = AdapterIdInput {
            force_allow_id: supplied.is_some(),
            supports_native_uuid,
        };
        self.adapter_id_with_policy(model, supplied, policy)
    }

    /// Resolve an ID with the policy active after preceding schema callbacks.
    #[doc(hidden)]
    pub fn adapter_id_with_policy(
        &self,
        model: &str,
        supplied: Option<String>,
        policy: AdapterIdInput,
    ) -> AuthResult<Option<String>> {
        self.adapter_create_id_input(model, supplied.map(crate::FieldValue::String), policy)?
            .map(|value| crate::SchemaValue::<String>::from_field(value).display_string())
            .transpose()
    }

    /// Apply ID creation defaults before the current adapter input policy.
    #[doc(hidden)]
    pub fn adapter_create_id_input(
        &self,
        model: &str,
        supplied: Option<crate::FieldValue>,
        policy: AdapterIdInput,
    ) -> AuthResult<Option<crate::FieldValue>> {
        let required = match self {
            Self::Serial => policy.force_allow_id,
            Self::Uuid => !policy.supports_native_uuid,
            _ => true,
        };
        let supplied =
            supplied.filter(|value| !value.is_undefined() && !(required && value.is_null()));
        let value = match supplied {
            Some(value) => value,
            None if matches!(self, Self::Uuid) && policy.supports_native_uuid => return Ok(None),
            None => match self.generate(IdGenerationRequest { model, size: None })? {
                Some(value) => crate::FieldValue::String(value),
                None => return Ok(None),
            },
        };
        self.adapter_id_input(value, policy)
    }

    /// Bind a primary-key query without converting runtime values to strings.
    #[doc(hidden)]
    pub fn adapter_id_query(&self, value: crate::FieldValue) -> AuthResult<crate::FieldValue> {
        if matches!(self, Self::Serial) {
            serial_reference_query_value(value)
        } else {
            Ok(value)
        }
    }

    /// Apply the current adapter ID input policy without converting runtime values to strings.
    #[doc(hidden)]
    pub fn adapter_id_input(
        &self,
        value: crate::FieldValue,
        policy: AdapterIdInput,
    ) -> AuthResult<Option<crate::FieldValue>> {
        if !value.is_truthy() {
            return Ok(None);
        }
        match self {
            Self::Serial => {
                let number = crate::query::field_number(&value)?;
                Ok((!number.is_nan()).then_some(crate::FieldValue::Number(number)))
            }
            Self::Uuid if !policy.force_allow_id => {
                Ok((!policy.supports_native_uuid).then_some(value))
            }
            Self::Uuid if value.is_string() => {
                let valid = value.display_utf16()?.to_utf8().is_ok_and(|text| {
                    text.len() == 36
                        && uuid::Uuid::parse_str(&text).is_ok_and(|id| {
                            (1..=5).contains(&id.get_version_num())
                                && id.get_variant() == uuid::Variant::RFC4122
                        })
                });
                if !valid {
                    tracing::warn!("Invalid forced UUID; the adapter omits the ID");
                }
                Ok(valid.then_some(value))
            }
            Self::Uuid if policy.supports_native_uuid => Ok(None),
            Self::Uuid => Ok(Some(crate::FieldValue::String(
                uuid::Uuid::new_v4().to_string(),
            ))),
            _ => Ok(Some(value)),
        }
    }
}

pub fn random_id(size: Option<usize>) -> String {
    Alphanumeric.sample_string(
        &mut rand::thread_rng(),
        size.filter(|size| *size != 0).unwrap_or(32),
    )
}

pub(crate) fn serial_reference_value(value: crate::FieldValue) -> AuthResult<crate::FieldValue> {
    serial_reference(value, false)
}

pub(crate) fn serial_reference_query_value(
    value: crate::FieldValue,
) -> AuthResult<crate::FieldValue> {
    serial_reference(value, true)
}

fn serial_reference(value: crate::FieldValue, query: bool) -> AuthResult<crate::FieldValue> {
    let convert = |value: crate::FieldValue| {
        if value.is_null() && !query {
            Ok(value)
        } else {
            crate::query::field_number(&value).map(crate::FieldValue::Number)
        }
    };
    match value {
        crate::FieldValue::Array(values) => values
            .iter()
            .cloned()
            .map(convert)
            .collect::<AuthResult<Vec<_>>>()
            .map(Into::into),
        value => convert(value),
    }
}
