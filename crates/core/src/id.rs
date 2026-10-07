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
        if let Some(id) = supplied {
            if id.is_empty() {
                return Ok(None);
            }
            if matches!(self, Self::Uuid)
                && !(id.len() == 36
                    && uuid::Uuid::parse_str(&id).is_ok_and(|id| {
                        (1..=5).contains(&id.get_version_num())
                            && id.get_variant() == uuid::Variant::RFC4122
                    }))
            {
                tracing::warn!("Invalid forced UUID; the adapter omits the ID");
                return Ok(None);
            }
            if matches!(self, Self::Serial) {
                let number = crate::query::number(&serde_json::Value::String(id))?;
                return Ok((!number.is_nan()).then(|| crate::schema_value::number_string(number)));
            }
            return Ok(Some(id));
        }
        if matches!(self, Self::Uuid) && supports_native_uuid {
            return Ok(None);
        }
        Ok(self
            .generate(IdGenerationRequest { model, size: None })?
            .filter(|id| !id.is_empty()))
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
