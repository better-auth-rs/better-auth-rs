//! Model-aware IDs. Credentials use independent random values.

use crate::AuthResult;
use rand::distributions::{Alphanumeric, DistString};
use std::{fmt, sync::Arc};

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
                && !uuid::Uuid::parse_str(&id).is_ok_and(|id| {
                    (1..=5).contains(&id.get_version_num())
                        && id.get_variant() == uuid::Variant::RFC4122
                })
            {
                tracing::warn!("Invalid forced UUID; the adapter omits the ID");
                return Ok(None);
            }
            if matches!(self, Self::Serial) {
                return Ok(
                    if id
                        .trim_matches(|ch: char| {
                            (ch.is_whitespace() && ch != '\u{85}') || ch == '\u{feff}'
                        })
                        .is_empty()
                    {
                        Some("0".into())
                    } else {
                        crate::organization_fields::numeric_filter(&id)
                            .map(crate::schema_value::number_string)
                    },
                );
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
