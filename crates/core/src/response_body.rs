use crate::{AuthResult, FieldValue};
use std::borrow::Cow;

/// One endpoint result, encoded only when a consumer requests an HTTP body.
#[derive(Debug, Clone)]
pub enum ResponseBody {
    Native(FieldValue),
    Bytes(Vec<u8>),
}

impl ResponseBody {
    /// Read the current endpoint result. Byte replacements cross a JSON boundary.
    pub fn field_value(&self) -> AuthResult<FieldValue> {
        match self {
            Self::Native(value) => Ok(value.clone()),
            Self::Bytes(bytes) if bytes.is_empty() => Ok(FieldValue::Undefined),
            Self::Bytes(bytes) => FieldValue::from_json(serde_json::from_slice(bytes)?),
        }
    }

    /// Observe the JSON representation without replacing the native result.
    pub fn json(&self) -> AuthResult<Option<serde_json::Value>> {
        match self {
            Self::Native(value) => value.json(),
            Self::Bytes(bytes) if bytes.is_empty() => Ok(None),
            Self::Bytes(bytes) => Ok(Some(serde_json::from_slice(bytes)?)),
        }
    }

    /// Encode the native result at an explicit byte boundary.
    pub fn bytes(&self) -> AuthResult<Cow<'_, [u8]>> {
        match self {
            Self::Native(value) => Ok(Cow::Owned(
                value.stringify()?.unwrap_or_default().into_bytes(),
            )),
            Self::Bytes(bytes) => Ok(Cow::Borrowed(bytes)),
        }
    }

    pub fn into_bytes(self) -> AuthResult<Vec<u8>> {
        match self {
            Self::Native(value) => Ok(value.stringify()?.unwrap_or_default().into_bytes()),
            Self::Bytes(bytes) => Ok(bytes),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::Native(value) => matches!(value, FieldValue::Undefined),
            Self::Bytes(bytes) => bytes.is_empty(),
        }
    }
}
