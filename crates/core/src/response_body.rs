use crate::{AuthError, AuthResult, FieldValue};
use std::{borrow::Cow, sync::Arc};

/// Immutable Blob contents. Clones of a Blob response retain the same object identity.
#[derive(Debug)]
pub struct ResponseBlob {
    bytes: Arc<[u8]>,
    mime_type: String,
}

impl ResponseBlob {
    /// Apply the File API MIME normalization used by the Blob constructor.
    pub fn new(bytes: impl Into<Arc<[u8]>>, mime_type: impl Into<String>) -> Self {
        let mime_type = mime_type.into();
        let mime_type = if mime_type.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
            mime_type.to_ascii_lowercase()
        } else {
            String::new()
        };
        Self {
            bytes: bytes.into(),
            mime_type,
        }
    }

    /// Borrow the Blob contents without changing the shared object.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Read the normalized MIME type, which can be empty.
    pub fn mime_type(&self) -> &str {
        &self.mime_type
    }
}

/// One endpoint result, encoded only when a consumer requests an HTTP body.
#[derive(Debug, Clone)]
pub enum ResponseBody {
    Native(FieldValue),
    /// An ArrayBuffer or view, before HTTP materialization. Clones retain the same buffer.
    Binary(Arc<[u8]>),
    /// A shared Blob object, before HTTP materialization.
    Blob(Arc<ResponseBlob>),
    /// A null HTTP body, distinct from a present body with zero bytes.
    Empty,
    /// An explicit Response body or an already materialized HTTP body.
    Bytes(Vec<u8>),
}

impl ResponseBody {
    /// Read the current endpoint result. Byte replacements cross a JSON boundary.
    pub fn field_value(&self) -> AuthResult<FieldValue> {
        match self {
            Self::Empty => Ok(FieldValue::Undefined),
            Self::Native(value) => Ok(value.clone()),
            Self::Bytes(bytes) if bytes.is_empty() => Ok(FieldValue::Undefined),
            Self::Bytes(bytes) => FieldValue::parse_json(
                serde_json::from_slice::<&serde_json::value::RawValue>(bytes)?.get(),
            ),
            Self::Binary(_) | Self::Blob(_) => Err(AuthError::type_error(
                "Binary and Blob results are not field values",
            )),
        }
    }

    /// Project field values as JSON, or parse an encoded body without replacing the result.
    /// Binary and Blob values require explicit byte decoding because their native types are not field values.
    pub fn json(&self) -> AuthResult<Option<serde_json::Value>> {
        match self {
            Self::Empty => Ok(None),
            Self::Native(value) => value.json(),
            Self::Bytes(bytes) if bytes.is_empty() => Ok(None),
            Self::Bytes(bytes) => Ok(Some(serde_json::from_slice(bytes)?)),
            Self::Binary(_) | Self::Blob(_) => Err(AuthError::type_error(
                "Binary and Blob results do not have a JSON value",
            )),
        }
    }

    /// Encode the native result at an explicit byte boundary.
    pub fn bytes(&self) -> AuthResult<Cow<'_, [u8]>> {
        match self {
            Self::Empty => Ok(Cow::Borrowed(&[])),
            Self::Native(FieldValue::String(value)) => Ok(Cow::Borrowed(value.as_bytes())),
            Self::Native(FieldValue::Utf16String(value)) => Ok(Cow::Owned(
                String::from_utf16_lossy(value.as_utf16()).into_bytes(),
            )),
            Self::Native(FieldValue::Number(value)) if value.is_nan() => Ok(Cow::Borrowed(b"NaN")),
            Self::Native(FieldValue::Function(_)) => Err(AuthError::type_error(
                "Function results cannot be represented as an HTTP body",
            )),
            Self::Native(value) => Ok(Cow::Owned(
                value.stringify()?.unwrap_or_default().into_bytes(),
            )),
            Self::Binary(bytes) => Ok(Cow::Borrowed(bytes)),
            Self::Blob(blob) => Ok(Cow::Borrowed(blob.bytes())),
            Self::Bytes(bytes) => Ok(Cow::Borrowed(bytes)),
        }
    }

    pub fn into_bytes(self) -> AuthResult<Vec<u8>> {
        match self {
            Self::Bytes(bytes) => Ok(bytes),
            body => Ok(body.bytes()?.into_owned()),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::Empty => true,
            Self::Native(FieldValue::String(value)) => value.is_empty(),
            Self::Native(FieldValue::Utf16String(value)) => value.as_utf16().is_empty(),
            Self::Native(value) => matches!(value, FieldValue::Undefined),
            Self::Binary(bytes) => bytes.is_empty(),
            Self::Blob(blob) => blob.bytes().is_empty(),
            Self::Bytes(bytes) => bytes.is_empty(),
        }
    }

    pub(crate) fn http_content_type(&self) -> &str {
        match self {
            Self::Native(value) if value.is_string() && value.is_truthy() => "text/plain",
            Self::Binary(_) => "application/octet-stream",
            Self::Blob(blob) if !blob.mime_type().is_empty() => blob.mime_type(),
            Self::Blob(_) => "application/octet-stream",
            Self::Native(_) | Self::Bytes(_) | Self::Empty => "application/json",
        }
    }

    pub(crate) fn is_null_body(&self) -> bool {
        matches!(self, Self::Native(FieldValue::Undefined) | Self::Empty)
    }
}
