use super::*;
use std::{future::Future, pin::Pin, sync::Arc};

/// Expected token recipients, preserving the string or array claim representation.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum JwtAudience {
    /// One recipient encoded as a string.
    Single(String),
    /// Recipients encoded as an array, including an explicit empty array.
    Multiple(Vec<String>),
}

impl From<String> for JwtAudience {
    fn from(value: String) -> Self {
        Self::Single(value)
    }
}

impl From<&str> for JwtAudience {
    fn from(value: &str) -> Self {
        Self::Single(value.into())
    }
}

impl From<Vec<String>> for JwtAudience {
    fn from(value: Vec<String>) -> Self {
        Self::Multiple(value)
    }
}

/// Default expiration when a payload does not supply its own `exp` claim.
#[derive(Clone, Debug)]
pub enum JwtExpiration {
    /// Lifetime relative to the payload's issue time, or the current time when omitted.
    After(Duration),
    /// Absolute NumericDate in seconds. Fractional values remain observable.
    At(serde_json::Number),
}

impl From<Duration> for JwtExpiration {
    fn from(value: Duration) -> Self {
        Self::After(value)
    }
}

impl From<chrono::DateTime<Utc>> for JwtExpiration {
    fn from(value: chrono::DateTime<Utc>) -> Self {
        Self::At(value.timestamp().into())
    }
}

impl From<i64> for JwtExpiration {
    fn from(value: i64) -> Self {
        Self::At(value.into())
    }
}

/// An asynchronous application callback result.
pub type JwtCallbackFuture<T> = Pin<Box<dyn Future<Output = AuthResult<T>> + Send>>;
/// Define claims from the complete authenticated session and user object.
pub type JwtDefinePayload =
    Arc<dyn Fn(Value) -> JwtCallbackFuture<Map<String, Value>> + Send + Sync>;
/// Select a subject from the complete authenticated session and user object.
pub type JwtGetSubject = Arc<dyn Fn(Value) -> JwtCallbackFuture<String> + Send + Sync>;
/// Sign with application-managed keys. The callback must set `alg` and `kid`.
pub type JwtCustomSign =
    Arc<dyn Fn(Map<String, Value>, JwtSigningOptions) -> JwtCallbackFuture<String> + Send + Sync>;

/// Define a payload while retaining the original Session object and dynamic return value.
pub type JwtNativeDefinePayload =
    Arc<dyn Fn(FieldValue) -> JwtCallbackFuture<FieldValue> + Send + Sync>;
/// Select a native subject. Null and undefined use the current Session User ID.
pub type JwtNativeGetSubject =
    Arc<dyn Fn(FieldValue) -> JwtCallbackFuture<FieldValue> + Send + Sync>;
/// Sign native claims, the optional protected header, and the key-selection object.
pub type JwtNativeCustomSign =
    Arc<dyn Fn(FieldValue, FieldValue, FieldValue) -> JwtCallbackFuture<FieldValue> + Send + Sync>;

impl JwtPlugin {
    /// Define claims through an explicit JSON callback boundary.
    pub fn define_payload(self, callback: JwtDefinePayload) -> Self {
        self.define_payload_native(Arc::new(move |session| {
            let callback = callback.clone();
            Box::pin(async move {
                Ok(FieldMap::from_json(callback(callback_json(&session)?).await?)?.into())
            })
        }))
    }

    /// Define claims without serializing the original Session or callback return value.
    pub fn define_payload_native(mut self, callback: JwtNativeDefinePayload) -> Self {
        self.config.define_payload = Some(callback);
        Self::with_config(self.config)
    }

    /// Select a string subject through an explicit JSON callback boundary.
    pub fn get_subject(self, callback: JwtGetSubject) -> Self {
        self.get_subject_native(Arc::new(move |session| {
            let callback = callback.clone();
            Box::pin(async move { Ok(callback(callback_json(&session)?).await?.into()) })
        }))
    }

    /// Select a native subject, preserving nullish fallback and other dynamic values.
    pub fn get_subject_native(mut self, callback: JwtNativeGetSubject) -> Self {
        self.config.get_subject = Some(callback);
        Self::with_config(self.config)
    }

    /// Sign JSON claims and return a string through the typed convenience boundary.
    pub fn custom_sign(self, callback: JwtCustomSign) -> Self {
        self.custom_sign_native(Arc::new(move |payload, header, selection| {
            let callback = callback.clone();
            Box::pin(async move {
                let payload = serde_json::from_value(callback_json(&payload)?)?;
                let key = selection.model_property("signingKeyId")?;
                let algorithm = selection.model_property("signingAlgorithm")?;
                let options = JwtSigningOptions {
                    key_id: key.json()?.map(serde_json::from_value).transpose()?,
                    algorithm: algorithm.json()?.map(serde_json::from_value).transpose()?,
                    header: if header.is_undefined() {
                        Map::new()
                    } else {
                        serde_json::from_value(callback_json(&header)?)?
                    },
                };
                Ok(callback(payload, options).await?.into())
            })
        }))
    }

    /// Sign native claims without narrowing the header, own undefined fields, or return value.
    pub fn custom_sign_native(mut self, callback: JwtNativeCustomSign) -> Self {
        self.config.custom_sign = Some(callback);
        Self::with_config(self.config)
    }
}

fn callback_json(value: &FieldValue) -> AuthResult<Value> {
    value.json()?.ok_or_else(|| {
        AuthError::type_error("The JSON JWT callback input has no JSON representation")
    })
}

/// Per-call protected headers and key selection, matching upstream signing overrides.
#[derive(Clone, Debug, Default)]
pub struct JwtSigningOptions {
    /// Pin a previously provisioned key. Missing or expired keys fail.
    pub key_id: Option<String>,
    /// Pin an algorithm. Only configured algorithms can be provisioned lazily.
    pub algorithm: Option<JwtAlgorithm>,
    /// Additional protected headers. Local signing always supplies `alg` and `kid`.
    pub header: Map<String, Value>,
}

/// Parameters for primary or lazily provisioned additional signing keys.
#[derive(Clone, Copy, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JwtKeyPairConfig {
    /// Signing algorithm.
    #[serde(rename = "alg")]
    pub algorithm: JwtAlgorithm,
    /// RSA modulus length for RS256 and PS256. Defaults to 2048 bits.
    #[serde(default = "default_modulus_length")]
    pub modulus_length: u32,
}

impl JwtKeyPairConfig {
    /// Use the upstream default key parameters for an algorithm.
    pub fn new(algorithm: JwtAlgorithm) -> Self {
        Self {
            algorithm,
            modulus_length: 2048,
        }
    }
}

fn default_modulus_length() -> u32 {
    2048
}
