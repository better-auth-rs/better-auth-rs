use std::time::Duration;

use better_auth_core::{AuthError, AuthResult, FieldValue, SchemaValue, Utf16String};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{OAuthProvider, OAuthUserInfo, OAuthUserInfoRequest, defaults::ProviderKind};
use crate::plugins::oauth::{generic_profile::decode_claims, id_token, oidc::OidcVerifier};

const ISSUER: &str = "https://appleid.apple.com";
const JWKS_URL: &str = "https://appleid.apple.com/auth/keys";

/// Audience selection for Sign in with Apple.
#[derive(Clone, Default)]
pub struct AppleOptions {
    /// Explicit accepted audiences. An omitted or empty list uses the bundle or client identifiers.
    pub audience: Option<Vec<String>>,
    /// Accepted bundle identifier when an explicit audience list is absent or empty.
    pub app_bundle_identifier: Option<String>,
    /// Additional accepted client identifiers after the primary `OAuthProvider::client_id`.
    pub additional_client_ids: Vec<String>,
    #[cfg(test)]
    pub(in crate::plugins::oauth) jwks_url: Option<String>,
}

impl AppleOptions {
    pub(in crate::plugins::oauth) fn audiences(&self, client_id: &str) -> Vec<String> {
        if let Some(audience) = self.audience.as_ref().filter(|values| !values.is_empty()) {
            audience.clone()
        } else if let Some(bundle) = self
            .app_bundle_identifier
            .as_ref()
            .filter(|value| !value.is_empty())
        {
            vec![bundle.clone()]
        } else {
            std::iter::once(client_id.to_owned())
                .chain(self.additional_client_ids.iter().cloned())
                .collect()
        }
    }

    pub(in crate::plugins::oauth) async fn verify(
        &self,
        client_id: &str,
        token: &str,
        nonce: Option<&str>,
    ) -> AuthResult<Value> {
        let jwks_url = JWKS_URL;
        #[cfg(test)]
        let jwks_url = self.jwks_url.as_deref().unwrap_or(jwks_url);
        let verifier = OidcVerifier::with_policy(
            jwks_url
                .parse()
                .map_err(|error: url::ParseError| AuthError::internal(error.to_string()))?,
            ISSUER.into(),
            self.audiences(client_id),
            None,
            Some(Duration::from_secs(3600)),
        )
        .map_err(|error| AuthError::internal(error.to_string()))?;
        let claims = verifier
            .verify(token, None)
            .await
            .map_err(|_| id_token::invalid())?;
        if let Some(nonce) = nonce.filter(|value| !value.is_empty()) {
            let claim = claims.get("nonce").and_then(Value::as_str);
            let hashed = hex::encode(Sha256::digest(nonce.as_bytes()));
            if claim != Some(nonce) && claim != Some(hashed.as_str()) {
                return Err(id_token::invalid());
            }
        }
        Ok(claims)
    }
}

impl OAuthProvider {
    /// Configure Apple authorization, token grants, and direct ID-token verification.
    /// `client_secret` is the configured Apple secret; this constructor does not generate one.
    pub fn apple(client_id: &str, client_secret: &str, options: AppleOptions) -> Self {
        Self {
            kind: ProviderKind::Apple(options),
            ..Self::custom(
                client_id,
                client_secret,
                "https://appleid.apple.com/auth/authorize",
                "https://appleid.apple.com/auth/token",
            )
        }
    }

    pub(in crate::plugins::oauth) fn apple_options(&self) -> Option<&AppleOptions> {
        match &self.kind {
            ProviderKind::Apple(options) => Some(options),
            _ => None,
        }
    }
}

pub(in crate::plugins::oauth) fn profile(
    request: &OAuthUserInfoRequest,
    verified: Option<Value>,
) -> AuthResult<Option<Value>> {
    let claims = match verified {
        Some(claims) => claims,
        None => {
            if !request.id_token.is_truthy()? {
                return Ok(None);
            }
            let token = request.id_token.field_value();
            decode_claims(&crate::plugins::oauth::providers::jwt_string(&token)?)
                .ok_or_else(|| AuthError::internal("Invalid Apple ID-token claims"))?
        }
    };
    enrich_profile(claims, &request.user.field_value()).map(Some)
}

fn enrich_profile(mut claims: Value, user: &FieldValue) -> AuthResult<Value> {
    let user_name = if user.is_null() || user.is_undefined() {
        FieldValue::Undefined
    } else {
        user.model_property("name")?
    };
    let name = if user_name.is_truthy() {
        let mut units = Vec::new();
        for (index, property) in ["firstName", "lastName"].into_iter().enumerate() {
            if index != 0 {
                units.push(u16::from(b' '));
            }
            let value = user.model_property("name")?.model_property(property)?;
            if value.is_truthy() {
                units.extend_from_slice(value.display_utf16()?.as_utf16());
            }
        }
        let name = Utf16String::from_units(units).to_utf8().map_err(|error| {
            AuthError::internal(format!(
                "JSON value cannot represent unpaired UTF-16 surrogates: {error}"
            ))
        })?;
        Value::String(
            name.trim_matches(crate::plugins::helpers::oauth_scope_whitespace)
                .to_owned(),
        )
    } else {
        let name = claims.get("name").cloned().unwrap_or_default();
        if FieldValue::from_json(name.clone())?.is_truthy() {
            name
        } else {
            Value::String(String::new())
        }
    };
    let _ = claims
        .as_object_mut()
        .ok_or_else(|| AuthError::internal("Apple claims must be an object"))?
        .insert("name".into(), name);
    Ok(claims)
}

pub(super) fn decode_profile(profile: Value) -> Result<OAuthUserInfo, String> {
    let verified = match profile.get("email_verified") {
        Some(Value::Bool(value)) => *value,
        Some(Value::String(value)) => value == "true",
        _ => false,
    };
    Ok(OAuthUserInfo {
        id: profile
            .get("sub")
            .and_then(Value::as_str)
            .ok_or("missing Apple subject")?
            .into(),
        name: SchemaValue::from_field(
            FieldValue::from_json(
                profile
                    .get("name")
                    .cloned()
                    .unwrap_or_else(|| Value::String(String::new())),
            )
            .map_err(|error| error.to_string())?,
        ),
        email: super::defaults::profile_email(&profile)?,
        image: None,
        email_verified: Some(verified).into(),
        additional_fields: Default::default(),
    })
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::panic_in_result_fn,
        reason = "The callback regressions must fail immediately on unexpected property access, conversion, or output"
    )]

    use super::*;
    use better_auth_core::{FieldFunction, FieldMap, FieldObject};
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    #[test]
    fn native_callback_names_keep_truthiness_and_template_conversion() -> AuthResult<()> {
        for (user, expected) in [
            (json!(null), json!(17)),
            (json!(false), json!(17)),
            (json!({"name": false}), json!(17)),
            (json!({"name": true}), json!("")),
            (json!({"name":{"firstName":7,"lastName":false}}), json!("7")),
            (
                json!({"name":{"firstName":["A",null,2],"lastName":{}}}),
                json!("A,,2 [object Object]"),
            ),
            (
                json!({"name":{"firstName":"\u{feff}Ada","lastName":"Lovelace\u{a0}"}}),
                json!("Ada Lovelace"),
            ),
        ] {
            let profile = enrich_profile(
                json!({"sub":"apple-owner","name":17}),
                &FieldValue::from_json(user)?,
            )?;
            assert_eq!(profile, json!({"sub":"apple-owner","name":expected}));
            let decoded = decode_profile(profile).map_err(AuthError::internal)?;
            assert_eq!(decoded.name.field_value().json()?, Some(expected));
        }
        Ok(())
    }

    #[test]
    fn native_callback_names_observe_conversion_mutations_and_keep_errors() -> AuthResult<()> {
        for fail in [false, true] {
            let events = Arc::new(Mutex::new(Vec::<String>::new()));
            let user = FieldObject::from(FieldMap::new());
            let changed_user = user.clone();
            let converted = events.clone();
            let last_converted = events.clone();
            let last: FieldValue = FieldMap::from([(
                "toString".into(),
                FieldFunction::contextual(move |receiver, arguments| {
                    assert!(receiver.is_object());
                    assert!(arguments.is_empty());
                    last_converted.lock().unwrap().push("last:toString".into());
                    Ok("Second".into())
                })
                .into(),
            )])
            .into();
            let first = FieldMap::from([(
                "toString".into(),
                FieldFunction::contextual(move |receiver, arguments| {
                    assert!(receiver.is_object());
                    assert!(arguments.is_empty());
                    converted.lock().unwrap().push("first:toString".into());
                    changed_user.set(
                        "name",
                        FieldMap::from([("lastName".into(), last.clone())]).into(),
                    )?;
                    if fail {
                        return Err(AuthError::internal("native Apple conversion failure"));
                    }
                    Ok("First".into())
                })
                .into(),
            )])
            .into();
            user.set(
                "name",
                FieldMap::from([
                    ("firstName".into(), first),
                    ("lastName".into(), "stale".into()),
                ])
                .into(),
            )?;
            let request = OAuthUserInfoRequest {
                user: SchemaValue::from_field(user.clone().into()),
                ..Default::default()
            };
            let result = profile(&request, Some(json!({"sub":"apple-owner"})));
            let _ = user.delete("name")?;
            if fail {
                assert!(
                    matches!(result, Err(AuthError::Internal(message)) if message == "native Apple conversion failure")
                );
                assert_eq!(*events.lock().unwrap(), ["first:toString"]);
            } else {
                assert_eq!(
                    result?,
                    Some(json!({"sub":"apple-owner","name":"First Second"}))
                );
                assert_eq!(*events.lock().unwrap(), ["first:toString", "last:toString"]);
            }
        }
        Ok(())
    }
}
