use serde_json::{Map, Value, json};

use crate::{AuthError, AuthResult};

use super::{OpenApiPluginMetadata, metadata::ordered_properties};

impl OpenApiPluginMetadata {
    /// Apply Device grant documentation without changing the pinned standalone endpoints.
    pub fn device_authorization_grant(
        mut self,
        request_error_codes: &[String],
        request_responses: &Map<String, Value>,
        verification_properties: &Map<String, Value>,
    ) -> AuthResult<Self> {
        let conflicts: Vec<_> = verification_properties
            .keys()
            .filter(|name| {
                matches!(
                    name.as_str(),
                    "user_code" | "status" | "client_id" | "scope"
                )
            })
            .map(String::as_str)
            .collect();
        if !conflicts.is_empty() {
            return Err(AuthError::config(format!(
                "Device authorization grant verification fields must be additional and cannot redefine response fields: {}",
                conflicts.join(", "),
            )));
        }

        let code = self
            .endpoint_mut("deviceCode")
            .ok_or_else(|| AuthError::config("OpenAPI Device endpoint deviceCode is absent"))?;
        let request = code
            .metadata
            .request_body
            .as_mut()
            .and_then(|body| body.pointer_mut("/content/application~1json/schema"))
            .and_then(Value::as_object_mut)
            .ok_or_else(|| AuthError::config("OpenAPI Device request schema is absent"))?;
        let properties = request
            .get_mut("properties")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| AuthError::config("OpenAPI Device request properties are absent"))?;
        // The grant replaces the described field with a new optional string schema.
        let _ = properties.insert("client_id".into(), json!({"type":"string"}));
        if let Some(required) = request.get_mut("required").and_then(Value::as_array_mut) {
            required.retain(|field| field.as_str() != Some("client_id"));
            if required.is_empty() {
                let _ = request.remove("required");
            }
        }

        let error_codes = code
            .metadata
            .responses
            .get_mut("400")
            .and_then(|response| {
                response.pointer_mut("/content/application~1json/schema/properties/error/enum")
            })
            .and_then(Value::as_array_mut)
            .ok_or_else(|| AuthError::config("OpenAPI Device request error codes are absent"))?;
        error_codes.extend(request_error_codes.iter().cloned().map(Value::String));
        let mut responses = request_responses.clone();
        responses.extend(std::mem::take(&mut code.metadata.responses));
        code.metadata.responses = ordered_properties(responses);

        let verify = self
            .endpoint_mut("deviceVerify")
            .ok_or_else(|| AuthError::config("OpenAPI Device endpoint deviceVerify is absent"))?;
        let properties = verify
            .metadata
            .responses
            .get_mut("200")
            .and_then(|response| {
                response.pointer_mut("/content/application~1json/schema/properties")
            })
            .and_then(Value::as_object_mut)
            .ok_or_else(|| {
                AuthError::config("OpenAPI Device verification properties are absent")
            })?;
        properties.extend(verification_properties.clone());
        *properties = ordered_properties(std::mem::take(properties));
        Ok(self)
    }
}
