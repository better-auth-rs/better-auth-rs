pub(crate) use better_auth_core::wire::PasskeyView;
use serde::{Deserialize, Serialize};
use validator::Validate;

// -- Request types --

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VerifyRegistrationRequest {
    pub(super) response: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) create_session: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VerifyAuthenticationRequest {
    pub(super) response: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeletePasskeyRequest {
    pub(super) id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UpdatePasskeyRequest {
    pub(super) id: String,
    #[validate(length(min = 1))]
    pub(super) name: String,
}

// -- Response helpers --

#[derive(Debug, Serialize)]
pub(crate) struct PasskeyResponse {
    pub(super) passkey: PasskeyView,
}

fn body_object(
    req: &better_auth_core::AuthRequest,
) -> Result<serde_json::Map<String, serde_json::Value>, better_auth_core::AuthResponse> {
    use crate::plugins::json_body;
    match req.input_body().map_err(|error| error.to_auth_response())? {
        Some(serde_json::Value::Object(value)) => Ok(value),
        value => Err(json_body::validation_error(&json_body::invalid_type(
            "body",
            "object",
            value.as_ref(),
        ))),
    }
}

pub(super) fn trim_name(value: &str) -> &str {
    value.trim_matches(|character: char| {
        character == '\u{feff}' || (character.is_whitespace() && character != '\u{0085}')
    })
}

impl VerifyRegistrationRequest {
    pub(super) fn parse(
        req: &better_auth_core::AuthRequest,
    ) -> Result<Self, better_auth_core::AuthResponse> {
        use crate::plugins::json_body;
        if let Some(body) = req.validated_body::<Self>() {
            return Ok(body.clone());
        }
        let body = body_object(req)?;
        let mut errors = Vec::new();
        if !body.contains_key("response") {
            errors.push(json_body::invalid_type(
                "body.response",
                "nonoptional",
                None,
            ));
        }
        errors.extend(
            [("name", "string"), ("createSession", "boolean")]
                .into_iter()
                .filter_map(|(name, expected)| {
                    body.get(name)
                        .filter(|value| json_body::type_name(Some(value)) != expected)
                        .map(|value| {
                            json_body::invalid_type(&format!("body.{name}"), expected, Some(value))
                        })
                }),
        );
        if !errors.is_empty() {
            return Err(json_body::validation_error(&errors.join("; ")));
        }
        Ok(Self {
            response: body
                .get("response")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
            name: body
                .get("name")
                .and_then(serde_json::Value::as_str)
                .map(|value| trim_name(value).to_owned()),
            create_session: body
                .get("createSession")
                .and_then(serde_json::Value::as_bool),
        })
    }
}
impl VerifyAuthenticationRequest {
    pub(super) fn parse(
        req: &better_auth_core::AuthRequest,
    ) -> Result<Self, better_auth_core::AuthResponse> {
        use crate::plugins::json_body;
        if let Some(body) = req.validated_body::<Self>() {
            return Ok(body.clone());
        }
        let body = body_object(req)?;
        match body.get("response") {
            Some(response @ serde_json::Value::Object(_)) => Ok(Self {
                response: response.clone(),
            }),
            value => Err(json_body::validation_error(&json_body::invalid_type(
                "body.response",
                "record",
                value,
            ))),
        }
    }
}

fn projected<T: Serialize + Send + Sync + 'static>(
    body: T,
) -> better_auth_core::AuthResult<better_auth_core::endpoint_input::ValidatedBody> {
    Ok(better_auth_core::endpoint_input::ValidatedBody::new(
        Some(serde_json::to_value(&body)?),
        body,
    ))
}
pub(super) fn registration_body(
    req: &better_auth_core::AuthRequest,
) -> better_auth_core::AuthResult<better_auth_core::endpoint_input::ValidatedBody> {
    projected(VerifyRegistrationRequest::parse(req).map_err(better_auth_core::AuthError::from)?)
}
pub(super) fn authentication_body(
    req: &better_auth_core::AuthRequest,
) -> better_auth_core::AuthResult<better_auth_core::endpoint_input::ValidatedBody> {
    projected(VerifyAuthenticationRequest::parse(req).map_err(better_auth_core::AuthError::from)?)
}
pub(super) fn deletion_body(
    req: &better_auth_core::AuthRequest,
) -> better_auth_core::AuthResult<better_auth_core::endpoint_input::ValidatedBody> {
    let (body, _) =
        crate::plugins::json_body::string_input::<DeletePasskeyRequest>(req, &[("id", true)])?;
    projected(body)
}
pub(super) fn update_body(
    req: &better_auth_core::AuthRequest,
) -> better_auth_core::AuthResult<better_auth_core::endpoint_input::ValidatedBody> {
    use crate::plugins::json_body;
    let body = body_object(req).map_err(better_auth_core::AuthError::from)?;
    let mut errors = Vec::new();
    for name in ["id", "name"] {
        match body.get(name) {
            Some(serde_json::Value::String(value))
                if name == "name" && trim_name(value).is_empty() =>
            {
                errors.push(
                    "[body.name] Too small: expected string to have >=1 characters".to_owned(),
                )
            }
            Some(serde_json::Value::String(_)) => {}
            value => errors.push(json_body::invalid_type(
                &format!("body.{name}"),
                "string",
                value,
            )),
        }
    }
    if !errors.is_empty() {
        return Err(json_body::validation_error(&errors.join("; ")).into());
    }
    let mut typed: UpdatePasskeyRequest = serde_json::from_value(serde_json::Value::Object(body))?;
    typed.name = trim_name(&typed.name).to_owned();
    projected(typed)
}
pub(super) fn read<T: Clone + Send + Sync + 'static>(
    req: &better_auth_core::AuthRequest,
    validator: fn(
        &better_auth_core::AuthRequest,
    )
        -> better_auth_core::AuthResult<better_auth_core::endpoint_input::ValidatedBody>,
) -> better_auth_core::AuthResult<T> {
    if let Some(body) = req.validated_body::<T>() {
        return Ok(body.clone());
    }
    validator(req)?.get::<T>().cloned().ok_or_else(|| {
        better_auth_core::AuthError::internal(
            "Passkey body validator returned a different input type",
        )
    })
}
