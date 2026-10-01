use better_auth_core::{AuthError, AuthRequest, AuthResult, endpoint_input::ValidatedBody};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use super::types::{LinkSocialRequest, SocialSignInRequest};
use crate::plugins::json_body::{invalid_type, validation_error};

#[derive(Clone, Copy)]
enum Kind {
    String,
    Provider,
    Boolean,
    Number,
    Strings,
    Record { strings: bool },
    Object(&'static [Field]),
}
type Field = (&'static str, Kind, bool);

const NAME: &[Field] = &[
    ("firstName", Kind::String, false),
    ("lastName", Kind::String, false),
];
const USER: &[Field] = &[
    ("name", Kind::Object(NAME), false),
    ("email", Kind::String, false),
];
const SIGN_IN_TOKEN: &[Field] = &[
    ("token", Kind::String, true),
    ("nonce", Kind::String, false),
    ("accessToken", Kind::String, false),
    ("refreshToken", Kind::String, false),
    ("expiresAt", Kind::Number, false),
    ("user", Kind::Object(USER), false),
];
const LINK_TOKEN: &[Field] = &[
    ("token", Kind::String, true),
    ("nonce", Kind::String, false),
    ("accessToken", Kind::String, false),
    ("refreshToken", Kind::String, false),
];

pub(super) fn read<T: Clone + Send + Sync + 'static>(req: &AuthRequest) -> AuthResult<T> {
    if let Some(body) = req.validated_body::<T>() {
        return Ok(body.clone());
    }
    validate(req)?
        .get::<T>()
        .cloned()
        .ok_or_else(|| AuthError::internal("OAuth body validator returned a different input type"))
}

fn typed<T: DeserializeOwned + Send + Sync + 'static>(body: Value) -> AuthResult<ValidatedBody> {
    Ok(ValidatedBody::new(
        Some(body.clone()),
        serde_json::from_value::<T>(body)?,
    ))
}

pub(super) fn validate(req: &AuthRequest) -> AuthResult<ValidatedBody> {
    use Kind::*;
    let fields: &[Field] = match req.path() {
        "/sign-in/social" => &[
            ("callbackURL", String, false),
            ("newUserCallbackURL", String, false),
            ("errorCallbackURL", String, false),
            ("provider", Provider, true),
            ("disableRedirect", Boolean, false),
            ("idToken", Object(SIGN_IN_TOKEN), false),
            ("scopes", Strings, false),
            ("requestSignUp", Boolean, false),
            ("loginHint", String, false),
            ("additionalParams", Record { strings: true }, false),
            ("additionalData", Record { strings: false }, false),
        ],
        "/link-social" => &[
            ("callbackURL", String, false),
            ("provider", Provider, true),
            ("idToken", Object(LINK_TOKEN), false),
            ("requestSignUp", Boolean, false),
            ("scopes", Strings, false),
            ("errorCallbackURL", String, false),
            ("disableRedirect", Boolean, false),
            ("loginHint", String, false),
            ("additionalParams", Record { strings: true }, false),
            ("additionalData", Record { strings: false }, false),
        ],
        _ => return Err(AuthError::internal("Unknown OAuth body schema")),
    };
    let mut errors = Vec::new();
    let body = project_object(req.input_body()?.as_ref(), "body", fields, &mut errors);
    if !errors.is_empty() {
        return Err(validation_error(&errors.join("; ")).into());
    }
    if req.path() == "/sign-in/social" {
        typed::<SocialSignInRequest>(body)
    } else {
        typed::<LinkSocialRequest>(body)
    }
}

fn project_object(
    input: Option<&Value>,
    location: &str,
    fields: &[Field],
    errors: &mut Vec<String>,
) -> Value {
    let Some(body) = input.and_then(Value::as_object) else {
        errors.push(invalid_type(location, "object", input));
        return Value::Null;
    };
    let mut output = Map::new();
    for &(name, kind, required) in fields {
        let value = body.get(name);
        if value.is_none() && !required {
            continue;
        }
        let location = format!("{location}.{name}");
        let (valid, expected) = match kind {
            Kind::String | Kind::Provider => (value.is_some_and(Value::is_string), "string"),
            Kind::Boolean => (value.is_some_and(Value::is_boolean), "boolean"),
            Kind::Number => (value.is_some_and(Value::is_number), "number"),
            Kind::Strings => (value.is_some_and(Value::is_array), "array"),
            Kind::Record { .. } => (value.is_some_and(Value::is_object), "record"),
            Kind::Object(_) => (value.is_some_and(Value::is_object), "object"),
        };
        if !valid {
            errors.push(if matches!(kind, Kind::Provider) {
                format!("[{location}] Invalid input")
            } else {
                invalid_type(&location, expected, value)
            });
            continue;
        }
        let Some(value) = value else { continue };
        let projected = match kind {
            Kind::Object(fields) => project_object(Some(value), &location, fields, errors),
            Kind::Strings => {
                if let Some(values) = value.as_array() {
                    for (index, value) in values.iter().enumerate() {
                        if !value.is_string() {
                            errors.push(invalid_type(
                                &format!("{location}.{index}"),
                                "string",
                                Some(value),
                            ));
                        }
                    }
                }
                value.clone()
            }
            Kind::Record { strings } => {
                let mut record = Map::new();
                if let Some(values) = value.as_object() {
                    let before = errors.len();
                    for (key, value) in values {
                        if strings && !value.is_string() {
                            errors.push(invalid_type(
                                &format!("{location}.{key}"),
                                "string",
                                Some(value),
                            ));
                        }
                        if key != "__proto__" {
                            let _ = record.insert(key.clone(), value.clone());
                        }
                    }
                    if strings
                        && before == errors.len()
                        && record.keys().any(|key| {
                            super::authorization::RESERVED_PARAMS.contains(&key.as_str())
                        })
                    {
                        errors.push(format!("[{location}] additionalParams cannot include reserved OAuth parameters: {}", super::authorization::RESERVED_PARAMS.join(", ")));
                    }
                }
                Value::Object(record)
            }
            _ => value.clone(),
        };
        let _ = output.insert(name.into(), projected);
    }
    Value::Object(output)
}
