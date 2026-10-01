mod routes;
pub(crate) use routes::*;

use better_auth_core::AuthResult;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use super::json_body::{invalid_type, validation_error};

pub(crate) fn parse<T: Default + DeserializeOwned>(query: &Option<Value>) -> AuthResult<T> {
    query
        .clone()
        .map(serde_json::from_value)
        .transpose()
        .map(|value| value.unwrap_or_default())
        .map_err(Into::into)
}

fn object(query: Option<Value>, optional: bool) -> AuthResult<Option<Map<String, Value>>> {
    match query {
        None if optional => Ok(None),
        Some(Value::Object(query)) => Ok(Some(query)),
        value => Err(validation_error(&invalid_type("query", "object", value.as_ref())).into()),
    }
}

pub(crate) fn strings(
    query: Option<Value>,
    optional: bool,
    fields: &[(&str, bool)],
) -> AuthResult<Option<Value>> {
    let Some(mut input) = object(query, optional)? else {
        return Ok(None);
    };
    let mut output = Map::new();
    let mut errors = Vec::new();
    for (name, required) in fields {
        match input.remove(*name) {
            Some(value @ Value::String(_)) => {
                let _ = output.insert((*name).to_owned(), value);
            }
            None if !required => {}
            value => errors.push(invalid_type(
                &format!("query.{name}"),
                "string",
                value.as_ref(),
            )),
        }
    }
    finish(output, errors)
}

fn finish(output: Map<String, Value>, errors: Vec<String>) -> AuthResult<Option<Value>> {
    if errors.is_empty() {
        Ok(Some(Value::Object(output)))
    } else {
        Err(validation_error(&errors.join("; ")).into())
    }
}

pub(crate) fn string_map(
    query: &Option<Value>,
) -> AuthResult<std::collections::HashMap<String, String>> {
    parse(query)
}

pub(crate) fn callback(query: Option<Value>) -> AuthResult<Option<Value>> {
    strings(
        query,
        true,
        &[
            ("code", false),
            ("error", false),
            ("device_id", false),
            ("error_description", false),
            ("state", false),
            ("user", false),
            ("iss", false),
        ],
    )
}

pub(crate) fn get_user(query: Option<Value>) -> AuthResult<Option<Value>> {
    strings(query, false, &[("id", true)])
}

pub(crate) fn popup(query: Option<Value>) -> AuthResult<Option<Value>> {
    strings(
        query,
        false,
        &[
            ("provider", true),
            ("popupOrigin", true),
            ("popupNonce", false),
            ("callbackURL", false),
            ("errorCallbackURL", false),
            ("newUserCallbackURL", false),
            ("scopes", false),
            ("requestSignUp", false),
            ("additionalData", false),
        ],
    )
}

pub(crate) fn proxy(query: Option<Value>) -> AuthResult<Option<Value>> {
    strings(query, false, &[("callbackURL", true), ("profile", false)])
}

pub(crate) fn magic_link(query: Option<Value>) -> AuthResult<Option<Value>> {
    strings(
        query,
        false,
        &[
            ("token", true),
            ("callbackURL", false),
            ("errorCallbackURL", false),
            ("newUserCallbackURL", false),
        ],
    )
}

pub(crate) fn verify_email(query: Option<Value>) -> AuthResult<Option<Value>> {
    strings(query, false, &[("token", true), ("callbackURL", false)])
}

pub(crate) fn device(query: Option<Value>) -> AuthResult<Option<Value>> {
    strings(query, false, &[("user_code", true)])
}

pub(crate) fn list_members(query: Option<Value>) -> AuthResult<Option<Value>> {
    list(query, false)
}
pub(crate) fn list_users(query: Option<Value>) -> AuthResult<Option<Value>> {
    list(query, true)
}

fn list(query: Option<Value>, admin: bool) -> AuthResult<Option<Value>> {
    let Some(mut input) = object(query, !admin)? else {
        return Ok(None);
    };
    let fields = if admin {
        &[
            "searchValue",
            "searchField",
            "searchOperator",
            "limit",
            "offset",
            "sortBy",
            "sortDirection",
            "filterField",
            "filterValue",
            "filterOperator",
        ][..]
    } else {
        &[
            "limit",
            "offset",
            "sortBy",
            "sortDirection",
            "filterField",
            "filterValue",
            "filterOperator",
            "organizationId",
            "organizationSlug",
        ][..]
    };
    let mut output = Map::new();
    let mut errors = Vec::new();
    for name in fields {
        let Some(value) = input.remove(*name) else {
            continue;
        };
        let choices: &[&str] = match *name {
            "searchField" => &["email", "name"],
            "searchOperator" => &["contains", "starts_with", "ends_with"],
            "sortDirection" => &["asc", "desc"],
            "filterOperator" => &[
                "eq",
                "ne",
                "lt",
                "lte",
                "gt",
                "gte",
                "in",
                "not_in",
                "contains",
                "starts_with",
                "ends_with",
            ],
            _ => &[],
        };
        let error = if !choices.is_empty() {
            if value.as_str().is_some_and(|value| choices.contains(&value)) {
                None
            } else {
                Some(format!(
                    "[query.{name}] Invalid option: expected one of {}",
                    choices
                        .iter()
                        .map(|choice| format!("\"{choice}\""))
                        .collect::<Vec<_>>()
                        .join("|")
                ))
            }
        } else if matches!(*name, "limit" | "offset") {
            (!value.is_string() && !value.is_number())
                .then(|| format!("[query.{name}] Invalid input"))
        } else if *name == "filterValue" {
            let valid = value.is_string()
                || value.is_number()
                || value.is_boolean()
                || value.as_array().is_some_and(|values| {
                    values.iter().all(Value::is_string) || values.iter().all(Value::is_number)
                });
            (!valid).then(|| format!("[query.{name}] Invalid input"))
        } else {
            (!value.is_string())
                .then(|| invalid_type(&format!("query.{name}"), "string", Some(&value)))
        };
        if let Some(error) = error {
            errors.push(error);
        } else {
            let _ = output.insert((*name).to_owned(), value);
        }
    }
    finish(output, errors)
}
