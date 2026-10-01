use super::{finish, object, strings};
use crate::plugins::json_body::{invalid_type, validation_error};
use better_auth_core::AuthResult;
use serde_json::{Map, Value};

pub(crate) fn passkey_registration(query: Option<Value>) -> AuthResult<Option<Value>> {
    let Some(mut input) = object(query, true)? else {
        return Ok(None);
    };
    let mut output = Map::new();
    let mut errors = Vec::new();
    for name in ["authenticatorAttachment", "name", "context"] {
        let Some(value) = input.remove(name) else {
            continue;
        };
        if name == "authenticatorAttachment" {
            if !matches!(value.as_str(), Some("platform" | "cross-platform")) {
                errors.push("[query.authenticatorAttachment] Invalid option: expected one of \"platform\"|\"cross-platform\"".into());
                continue;
            }
        } else if !value.is_string() {
            errors.push(invalid_type(
                &format!("query.{name}"),
                "string",
                Some(&value),
            ));
            continue;
        }
        let _ = output.insert(name.into(), value);
    }
    finish(output, errors)
}

pub(crate) fn api_key_get(query: Option<Value>) -> AuthResult<Option<Value>> {
    strings(query, false, &[("configId", false), ("id", true)])
}

pub(crate) fn api_key_list(query: Option<Value>) -> AuthResult<Option<Value>> {
    let Some(mut input) = object(query, true)? else {
        return Ok(None);
    };
    let mut output = Map::new();
    let mut errors = Vec::new();
    for name in [
        "configId",
        "organizationId",
        "limit",
        "offset",
        "sortBy",
        "sortDirection",
    ] {
        let Some(value) = input.remove(name) else {
            continue;
        };
        if matches!(name, "limit" | "offset") {
            let value = better_auth_core::query::number(&value)?;
            let prefix = format!("[query.{name}]");
            if !value.is_finite() {
                errors.push(format!(
                    "{prefix} Invalid input: expected number, received {}",
                    if value.is_nan() { "NaN" } else { "Infinity" }
                ));
            } else if value.fract() != 0.0 {
                errors.push(format!(
                    "{prefix} Invalid input: expected int, received number"
                ));
            } else {
                if value > 9_007_199_254_740_991.0 {
                    errors.push(format!(
                        "{prefix} Too big: expected int to be <=9007199254740991"
                    ));
                }
                if value < -9_007_199_254_740_991.0 {
                    errors.push(format!(
                        "{prefix} Too small: expected int to be >=-9007199254740991"
                    ));
                }
                if value < 0.0 {
                    errors.push(format!("{prefix} Too small: expected number to be >=0"));
                }
                if (0.0..=9_007_199_254_740_991.0).contains(&value) {
                    let _ = output.insert(name.into(), Value::from(value as u64));
                }
            }
        } else if name == "sortDirection" && !matches!(value.as_str(), Some("asc" | "desc")) {
            errors.push(
                "[query.sortDirection] Invalid option: expected one of \"asc\"|\"desc\"".into(),
            );
        } else if !value.is_string() {
            errors.push(invalid_type(
                &format!("query.{name}"),
                "string",
                Some(&value),
            ));
        } else {
            let _ = output.insert(name.into(), value);
        }
    }
    finish(output, errors)
}

pub(crate) fn reset_password_token(query: Option<Value>) -> AuthResult<Option<Value>> {
    strings(query, false, &[("callbackURL", true)])
}
pub(crate) fn reset_password(query: Option<Value>) -> AuthResult<Option<Value>> {
    strings(query, true, &[("token", false)])
}
pub(crate) fn organization(query: Option<Value>) -> AuthResult<Option<Value>> {
    strings(
        query,
        true,
        &[("organizationId", false), ("organizationSlug", false)],
    )
}
pub(crate) fn organization_id(query: Option<Value>) -> AuthResult<Option<Value>> {
    strings(query, true, &[("organizationId", false)])
}
pub(crate) fn invitation(query: Option<Value>) -> AuthResult<Option<Value>> {
    strings(query, false, &[("id", true)])
}
pub(crate) fn user_invitations(query: Option<Value>) -> AuthResult<Option<Value>> {
    strings(query, true, &[("email", false)])
}
pub(crate) fn user_teams(query: Option<Value>) -> AuthResult<Option<Value>> {
    strings(query, true, &[("userId", false), ("organizationId", false)])
}
pub(crate) fn team_members(query: Option<Value>) -> AuthResult<Option<Value>> {
    strings(query, true, &[("teamId", false)])
}
pub(crate) fn active_member_role(query: Option<Value>) -> AuthResult<Option<Value>> {
    strings(
        query,
        true,
        &[
            ("userId", false),
            ("organizationId", false),
            ("organizationSlug", false),
        ],
    )
}

pub(crate) fn full_organization(query: Option<Value>) -> AuthResult<Option<Value>> {
    let Some(mut input) = object(query, true)? else {
        return Ok(None);
    };
    let mut output = Map::new();
    let mut errors = Vec::new();
    for name in ["organizationId", "organizationSlug", "membersLimit"] {
        let Some(value) = input.remove(name) else {
            continue;
        };
        if name == "membersLimit" {
            match value {
                Value::Number(_) => {
                    let _ = output.insert(name.into(), value);
                }
                Value::String(value) => {
                    let _ = output.insert(
                        name.into(),
                        Value::from(better_auth_core::query::parse_integer(&value)),
                    );
                }
                _ => errors.push("[query.membersLimit] Invalid input".into()),
            }
        } else if !value.is_string() {
            errors.push(invalid_type(
                &format!("query.{name}"),
                "string",
                Some(&value),
            ));
        } else {
            let _ = output.insert(name.into(), value);
        }
    }
    finish(output, errors)
}

pub(crate) fn organization_role(query: Option<Value>) -> AuthResult<Option<Value>> {
    let Some(query) = query else {
        return Ok(None);
    };
    let Some(input) = query.as_object() else {
        return Err(validation_error(&format!(
            "{}; [query] Invalid input",
            invalid_type("query", "object", Some(&query))
        ))
        .into());
    };
    let mut output = Map::new();
    let mut errors = Vec::new();
    if let Some(value) = input.get("organizationId") {
        if value.is_string() {
            let _ = output.insert("organizationId".into(), value.clone());
        } else {
            errors.push(invalid_type("query.organizationId", "string", Some(value)));
        }
    }
    // The first successful union branch strips the other selector.
    if let Some((name, value)) = ["roleName", "roleId"].into_iter().find_map(|name| {
        input
            .get(name)
            .filter(|value| value.as_str().is_some_and(|value| !value.is_empty()))
            .map(|value| (name, value))
    }) {
        let _ = output.insert(name.into(), value.clone());
    } else {
        let field = match (
            input.get("roleName").and_then(Value::as_str),
            input.get("roleId").and_then(Value::as_str),
        ) {
            (Some(""), None) => Some("roleName"),
            (None, Some("")) => Some("roleId"),
            _ => None,
        };
        errors.push(field.map_or_else(
            || "[query] Invalid input".into(),
            |name| format!("[query.{name}] Too small: expected string to have >=1 characters"),
        ));
    }
    finish(output, errors)
}

pub(crate) fn account_selection(query: Option<Value>) -> AuthResult<Option<Value>> {
    let Some(Value::Object(input)) = query.as_ref() else {
        return Err(validation_error("[query] Invalid input").into());
    };
    if input.get("userId").is_some_and(|value| !value.is_string()) {
        return Err(validation_error("[query] Invalid input").into());
    }
    let id = input.get("accountId").is_some_and(Value::is_string);
    let cookie = input.get("useAccountCookie") == Some(&Value::Bool(true));
    let field = match (id, cookie) {
        (true, false) => "accountId",
        (false, true) => "useAccountCookie",
        _ => return Err(validation_error("[query] Invalid input").into()),
    };
    let unknown = input
        .keys()
        .filter(|name| name.as_str() != field && name.as_str() != "userId")
        .map(|name| Value::String(name.clone()).to_string())
        .collect::<Vec<_>>();
    if !unknown.is_empty() {
        return Err(validation_error(&format!(
            "[query] Unrecognized key{}: {}",
            if unknown.len() == 1 { "" } else { "s" },
            unknown.join(", ")
        ))
        .into());
    }
    Ok(query)
}
