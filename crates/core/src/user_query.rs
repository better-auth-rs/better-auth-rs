//! Internal helpers for applying admin user-list query semantics.

use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use std::cmp::Ordering;

use crate::store::schema::resolve_field_name;
use crate::types::ListUsersParams;
use crate::user_fields::{UserConfig, UserFieldConfig, UserFieldType};
use crate::{AuthResult, UserView, entity::AuthUser};

fn string_field(user: &UserView, field: &str) -> Option<String> {
    match field {
        "id" | "_id" => user.id().into_owned().as_str().map(str::to_owned),
        "email" => user.email().map(str::to_owned),
        "name" => match &user.name {
            crate::SchemaValue::Typed(value) => value.clone(),
            _ => None,
        },
        "username" => user.username().map(str::to_owned),
        "role" => user.role().map(str::to_owned),
        _ => None,
    }
}

fn bool_field(user: &UserView, field: &str) -> Option<bool> {
    match field {
        "banned" => Some(user.banned()),
        _ => None,
    }
}

fn date_field(user: &UserView, field: &str) -> Option<DateTime<Utc>> {
    match field {
        "createdAt" => Some(user.created_at()),
        "updatedAt" => Some(user.updated_at()),
        "banExpires" => user.ban_expires(),
        _ => None,
    }
}

fn matches_search(user: &UserView, params: &ListUsersParams) -> bool {
    let Some(search_value) = params.search_value.as_deref() else {
        return true;
    };

    let field = params.search_field.as_deref().unwrap_or("email");
    let operator = params.search_operator.as_deref().unwrap_or("contains");
    let haystack = match string_field(user, field) {
        Some(value) => value,
        None => return false,
    };

    match operator {
        "contains" => haystack.contains(search_value),
        "starts_with" => haystack.starts_with(search_value),
        "ends_with" => haystack.ends_with(search_value),
        _ => false,
    }
}

fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn parse_date(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn compare_string(lhs: &str, rhs: &str, operator: &str) -> bool {
    match operator {
        "eq" => lhs == rhs,
        "ne" => lhs != rhs,
        "lt" => lhs < rhs,
        "lte" => lhs <= rhs,
        "gt" => lhs > rhs,
        "gte" => lhs >= rhs,
        "contains" => lhs.contains(rhs),
        "starts_with" => lhs.starts_with(rhs),
        "ends_with" => lhs.ends_with(rhs),
        _ => false,
    }
}

fn compare_bool(lhs: bool, rhs: bool, operator: &str) -> bool {
    match operator {
        "eq" => lhs == rhs,
        "ne" => lhs != rhs,
        _ => false,
    }
}

fn compare_date(lhs: DateTime<Utc>, rhs: DateTime<Utc>, operator: &str) -> bool {
    match operator {
        "eq" => lhs == rhs,
        "ne" => lhs != rhs,
        "lt" => lhs < rhs,
        "lte" => lhs <= rhs,
        "gt" => lhs > rhs,
        "gte" => lhs >= rhs,
        _ => false,
    }
}

fn matches_filter(user: &UserView, params: &ListUsersParams) -> bool {
    let Some(filter_value) = params.filter_value.as_ref() else {
        return true;
    };
    let field = params.filter_field.as_deref().unwrap_or("email");
    let operator = params.filter_operator.as_deref().unwrap_or("eq");
    let matches = |expected: &serde_json::Value, operator: &str| {
        if let Some(value) = string_field(user, field) {
            return expected
                .as_str()
                .is_some_and(|expected| compare_string(&value, expected, operator));
        }
        if let Some(value) = bool_field(user, field) {
            let expected = expected
                .as_bool()
                .or_else(|| expected.as_str().and_then(parse_bool));
            return expected.is_some_and(|expected| compare_bool(value, expected, operator));
        }
        if let Some(value) = date_field(user, field) {
            return expected
                .as_str()
                .and_then(parse_date)
                .is_some_and(|expected| compare_date(value, expected, operator));
        }
        false
    };
    match_filter(filter_value, operator, matches)
}

fn match_filter(
    filter_value: &Value,
    operator: &str,
    matches: impl Fn(&Value, &str) -> bool,
) -> bool {
    if matches!(operator, "in" | "not_in") {
        let Some(values) = filter_value.as_array() else {
            return false;
        };
        let present = values.iter().any(|expected| matches(expected, "eq"));
        return if operator == "in" { present } else { !present };
    }
    matches(filter_value, operator)
}

pub(crate) fn declared_field<'a>(
    name: &str,
    fields: &'a UserConfig,
) -> Option<(&'a str, &'a UserFieldConfig)> {
    let (logical, field) = fields.fields().get_key_value(name).or_else(|| {
        fields.fields().iter().find(|(logical, field)| {
            resolve_field_name(field.field_name.as_deref(), logical) == name
        })
    })?;
    Some((logical, field))
}

fn additional_field<'a>(
    name: &str,
    fields: &'a UserConfig,
) -> Option<(&'a str, &'a UserFieldConfig)> {
    if name == "_id" || UserView::NATIVE_FIELDS.contains(&name) {
        return None;
    }
    let (logical, field) = declared_field(name, fields)?;
    if logical == "_id" || UserView::NATIVE_FIELDS.contains(&logical) {
        return None;
    }
    Some((
        resolve_field_name(field.field_name.as_deref(), logical),
        field,
    ))
}

/// Convert number and boolean query values without invoking field input transforms.
pub fn bind_filter(field: &UserFieldConfig, value: &Value) -> AuthResult<Value> {
    let number = |value: f64| -> AuthResult<Value> {
        Ok(serde_json::from_str(&crate::schema_value::number_string(
            value,
        ))?)
    };
    match (&field.field_type, value) {
        (UserFieldType::Number, Value::String(value)) => {
            crate::organization_fields::numeric_filter(value)
                .map(number)
                .transpose()
                .map(|number| number.unwrap_or_else(|| Value::String(value.clone())))
        }
        (UserFieldType::Number, Value::Array(values)) => {
            let numbers = values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .and_then(crate::organization_fields::numeric_filter)
                })
                .collect::<Option<Vec<_>>>();
            match numbers {
                Some(numbers) => numbers
                    .into_iter()
                    .map(number)
                    .collect::<AuthResult<Vec<_>>>()
                    .map(Value::Array),
                None => Ok(value.clone()),
            }
        }
        (UserFieldType::Boolean, Value::String(value)) => Ok(Value::Bool(value == "true")),
        _ => Ok(value.clone()),
    }
}

fn additional_filter<'a>(
    params: &ListUsersParams,
    fields: &'a UserConfig,
) -> AuthResult<Option<(&'a str, &'a UserFieldConfig, Value)>> {
    let Some(value) = params.filter_value.as_ref() else {
        return Ok(None);
    };
    let name = params.filter_field.as_deref().unwrap_or("email");
    if name == "_id" || UserView::NATIVE_FIELDS.contains(&name) {
        return Ok(None);
    }
    let (logical, field) = declared_field(name, fields).ok_or_else(|| {
        crate::AuthError::internal(format!("Field {name} not found in model user"))
    })?;
    if logical == "_id" || UserView::NATIVE_FIELDS.contains(&logical) {
        return Ok(None);
    }
    Ok(Some((
        resolve_field_name(field.field_name.as_deref(), logical),
        field,
        bind_filter(field, value)?,
    )))
}

fn matches_value(actual: Option<&Value>, expected: &Value, operator: &str) -> bool {
    match (actual, expected) {
        (Some(Value::String(actual)), Value::String(expected)) => {
            compare_string(actual, expected, operator)
        }
        (Some(Value::Bool(actual)), Value::Bool(expected)) => {
            compare_bool(*actual, *expected, operator)
        }
        (Some(Value::Number(actual)), Value::Number(expected)) => {
            let ordering = actual.as_f64().partial_cmp(&expected.as_f64());
            match operator {
                "eq" => ordering.is_some_and(Ordering::is_eq),
                "ne" => ordering.is_some_and(|ordering| !ordering.is_eq()),
                "lt" => ordering.is_some_and(Ordering::is_lt),
                "lte" => ordering.is_some_and(|ordering| !ordering.is_gt()),
                "gt" => ordering.is_some_and(Ordering::is_gt),
                "gte" => ordering.is_some_and(|ordering| !ordering.is_lt()),
                _ => false,
            }
        }
        _ => false,
    }
}

fn matches_record(
    (user, raw): (&UserView, &Map<String, Value>),
    params: &ListUsersParams,
    filter: &Option<(&str, &UserFieldConfig, Value)>,
) -> bool {
    matches_search(user, params)
        && match filter {
            Some((name, field, value)) => {
                let operator = params.filter_operator.as_deref().unwrap_or("eq");
                let actual = raw.get(*name);
                if matches!(
                    field.field_type,
                    UserFieldType::String | UserFieldType::Boolean | UserFieldType::Number
                ) && field.references.is_none()
                    && value.is_null()
                    && matches!(operator, "eq" | "ne")
                {
                    match operator {
                        "eq" => actual.is_none_or(Value::is_null),
                        _ => !matches!(actual, Some(Value::Null)),
                    }
                } else {
                    match_filter(value, operator, |expected, operator| {
                        matches_value(actual, expected, operator)
                    })
                }
            }
            None => matches_filter(user, params),
        }
}

fn compare_values(left: Option<&Value>, right: Option<&Value>, direction: &str) -> Ordering {
    let ordering = match (left, right) {
        (Some(Value::Number(left)), Some(Value::Number(right))) => left
            .as_f64()
            .partial_cmp(&right.as_f64())
            .unwrap_or(Ordering::Equal),
        (Some(Value::String(left)), Some(Value::String(right))) => left.cmp(right),
        (Some(Value::Bool(left)), Some(Value::Bool(right))) => left.cmp(right),
        (None | Some(Value::Null), None | Some(Value::Null)) => Ordering::Equal,
        (None | Some(Value::Null), _) => Ordering::Less,
        (_, None | Some(Value::Null)) => Ordering::Greater,
        _ => Ordering::Equal,
    };
    if direction == "asc" {
        ordering
    } else {
        ordering.reverse()
    }
}

fn compare_option_strings(lhs: Option<String>, rhs: Option<String>, direction: &str) -> Ordering {
    match direction {
        "asc" => lhs.cmp(&rhs),
        _ => rhs.cmp(&lhs),
    }
}

fn compare_option_dates(
    lhs: Option<DateTime<Utc>>,
    rhs: Option<DateTime<Utc>>,
    direction: &str,
) -> Ordering {
    match direction {
        "asc" => lhs.cmp(&rhs),
        _ => rhs.cmp(&lhs),
    }
}

/// Bind a user filter once while retaining adapter-specific sort validation timing.
pub struct PreparedUserQuery<'a> {
    params: &'a ListUsersParams,
    fields: &'a UserConfig,
    filter: Option<(&'a str, &'a UserFieldConfig, Value)>,
}

impl<'a> PreparedUserQuery<'a> {
    /// Resolve and bind the filter without validating the sort declaration.
    pub fn new(params: &'a ListUsersParams, fields: &'a UserConfig) -> AuthResult<Self> {
        Ok(Self {
            params,
            fields,
            filter: additional_filter(params, fields)?,
        })
    }

    /// Report whether a declared name selects an additional field instead of a native getter.
    pub fn is_additional_field(&self, name: &str) -> bool {
        additional_field(name, self.fields).is_some()
    }

    /// Validate a nonempty sort declaration before a SQL adapter executes its query.
    pub fn validate_sort(&self) -> AuthResult<()> {
        if let Some(name) = self
            .params
            .sort_by
            .as_deref()
            .filter(|name| !name.is_empty())
            && name != "_id"
            && !UserView::NATIVE_FIELDS.contains(&name)
            && declared_field(name, self.fields).is_none()
        {
            return Err(crate::AuthError::internal(format!(
                "Field {name} not found in model user"
            )));
        }
        Ok(())
    }

    /// Count fresh raw rows without sorting, paging, or output transforms.
    pub fn count<'r, T: 'r>(
        &self,
        users: impl IntoIterator<Item = &'r T>,
        record: impl Fn(&T) -> (&UserView, &Map<String, Value>),
    ) -> usize {
        users
            .into_iter()
            .filter(|user| matches_record(record(user), self.params, &self.filter))
            .count()
    }

    /// Select original rows, validating sort only when filtered rows require comparison.
    /// SQL adapters must also call `validate_sort` before their database read.
    pub fn select<T>(
        &self,
        mut users: Vec<T>,
        record: impl Fn(&T) -> (&UserView, &Map<String, Value>),
    ) -> AuthResult<(Vec<T>, usize)> {
        let params = self.params;
        let fields = self.fields;
        users.retain(|user| matches_record(record(user), params, &self.filter));
        if users.len() > 1 {
            self.validate_sort()?;
        }

        if let Some(sort_by) = params.sort_by.as_deref().filter(|value| !value.is_empty()) {
            let sort_direction = params
                .sort_direction
                .as_deref()
                .filter(|value| !value.is_empty())
                .unwrap_or("asc");
            let additional_sort = additional_field(sort_by, fields).map(|(name, _)| name);

            users.sort_by(|lhs, rhs| {
                let ((lhs, left), (rhs, right)) = (record(lhs), record(rhs));
                if let Some(name) = additional_sort {
                    return compare_values(left.get(name), right.get(name), sort_direction);
                }
                match sort_by {
                    "id" | "_id" | "email" | "name" | "username" | "role" => {
                        compare_option_strings(
                            string_field(lhs, sort_by),
                            string_field(rhs, sort_by),
                            sort_direction,
                        )
                    }
                    "createdAt" | "updatedAt" | "banExpires" => compare_option_dates(
                        date_field(lhs, sort_by),
                        date_field(rhs, sort_by),
                        sort_direction,
                    ),
                    "banned" => match sort_direction {
                        "asc" => bool_field(lhs, sort_by).cmp(&bool_field(rhs, sort_by)),
                        _ => bool_field(rhs, sort_by).cmp(&bool_field(lhs, sort_by)),
                    },
                    _ => compare_option_dates(
                        date_field(lhs, "createdAt"),
                        date_field(rhs, "createdAt"),
                        sort_direction,
                    ),
                }
            });
        }

        let total = users.len();
        let paged = crate::query::paginate_memory(users, params.limit, params.offset);

        Ok((paged, total))
    }
}

/// Count matching rows without sorting, paging, or applying output transforms.
pub fn count_users<'a, T: 'a>(
    users: impl IntoIterator<Item = &'a T>,
    params: &ListUsersParams,
    fields: &UserConfig,
    record: impl Fn(&T) -> (&UserView, &Map<String, Value>),
) -> AuthResult<usize> {
    Ok(PreparedUserQuery::new(params, fields)?.count(users, record))
}

/// Select raw user records while retaining each adapter's original row association.
pub fn apply_list_users_by<T>(
    users: Vec<T>,
    params: &ListUsersParams,
    fields: &UserConfig,
    record: impl Fn(&T) -> (&UserView, &Map<String, Value>),
) -> AuthResult<(Vec<T>, usize)> {
    PreparedUserQuery::new(params, fields)?.select(users, record)
}
