//! Internal helpers for applying admin user-list query semantics.

use chrono::{DateTime, Utc};
use std::cmp::Ordering;

use crate::entity::AuthUser;
use crate::types::ListUsersParams;

fn string_field(user: &impl AuthUser, field: &str) -> Option<String> {
    match field {
        "id" | "_id" => Some(user.id().into_owned()),
        "email" => user.email().map(str::to_owned),
        "name" => user.name().map(str::to_owned),
        "username" => user.username().map(str::to_owned),
        "role" => user.role().map(str::to_owned),
        _ => None,
    }
}

fn bool_field(user: &impl AuthUser, field: &str) -> Option<bool> {
    match field {
        "banned" => Some(user.banned()),
        _ => None,
    }
}

fn date_field(user: &impl AuthUser, field: &str) -> Option<DateTime<Utc>> {
    match field {
        "createdAt" => Some(user.created_at()),
        "updatedAt" => Some(user.updated_at()),
        "banExpires" => user.ban_expires(),
        _ => None,
    }
}

fn matches_search(user: &impl AuthUser, params: &ListUsersParams) -> bool {
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

fn matches_filter(user: &impl AuthUser, params: &ListUsersParams) -> bool {
    let Some(filter_value) = params.filter_value.as_deref() else {
        return true;
    };

    let field = params.filter_field.as_deref().unwrap_or("email");
    let operator = params.filter_operator.as_deref().unwrap_or("eq");

    if let Some(value) = string_field(user, field) {
        return compare_string(&value, filter_value, operator);
    }

    if let Some(value) = bool_field(user, field) {
        return parse_bool(filter_value)
            .is_some_and(|filter| compare_bool(value, filter, operator));
    }

    if let Some(value) = date_field(user, field) {
        return parse_date(filter_value)
            .is_some_and(|filter| compare_date(value, filter, operator));
    }

    false
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

/// Apply Better Auth admin list-users semantics to a user collection.
pub fn apply_list_users<T: AuthUser + Clone>(
    mut users: Vec<T>,
    params: &ListUsersParams,
) -> (Vec<T>, usize) {
    users.retain(|user| matches_search(user, params) && matches_filter(user, params));

    let sort_by = params.sort_by.as_deref().unwrap_or("createdAt");
    let sort_direction = params.sort_direction.as_deref().unwrap_or("desc");

    users.sort_by(|lhs, rhs| match sort_by {
        "id" | "_id" | "email" | "name" | "username" | "role" => compare_option_strings(
            string_field(lhs, sort_by),
            string_field(rhs, sort_by),
            sort_direction,
        ),
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
    });

    let total = users.len();
    let offset = params.offset.unwrap_or(0);
    let limit = params.limit.unwrap_or(total);
    let paged = users.into_iter().skip(offset).take(limit).collect();

    (paged, total)
}
