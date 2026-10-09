//! Internal helpers for applying admin user-list query semantics.

use crate::{FieldDate, FieldMap, FieldValue as Value};
use chrono::{DateTime, Utc};
use std::cmp::Ordering;

use crate::store::schema::resolve_field_name;
use crate::types::ListUsersParams;
use crate::user_fields::{UserConfig, UserFieldConfig, UserFieldType};
use crate::{AuthRecordFields, AuthResult, UserView};

fn string_field(user: &UserView, field: &str) -> Option<Value> {
    let value = user.native_field_value(if field == "_id" { "id" } else { field });
    value.filter(|value| matches!(value, Value::String(_) | Value::Utf16String(_)))
}

fn bool_field(user: &UserView, field: &str) -> Option<bool> {
    match field {
        "banned" => user.banned.field_value().as_bool(),
        _ => None,
    }
}

fn date_field(user: &UserView, field: &str) -> Option<FieldDate> {
    match field {
        "createdAt" => user.created_at.field_value().as_date().cloned(),
        "updatedAt" => user.updated_at.field_value().as_date().cloned(),
        "banExpires" => user.ban_expires.field_value().as_date().cloned(),
        _ => None,
    }
}

fn matches_search(user: &UserView, params: &ListUsersParams) -> bool {
    let Some(search_value) = params
        .search_value
        .as_deref()
        .filter(|value| !value.is_empty())
    else {
        return true;
    };

    let field = params
        .search_field
        .as_deref()
        .filter(|name| !name.is_empty())
        .unwrap_or("email");
    let operator = params.search_operator.as_deref().unwrap_or("contains");
    let haystack = match string_field(user, field) {
        Some(value) => value,
        None => return false,
    };

    matches!(operator, "contains" | "starts_with" | "ends_with")
        && compare_string(&haystack, &Value::from(search_value), operator)
}

fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn parse_date(value: &str) -> Option<FieldDate> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| FieldDate::from(value.with_timezone(&Utc)))
}

fn compare_string(lhs: &Value, rhs: &Value, operator: &str) -> bool {
    let (Some(lhs), Some(rhs)) = (
        crate::query::field_string_units(lhs),
        crate::query::field_string_units(rhs),
    ) else {
        return false;
    };
    match operator {
        "eq" => lhs == rhs,
        "ne" => lhs != rhs,
        "lt" => lhs < rhs,
        "lte" => lhs <= rhs,
        "gt" => lhs > rhs,
        "gte" => lhs >= rhs,
        "contains" => rhs.is_empty() || lhs.windows(rhs.len()).any(|window| window == &*rhs),
        "starts_with" => lhs.starts_with(&rhs),
        "ends_with" => lhs.ends_with(&rhs),
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

fn compare_date(lhs: FieldDate, rhs: FieldDate, operator: &str) -> bool {
    let (lhs, rhs) = (lhs.milliseconds(), rhs.milliseconds());
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
    let field = params
        .filter_field
        .as_deref()
        .filter(|name| !name.is_empty())
        .unwrap_or("email");
    let operator = params.filter_operator.as_deref().unwrap_or("eq");
    let matches = |expected: &Value, operator: &str| {
        if let Some(value) = string_field(user, field) {
            return compare_string(&value, expected, operator);
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
    match (&field.field_type, value) {
        (UserFieldType::Number, Value::String(value)) => {
            crate::organization_fields::numeric_filter(value)
                .map(Value::Number)
                .map_or_else(|| Ok(Value::String(value.clone())), Ok)
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
                Some(numbers) => Ok(numbers
                    .into_iter()
                    .map(Value::Number)
                    .collect::<Vec<_>>()
                    .into()),
                None => Ok(value.clone()),
            }
        }
        (UserFieldType::Boolean, value @ (Value::String(_) | Value::Utf16String(_))) => {
            Ok(Value::Bool(value.strict_equals(&Value::from("true"))))
        }
        _ => Ok(value.clone()),
    }
}

fn additional_filter<'a>(
    params: &ListUsersParams,
    fields: &'a UserConfig,
    on_field: &mut impl FnMut() -> AuthResult<()>,
) -> AuthResult<Option<(&'a str, &'a UserFieldConfig, Value)>> {
    let Some(value) = params.filter_value.as_ref() else {
        return Ok(None);
    };
    let name = params
        .filter_field
        .as_deref()
        .filter(|name| !name.is_empty())
        .unwrap_or("email");
    if name == "_id" || UserView::NATIVE_FIELDS.contains(&name) {
        on_field()?;
        return Ok(None);
    }
    let (logical, field) = declared_field(name, fields).ok_or_else(|| {
        crate::AuthError::internal(format!("Field {name} not found in model user"))
    })?;
    on_field()?;
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
        (
            Some(actual @ (Value::String(_) | Value::Utf16String(_))),
            expected @ (Value::String(_) | Value::Utf16String(_)),
        ) => compare_string(actual, expected, operator),
        (Some(Value::Bool(actual)), Value::Bool(expected)) => {
            compare_bool(*actual, *expected, operator)
        }
        (Some(Value::Number(actual)), Value::Number(expected)) => {
            let ordering = actual.partial_cmp(expected);
            match operator {
                "eq" => ordering.is_some_and(Ordering::is_eq),
                "ne" => actual != expected,
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

fn matches_memory_value(actual: &Value, expected: &Value, operator: &str) -> AuthResult<bool> {
    match operator {
        "eq" => Ok(crate::query::field_matches_equality(actual, expected)),
        "ne" => Ok(!actual.strict_equals(expected)),
        "in" | "not_in" => {
            let values = expected
                .as_array()
                .ok_or_else(|| crate::AuthError::internal("Value must be an array"))?;
            let present = values
                .iter()
                .any(|expected| actual.same_value_zero(expected));
            Ok(if operator == "in" { present } else { !present })
        }
        "lt" | "lte" | "gt" | "gte" => {
            if expected.is_null() {
                return Ok(false);
            }
            let order = crate::query::field_compare(actual, expected)?;
            Ok(match operator {
                "lt" => order == Some(Ordering::Less),
                "lte" => matches!(order, Some(Ordering::Less | Ordering::Equal)),
                "gt" => order == Some(Ordering::Greater),
                _ => matches!(order, Some(Ordering::Greater | Ordering::Equal)),
            })
        }
        "contains" | "starts_with" | "ends_with" => {
            if operator == "contains" {
                match actual {
                    Value::Undefined | Value::Null => return Ok(false),
                    Value::Array(values) => {
                        return Ok(values.iter().any(|value| value.same_value_zero(expected)));
                    }
                    _ => {}
                }
            }
            if matches!(actual, Value::String(_) | Value::Utf16String(_)) {
                return Ok(compare_string(
                    actual,
                    &Value::from(expected.display_utf16()?),
                    operator,
                ));
            }
            let method = match operator {
                "contains" => "includes",
                "starts_with" => "startsWith",
                _ => "endsWith",
            };
            let message = match actual {
                Value::Undefined => {
                    format!("undefined is not an object (evaluating 'record[field].{method}')")
                }
                Value::Null => {
                    format!("null is not an object (evaluating 'record[field].{method}')")
                }
                _ => format!("record[field].{method} is not a function"),
            };
            Err(crate::AuthError::internal(message))
        }
        _ => Ok(false),
    }
}

fn matches_record(
    (user, raw): (&UserView, &FieldMap),
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
                        "eq" => actual.is_none_or(|value| value.is_null() || value.is_undefined()),
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
        (Some(Value::Number(left)), Some(Value::Number(right))) => {
            left.partial_cmp(right).unwrap_or(Ordering::Equal)
        }
        (
            Some(left @ (Value::String(_) | Value::Utf16String(_))),
            Some(right @ (Value::String(_) | Value::Utf16String(_))),
        ) => crate::query::field_string_units(left).cmp(&crate::query::field_string_units(right)),
        (Some(Value::Bool(left)), Some(Value::Bool(right))) => left.cmp(right),
        (
            None | Some(Value::Null | Value::Undefined),
            None | Some(Value::Null | Value::Undefined),
        ) => Ordering::Equal,
        (None | Some(Value::Null | Value::Undefined), _) => Ordering::Less,
        (_, None | Some(Value::Null | Value::Undefined)) => Ordering::Greater,
        _ => Ordering::Equal,
    };
    if direction == "asc" {
        ordering
    } else {
        ordering.reverse()
    }
}

fn compare_option_strings(lhs: Option<Value>, rhs: Option<Value>, direction: &str) -> Ordering {
    compare_values(lhs.as_ref(), rhs.as_ref(), direction)
}

fn compare_option_dates(
    lhs: Option<FieldDate>,
    rhs: Option<FieldDate>,
    direction: &str,
) -> Ordering {
    let compare = |left: Option<FieldDate>, right: Option<FieldDate>| match (left, right) {
        (Some(left), Some(right)) => left
            .milliseconds()
            .partial_cmp(&right.milliseconds())
            .unwrap_or(Ordering::Equal),
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
    };
    if direction == "asc" {
        compare(lhs, rhs)
    } else {
        compare(rhs, lhs)
    }
}

/// Bind a user filter once while retaining adapter-specific sort validation timing.
pub struct PreparedUserQuery<'a> {
    params: &'a ListUsersParams,
    fields: &'a UserConfig,
    filter: Option<(&'a str, &'a UserFieldConfig, Value)>,
    memory_filter: Option<Value>,
    memory_search: Option<Value>,
}

impl<'a> PreparedUserQuery<'a> {
    /// Resolve and bind Where fields without validating the sort declaration.
    pub fn new(params: &'a ListUsersParams, fields: &'a UserConfig) -> AuthResult<Self> {
        Self::prepare(params, fields, || Ok(()))
    }

    /// Resolve query fields in Where order and retain each successful lookup in the adapter runtime.
    #[doc(hidden)]
    pub fn for_adapter(
        params: &'a ListUsersParams,
        fields: &'a UserConfig,
        runtime: &crate::plugin_runtime::ModelFields,
    ) -> AuthResult<Self> {
        Self::prepare(params, fields, || {
            runtime.begin_id_query(crate::store::schema::EntityRole::User)
        })
    }

    /// Restore input policies when an adapter repeats this validated Where query for a count.
    #[doc(hidden)]
    pub fn begin_adapter_count(
        &self,
        runtime: &crate::plugin_runtime::ModelFields,
    ) -> AuthResult<()> {
        if self.params.filter_value.is_some()
            || self
                .params
                .search_value
                .as_deref()
                .is_some_and(|value| !value.is_empty())
        {
            runtime.begin_id_query(crate::store::schema::EntityRole::User)?;
        }
        Ok(())
    }

    fn prepare(
        params: &'a ListUsersParams,
        fields: &'a UserConfig,
        mut on_field: impl FnMut() -> AuthResult<()>,
    ) -> AuthResult<Self> {
        if params
            .search_value
            .as_deref()
            .is_some_and(|value| !value.is_empty())
        {
            let name = params
                .search_field
                .as_deref()
                .filter(|name| !name.is_empty())
                .unwrap_or("email");
            if name != "_id"
                && !UserView::NATIVE_FIELDS.contains(&name)
                && declared_field(name, fields).is_none()
            {
                return Err(crate::AuthError::internal(format!(
                    "Field {name} not found in model user"
                )));
            }
            on_field()?;
        }
        let filter = additional_filter(params, fields, &mut on_field)?;
        Ok(Self {
            params,
            fields,
            filter,
            memory_filter: None,
            memory_search: None,
        })
    }

    /// Bind Memory search and filter values with the adapter's complete field policy.
    pub fn bind_memory_filter(
        mut self,
        mut bind: impl FnMut(&str, Value) -> AuthResult<Value>,
    ) -> AuthResult<Self> {
        if let Some(value) = self
            .params
            .search_value
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            let name = self
                .params
                .search_field
                .as_deref()
                .filter(|name| !name.is_empty())
                .unwrap_or("email");
            let declared = declared_field(name, self.fields);
            let name = declared.map_or(name, |(logical, _)| logical);
            self.memory_search = Some(bind(name, Value::from(value))?);
        }
        let name = self
            .params
            .filter_field
            .as_deref()
            .filter(|name| !name.is_empty())
            .unwrap_or("email");
        let declared = declared_field(name, self.fields);
        let name = declared.map_or(name, |(logical, _)| logical);
        self.memory_filter = self
            .params
            .filter_value
            .clone()
            .map(|value| bind(name, value))
            .transpose()?;
        Ok(self)
    }

    fn memory_value(&self, (user, raw): (&UserView, &FieldMap), name: &str) -> AuthResult<Value> {
        let name = if name == "_id" { "id" } else { name };
        let storage = declared_field(name, self.fields).map_or(name, |(logical, field)| {
            resolve_field_name(field.field_name.as_deref(), logical)
        });
        if UserView::NATIVE_FIELDS.contains(&storage) {
            return Ok(user.field_values()?.remove(storage).unwrap_or_default());
        }
        Ok(raw.get(storage).cloned().unwrap_or_default())
    }

    fn matches_memory(&self, record: (&UserView, &FieldMap)) -> AuthResult<bool> {
        if let Some(expected) = self
            .params
            .search_value
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            let field = self
                .params
                .search_field
                .as_deref()
                .filter(|name| !name.is_empty())
                .unwrap_or("email");
            if !matches_memory_value(
                &self.memory_value(record, field)?,
                self.memory_search
                    .as_ref()
                    .unwrap_or(&Value::from(expected)),
                self.params.search_operator.as_deref().unwrap_or("contains"),
            )? {
                return Ok(false);
            }
        }
        let Some(expected) = self
            .memory_filter
            .as_ref()
            .or_else(|| self.filter.as_ref().map(|(_, _, value)| value))
            .or(self.params.filter_value.as_ref())
        else {
            return Ok(true);
        };
        let field = self
            .params
            .filter_field
            .as_deref()
            .filter(|name| !name.is_empty())
            .unwrap_or("email");
        matches_memory_value(
            &self.memory_value(record, field)?,
            expected,
            self.params.filter_operator.as_deref().unwrap_or("eq"),
        )
    }

    /// Count Memory rows with native object identity and JavaScript comparisons.
    pub fn count_memory<'r, T: 'r>(
        &self,
        users: impl IntoIterator<Item = &'r T>,
        record: impl Fn(&T) -> (&UserView, &FieldMap),
    ) -> AuthResult<usize> {
        users.into_iter().try_fold(0, |count, user| {
            self.matches_memory(record(user))
                .map(|matched| count + usize::from(matched))
        })
    }

    /// Select Memory rows without serializing their native field values.
    pub fn select_memory<T>(
        &self,
        users: Vec<T>,
        record: impl Fn(&T) -> (&UserView, &FieldMap),
    ) -> AuthResult<(Vec<T>, usize)> {
        let mut selected = Vec::with_capacity(users.len());
        for user in users {
            if self.matches_memory(record(&user))? {
                selected.push(user);
            }
        }
        if selected.len() > 1 {
            self.validate_sort()?;
        }
        if let Some(name) = self
            .params
            .sort_by
            .as_deref()
            .filter(|name| !name.is_empty())
        {
            let descending = self
                .params
                .sort_direction
                .as_deref()
                .filter(|value| !value.is_empty())
                .unwrap_or("asc")
                != "asc";
            crate::memory_sort::sort(&mut selected, descending, |user| {
                self.memory_value(record(user), name)
            })?;
        }
        let total = selected.len();
        Ok((
            crate::query::paginate_memory(selected, self.params.limit, self.params.offset),
            total,
        ))
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
        record: impl Fn(&T) -> (&UserView, &FieldMap),
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
        record: impl Fn(&T) -> (&UserView, &FieldMap),
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
    record: impl Fn(&T) -> (&UserView, &FieldMap),
) -> AuthResult<usize> {
    Ok(PreparedUserQuery::new(params, fields)?.count(users, record))
}

/// Select raw user records while retaining each adapter's original row association.
pub fn apply_list_users_by<T>(
    users: Vec<T>,
    params: &ListUsersParams,
    fields: &UserConfig,
    record: impl Fn(&T) -> (&UserView, &FieldMap),
) -> AuthResult<(Vec<T>, usize)> {
    PreparedUserQuery::new(params, fields)?.select(users, record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_string_filters_and_sorting_preserve_utf16_code_units() {
        let supplementary = Value::from("😀");
        let private_use = Value::from("\u{e000}");
        let lone = Value::Utf16String(crate::Utf16String::prefix("😀", 1));
        let same_text = Value::Utf16String(crate::Utf16String::from("😀"));
        assert!(matches_value(Some(&supplementary), &private_use, "lt"));
        assert!(matches_value(Some(&supplementary), &same_text, "eq"));
        assert!(matches_value(Some(&supplementary), &lone, "contains"));
        assert!(matches_value(Some(&supplementary), &lone, "starts_with"));
        assert!(!matches_value(Some(&supplementary), &lone, "ends_with"));
        assert_eq!(
            compare_values(Some(&supplementary), Some(&private_use), "asc"),
            Ordering::Less
        );
        assert_eq!(
            compare_option_strings(Some(lone), Some(supplementary), "desc"),
            Ordering::Greater
        );
    }

    #[tokio::test]
    async fn memory_queries_retain_native_date_identity_and_nan_membership() -> AuthResult<()> {
        use crate::store::{EphemeralStore, UserStore};
        let user = EphemeralStore::default()
            .create_user(crate::CreateUser::new())
            .await?;
        let config = UserConfig::default();
        let shared = user.created_at.field_value();
        let distinct = Value::from(FieldDate::from_milliseconds(
            user.created_at.date_milliseconds()?,
        ));
        for (expected, operator, matches) in [
            (shared.clone(), "eq", 1),
            (distinct.clone(), "eq", 0),
            (Value::from(vec![shared]), "in", 1),
            (distinct, "lte", 1),
        ] {
            let params = ListUsersParams {
                filter_field: Some("createdAt".into()),
                filter_value: Some(expected),
                filter_operator: Some(operator.into()),
                ..Default::default()
            };
            let query = PreparedUserQuery::new(&params, &config)?;
            assert_eq!(
                query.count_memory([&user], |user| (user, &user.additional_fields))?,
                matches
            );
            let (selected, total) =
                query.select_memory(vec![user.clone()], |user| (user, &user.additional_fields))?;
            assert_eq!(selected.len(), matches);
            assert_eq!(total, matches);
        }
        let nan = Value::Number(f64::NAN);
        assert!(!matches_memory_value(&nan, &nan, "eq")?);
        assert!(matches_memory_value(
            &nan,
            &Value::from(vec![nan.clone()]),
            "in"
        )?);
        assert!(!matches_memory_value(&nan, &Value::from(0.0), "gte")?);
        Ok(())
    }
}
