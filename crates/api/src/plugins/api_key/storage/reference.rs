use std::collections::HashMap;
use std::sync::{Arc, OnceLock, Weak};

use better_auth_core::{
    ApiKey, AuthError, AuthResult, FieldValue, Utf16String,
    query::{field_number, field_string_units},
    store::SecondaryStorage,
};
use tokio::sync::Mutex;

type ReferenceLocks = std::sync::Mutex<HashMap<Vec<u16>, Weak<Mutex<()>>>>;

pub(super) fn cache_key(prefix: &str, value: &FieldValue) -> AuthResult<FieldValue> {
    let mut units = prefix.encode_utf16().collect::<Vec<_>>();
    units.extend_from_slice(value.display_utf16()?.as_utf16());
    Ok(Utf16String::from_units(units).into())
}

pub(super) async fn read(
    storage: &dyn SecondaryStorage,
    key: &FieldValue,
) -> AuthResult<FieldValue> {
    Ok(match storage.get_native(key).await? {
        // The upstream catch applies only to JSON.parse, not to later method calls.
        Some(FieldValue::String(text)) => {
            FieldValue::parse_json(&text).unwrap_or_else(|_| Vec::<FieldValue>::new().into())
        }
        Some(FieldValue::Utf16String(_)) => {
            // ponytail: Parse raw UTF-16 JSON text when the shared parser accepts unpaired code units.
            return Err(AuthError::internal(
                "API key cache JSON text requires UTF-16 parsing support",
            ));
        }
        Some(value @ FieldValue::Array(_)) => value,
        _ => Vec::<FieldValue>::new().into(),
    })
}

fn property(value: &FieldValue, name: &str) -> AuthResult<FieldValue> {
    Ok(match value {
        FieldValue::Null | FieldValue::Undefined => {
            let kind = if value.is_null() { "null" } else { "undefined" };
            return Err(AuthError::internal(format!(
                "Cannot read properties of {kind} (reading '{name}')"
            )));
        }
        FieldValue::Array(values) if name == "length" => (values.len() as f64).into(),
        FieldValue::Array(values) => name
            .parse::<usize>()
            .ok()
            .and_then(|index| values.get(index))
            .cloned()
            .unwrap_or_default(),
        FieldValue::Object(fields) => fields.get(name).cloned().unwrap_or_default(),
        value => match field_string_units(value) {
            Some(units) if name == "length" => (units.len() as f64).into(),
            Some(units) => name
                .parse::<usize>()
                .ok()
                .and_then(|index| units.get(index))
                .map(|unit| Utf16String::from_units(vec![*unit]).into())
                .unwrap_or_default(),
            None => FieldValue::Undefined,
        },
    })
}

pub(super) fn has_entries(value: &FieldValue) -> AuthResult<bool> {
    Ok(field_number(&property(value, "length")?)? > 0.0)
}

pub(super) fn items(value: &FieldValue) -> AuthResult<Vec<FieldValue>> {
    let length = property(value, "length")?;
    let count = field_number(&length)?;
    if length.is_number()
        && (!count.is_finite() || count < 0.0 || count.fract() != 0.0 || count > u32::MAX as f64)
    {
        return Err(AuthError::internal("Invalid array length"));
    }
    if !length.is_number()
        && (count.is_nan() || count < 1.0)
        && !length.is_null()
        && !length.is_undefined()
    {
        // ponytail: Preserve new Array(length)'s untouched element when the list boundary supports raw cache results.
        return Err(AuthError::internal(
            "API key cache list requires native results for a nonnumeric length",
        ));
    }
    (0..count.ceil() as usize)
        .map(|index| property(value, &index.to_string()))
        .collect()
}

fn next(value: FieldValue, id: &FieldValue, insert: bool) -> AuthResult<FieldValue> {
    if let FieldValue::Array(values) = &value {
        if insert && values.iter().any(|value| value.same_value_zero(id)) {
            return Ok(value);
        }
        let mut values = values.to_vec();
        if insert {
            values.push(id.clone());
        } else {
            values.retain(|value| !value.strict_equals(id));
        }
        return Ok(values.into());
    }
    if insert && let Some(units) = field_string_units(&value) {
        let needle = id.display_utf16()?;
        if needle.as_utf16().is_empty()
            || units
                .windows(needle.as_utf16().len())
                .any(|part| part == needle.as_utf16())
        {
            return Ok(value);
        }
        // String iteration yields code points; indexed reads yield UTF-16 code units.
        let mut values = char::decode_utf16(units.iter().copied())
            .map(|value| match value {
                Ok(value) => value.to_string().into(),
                Err(error) => Utf16String::from_units(vec![error.unpaired_surrogate()]).into(),
            })
            .collect::<Vec<FieldValue>>();
        values.push(id.clone());
        return Ok(values.into());
    }
    let method = if insert { "includes" } else { "filter" };
    let _ = property(&value, method)?;
    Err(AuthError::internal(format!(
        "ids.{method} is not a function"
    )))
}

pub(super) fn stringify(value: &FieldValue) -> AuthResult<String> {
    value
        .stringify()?
        .ok_or_else(|| AuthError::internal("API key reference serialization omitted the value"))
}

pub(super) async fn modify_reference(
    storage: &dyn SecondaryStorage,
    key: &ApiKey,
    insert: bool,
) -> AuthResult<()> {
    // The upstream lock coordinates reference-list writers only within this process.
    let index = cache_key("api-key:by-ref:", &key.reference_id.field_value())?;
    let units = index.display_utf16()?.as_utf16().to_vec();
    static LOCKS: OnceLock<ReferenceLocks> = OnceLock::new();
    let lock = {
        let mut locks = LOCKS
            .get_or_init(Default::default)
            .lock()
            .map_err(|_| AuthError::internal("API key reference-list lock poisoned"))?;
        locks.retain(|_, lock| lock.strong_count() > 0);
        match locks.get(&units).and_then(Weak::upgrade) {
            Some(lock) => lock,
            None => {
                let lock = Arc::new(Mutex::new(()));
                let _ = locks.insert(units, Arc::downgrade(&lock));
                lock
            }
        }
    };
    let _guard = lock.lock().await;
    let value = next(read(storage, &index).await?, &key.id.field_value(), insert)?;
    if property(&value, "length")?.strict_equals(&0.0.into()) {
        storage.delete_native(&index).await
    } else {
        storage.set_native(&index, &stringify(&value)?, None).await
    }
}

#[cfg(test)]
mod tests;
