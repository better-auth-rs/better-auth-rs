use super::*;
use crate::{FieldMap, SchemaValue};
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

fn unconvertible_name() -> FieldValue {
    FieldMap::from_iter([("toString".into(), FieldValue::Number(0.0))]).into()
}

async fn create_names(names: &[FieldValue]) -> AuthResult<EphemeralStore> {
    let store = EphemeralStore::default();
    for (index, name) in names.iter().enumerate() {
        let _ = store
            .create_api_key(CreateApiKey {
                name: SchemaValue::from_field(name.clone()),
                key_hash: format!("stored-{index}"),
                ..input()
            })
            .await?;
    }
    Ok(store)
}

#[tokio::test]
async fn name_sort_skips_conversion_when_only_nullish_names_can_be_compared() -> AuthResult<()> {
    let object = unconvertible_name();
    for nullish in [FieldValue::Null, FieldValue::Undefined] {
        for names in [
            vec![nullish.clone(), object.clone()],
            vec![object.clone(), nullish.clone()],
        ] {
            let store = create_names(&names).await?;
            for (direction, expected) in [
                ("asc", vec![nullish.clone(), object.clone()]),
                ("desc", vec![object.clone(), nullish.clone()]),
            ] {
                let rows = store
                    .find_api_keys_by_reference("owner", Some(("name", direction)))
                    .await?;
                assert_eq!(
                    rows.iter()
                        .map(|row| row.name.field_value())
                        .collect::<Vec<_>>(),
                    expected
                );
                assert_eq!(
                    store
                        .lock()?
                        .api_keys
                        .snapshot()?
                        .iter()
                        .map(|row| row.name.field_value())
                        .collect::<Vec<_>>(),
                    names
                );
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn name_sort_preserves_conversion_errors_when_both_names_are_non_nullish() -> AuthResult<()> {
    let object = unconvertible_name();
    for names in [
        vec![FieldValue::from("desk"), object.clone()],
        vec![object, FieldValue::from("desk")],
    ] {
        let store = create_names(&names).await?;
        for direction in ["asc", "desc"] {
            assert!(matches!(
                store
                    .find_api_keys_by_reference("owner", Some(("name", direction)))
                    .await,
                Err(AuthError::Internal(message))
                    if message == "Cannot convert object to primitive value"
            ));
            assert_eq!(
                store
                    .find_api_keys_by_reference("owner", None)
                    .await?
                    .iter()
                    .map(|row| row.name.field_value())
                    .collect::<Vec<_>>(),
                names
            );
        }
    }
    Ok(())
}

fn typed_fixture_name(value: &Value) -> AuthResult<FieldValue> {
    if let Some(value) = value.as_bool() {
        return Ok(FieldValue::Bool(value));
    }
    if value["type"] == "date"
        && let Some(value) = value["value"].as_str()
    {
        return chrono::DateTime::parse_from_rfc3339(value)
            .map(|value| FieldDate::from(value.with_timezone(&Utc)).into())
            .map_err(|error| AuthError::internal(format!("Invalid fixture Date: {error}")));
    }
    Err(AuthError::internal(
        "Expected a Date or Boolean fixture name",
    ))
}

fn observe_typed_names(rows: &[ApiKey]) -> AuthResult<Value> {
    rows.iter()
        .map(|row| {
            let value = match row.name.field_value() {
                FieldValue::Bool(value) => json!(value),
                FieldValue::Date(value) => {
                    let date = value
                        .to_datetime()?
                        .ok_or_else(|| AuthError::internal("Expected a valid fixture Date"))?;
                    json!({"type": "date", "value": date.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)})
                }
                _ => return Err(AuthError::internal("Expected a Date or Boolean stored name")),
            };
            Ok(json!({"id": row.id, "present": !row.name.is_undefined(), "value": value}))
        })
        .collect::<AuthResult<Vec<_>>>()
        .map(Value::Array)
}

#[tokio::test]
async fn date_and_boolean_name_sorts_match_pinned_unpaginated_rows() -> AuthResult<()> {
    let fixture: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/memory-sort-1.7.6.json"
    )))?;
    let cases = fixture["cases"]
        .as_array()
        .ok_or_else(|| AuthError::internal("Expected Memory sorting fixture cases"))?;
    for name in ["dates", "booleans"] {
        let case = cases
            .iter()
            .find(|case| case["name"] == name)
            .ok_or_else(|| AuthError::internal("Missing typed Memory sorting fixture case"))?;
        let seeds = case["seeds"]
            .as_array()
            .ok_or_else(|| AuthError::internal("Expected Memory sorting seeds"))?;
        let ids = seeds
            .iter()
            .map(|seed| {
                seed["input"]["id"]
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| AuthError::internal("Expected fixture API Key ID"))
            })
            .collect::<AuthResult<VecDeque<_>>>()?;
        let ids = Mutex::new(ids);
        let mut config = crate::AuthConfig::default();
        config.advanced.database.generate_id = Some(crate::id::IdGeneration::Custom(
            crate::id::IdGenerator::new(move |_| {
                ids.lock()
                    .map_err(|_| AuthError::internal("Fixture ID lock poisoned"))?
                    .pop_front()
                    .map(Some)
                    .ok_or_else(|| AuthError::internal("Fixture API Key IDs exhausted"))
            }),
        ));
        let store = EphemeralStore::new(Arc::new(config));
        for seed in seeds {
            let row = store
                .create_api_key(CreateApiKey {
                    name: SchemaValue::from_field(typed_fixture_name(&seed["input"]["name"])?),
                    ..input()
                })
                .await?;
            assert_eq!(observe_typed_names(&[row])?, json!([seed["result"]]));
        }
        let stored = store.lock()?.api_keys.snapshot()?;
        assert_eq!(observe_typed_names(&stored)?, case["stored"]);
        let operations = case["operations"]
            .as_array()
            .ok_or_else(|| AuthError::internal("Expected Memory sorting operations"))?;
        for (operation, sort) in [
            ("unsorted", None),
            ("ascending", Some(("name", "asc"))),
            ("descending", Some(("name", "desc"))),
        ] {
            let expected = operations
                .iter()
                .find(|candidate| candidate["name"] == operation)
                .ok_or_else(|| AuthError::internal("Missing Memory sorting operation"))?;
            let rows = store.find_api_keys_by_reference("owner", sort).await?;
            assert_eq!(
                observe_typed_names(&rows)?,
                expected["rows"],
                "{name}: {operation}"
            );
            assert_eq!(store.lock()?.api_keys.snapshot()?, stored);
        }
    }
    Ok(())
}

#[tokio::test]
async fn date_name_sort_does_not_require_chrono_string_conversion() -> AuthResult<()> {
    let earlier = FieldValue::Date(FieldDate::from_milliseconds(-8_640_000_000_000_000.0));
    let later = FieldValue::Date(FieldDate::from_milliseconds(8_640_000_000_000_000.0));
    let names = [later.clone(), earlier.clone()];
    let store = create_names(&names).await?;
    let stored = store.lock()?.api_keys.snapshot()?;
    for (direction, expected) in [
        ("asc", [earlier.clone(), later.clone()]),
        ("desc", [later, earlier]),
    ] {
        let rows = store
            .find_api_keys_by_reference("owner", Some(("name", direction)))
            .await?;
        assert_eq!(
            rows.iter()
                .map(|row| row.name.field_value())
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(store.lock()?.api_keys.snapshot()?, stored);
    }
    Ok(())
}
