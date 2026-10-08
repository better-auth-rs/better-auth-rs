use super::*;
use crate::store::{ListOrganizationMembersParams, MemberStore, UserStore, schema::EntityRole};
use crate::user_fields::{
    FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform, UserFieldType,
};

fn fixture() -> AuthResult<Value> {
    Ok(serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/memory-sort-1.7.6.json"
    )))?)
}

fn array(value: &Value) -> AuthResult<&[Value]> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| AuthError::internal("Expected a sort fixture array"))
}

fn text(value: &Value) -> AuthResult<&str> {
    value
        .as_str()
        .ok_or_else(|| AuthError::internal("Expected sort fixture text"))
}

fn field(value: &Value) -> AuthResult<FieldValue> {
    match value {
        Value::Object(object) => match object.get("type").and_then(Value::as_str) {
            Some("undefined") => Ok(FieldValue::Undefined),
            Some("utf16") => Ok(crate::Utf16String::from_units(serde_json::from_value(
                value["value"].clone(),
            )?)
            .into()),
            Some("date") => Ok(FieldDate::from(
                chrono::DateTime::parse_from_rfc3339(text(&value["value"])?)
                    .map_err(|error| {
                        AuthError::internal(format!("Invalid sort fixture Date: {error}"))
                    })?
                    .with_timezone(&Utc),
            )
            .into()),
            Some("number") => Ok(FieldValue::Number(match text(&value["value"])? {
                "-0" => -0.0,
                "NaN" => f64::NAN,
                "Infinity" => f64::INFINITY,
                "-Infinity" => f64::NEG_INFINITY,
                _ => return Err(AuthError::internal("Unknown tagged sort fixture number")),
            })),
            _ => object
                .iter()
                .map(|(key, value)| Ok((key.clone(), field(value)?)))
                .collect::<AuthResult<FieldMap>>()
                .map(Into::into),
        },
        Value::Array(values) => values
            .iter()
            .map(field)
            .collect::<AuthResult<Vec<_>>>()
            .map(Into::into),
        _ => FieldValue::from_json(value.clone()),
    }
}

fn observe(value: &FieldValue) -> AuthResult<Value> {
    Ok(match value {
        FieldValue::Undefined => json!({"type":"undefined"}),
        FieldValue::Utf16String(value) => match value.to_utf8() {
            Ok(value) => json!(value),
            Err(_) => json!({"type":"utf16", "value":value.as_utf16()}),
        },
        FieldValue::Date(date) => json!({
            "type":"date",
            "value": if date.milliseconds().is_finite() {
                value.json()?.ok_or_else(|| AuthError::internal("A valid sort Date must have a JSON observation"))?
            } else {
                json!("Invalid Date")
            }
        }),
        FieldValue::Number(value) if *value == 0.0 && value.is_sign_negative() => {
            json!({"type":"number", "value":"-0"})
        }
        FieldValue::Number(value) if !value.is_finite() => {
            json!({"type":"number", "value":crate::schema_value::number_string(*value)})
        }
        FieldValue::Array(values) => {
            Value::Array(values.iter().map(observe).collect::<AuthResult<_>>()?)
        }
        FieldValue::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| Ok((key.clone(), observe(value)?)))
                .collect::<AuthResult<_>>()?,
        ),
        _ => value.json()?.ok_or_else(|| {
            AuthError::internal("A defined sort value must have a JSON observation")
        })?,
    })
}

fn rows(values: &[ApiKey], raw: bool) -> AuthResult<Value> {
    values
        .iter()
        .map(|row| {
            Ok(json!({
                "id":row.id,
                // Projection visits every declared field; raw storage omits undefined values.
                "present":!raw || !row.name.is_undefined(),
                "value":observe(&row.name.field_value())?,
            }))
        })
        .collect::<AuthResult<Vec<_>>>()
        .map(Value::Array)
}

type Events = Arc<Mutex<Vec<Value>>>;

fn take_events(events: &Events) -> AuthResult<Value> {
    let mut events = events
        .lock()
        .map_err(|_| AuthError::internal("Sort event lock poisoned"))?;
    Ok(Value::Array(std::mem::take(&mut *events)))
}

fn transform(events: &Events, phase: &'static str) -> UserFieldTransform {
    let events = events.clone();
    UserFieldTransform::new(move |value| {
        events
            .lock()
            .map_err(|_| AuthError::internal("Sort event lock poisoned"))?
            .push(json!({"phase":phase, "value":observe(&value)?}));
        Ok(value)
    })
}

fn store(case: &Value, events: &Events) -> AuthResult<EphemeralStore> {
    let ids = array(&case["seeds"])?
        .iter()
        .map(|seed| text(&seed["input"]["id"]).map(str::to_owned))
        .collect::<AuthResult<VecDeque<_>>>()?;
    let ids = Mutex::new(ids);
    let mut config = crate::AuthConfig::default();
    config.advanced.database.generate_id = Some(crate::id::IdGeneration::Custom(
        crate::id::IdGenerator::new(move |_| {
            ids.lock()
                .map_err(|_| AuthError::internal("Sort ID lock poisoned"))?
                .pop_front()
                .map(Some)
                .ok_or_else(|| AuthError::internal("Sort fixture IDs exhausted"))
        }),
    ));
    let mut store = EphemeralStore::new(Arc::new(config));
    store.model_fields.register(
        EntityRole::ApiKey,
        UserConfig {
            additional_fields: Some(
                [(
                    "name".into(),
                    UserFieldConfig {
                        field_type: match text(&case["declaration"])? {
                            "string" => UserFieldType::String,
                            "json" => UserFieldType::Json,
                            _ => {
                                return Err(AuthError::internal(
                                    "Unknown sort fixture declaration",
                                ));
                            }
                        },
                        field_name: Some("stored_name".into()),
                        required: Some(false),
                        transform: Some(FieldTransforms {
                            input: Some(transform(events, "input")),
                            output: Some(transform(events, "output")),
                        }),
                        ..Default::default()
                    },
                )]
                .into_iter()
                .collect(),
            ),
        },
    )?;
    Ok(store)
}

async fn query(store: &EphemeralStore, operation: &str) -> AuthResult<Vec<ApiKey>> {
    let direction = match operation {
        "unsorted" => None,
        "ascending" | "ascending-page" => Some("asc"),
        "descending" | "descending-page" => Some("desc"),
        _ => return Err(AuthError::internal("Unknown Memory sort operation")),
    };
    if !operation.ends_with("-page") {
        return store
            .find_api_keys_by_reference("owner", direction.map(|direction| ("name", direction)))
            .await;
    }
    // The store trait has no offset argument. Exercise the same raw sort, page and projection boundaries.
    let selected = {
        let mut selected = store
            .lock()?
            .api_keys
            .select_refs(|row| row.reference_id == "owner")?
            .into_iter()
            .map(|source| Ok((source.read(|row| Ok(row.clone()))?, source)))
            .collect::<AuthResult<Vec<_>>>()?;
        crate::memory_sort::sort(&mut selected, direction == Some("desc"), |(row, _)| {
            Ok(row.name.field_value())
        })?;
        crate::query::paginate_memory(selected, Some(2.0), Some(1.0))
    };
    store.project_api_key_refs(selected).await
}

#[test]
fn complete_string_matrices_match_pinned_icu_collation() -> AuthResult<()> {
    let fixture = fixture()?;
    let comparator = crate::memory_sort::Comparator::default();
    for (matrix, count) in [("stringComparisons", 31), ("rawUtf16Comparisons", 14)] {
        let values = array(&fixture[matrix]["values"])?;
        let signs = array(&fixture[matrix]["signs"])?;
        assert_eq!(values.len(), count);
        assert_eq!(signs.len(), count);
        for (left, expected) in values.iter().zip(signs) {
            let expected = array(expected)?;
            assert_eq!(expected.len(), count);
            for (right, expected) in values.iter().zip(expected) {
                let order = comparator.compare(&field(left)?, &field(right)?)?;
                let sign = match order {
                    std::cmp::Ordering::Less => -1,
                    std::cmp::Ordering::Equal => 0,
                    std::cmp::Ordering::Greater => 1,
                };
                assert_eq!(json!(sign), *expected, "{matrix}: {left} versus {right}");
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn all_name_sort_cases_match_rows_errors_callbacks_and_storage() -> AuthResult<()> {
    let fixture = fixture()?;
    let cases = array(&fixture["cases"])?;
    assert_eq!(
        cases
            .iter()
            .map(|case| text(&case["name"]))
            .collect::<AuthResult<Vec<_>>>()?,
        [
            "strings",
            "string-ties",
            "numbers",
            "booleans",
            "nullish",
            "dates",
            "heterogeneous-raw",
            "heterogeneous-json",
            "json-documents",
            "nonconvertible-single",
            "nonconvertible-pair",
            "utf16-strings",
        ]
    );
    for case in cases {
        let name = text(&case["name"])?;
        let events = Arc::new(Mutex::new(Vec::new()));
        let store = store(case, &events)?;
        for seed in array(&case["seeds"])? {
            let value = seed["input"]
                .get("name")
                .map(field)
                .transpose()?
                .unwrap_or_default();
            let row = store
                .create_api_key(CreateApiKey {
                    name: SchemaValue::from_field(value),
                    ..input()
                })
                .await?;
            assert_eq!(
                rows(&[row], false)?,
                json!([seed["result"]]),
                "{name}: seed result"
            );
            assert_eq!(take_events(&events)?, seed["events"], "{name}: seed events");
        }
        assert_eq!(
            rows(&store.lock()?.api_keys.snapshot()?, true)?,
            case["stored"],
            "{name}: raw seeds"
        );
        let operations = array(&case["operations"])?;
        assert_eq!(
            operations
                .iter()
                .map(|operation| text(&operation["name"]))
                .collect::<AuthResult<Vec<_>>>()?,
            [
                "unsorted",
                "ascending",
                "descending",
                "ascending-page",
                "descending-page"
            ]
        );
        for operation in operations {
            let operation_name = text(&operation["name"])?;
            match query(&store, operation_name).await {
                Ok(result) => {
                    assert_eq!(operation["returned"], true, "{name}: {operation_name}");
                    assert_eq!(
                        rows(&result, false)?,
                        operation["rows"],
                        "{name}: {operation_name}"
                    );
                }
                Err(AuthError::Internal(message)) => {
                    assert_eq!(
                        operation["returned"], false,
                        "{name}: {operation_name}: {message}"
                    );
                    assert_eq!(
                        operation["error"],
                        json!({"name":"TypeError", "message":message, "properties":{}})
                    );
                }
                Err(error) => return Err(error),
            }
            assert_eq!(
                take_events(&events)?,
                operation["events"],
                "{name}: {operation_name}: events"
            );
            assert_eq!(
                rows(&store.lock()?.api_keys.snapshot()?, true)?,
                operation["stored"],
                "{name}: {operation_name}: raw rows"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn user_and_member_queries_use_locale_order_and_preserve_stable_pages() -> AuthResult<()> {
    let fixture = fixture()?;
    for case in array(&fixture["cases"])?.iter().filter(|case| {
        matches!(
            case["name"].as_str(),
            Some("strings" | "string-ties" | "utf16-strings")
        )
    }) {
        let store = EphemeralStore::default();
        for seed in array(&case["seeds"])? {
            let id = text(&seed["input"]["id"])?;
            let name = field(&seed["input"]["name"])?;
            let _ = store
                .create_user(crate::CreateUser {
                    email: Some(id.into()),
                    name: SchemaValue::from_field(name.clone()),
                    ..crate::CreateUser::new()
                })
                .await?;
            let _ = store
                .create_member(crate::CreateMember {
                    role: SchemaValue::from_field(name),
                    ..crate::CreateMember::new("sort-organization", id, "member")
                })
                .await?;
        }
        let users_before = store.lock()?.users.snapshot()?;
        let members_before = store.lock()?.members.snapshot()?;
        for operation in array(&case["operations"])?
            .iter()
            .filter(|operation| operation["name"] != "unsorted")
        {
            let name = text(&operation["name"])?;
            let direction = if name.starts_with("ascending") {
                "asc"
            } else {
                "desc"
            };
            let (limit, offset) = if name.ends_with("-page") {
                (Some(2.0), Some(1.0))
            } else {
                (None, None)
            };
            let (users, total) = store
                .list_users(crate::ListUsersParams {
                    sort_by: Some("name".into()),
                    sort_direction: Some(direction.into()),
                    limit,
                    offset,
                    ..Default::default()
                })
                .await?;
            assert_eq!(total, users_before.len());
            let users = users.iter().map(|user| Ok(json!({"id":user.email, "present":true, "value":observe(&user.name.field_value())?})))
                .collect::<AuthResult<Vec<_>>>()?;
            assert_eq!(
                json!(users),
                operation["rows"],
                "User {}: {name}",
                case["name"]
            );
            let (members, total) = store
                .query_organization_members(&ListOrganizationMembersParams {
                    organization_id: "sort-organization".into(),
                    sort_by: Some("role".into()),
                    sort_direction: Some(direction.into()),
                    limit,
                    offset,
                    ..Default::default()
                })
                .await?;
            assert_eq!(total, members_before.len());
            let members = members.iter().map(|member| Ok(json!({"id":member.user_id, "present":true, "value":observe(&member.role.field_value())?})))
                .collect::<AuthResult<Vec<_>>>()?;
            assert_eq!(
                json!(members),
                operation["rows"],
                "Member {}: {name}",
                case["name"]
            );
            assert_eq!(store.lock()?.users.snapshot()?, users_before);
            assert_eq!(store.lock()?.members.snapshot()?, members_before);
        }
    }
    Ok(())
}
