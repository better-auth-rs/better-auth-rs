#![expect(
    clippy::indexing_slicing,
    reason = "Fixture indexing must fail when an expected record or property is missing."
)]

use super::*;
use crate::organization_fields::OrganizationFields;
use crate::store::{OrganizationRoleStore, TeamStore};
use crate::user_fields::UserConfig;

mod operations;
mod selector_values;
mod status_policies;

const MODELS: [(&str, EntityRole, &str); 5] = [
    ("organization", EntityRole::Organization, "name"),
    ("member", EntityRole::Member, "role"),
    ("invitation", EntityRole::Invitation, "status"),
    ("team", EntityRole::Team, "name"),
    ("organizationRole", EntityRole::OrganizationRole, "role"),
];
const TABLES: [&str; 10] = [
    "user",
    "session",
    "account",
    "verification",
    "organization",
    "member",
    "invitation",
    "team",
    "organizationRole",
    "teamMember",
];

fn role(model: &str) -> AuthResult<EntityRole> {
    match model {
        "user" => Ok(EntityRole::User),
        "session" => Ok(EntityRole::Session),
        "account" => Ok(EntityRole::Account),
        "verification" => Ok(EntityRole::Verification),
        "teamMember" => Ok(EntityRole::TeamMember),
        _ => required(MODELS.iter().find(|(name, _, _)| *name == model)).map(|(_, role, _)| *role),
    }
}

fn configured_fields(
    fields: &mut OrganizationFields,
    role: EntityRole,
) -> AuthResult<&mut UserConfig> {
    match role {
        EntityRole::Organization => Ok(&mut fields.organization),
        EntityRole::Member => Ok(&mut fields.member),
        EntityRole::Invitation => Ok(&mut fields.invitation),
        EntityRole::Team => Ok(&mut fields.team),
        EntityRole::OrganizationRole => Ok(&mut fields.organization_role),
        _ => Err(AuthError::internal(
            "Unknown Organization alias configuration model",
        )),
    }
}

fn id_alias() -> UserFieldConfig {
    UserFieldConfig {
        field_name: Some("lookup".into()),
        ..Default::default()
    }
}

fn value_observation(value: &Value) -> AuthResult<JsonValue> {
    match value {
        Value::Object(value) => Ok(JsonValue::Object(
            value
                .snapshot_fields()?
                .into_iter()
                .map(|(name, value)| Ok((name, value_observation(&value)?)))
                .collect::<AuthResult<serde_json::Map<String, JsonValue>>>()?,
        )),
        Value::Array(value) => Ok(JsonValue::Array(
            value
                .snapshot()?
                .iter()
                .map(value_observation)
                .collect::<AuthResult<Vec<_>>>()?,
        )),
        Value::Undefined => Ok(json!({"type":"undefined"})),
        Value::Date(_) => Ok(json!({"type":"date","value":required(value.json()?)?})),
        Value::Number(number) if !number.is_finite() => Ok(json!({
            "type":"number", "value":crate::SchemaValue::<String>::from_field(value.clone()).display_string()?,
        })),
        value => required(value.json()?),
    }
}

fn key_order(value: &Value, path: Vec<String>) -> AuthResult<Vec<JsonValue>> {
    let fields = match value {
        Value::Object(object) => object.snapshot_fields()?,
        Value::Array(array) => array
            .snapshot()?
            .into_iter()
            .enumerate()
            .map(|(index, value)| (index.to_string(), value))
            .collect(),
        _ => return Ok(Vec::new()),
    };
    let mut output = vec![json!({"path":path,"keys":fields.keys().collect::<Vec<_>>()})];
    for (name, value) in fields {
        let mut child = path.clone();
        child.push(name);
        output.extend(key_order(&value, child)?);
    }
    Ok(output)
}

fn field(
    mut declaration: UserFieldConfig,
    label: String,
    trace: &Events,
    mutation: Option<super::super::rows::RowRef<FieldMap>>,
) -> UserFieldConfig {
    let input_trace = trace.clone();
    let output_trace = trace.clone();
    let output_label = label.clone();
    declaration.transform = Some(FieldTransforms {
        input: Some(UserFieldTransform::new(move |value| {
            record(
                &input_trace,
                json!(["input", label, value_observation(&value)?]),
            )?;
            if let Some(selected) = &mutation {
                let before = observe(selected.snapshot()?, false)?;
                selected.apply_patch([("lookup".into(), "changed-alias".into())].into())?;
                record(
                    &input_trace,
                    json!([
                        "mutation",
                        "invitation.lookup",
                        before,
                        observe(selected.snapshot()?, false)?,
                    ]),
                )?;
            }
            Ok(value)
        })),
        output: Some(UserFieldTransform::new(move |value| {
            record(
                &output_trace,
                json!(["output", output_label, value_observation(&value)?]),
            )?;
            Ok(value)
        })),
    });
    declaration
}

fn seed(store: &EphemeralStore, expected: &JsonValue) -> AuthResult<()> {
    for model in TABLES {
        let rows = required(expected[model].as_array())?;
        let values = rows
            .iter()
            .map(core_query_alias_tests::revive_fields)
            .collect::<AuthResult<Vec<_>>>()?;
        store.operation(|operation| {
            let table = operation.create_table(role(model)?)?;
            for value in values {
                let _ = table.push(value)?;
            }
            Ok(())
        })?;
    }
    Ok(())
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "The contract rejects unrelated table mutations while propagating snapshot errors."
)]
fn memory(store: &EphemeralStore) -> AuthResult<JsonValue> {
    let state = store.operation(|operation| operation.capture_state())?;
    let mut output = serde_json::Map::new();
    for model in TABLES {
        let rows = state
            .fixture_table(model)
            .snapshot()?
            .into_iter()
            .map(|fields| value_observation(&fields.into()))
            .collect::<AuthResult<Vec<_>>>()?;
        let _ = output.insert(model.into(), json!(rows));
    }
    for model in state.keys() {
        if !TABLES.contains(&model.as_str()) {
            assert_eq!(
                state.fixture_table(&model).len()?,
                0,
                "Unexpected write to {model}"
            );
        }
    }
    Ok(output.into())
}

fn configured_store(
    case: &JsonValue,
    trace: &Events,
) -> AuthResult<(EphemeralStore, OrganizationFields)> {
    let scenario = required(case["scenario"].as_str())?;
    let joined = scenario.starts_with("member-user-");
    let own_selector = scenario.starts_with("invitation-own-selector-update-");
    let atomic = scenario.starts_with("invitation-atomic-") || own_selector;
    let model = if joined {
        "member"
    } else if atomic {
        "invitation"
    } else {
        required(case["model"].as_str())?
    };
    let (_, model_role, probe) = required(MODELS.iter().find(|(name, _, _)| *name == model))?;
    let mut config = AuthConfig::default();
    if joined {
        config.advanced.database.joins = Some(required(case["joins"].as_bool())?);
        let native_name = required(config.user.user_field_schema().fields().get("name"))?.clone();
        let _ = config.user.fields_mut().insert("id".into(), id_alias());
        let _ = config.user.fields_mut().insert(
            "name".into(),
            field(native_name, "user.name".into(), trace, None),
        );
    }
    let store = EphemeralStore::new(Arc::new(config));
    let first = required(required(case["steps"].as_array())?.first())?;
    seed(&store, &first["before"])?;
    let mutation = if case["mutate"] == true {
        Some(store.operation(|operation| {
            required(operation.capture_table(EntityRole::Invitation)?.row_at(0)?)
        })?)
    } else {
        None
    };
    let mut fields = OrganizationFields::default();
    let native = fields.schema_for(*model_role)?;
    let configured = configured_fields(&mut fields, *model_role)?;
    if own_selector {
        let column = required(case["column"].as_str())?;
        let mapped = UserFieldConfig {
            field_name: Some(column.into()),
            ..Default::default()
        };
        let _ = configured.fields_mut().insert("id".into(), mapped.clone());
        let trace = trace.clone();
        let _ = configured.fields_mut().insert(
            "claimLookup".into(),
            UserFieldConfig {
                on_update: Some(crate::user_fields::UserFieldFactory::new(move || {
                    record(
                        &trace,
                        json!(["onUpdate", "invitation.claimLookup", "claimed-alias"]),
                    )?;
                    Ok("claimed-alias".into())
                })),
                ..mapped
            },
        );
    } else {
        if !joined {
            let _ = configured.fields_mut().insert("id".into(), id_alias());
        }
        let _ = configured.fields_mut().insert(
            (*probe).into(),
            field(
                required(native.fields().get(*probe))?.clone(),
                format!("{model}.{probe}"),
                trace,
                mutation,
            ),
        );
    }
    if scenario.ends_with("-unique") {
        let mut reference = required(native.fields().get("userId"))?.clone();
        reference.unique = Some(true);
        let _ = configured.fields_mut().insert("userId".into(), reference);
    }
    if matches!(*model_role, EntityRole::Team | EntityRole::OrganizationRole)
        && case["operation"] == "update"
    {
        let clock = date(required(first["result"]["updatedAt"]["value"].as_str())?)?;
        let mut declaration = required(native.fields().get("updatedAt"))?.clone();
        let _ = required(declaration.on_update.as_ref())?;
        // The source fixture replays this clock. System clock sampling is outside this field-policy contract.
        declaration.on_update = Some(crate::user_fields::UserFieldFactory::new(move || {
            Ok(clock.clone().into())
        }));
        let _ = configured
            .fields_mut()
            .insert("updatedAt".into(), declaration);
    }
    store.configure_organization_fields(fields.clone())?;
    Ok((store, fields))
}

async fn verify_case(case: &JsonValue) -> AuthResult<()> {
    let trace = Events::default();
    let (store, fields) = configured_store(case, &trace)?;
    let scenario = required(case["scenario"].as_str())?;
    let steps = required(case["steps"].as_array())?;
    for (index, expected) in steps.iter().enumerate() {
        let before = memory(&store)?;
        let (input, result) = operations::execute(&store, &fields, case, index).await?;
        let observed_events = std::mem::take(
            &mut *trace
                .lock()
                .map_err(|_| AuthError::internal("Organization alias event lock poisoned"))?,
        );
        assert_eq!(expected["returned"], true, "{scenario}/{index}");
        if scenario.starts_with("invitation-own-selector-update-") {
            // The Rust method has no fromStatus parameter. Invitation acceptance tests cover the pending predicate.
            assert_eq!(
                expected["input"],
                json!({"invitationId":"invitation-alias","status":"accepted","fromStatus":"pending"})
            );
            assert_eq!(
                input,
                json!({"invitationId":"invitation-alias","status":"accepted"})
            );
        } else {
            assert_eq!(expected["input"], input, "{scenario}/{index} input");
        }
        assert_eq!(expected["before"], before, "{scenario}/{index} before");
        assert_eq!(
            expected["after"],
            memory(&store)?,
            "{scenario}/{index} after"
        );
        assert_eq!(
            expected["events"],
            json!(observed_events),
            "{scenario}/{index} callbacks"
        );
        assert_eq!(
            expected["keyOrder"],
            json!(key_order(&result, Vec::new())?),
            "{scenario}/{index} key order"
        );
        if scenario == "organization-delete" {
            // The Rust store returns unit; the upstream helper returns the unchanged requested ID.
            assert!(result.is_undefined());
            assert_eq!(expected["result"], case["alias"]);
        } else {
            assert_eq!(
                expected["result"],
                value_observation(&result)?,
                "{scenario}/{index} result"
            );
        }
    }
    Ok(())
}

async fn verify_fixture(source: &str, expected: Vec<String>) -> AuthResult<()> {
    let fixture: JsonValue = serde_json::from_str(source)?;
    assert_eq!(fixture["version"], "1.7.6");
    assert_eq!(fixture["backend"], "memory");
    let cases = required(fixture["cases"].as_array())?;
    assert_eq!(
        cases
            .iter()
            .map(|case| case["scenario"].clone())
            .collect::<Vec<_>>(),
        expected
            .into_iter()
            .map(JsonValue::String)
            .collect::<Vec<_>>()
    );
    for case in cases {
        verify_case(case).await?;
    }
    Ok(())
}

#[tokio::test]
async fn organization_queries_match_first_id_alias_join_and_atomic_source_contracts()
-> AuthResult<()> {
    let mut expected: Vec<String> = MODELS
        .into_iter()
        .flat_map(|(model, _, _)| {
            ["find", "update", "delete"].map(|operation| format!("{model}-{operation}"))
        })
        .collect();
    expected.extend(
        [
            "member-user-fallback",
            "member-user-native",
            "invitation-atomic-retained-alias",
            "invitation-atomic-mutated-alias",
        ]
        .map(str::to_owned),
    );
    verify_fixture(
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/organization-query-id-alias-1.7.6.json"
        )),
        expected,
    )
    .await
}

#[tokio::test]
async fn unique_member_references_match_singular_id_alias_source_contracts() -> AuthResult<()> {
    verify_fixture(
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/organization-query-id-alias-unique-1.7.6.json"
        )),
        ["member-user-fallback-unique", "member-user-native-unique"]
            .map(str::to_owned)
            .into(),
    )
    .await
}

#[tokio::test]
async fn invitation_own_selector_writes_match_complete_adapter_results() -> AuthResult<()> {
    verify_fixture(
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/invitation-claim-selector-update-1.7.6.json"
        )),
        [
            "invitation-own-selector-update-id",
            "invitation-own-selector-update-lookup",
        ]
        .map(str::to_owned)
        .into(),
    )
    .await
}
