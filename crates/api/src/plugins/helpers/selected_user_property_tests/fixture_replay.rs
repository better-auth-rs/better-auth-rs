//! Replay the complete selected-User contract without reading its accessor during observation.

use super::*;
use better_auth_core::{AuthConfig, AuthContext, AuthRecordFields};
use serde_json::{Value as Json, json};
use test_helpers::native_observation::assert_replay;

use crate::plugins::test_helpers::native_source as source;

pub(super) struct Before<'a> {
    context: &'a AuthContext<StatelessSchema>,
    store: &'a EphemeralStore,
    trace: &'a Trace,
    selected: &'a SelectedUser,
    user: Json,
    storage: Json,
}

pub(super) fn fixed_creation_fields(config: &mut AuthConfig) {
    let schema = better_auth_core::store::session_field_schema(&config.session, &FieldMap::new());
    for (name, value) in [
        ("token", FieldValue::from("b".repeat(32))),
        (
            "expiresAt",
            FieldDate::from_milliseconds(NOW + 604_800_000.0).into(),
        ),
        ("createdAt", FieldDate::from_milliseconds(NOW).into()),
        ("updatedAt", FieldDate::from_milliseconds(NOW).into()),
    ] {
        let mut field = schema.fields()[name].clone();
        field.default_value = None;
        field.default_value_fn = Some(UserFieldFactory::new(move || Ok(value.clone())));
        let _ = config.session.fields_mut().insert(name.into(), field);
    }
}

async fn storage(
    context: &AuthContext<StatelessSchema>,
    store: &EphemeralStore,
) -> AuthResult<FieldValue> {
    let sessions = context.database.get_user_sessions_value(&7.into()).await?;
    let accounts = context.database.get_user_accounts_value(&7.into()).await?;
    Ok(FieldMap::from([
        (
            "user".into(),
            store
                .storage_rows(EntityRole::User)?
                .into_iter()
                .map(FieldValue::from)
                .collect::<Vec<_>>()
                .into(),
        ),
        (
            "session".into(),
            sessions
                .into_iter()
                .map(|row| FieldValue::from(FieldMap::from(row)))
                .collect::<Vec<_>>()
                .into(),
        ),
        (
            "account".into(),
            accounts
                .into_iter()
                .map(|row| row.field_values().map(FieldValue::from))
                .collect::<AuthResult<Vec<_>>>()?
                .into(),
        ),
        (
            "verification".into(),
            store
                .storage_rows(EntityRole::Verification)?
                .into_iter()
                .map(FieldValue::from)
                .collect::<Vec<_>>()
                .into(),
        ),
    ])
    .into())
}

fn selected_user(user: &SelectedUser, native: &mut NativeObservation) -> AuthResult<Json> {
    let (kind, mut keys, mut properties) = match &user.value {
        FieldValue::Object(_) => ("object", Vec::new(), Vec::new()),
        FieldValue::Array(array) => {
            assert!(array.own_indices()?.is_empty());
            (
                "array",
                vec!["length".to_owned()],
                vec![json!(["length", {"enumerable":false,"value":array.len()?}])],
            )
        }
        FieldValue::Function(_) => ("function", Vec::new(), Vec::new()),
        FieldValue::Date(_) => ("date", Vec::new(), Vec::new()),
        _ => {
            return Err(AuthError::internal(
                "The selected User must retain its native shape",
            ));
        }
    };
    for name in user.properties.own_keys()? {
        assert_eq!(name, "id");
        let descriptor = user.properties.own_property_descriptor(&name)?.unwrap();
        // The same test-source getter supplies both property reads and descriptor identity.
        properties.push(json!([name, {
            "enumerable":descriptor.enumerable,
            "get":native.observe(&user.getter.clone().into())?,
            "set":native.observe(&FieldValue::Undefined)?,
        }]));
        keys.push(name);
    }
    let mut observed =
        json!({"identity":"object-1","type":kind,"ownKeys":keys,"properties":properties});
    if matches!(user.value, FieldValue::Function(_)) {
        observed["value"] = native.observe(&user.value)?;
    } else if matches!(user.value, FieldValue::Date(_)) {
        observed["value"] = native.observe(&user.value)?["value"].clone();
    }
    Ok(observed)
}

pub(super) async fn before<'a>(
    context: &'a AuthContext<StatelessSchema>,
    store: &'a EphemeralStore,
    trace: &'a Trace,
    user: &'a SelectedUser,
) -> AuthResult<Before<'a>> {
    let stored = storage(context, store).await?;
    let mut native = trace.native.lock().unwrap();
    let storage = native.observe(&stored)?;
    let observed = selected_user(user, &mut native)?;
    assert!(native.events.is_empty());
    assert_eq!(trace.reads.load(Ordering::SeqCst), 0);
    Ok(Before {
        context,
        store,
        trace,
        selected: user,
        user: observed,
        storage,
    })
}

fn error(value: &FieldValue) -> AuthResult<(Json, Vec<String>)> {
    let mut native = NativeObservation::default();
    let name = value.model_property("name")?;
    let error = if name.is_undefined() {
        json!({"thrown":native.observe(value)?})
    } else {
        let object = value.as_object().unwrap();
        let mut properties = FieldMap::new();
        for key in object.own_keys()? {
            if !["stack", "name", "message"].contains(&key.as_str()) {
                let _ = properties.insert(key.clone(), object.get(&key)?.unwrap_or_default());
            }
        }
        json!({"name":native.observe(&name)?,"message":native.observe(&value.model_property("message")?)?,"properties":native.observe(&properties.into())?})
    };
    Ok((error, native.function_ids()))
}

fn source_user(value: &Json) -> AuthResult<Json> {
    let keys = value["ownKeys"].as_array().unwrap();
    let properties = value["properties"].as_array().unwrap();
    assert_eq!(
        keys,
        &properties
            .iter()
            .map(|property| property[0].clone())
            .collect::<Vec<_>>()
    );
    let function = value["type"] == "function";
    if function {
        assert_eq!(
            value["ownKeys"],
            json!(["length", "name", "prototype", "id"])
        );
    }
    let mut kept_keys = Vec::new();
    let mut kept_properties = Vec::new();
    for property in properties {
        let name = property[0].as_str().unwrap();
        if function && ["length", "name", "prototype"].contains(&name) {
            continue;
        }
        let descriptor = &property[1];
        let mut kept =
            serde_json::Map::from_iter([("enumerable".into(), descriptor["enumerable"].clone())]);
        for (key, value) in descriptor.as_object().unwrap() {
            if ["enumerable", "writable", "configurable"].contains(&key.as_str()) {
                continue;
            }
            assert!(["value", "get", "set"].contains(&key.as_str()));
            let value = source::source_value_with(value, &|value| {
                if value.get("identity").is_some() && value["type"] == "function" {
                    assert_eq!(value["value"]["type"], "function");
                    Ok(Some(value["value"].clone()))
                } else {
                    Ok(None)
                }
            })?;
            let _ = kept.insert(key.clone(), value);
        }
        kept_keys.push(name);
        kept_properties.push(json!([name, kept]));
    }
    let mut selected = json!({"identity":value["identity"],"type":value["type"],"ownKeys":kept_keys,"properties":kept_properties});
    if let Some(value) = value.get("value") {
        selected["value"] = value.clone();
    }
    Ok(selected)
}

fn expected(case: &Json) -> AuthResult<Json> {
    let events = case["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| {
            event
                .as_object()
                .unwrap()
                .iter()
                .map(|(name, value)| Ok((name.clone(), source::source_value(value)?)))
                .collect::<AuthResult<serde_json::Map<_, _>>>()
                .map(Json::from)
        })
        .collect::<AuthResult<Vec<_>>>()?;
    Ok(json!({
        "shape":case["shape"],"throwsAt":case["throwsAt"],"changing":case["changing"],"reads":case["reads"],
        "userBefore":source_user(&case["userBefore"])?,"before":source::source_value(&case["before"])?,
        "outcome":case["outcome"],"after":source::source_value(&case["after"])?,"userAfter":source_user(&case["userAfter"])?,
        "events":events,"functionIds":case["functions"].as_array().unwrap().iter().map(|function| function["identity"].clone()).collect::<Vec<_>>(),
        "errorFunctions":case["errorFunctions"],
    }))
}

impl Before<'_> {
    pub(super) async fn assert_case(self, case: &Json, thrown: FieldValue) -> AuthResult<()> {
        let stored = storage(self.context, self.store).await?;
        let (error, error_functions) = error(&thrown)?;
        let trace = self.trace;
        let mut native = trace.native.lock().unwrap();
        let after = native.observe(&stored)?;
        let user_after = selected_user(self.selected, &mut native)?;
        let actual = json!({
            "shape":case["shape"],"throwsAt":trace.throws_at,"changing":trace.changing,"reads":trace.reads.load(Ordering::SeqCst),
            "userBefore":self.user,"before":self.storage,
            "outcome":{"returned":false,"sameOriginal":thrown.strict_equals(&trace.original),"error":error},
            "after":after,"userAfter":user_after,"events":native.events,"functionIds":native.function_ids(),"errorFunctions":error_functions,
        });
        let label = format!(
            "selected-user/{}/{}/{}",
            case["shape"], case["throwsAt"], case["changing"]
        );
        assert_replay(&actual, &expected(case)?, &label);
        Ok(())
    }
}

#[tokio::test]
async fn selected_user_property_fixture_replays_all_twenty_cases() -> AuthResult<()> {
    let fixture: Json = serde_json::from_str(include_str!(
        "../../../../../../tests/fixtures/selected-user-property-1.7.6.json"
    ))?;
    let coverage: Json = serde_json::from_str(include_str!(
        "../../../../../../tests/fixtures/selected-user-property-runtime-coverage.json"
    ))?;
    assert_eq!(fixture["version"], "1.7.6");
    assert_eq!(fixture["now"], NOW);
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 20);
    assert_eq!(coverage["caseCount"], cases.len());
    for case in cases {
        run_case(
            case["shape"].as_str().unwrap(),
            case["throwsAt"].as_u64().unwrap() as usize,
            case["changing"].as_bool().unwrap(),
            Some(case),
        )
        .await?;
    }
    Ok(())
}
