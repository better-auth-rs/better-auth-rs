//! Compare native Store results with the complete upstream Memory observation.

use super::*;
use crate::session::SessionData;
use crate::store::{AccountOwner, UserAccounts};
use serde::Deserialize;
use serde_json::{Value as Json, json};

mod objects;
mod page;
mod state;

mod values {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/support/device_where_values.rs"
    ));
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Model {
    User,
    Account,
    Session,
}

impl Model {
    fn name(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Account => "account",
            Self::Session => "session",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Operation {
    Owner,
    Session,
    Sessions,
    Accounts,
    Page,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Scenario {
    name: String,
    model: Model,
    operation: Operation,
    parent_ids: Vec<Json>,
    #[serde(default)]
    owner_ids: Vec<String>,
    #[serde(default)]
    child_ids: Vec<Json>,
    default_limit: Option<f64>,
    offset: Option<f64>,
    limit: Option<f64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    version: String,
    scenarios: Vec<Scenario>,
    cases: Vec<Json>,
}

fn relation<T>(
    selected: JoinValue<T>,
    fields: impl Fn(T) -> AuthResult<FieldMap>,
) -> AuthResult<Value> {
    match selected {
        JoinValue::One(Some(row)) => Ok(fields(row)?.into()),
        JoinValue::One(None) => Ok(Value::Null),
        JoinValue::Many(rows) => Ok(rows
            .into_iter()
            .map(|row| fields(row).map(Value::from))
            .collect::<AuthResult<Vec<_>>>()?
            .into()),
    }
}

fn owner(selected: Option<AccountOwner>) -> AuthResult<Value> {
    let Some(selected) = selected else {
        return Ok(Value::Null);
    };
    let account = selected.account.internal_fields()?.into();
    if matches!(&selected.user, JoinValue::One(None)) {
        return Ok(FieldMap::from([
            ("kind".into(), "orphaned".into()),
            ("account".into(), account),
        ])
        .into());
    }
    Ok(FieldMap::from([
        ("kind".into(), "owned".into()),
        (
            "user".into(),
            relation(selected.user, |user| Ok(FieldMap::from(user)))?,
        ),
        ("account".into(), account),
    ])
    .into())
}

fn accounts(selected: Option<UserAccounts>) -> AuthResult<Value> {
    let Some(selected) = selected else {
        return Ok(Value::Null);
    };
    Ok(FieldMap::from([
        ("user".into(), FieldMap::from(selected.user).into()),
        (
            "accounts".into(),
            relation(selected.accounts, |account| account.internal_fields())?,
        ),
    ])
    .into())
}

fn session_result(data: Option<SessionData<JoinValue<UserView>>>) -> AuthResult<Value> {
    let Some(data) = data else {
        return Ok(Value::Null);
    };
    if matches!(&data.user, JoinValue::One(None)) {
        return Ok(Value::Null);
    }
    Ok(FieldMap::from([
        ("session".into(), FieldMap::from(data.session).into()),
        (
            "user".into(),
            relation(data.user, |user| Ok(FieldMap::from(user)))?,
        ),
    ])
    .into())
}

async fn execute(store: &EphemeralStore, scenario: &Scenario) -> AuthResult<Value> {
    match scenario.operation {
        Operation::Owner => owner(
            store
                .get_account_owner("provider", "external-owner")
                .await?,
        ),
        Operation::Accounts => accounts(store.get_user_with_accounts(EMAIL).await?),
        Operation::Session => session_result(
            store
                .get_session_snapshot("shared-token")
                .await?
                .and_then(|(_, data)| data),
        ),
        Operation::Sessions => {
            let selected = store
                .get_session_snapshots(&["shared-token".into()], false)
                .await?;
            let rows = selected
                .into_iter()
                .map(|(_, data)| session_result(data))
                .collect::<AuthResult<Vec<_>>>()?;
            if rows.iter().any(Value::is_null) {
                return Ok(Vec::<Value>::new().into());
            }
            Ok(rows.into())
        }
        Operation::Page => page::execute(store, scenario).await,
    }
}

fn key_order(value: &Value, path: Vec<String>, output: &mut Vec<Json>) -> AuthResult<()> {
    let entries = match value {
        Value::Array(array) => array
            .own_indices()?
            .into_iter()
            .map(|index| Ok((index.to_string(), required(array.get(index)?)?)))
            .collect::<AuthResult<Vec<_>>>()?,
        Value::Object(object) => object
            .enumerable_keys()?
            .into_iter()
            .map(|key| Ok((key.clone(), required(object.get(&key)?)?)))
            .collect::<AuthResult<Vec<_>>>()?,
        _ => return Ok(()),
    };
    output.push(
        json!({"path": path, "keys": entries.iter().map(|(key, _)| key).collect::<Vec<_>>()}),
    );
    for (key, value) in entries {
        let mut child_path = path.clone();
        child_path.push(key);
        key_order(&value, child_path, output)?;
    }
    Ok(())
}

async fn capture(scenario: &Scenario) -> AuthResult<Json> {
    let state = state::Seeded::new(scenario)?;
    let before = state.observe()?;
    assert!(lock(&state.events)?.is_empty(), "{scenario:?}");
    let result = execute(&state.store, scenario).await;
    let mut observation = match result {
        Ok(result) => {
            let mut order = Vec::new();
            key_order(&result, Vec::new(), &mut order)?;
            json!({
                "returned": true,
                "result": values::observe(&result)?,
                "json": required(result.json()?)?,
                "keyOrder": order,
                "originalError": false,
            })
        }
        Err(error) => {
            let raw = required(error.raw_value())?;
            let object = required(raw.as_object())?;
            json!({
                "returned": false,
                "error": {
                    "name": values::observe(&raw.model_property("name")?)?,
                    "message": values::observe(&raw.model_property("message")?)?,
                    "properties": values::observe(raw)?,
                    "keys": object.enumerable_keys()?,
                },
                "originalError": raw.strict_equals(&state.failure),
            })
        }
    };
    let after = state.observe()?;
    let extra = json!({
        "backend": "memory", "joins": true, "scenario": scenario.name,
        "before": before, "events": lock(&state.events)?.clone(),
        "after": after, "storageUnchanged": before == after,
        "identities": state.identities()?,
    });
    required(observation.as_object_mut())?.extend(required(extra.as_object())?.clone());
    Ok(observation)
}

#[tokio::test]
async fn memory_native_join_grouping_matches_upstream_1_7_6() -> AuthResult<()> {
    let ordered = objects::object(
        FieldMap::from([
            ("label".into(), true.into()),
            ("9".into(), Value::Undefined),
            ("01".into(), Value::Undefined),
        ]),
        FieldMap::from([("2".into(), Value::Null), ("hidden".into(), Value::Null)]),
    );
    assert_eq!(
        ordered.own_property_keys()?,
        ["2", "9", "label", "01", "hidden"]
    );
    assert_eq!(
        required(ordered.as_object())?.enumerable_keys()?,
        ["9", "label", "01"]
    );
    let fixture: Fixture = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/memory-native-join-grouping-1.7.6.json"
    )))?;
    assert_eq!(fixture.version, "1.7.6");
    assert_eq!(fixture.scenarios.len(), 12);
    assert_eq!(fixture.cases.len(), fixture.scenarios.len());
    for (scenario, expected) in fixture.scenarios.iter().zip(&fixture.cases) {
        assert_eq!(expected.get("scenario"), Some(&json!(scenario.name)));
        assert_eq!(capture(scenario).await?, *expected, "{scenario:?}");
    }
    Ok(())
}
