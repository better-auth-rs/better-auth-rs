//! Seed raw Memory tables and retain their original table and row identities.

use super::*;
use crate::store::ephemeral::{rows::RowRef, table::TableRef};

const CAPTURE_TABLES: [&str; 4] = ["user", "session", "account", "verification"];
type Events = Arc<Mutex<Vec<Json>>>;

struct References {
    name: String,
    table: TableRef<FieldMap>,
    rows: Vec<RowRef<FieldMap>>,
}

pub(super) struct Seeded {
    pub(super) store: Arc<EphemeralStore>,
    pub(super) events: Events,
    pub(super) failure: Value,
    references: Vec<References>,
}

fn field(name: &'static str, events: &Events) -> UserFieldConfig {
    let events = events.clone();
    UserFieldConfig {
        required: Some(false),
        transform: Some(FieldTransforms {
            output: Some(UserFieldTransform::new(move |value| {
                lock(&events)?.push(json!(["output", name, values::observe(&value)?]));
                Ok(value)
            })),
            ..Default::default()
        }),
        ..Default::default()
    }
}

impl Seeded {
    pub(super) fn new(scenario: &Scenario) -> AuthResult<Self> {
        let events = Events::default();
        let mut config = config();
        config.advanced.database.default_find_many_limit =
            Some(scenario.default_limit.unwrap_or(100.0));
        let _ = config
            .user
            .fields_mut()
            .insert("name".into(), field("user.name", &events));
        let _ = config
            .session
            .fields_mut()
            .insert("userAgent".into(), field("session.userAgent", &events));
        let _ = config
            .account
            .additional_fields
            .insert("accessToken".into(), field("account.accessToken", &events));
        let store = Arc::new(EphemeralStore::empty(Arc::new(config)));
        store.operation(|op| {
            for name in CAPTURE_TABLES {
                op.replace_physical_table(
                    name.into(),
                    Some(TableRef::new(store.operations.clone())),
                )?;
            }
            Ok(())
        })?;
        let failure = objects::object(
            FieldMap::new(),
            FieldMap::from([
                ("name".into(), "Error".into()),
                (
                    "message".into(),
                    "Native parent ID conversion failed".into(),
                ),
            ]),
        );
        let mut state = Self {
            store,
            events,
            failure,
            references: Vec::new(),
        };
        state.seed(scenario)?;
        state.references = state.store.operation(|op| {
            op.root_keys()?
                .into_iter()
                .map(|name| {
                    let table = required(op.capture_physical_table(&name)?)?;
                    let rows = table.snapshot_refs()?;
                    Ok(References { name, table, rows })
                })
                .collect()
        })?;
        Ok(state)
    }

    fn parent_id(&self, input: &Json, index: usize) -> AuthResult<Value> {
        let Some(fields) = input.as_object() else {
            return values::revive(input);
        };
        let effect = required(fields.get("effect").and_then(Json::as_str))?.to_owned();
        let returned = fields
            .get("value")
            .map(values::revive)
            .transpose()?
            .unwrap_or_default();
        let enumerable = FieldMap::from([("effect".into(), effect.clone().into())]);
        let events = self.events.clone();
        let failure = self.failure.clone();
        let store = Arc::downgrade(&self.store);
        Ok(objects::object(
            enumerable,
            FieldMap::from([(
                "toString".into(),
                FieldFunction::contextual(move |_, _| {
                    lock(&events)?.push(json!(["group-id", index]));
                    match effect.as_str() {
                        "throw" => Err(AuthError::from_thrown(failure.clone())),
                        "mutate-first" => {
                            required(store.upgrade())?.operation(|op| {
                                let table = required(op.capture_physical_table("account")?)?;
                                let row = required(table.row_at(0)?)?;
                                row.set_field("accessToken".into(), "parent-0-after".into())?;
                                Ok(())
                            })?;
                            lock(&events)?.push(json!([
                                "mutate-first",
                                "account.accessToken",
                                "parent-0-after"
                            ]));
                            Ok(returned.clone())
                        }
                        _ => Err(AuthError::internal(format!(
                            "Unknown grouping fixture effect: {effect}"
                        ))),
                    }
                })
                .into(),
            )]),
        ))
    }

    fn seed(&self, scenario: &Scenario) -> AuthResult<()> {
        if !matches!(scenario.model, Model::User) {
            let users = ["user-a", "user-b", "user-c"]
                .into_iter()
                .enumerate()
                .map(|(index, id)| user(id.into(), &format!("User {index}")))
                .collect::<Vec<_>>();
            seed(&self.store, "user", &users)?;
        }
        let parents = scenario
            .parent_ids
            .iter()
            .enumerate()
            .map(|(index, input)| {
                let id = self.parent_id(input, index)?;
                Ok(match scenario.model {
                    Model::User => user(id, &format!("User {index}")),
                    Model::Account => account(
                        id,
                        required(scenario.owner_ids.get(index))?,
                        &format!("parent-{index}"),
                    ),
                    Model::Session => session(
                        id,
                        required(scenario.owner_ids.get(index))?,
                        &format!("parent-{index}"),
                    ),
                })
            })
            .collect::<AuthResult<Vec<_>>>()?;
        seed(&self.store, scenario.model.name(), &parents)?;
        if matches!(scenario.model, Model::User) {
            let children = scenario
                .child_ids
                .iter()
                .enumerate()
                .map(|(index, id)| {
                    Ok(account(
                        values::revive(id)?,
                        "user-a",
                        &format!("parent-{index}"),
                    ))
                })
                .collect::<AuthResult<Vec<_>>>()?;
            seed(&self.store, "account", &children)?;
        }
        Ok(())
    }

    pub(super) fn observe(&self) -> AuthResult<Json> {
        self.store.operation(|op| {
            let tables = op
                .root_keys()?
                .into_iter()
                .map(|name| {
                    let table = required(op.capture_physical_table(&name)?)?;
                    Ok((name, Value::from(table.array())))
                })
                .collect::<AuthResult<FieldMap>>()?;
            values::observe(&tables.into())
        })
    }

    pub(super) fn identities(&self) -> AuthResult<Json> {
        self.store.operation(|op| {
            let mut tables = true;
            let mut rows = true;
            for original in &self.references {
                let table = required(op.capture_physical_table(&original.name)?)?;
                tables &= table.array().same_array(&original.table.array());
                for (index, row) in original.rows.iter().enumerate() {
                    rows &= table
                        .row_at(index)?
                        .is_some_and(|current| current.same_row(row));
                }
            }
            Ok(json!({"tables": tables, "rows": rows}))
        })
    }
}
