#![cfg(feature = "seaorm2")]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Ordinary two-row contracts fail immediately when setup, channels, or captured shapes change."
)]
#![allow(
    unreachable_pub,
    reason = "SeaORM derives require public fixture entity types"
)]

#[path = "../compat-tests/rust-server/src/organization_fields/models.rs"]
mod models;

use better_auth_core::{
    AuthConfig, AuthError, AuthResponse, AuthResult, AuthSchema, AuthStore, CreateMember,
    CreateOrganization, CreateTeam, CreateUser, UpdateOrganization, UpdateTeam,
    organization_fields::OrganizationFields,
    store::EphemeralStore,
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform},
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, Schema},
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::{mpsc, oneshot};

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Organization,
    Team,
}

struct State {
    enabled: AtomicBool,
    events: Mutex<Vec<Value>>,
    first_source: String,
    gates: Mutex<[Option<oneshot::Receiver<()>>; 2]>,
    started: mpsc::UnboundedSender<usize>,
    finished: mpsc::UnboundedSender<()>,
}

impl State {
    fn text(&self, text: &str) -> String {
        if self.first_source == "A" {
            return text.into();
        }
        match text {
            "A" => "B",
            "B" => "A",
            "A-detail" => "B-detail",
            "B-detail" => "A-detail",
            "A-member" => "B-member",
            "B-member" => "A-member",
            _ => text,
        }
        .into()
    }
    fn event(&self, field: &str, value: &str) -> usize {
        let mut events = self.events.lock().unwrap();
        events.push(json!([field, value]));
        events.iter().filter(|event| event[0] != "member").count()
    }
    async fn wait(&self, row: usize) -> AuthResult<()> {
        let gate = self.gates.lock().unwrap()[row].take().unwrap();
        self.started.send(row).unwrap();
        gate.await
            .map_err(|_| AuthError::internal("Ordinary display gate closed"))
    }
}

fn failure() -> AuthError {
    AuthResponse::json(
        400,
        &json!({"code":"ORDINARY_FIELD_FAILURE", "message":"Ordinary display callback failed"}),
    )
    .unwrap()
    .with_header("x-ordinary-error", "original")
    .into()
}

fn field(output: Option<UserFieldTransform>, alias: bool) -> UserFieldConfig {
    UserFieldConfig {
        required: Some(false),
        field_name: alias.then(|| "stored_label".into()),
        transform: output.map(|output| FieldTransforms {
            output: Some(output),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn seed_fields() -> OrganizationFields {
    let mut fields = OrganizationFields::default();
    let _ = fields
        .member
        .fields_mut()
        .insert("label".into(), field(None, true));
    let _ = fields
        .team
        .fields_mut()
        .insert("label".into(), field(None, true));
    fields
}

async fn rows<S: AuthSchema>(
    store: &impl AuthStore<S>,
    kind: Kind,
    owner: &str,
) -> AuthResult<Vec<(String, Value)>> {
    match kind {
        Kind::Organization => Ok(store
            .list_user_organizations(owner)
            .await?
            .into_iter()
            .map(|row| {
                (
                    row.id.typed().unwrap().clone(),
                    json!({"name":row.name, "detail":row.logo}),
                )
            })
            .collect()),
        Kind::Team => Ok(store
            .list_user_teams(owner)
            .await?
            .into_iter()
            .map(|row| {
                (
                    row.id.typed().unwrap().clone(),
                    json!({"name":row.name, "detail":row.additional_fields["label"].json().unwrap()}),
                )
            })
            .collect()),
    }
}

async fn update_name<S: AuthSchema>(
    store: &impl AuthStore<S>,
    kind: Kind,
    id: &str,
    name: &str,
) -> AuthResult<()> {
    match kind {
        Kind::Organization => {
            let _ = store
                .update_organization(
                    id,
                    UpdateOrganization {
                        name: Some(name.to_owned().into()),
                        ..Default::default()
                    },
                )
                .await?;
        }
        Kind::Team => {
            let _ = store
                .update_team(
                    id,
                    UpdateTeam {
                        name: Some(name.to_owned().into()),
                        ..Default::default()
                    },
                )
                .await?;
        }
    }
    Ok(())
}

async fn check_case<S: AuthSchema, T: AuthStore<S> + Clone + 'static>(store: T, fixture: &Value) {
    let kind = if fixture["kind"] == "organization" {
        Kind::Organization
    } else {
        Kind::Team
    };
    let mode = fixture["mode"].as_str().unwrap().to_owned();
    store.configure_organization_fields(seed_fields()).unwrap();
    let owner = store
        .create_user(
            CreateUser::new()
                .with_name("Ordinary Owner")
                .with_email("owner@ordinary-join.test"),
        )
        .await
        .unwrap()
        .id
        .typed()
        .unwrap()
        .clone();
    let mut first_org = None;
    for name in ["A", "B"] {
        let mut input = CreateOrganization::new(name, format!("ordinary-{name}"));
        input.logo = Some(format!("{name}-detail")).into();
        let org = store.create_organization(input).await.unwrap();
        let org_id = org.id.typed().unwrap().clone();
        let mut input = CreateMember::new(&org_id, &owner, "member");
        let _ = input
            .additional_fields
            .insert("label".into(), format!("{name}-member").into());
        let _ = store.create_member(input).await.unwrap();
        let parent = first_org.get_or_insert(org_id).clone();
        let team = store
            .create_team(CreateTeam {
                name: name.into(),
                organization_id: parent.into(),
                additional_fields: [("label".into(), format!("{name}-detail").into())]
                    .into_iter()
                    .collect(),
                ..Default::default()
            })
            .await
            .unwrap();
        let _ = store
            .add_team_member(&team.id, &owner, None)
            .await
            .unwrap()
            .unwrap();
    }
    // Map the adapter's actual row order to the captured A/B display labels.
    // No query ordering is added and stored association IDs remain unchanged.
    let baseline = rows(&store, kind, &owner).await.unwrap();
    assert_eq!(baseline.len(), 2);
    let ids = Arc::new([baseline[0].0.clone(), baseline[1].0.clone()]);
    let (start, mut started) = mpsc::unbounded_channel();
    let (finish, mut finished) = mpsc::unbounded_channel();
    let (release_a, gate_a) = oneshot::channel();
    let (release_b, gate_b) = oneshot::channel();
    let state = Arc::new(State {
        enabled: AtomicBool::new(true),
        events: Mutex::default(),
        first_source: baseline[0].1["name"].as_str().unwrap().into(),
        gates: Mutex::new([Some(gate_a), Some(gate_b)]),
        started: start,
        finished: finish,
    });
    let first = if mode == "sync" {
        let state = state.clone();
        UserFieldTransform::new(move |value| {
            if !state.enabled.load(Ordering::Relaxed) {
                return Ok(value);
            }
            let text = state.text(value.as_str().unwrap());
            let sequence = state.event("name", &text);
            Ok(format!("{text}:{sequence}").into())
        })
    } else {
        let (state, mode, store, ids) = (state.clone(), mode.clone(), store.clone(), ids.clone());
        UserFieldTransform::new_async(move |value| {
            let (state, mode, store, ids) =
                (state.clone(), mode.clone(), store.clone(), ids.clone());
            async move {
                if !state.enabled.load(Ordering::Relaxed) {
                    return Ok(value);
                }
                let text = state.text(value.as_str().unwrap());
                let _ = state.event("name", &text);
                if mode == "async" {
                    state.wait(usize::from(text != "A")).await?;
                }
                if mode == "read" && text == "A" {
                    update_name(&store, kind, &ids[1], "B-after").await?;
                    let _ = state.event("display-update", "B-after");
                }
                if mode == "output-error" && text == "A" {
                    return Err(failure());
                }
                Ok(format!("{text}-visible").into())
            }
        })
    };
    let detail = {
        let (state, mode) = (state.clone(), mode.clone());
        UserFieldTransform::new(move |value| {
            if !state.enabled.load(Ordering::Relaxed) {
                return Ok(value);
            }
            let text = state.text(value.as_str().unwrap());
            let sequence = state.event("detail", &text);
            if text == "B-detail" {
                state.finished.send(()).unwrap();
            }
            Ok((if mode == "sync" {
                format!("{text}:{sequence}")
            } else {
                format!("{text}-visible")
            })
            .into())
        })
    };
    let parent = if mode == "parent-async" || mode == "parent-read" {
        let (state, mode, store, ids) = (state.clone(), mode.clone(), store.clone(), ids.clone());
        UserFieldTransform::new_async(move |value| {
            let (state, mode, store, ids) =
                (state.clone(), mode.clone(), store.clone(), ids.clone());
            async move {
                if !state.enabled.load(Ordering::Relaxed) {
                    return Ok(value);
                }
                let text = state.text(value.as_str().unwrap());
                let _ = state.event("member", &text);
                if mode == "parent-async" {
                    state.wait(usize::from(text != "A-member")).await?;
                }
                if mode == "parent-read" && text == "A-member" {
                    update_name(&store, kind, &ids[0], "A-before").await?;
                    let _ = state.event("member-display-update", "A-before");
                }
                Ok(value)
            }
        })
    } else {
        let (state, mode) = (state.clone(), mode.clone());
        UserFieldTransform::new(move |value| {
            if !state.enabled.load(Ordering::Relaxed) {
                return Ok(value);
            }
            let text = state.text(value.as_str().unwrap());
            let _ = state.event("member", &text);
            if mode == "parent-error" && text == "A-member" {
                return Err(failure());
            }
            Ok(value)
        })
    };
    let mut fields = seed_fields();
    let _ = fields
        .member
        .fields_mut()
        .insert("label".into(), field(Some(parent), true));
    let target = if kind == Kind::Organization {
        &mut fields.organization
    } else {
        &mut fields.team
    };
    target.fields_mut().clear();
    let _ = target
        .fields_mut()
        .insert("name".into(), field(Some(first), false));
    let _ = target.fields_mut().insert(
        if kind == Kind::Organization {
            "logo"
        } else {
            "label"
        }
        .into(),
        field(Some(detail), kind == Kind::Team),
    );
    store.configure_organization_fields(fields).unwrap();
    let controller = async {
        if mode == "async" || mode == "parent-async" {
            assert_eq!(
                [started.recv().await.unwrap(), started.recv().await.unwrap()],
                [0, 1]
            );
            let _ = state.event("controller", "both-started");
            release_b.send(()).unwrap();
            finished.recv().await.unwrap();
            let _ = state.event("controller", "release-first");
            release_a.send(()).unwrap();
        }
    };
    let (result, ()) = tokio::join!(rows(&store, kind, &owner), controller);
    let result = match result {
        Ok(rows) => json!({"rows":rows.into_iter().map(|(_, row)|row).collect::<Vec<_>>()}),
        Err(error) => {
            assert!(matches!(error, AuthError::Response(_)));
            let response = error.to_auth_response();
            assert_eq!(response.status, 400);
            assert_eq!(
                response.headers.get("x-ordinary-error").map(String::as_str),
                Some("original")
            );
            let body: Value = serde_json::from_slice(&response.body.bytes().unwrap()).unwrap();
            json!({"error":{"status":"BAD_REQUEST","code":body["code"],"message":body["message"]}})
        }
    };
    assert_eq!(result, fixture["result"], "{fixture}");
    let events = state.events.lock().unwrap().clone();
    if mode == "read" || mode == "parent-read" {
        assert_nested_phases(&events, &fixture["events"], &mode);
    } else {
        assert_eq!(json!(events), fixture["events"], "{fixture}");
    }
    state.enabled.store(false, Ordering::Relaxed);
    let mut stored = rows(&store, kind, &owner)
        .await
        .unwrap()
        .into_iter()
        .map(
            |(_, row)| json!({"name":state.text(row["name"].as_str().unwrap()),"detail":state.text(row["detail"].as_str().unwrap())}),
        )
        .collect::<Vec<_>>();
    stored.sort_by_key(|row| row["name"].as_str().unwrap().to_owned());
    assert_eq!(json!(stored), fixture["stored"]);
}

fn assert_nested_phases(events: &[Value], expected: &Value, mode: &str) {
    // Immediately ready nested futures have no JavaScript microtask boundary.
    // Preserve every callback and each row's order, plus the actual read/write dependency.
    let sorted = |events: &[Value]| {
        let mut values = events.iter().map(Value::to_string).collect::<Vec<_>>();
        values.sort();
        values
    };
    assert_eq!(sorted(events), sorted(expected.as_array().unwrap()));
    for name in ["A", "B", "A-before", "B-after"] {
        for index in events
            .iter()
            .enumerate()
            .filter(|(_, event)| **event == json!(["name", name]))
            .map(|(index, _)| index)
        {
            let detail = if name.starts_with('A') {
                "A-detail"
            } else {
                "B-detail"
            };
            assert!(
                events[index + 1..]
                    .iter()
                    .any(|event| event == &json!(["detail", detail]))
            );
        }
    }
    let at = |field: &str, value: &str| {
        events
            .iter()
            .position(|event| event == &json!([field, value]))
            .unwrap()
    };
    if mode == "read" {
        assert!(at("name", "B-after") < at("display-update", "B-after"));
        assert!(at("display-update", "B-after") < at("detail", "A-detail"));
    } else {
        assert!(at("member", "A-member") < at("member-display-update", "A-before"));
        let names = events
            .iter()
            .enumerate()
            .filter(|(_, event)| **event == json!(["name", "A-before"]))
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        assert_eq!(names.len(), 2);
        assert!(
            names[0] < at("member-display-update", "A-before")
                && at("member-display-update", "A-before") < names[1]
        );
    }
}

#[tokio::test]
async fn memory_join_continuations_match_pinned_ordinary_contracts() {
    let fixtures: Value = serde_json::from_str(include_str!(
        "fixtures/organization-join-continuation-1.7.6.json"
    ))
    .unwrap();
    for fixture in fixtures["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["backend"] == "memory")
    {
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            check_case(EphemeralStore::new(AuthConfig::default().into()), fixture),
        )
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn sqlite_join_continuations_match_pinned_ordinary_contracts() {
    let fixtures: Value = serde_json::from_str(include_str!(
        "fixtures/organization-join-continuation-1.7.6.json"
    ))
    .unwrap();
    for fixture in fixtures["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["backend"] == "sqlite")
    {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrator::run_migrations(&db).await.unwrap();
        let schema = Schema::new(db.get_database_backend());
        for statement in [
            schema.create_table_from_entity(models::organization::Entity),
            schema.create_table_from_entity(models::member::Entity),
            schema.create_table_from_entity(models::team::Entity),
            schema.create_table_from_entity(models::team_member::Entity),
        ] {
            let _ = db.execute(&statement).await.unwrap();
        }
        let store = SeaOrmStore::<BundledSchema>::new(AuthConfig::default(), db)
            .with_organization_schema::<models::Models>();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            check_case(store, fixture),
        )
        .await
        .unwrap();
    }
}
