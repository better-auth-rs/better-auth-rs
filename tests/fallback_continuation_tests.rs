#![cfg(feature = "seaorm2")]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "The ordinary two-row oracle requires exact fixture shapes and paired completion channels."
)]
#![allow(
    unreachable_pub,
    reason = "SeaORM derives require public fixture entity types"
)]

#[path = "../compat-tests/rust-server/src/organization_fields/models.rs"]
mod models;
#[path = "fallback_continuation_tests/session.rs"]
mod session;

use better_auth_core::{
    AuthConfig, AuthError, AuthResponse, AuthResult, AuthSchema, AuthStore, CreateInvitation,
    CreateOrganization, CreateSession, CreateUser, FieldDate, FieldValue, UpdateOrganization,
    UpdateUser,
    organization_fields::OrganizationFields,
    store::EphemeralStore,
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform},
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, Schema},
    store::{__private_test_support::migrator, entities},
};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::{mpsc, oneshot};

struct AppSchema;
impl AuthSchema for AppSchema {
    type User = entities::user::Model;
    type Session = session::Model;
    type Account = entities::account::Model;
    type Verification = entities::verification::Model;
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Session,
    Invitation,
}

struct State {
    enabled: AtomicBool,
    events: Mutex<Vec<Value>>,
    first_source: Mutex<String>,
    ids: Mutex<Vec<String>>,
    gates: Mutex<[Option<oneshot::Receiver<()>>; 2]>,
    started: mpsc::UnboundedSender<usize>,
    finished: mpsc::UnboundedSender<()>,
}
impl State {
    fn text(&self, value: &FieldValue) -> String {
        let text = value.as_str().unwrap();
        if *self.first_source.lock().unwrap() != "B" {
            return text.into();
        }
        match text {
            "A" => "B",
            "B" => "A",
            "A-detail" => "B-detail",
            "B-detail" => "A-detail",
            "A-parent" => "B-parent",
            "B-parent" => "A-parent",
            "A-marker" => "B-marker",
            "B-marker" => "A-marker",
            _ => text,
        }
        .into()
    }
    fn event(&self, field: &str, value: &str) -> usize {
        let mut events = self.events.lock().unwrap();
        events.push(json!([field, value]));
        events.len()
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

async fn update_name<S: AuthSchema>(
    store: &impl AuthStore<S>,
    kind: Kind,
    id: &str,
    name: &str,
) -> AuthResult<()> {
    if kind == Kind::Session {
        let _ = store
            .update_user(
                id,
                UpdateUser {
                    name: Some(name.to_owned()).into(),
                    ..Default::default()
                },
            )
            .await?;
    } else {
        let _ = store
            .update_organization(
                id,
                UpdateOrganization {
                    name: Some(name.into()),
                    ..Default::default()
                },
            )
            .await?;
    }
    Ok(())
}

fn transform<S: AuthSchema, T: AuthStore<S> + Clone + 'static>(
    state: &Arc<State>,
    slot: &Arc<Mutex<Option<T>>>,
    kind: Kind,
    mode: &str,
    stage: &'static str,
) -> UserFieldTransform {
    let (state, slot, mode) = (state.clone(), slot.clone(), mode.to_owned());
    if (stage == "name" && mode != "sync")
        || (stage == "parent" && matches!(mode.as_str(), "parent-async" | "parent-read"))
    {
        return UserFieldTransform::new_async(move |value| {
            let (state, slot, mode) = (state.clone(), slot.clone(), mode.clone());
            async move {
                if !state.enabled.load(Ordering::Relaxed) {
                    return Ok(value);
                }
                let text = state.text(&value);
                let _ = state.event(stage, &text);
                if (stage == "name" && mode == "async")
                    || (stage == "parent" && mode == "parent-async")
                {
                    state.wait(usize::from(!text.starts_with('A'))).await?;
                }
                if (stage == "name" && mode == "read" && text == "A")
                    || (stage == "parent" && mode == "parent-read" && text == "A-parent")
                {
                    let parent = stage == "parent";
                    let id = state.ids.lock().unwrap()[usize::from(!parent)].clone();
                    let store = slot.lock().unwrap().as_ref().unwrap().clone();
                    let name = if parent { "A-before" } else { "B-after" };
                    update_name(&store, kind, &id, name).await?;
                    let _ = state.event(
                        if parent {
                            "parent-display-update"
                        } else {
                            "display-update"
                        },
                        name,
                    );
                }
                if stage == "name" && mode == "output-error" && text == "A" {
                    return Err(failure());
                }
                Ok(format!("{text}-visible").into())
            }
        });
    }
    UserFieldTransform::new(move |value| {
        if !state.enabled.load(Ordering::Relaxed) {
            return Ok(value);
        }
        let text = state.text(&value);
        let index = state.event(stage, &text);
        if stage == "parent" && mode == "parent-error" && text == "A-parent" {
            return Err(failure());
        }
        if stage == "detail" && text == "B-detail" {
            state.finished.send(()).unwrap();
        }
        Ok(if mode == "sync" {
            format!("{text}:{index}")
        } else {
            format!("{text}-visible")
        }
        .into())
    })
}

fn field(output: UserFieldTransform, alias: bool) -> UserFieldConfig {
    UserFieldConfig {
        required: Some(false),
        field_name: alias.then(|| "storedLabel".into()),
        transform: Some(FieldTransforms {
            output: Some(output),
            ..Default::default()
        }),
        ..Default::default()
    }
}

async fn rows<S: AuthSchema>(
    store: &impl AuthStore<S>,
    kind: Kind,
    tokens: &[String],
) -> AuthResult<Vec<(String, Value)>> {
    if kind == Kind::Session {
        let mut result = Vec::new();
        for (session, snapshot) in store.get_session_snapshots(tokens, false).await? {
            let user = match snapshot {
                Some(data) => data.into_typed()?.unwrap().user,
                None => store.get_user_by_id_field(&session.user_id).await?.unwrap(),
            };
            assert_eq!(session.user_id, user.id);
            result.push((user.id.typed()?.clone(), json!({"parent":session.additional_fields["label"].json()?, "parentDetail":session.additional_fields["marker"].json()?, "name":user.name, "detail":user.image})));
        }
        Ok(result)
    } else {
        store.list_user_invitations("GUEST@ordinary-fallback.test").await?.into_iter().map(|row| {
            let child = row.organization.unwrap();
            assert_eq!(row.invitation.organization_id, child.id);
            Ok((child.id.typed().unwrap().clone(), json!({"parent":row.invitation.additional_fields["label"].json()?, "parentDetail":row.invitation.additional_fields["marker"].json()?, "name":child.name})))
        }).collect()
    }
}

async fn check_case<S: AuthSchema, T: AuthStore<S> + Clone + 'static>(
    factory: impl FnOnce(AuthConfig) -> T,
    fixture: &Value,
) {
    let kind = if fixture["kind"] == "session" {
        Kind::Session
    } else {
        Kind::Invitation
    };
    let mode = fixture["mode"].as_str().unwrap();
    let (start, mut started) = mpsc::unbounded_channel();
    let (finish, mut finished) = mpsc::unbounded_channel();
    let (release_a, gate_a) = oneshot::channel();
    let (release_b, gate_b) = oneshot::channel();
    let state = Arc::new(State {
        enabled: AtomicBool::new(false),
        events: Mutex::default(),
        first_source: Mutex::default(),
        ids: Mutex::default(),
        gates: Mutex::new([Some(gate_a), Some(gate_b)]),
        started: start,
        finished: finish,
    });
    let slot = Arc::new(Mutex::new(None));
    let make = |stage| transform::<S, T>(&state, &slot, kind, mode, stage);
    let mut config = AuthConfig::default();
    config.session.fields_mut().extend([
        ("label".into(), field(make("parent"), true)),
        ("marker".into(), field(make("parent-detail"), false)),
    ]);
    let mut organization = OrganizationFields::default();
    organization.invitation.fields_mut().extend([
        ("label".into(), field(make("parent"), true)),
        ("marker".into(), field(make("parent-detail"), false)),
    ]);
    if kind == Kind::Session {
        config.user.fields_mut().extend([
            ("name".into(), field(make("name"), false)),
            ("image".into(), field(make("detail"), false)),
        ]);
    } else {
        organization.organization.fields_mut().extend([
            ("name".into(), field(make("name"), false)),
            ("logo".into(), field(make("detail"), false)),
        ]);
    }
    let store = factory(config);
    store.configure_organization_fields(organization).unwrap();
    *slot.lock().unwrap() = Some(store.clone());
    let mut tokens = Vec::new();
    let mut inviter = None;
    for label in ["A", "B"] {
        let mut user = CreateUser::new()
            .with_name(label)
            .with_email(format!("{label}@ordinary-fallback.test"));
        user.image = Some(format!("{label}-detail")).into();
        let user = store.create_user(user).await.unwrap();
        let owner = inviter
            .get_or_insert(user.id.typed().unwrap().clone())
            .clone();
        let mut organization = CreateOrganization::new(label, format!("ordinary-{label}"));
        organization.logo = Some(format!("{label}-detail")).into();
        let organization = store.create_organization(organization).await.unwrap();
        let additional_fields = [
            ("label".into(), format!("{label}-parent").into()),
            ("marker".into(), format!("{label}-marker").into()),
        ]
        .into_iter()
        .collect();
        let expires_at = FieldDate::from(
            "2099-01-01T00:00:00Z"
                .parse::<chrono::DateTime<chrono::Utc>>()
                .unwrap(),
        );
        let session = store
            .create_session(CreateSession {
                inherited_fields: Default::default(),
                user_id: user.id,
                expires_at: expires_at.clone(),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
                additional_fields,
            })
            .await
            .unwrap();
        tokens.push(session.token.typed().unwrap().clone());
        let mut invitation = CreateInvitation::new(
            organization.id.typed().unwrap(),
            "guest@ordinary-fallback.test",
            "member",
            owner,
            expires_at,
        );
        invitation.additional_fields = [
            ("label".into(), format!("{label}-parent").into()),
            ("marker".into(), format!("{label}-marker").into()),
        ]
        .into_iter()
        .collect();
        let _ = store.create_invitation(invitation).await.unwrap();
    }
    tokens.reverse();
    let baseline = rows(&store, kind, &tokens).await.unwrap();
    assert_eq!(baseline.len(), 2);
    // Use actual adapter row order; callbacks change only display fields, never stored association IDs.
    *state.first_source.lock().unwrap() = baseline[0].1["name"].as_str().unwrap().into();
    *state.ids.lock().unwrap() = baseline.into_iter().map(|(id, _)| id).collect();
    state.enabled.store(true, Ordering::Relaxed);
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
    let (result, ()) = tokio::join!(rows(&store, kind, &tokens), controller);
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
            json!({"error":{"status":"BAD_REQUEST", "code":body["code"], "message":body["message"]}})
        }
    };
    assert_eq!(result, fixture["result"], "{fixture}");
    let events = state.events.lock().unwrap().clone();
    if mode == "read" || mode == "parent-read" {
        assert_nested_phases(&events, &fixture["events"], mode);
    } else {
        assert_eq!(json!(events), fixture["events"], "{fixture}");
    }
    state.enabled.store(false, Ordering::Relaxed);
    let mut stored = Vec::new();
    let ids = state.ids.lock().unwrap().clone();
    for id in ids {
        let (name, detail) = if kind == Kind::Session {
            let row = store.get_user_by_id(&id).await.unwrap().unwrap();
            (row.name.field_value(), row.image.field_value())
        } else {
            let row = store.get_organization_by_id(&id).await.unwrap().unwrap();
            (row.name.field_value(), row.logo.field_value())
        };
        stored.push(json!({"name":state.text(&name), "detail":state.text(&detail)}));
    }
    stored.sort_by_key(|row| row["name"].as_str().unwrap().to_owned());
    assert_eq!(json!(stored), fixture["stored"]);
    *slot.lock().unwrap() = None;
}

fn assert_nested_phases(events: &[Value], expected: &Value, mode: &str) {
    // Immediately ready Rust futures have no JS microtask boundary. Keep all callbacks and their data dependencies.
    let sorted = |events: &[Value]| {
        let mut values = events.iter().map(Value::to_string).collect::<Vec<_>>();
        values.sort();
        values
    };
    assert_eq!(sorted(events), sorted(expected.as_array().unwrap()));
    let at = |field: &str, value: &str| {
        events
            .iter()
            .position(|event| event == &json!([field, value]))
            .unwrap()
    };
    for row in ["A", "B"] {
        assert!(
            at("parent", &format!("{row}-parent")) < at("parent-detail", &format!("{row}-marker"))
        );
    }
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
    if mode == "read" {
        assert!(at("name", "B-after") < at("display-update", "B-after"));
        assert!(at("display-update", "B-after") < at("detail", "A-detail"));
    } else {
        let names: Vec<_> = events
            .iter()
            .enumerate()
            .filter(|(_, event)| **event == json!(["name", "A-before"]))
            .map(|(index, _)| index)
            .collect();
        assert_eq!(names.len(), 2);
        assert!(names[0] < at("parent-display-update", "A-before"));
        assert!(at("parent-display-update", "A-before") < at("parent-detail", "A-marker"));
        assert!(at("parent-detail", "A-marker") < names[1]);
    }
}

fn fixtures(backend: &str) -> Vec<Value> {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/fallback-continuation-1.7.6.json")).unwrap();
    fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["backend"] == backend)
        .cloned()
        .collect()
}

#[tokio::test]
async fn memory_fallback_continuations_match_pinned_ordinary_contracts() {
    for fixture in fixtures("memory") {
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            check_case(|config| EphemeralStore::new(config.into()), &fixture),
        )
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn sqlite_fallback_continuations_match_pinned_ordinary_contracts() {
    for fixture in fixtures("sqlite") {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrator::run_migrations(&db).await.unwrap();
        let schema = Schema::new(db.get_database_backend());
        for statement in [
            schema.create_table_from_entity(session::Entity),
            schema.create_table_from_entity(models::organization::Entity),
            schema.create_table_from_entity(models::invitation::Entity),
        ] {
            let _ = db.execute(&statement).await.unwrap();
        }
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            check_case(
                |config| {
                    SeaOrmStore::<AppSchema>::new(config, db)
                        .with_organization_schema::<models::Models>()
                },
                &fixture,
            ),
        )
        .await
        .unwrap();
    }
}
