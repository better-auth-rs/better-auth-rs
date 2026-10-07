#![cfg(feature = "seaorm2")]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "The pinned ordinary-data fixture requires exact shapes and controlled callback channels."
)]
#![allow(
    unreachable_pub,
    reason = "SeaORM fixture derives require public entity types"
)]

#[path = "../compat-tests/rust-server/src/organization_fields/models.rs"]
mod models;
#[path = "organization_native_join_tests/postgres.rs"]
mod postgres;
#[path = "organization_native_join_tests/support.rs"]
mod support;

use better_auth_core::{
    AuthConfig, AuthError, AuthResponse, AuthResult, AuthSchema, AuthStore, CreateInvitation,
    CreateOrganization, CreateTeam, CreateUser, Member, UpdateOrganization, UpdateTeam, UpdateUser,
    organization_fields::OrganizationFields,
    store::{EphemeralStore, MemberUser, OrganizationDetailsQuery, OrganizationKey},
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform},
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, DatabaseConnection, Schema},
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicBool, Ordering},
};
use support::State;
use tokio::sync::{mpsc, oneshot};

fn display_user(row: &better_auth_core::MemberUserView) -> Value {
    json!({"name":row.name,"image":row.image})
}
fn display_member(row: &MemberUser) -> Value {
    json!({"label":row.member.additional_fields["label"].json().unwrap(), "detail":row.member.additional_fields["detail"].json().unwrap(), "user":display_user(&row.user)})
}
fn display_organization(row: &better_auth_core::Organization) -> Value {
    json!({"name":row.name,"logo":row.logo})
}
fn display_team(row: &better_auth_core::Team) -> Value {
    json!({"name":row.name,"label":row.additional_fields["label"].json().unwrap()})
}
fn display_invitation(row: &better_auth_core::Invitation) -> Value {
    json!({"label":row.additional_fields["label"].json().unwrap(),"detail":row.additional_fields["detail"].json().unwrap()})
}
async fn query<S: AuthSchema>(store: &impl AuthStore<S>, fixture: &Value) -> AuthResult<Value> {
    Ok(match fixture["path"].as_str().unwrap() {
        "member-org" => display_member(&store.get_member_with_user("organization-a", "user-a").await?.unwrap()),
        "member-id" => display_member(&store.get_member_by_id_with_user("member-a").await?.unwrap()),
        "organizations" => json!(store.list_user_organizations("user-a").await?.iter().map(display_organization).collect::<Vec<_>>()),
        "teams" => json!(store.list_user_teams("user-a").await?.iter().map(display_team).collect::<Vec<_>>()),
        "invitations" => json!(store.list_user_invitations("RECIPIENT@ordinary-native-org.test").await?.into_iter().map(|row| {
            json!({"label":row.invitation.additional_fields["label"].json().unwrap(),"detail":row.invitation.additional_fields["detail"].json().unwrap(),"organizationName":row.organization.unwrap().name})
        }).collect::<Vec<_>>()),
        "full" => {
            let row = store.get_organization_details(OrganizationDetailsQuery {
                organization: OrganizationKey::Id("organization-a"), members_limit: fixture["membersLimit"].as_f64(),
                users_limit: 100.0, include_teams: fixture["includeTeams"].as_bool().unwrap_or(true),
            }).await?.unwrap();
            json!({"name":row.organization.name,"logo":row.organization.logo,
                "invitations":row.invitations.iter().map(display_invitation).collect::<Vec<_>>(),
                "members":row.members.iter().map(display_member).collect::<Vec<_>>(),
                "teams":row.teams.map(|rows| rows.iter().map(display_team).collect::<Vec<_>>())})
        }
        #[expect(
            clippy::unreachable,
            reason = "Every pinned fixture path must have an aggregate consumer."
        )]
        path => unreachable!("Unconsumed adapter aggregate: {path}"),
    })
}
async fn stored<S: AuthSchema>(store: &impl AuthStore<S>) -> Value {
    let mut organizations = Vec::new();
    let mut teams = Vec::new();
    let mut users = Vec::new();
    for suffix in ["a", "b"] {
        organizations.push(display_organization(
            &store
                .get_organization_by_id(&format!("organization-{suffix}"))
                .await
                .unwrap()
                .unwrap(),
        ));
        teams.push(display_team(
            &store
                .get_team(&format!("team-{suffix}"))
                .await
                .unwrap()
                .unwrap(),
        ));
        users.push(display_user(&better_auth_core::MemberUserView::from_user(
            &store
                .get_user_by_id(&format!("user-{suffix}"))
                .await
                .unwrap()
                .unwrap(),
        )));
    }
    let mut invitations = Vec::new();
    for suffix in ["a", "a-other", "b"] {
        invitations.push(display_invitation(
            &store
                .get_invitation_by_id(&format!("invitation-{suffix}"))
                .await
                .unwrap()
                .unwrap(),
        ));
    }
    json!({"organizations":organizations,"teams":teams,"invitations":invitations,"users":users})
}

fn assert_nested_phases(events: &[Value], fixture: &Value) {
    // Ready Rust futures have no JavaScript microtask boundary. Keep every callback and required dependency.
    let sorted = |rows: &[Value]| {
        let mut rows = rows.iter().map(Value::to_string).collect::<Vec<_>>();
        rows.sort();
        rows
    };
    assert_eq!(
        sorted(events),
        sorted(fixture["events"].as_array().unwrap()),
        "{fixture}"
    );
    let write = events
        .iter()
        .position(|row| row[0] == "display-write")
        .unwrap();
    let changed = &events[write];
    let model = changed[1].as_str().unwrap();
    let (field, value) = changed[2].as_object().unwrap().iter().next().unwrap();
    let changed_event = json!([format!("{model}.{field}"), value]);
    assert!(
        events[..write].contains(&changed_event),
        "The nested update completes its output before display-write"
    );
    for (first, second) in [
        ("member.label", "member.detail"),
        ("invitation.label", "invitation.detail"),
        ("organization.name", "organization.logo"),
        ("team.name", "team.label"),
        ("user.name", "user.image"),
    ] {
        for (index, event) in events.iter().enumerate().filter(|(_, row)| row[0] == first) {
            let prefix = event[1].as_str().unwrap();
            let suffix = second.split('.').next_back().unwrap();
            let unchanged = json!(format!("{prefix}-{suffix}"));
            let updated = json!(format!("{prefix}-{suffix}-after"));
            assert!(
                events[index + 1..]
                    .iter()
                    .any(|row| row[0] == second && (row[1] == unchanged || row[1] == updated)),
                "{events:?}"
            );
        }
    }
    let target = match (
        fixture["path"].as_str().unwrap(),
        fixture["mode"].as_str().unwrap(),
    ) {
        ("member-org", _) => json!(["member.label", "M-A"]),
        ("full", "parent-read") => json!(["organization.name", "O-A"]),
        ("full", _) => json!(["invitation.label", "I-A"]),
        ("organizations", _) => json!(["member.label", "M-A"]),
        ("invitations", _) => json!(["invitation.label", "I-A"]),
        ("teams", _) => json!(["team.name", "T-A"]),
        #[expect(
            clippy::unreachable,
            reason = "Every pinned nested-read fixture must have an expected callback target."
        )]
        _ => unreachable!(),
    };
    assert!(events[..write].contains(&target));
}

async fn check_case<S: AuthSchema, T: AuthStore<S> + 'static>(
    fixture: &Value,
    create: impl FnOnce(AuthConfig) -> T,
) {
    let path = fixture["path"].as_str().unwrap();
    let mode = fixture["mode"].as_str().unwrap();
    let (start, mut started) = mpsc::unbounded_channel();
    let (finish, mut finished) = mpsc::unbounded_channel();
    let (release, gate) = oneshot::channel();
    let state = Arc::new(State {
        unconfigured_logo: fixture["unconfiguredLogo"].as_bool().unwrap_or(false),
        enabled: AtomicBool::new(false),
        changed: AtomicBool::new(false),
        events: Mutex::default(),
        gate: Mutex::new(Some(gate)),
        started: start,
        finished: finish,
        store: Mutex::new(Weak::new()),
    });
    let mut config = AuthConfig::default();
    config.advanced.database.joins = fixture["joins"].as_bool();
    config.advanced.database.default_find_many_limit = fixture["limit"].as_f64();
    config.user.fields_mut().extend([
        (
            "name".into(),
            support::field::<S, T>(&state, path, mode, "user.name"),
        ),
        (
            "image".into(),
            support::field::<S, T>(&state, path, mode, "user.image"),
        ),
    ]);
    let store = Arc::new(create(config));
    *state.store.lock().unwrap() = Arc::downgrade(&store);
    store
        .configure_organization_fields(support::organization_fields::<S, T>(&state, path, mode))
        .unwrap();
    support::seed::<S>(&*store).await;
    state.enabled.store(true, Ordering::Relaxed);
    let controller = async {
        if matches!(mode, "parent-wait" | "child-wait") {
            started.recv().await.unwrap();
            let is_list = matches!(path, "organizations" | "invitations" | "teams");
            if is_list {
                finished.recv().await.unwrap();
            }
            state.events.lock().unwrap().push(json!([
                "controller",
                if is_list {
                    "peer-finished"
                } else {
                    "first-child-blocked"
                }
            ]));
            release.send(()).unwrap();
        }
    };
    let (result, ()) = tokio::join!(query::<S>(&*store, fixture), controller);
    match result {
        Ok(result) => {
            assert_eq!(result, fixture["result"], "{fixture}");
            assert_eq!(fixture["originalError"], false);
        }
        Err(error) => {
            assert!(matches!(error, AuthError::Response(_)), "{error:?}");
            let response = error.to_auth_response();
            assert_eq!(response.status, 400);
            assert_eq!(
                response.headers.get("x-ordinary-error").map(String::as_str),
                Some("original")
            );
            let body: Value = serde_json::from_slice(&response.body.bytes().unwrap()).unwrap();
            assert_eq!(
                json!({"status":"BAD_REQUEST","code":body["code"],"message":body["message"]}),
                fixture["error"]
            );
            assert_eq!(fixture["originalError"], true);
        }
    }
    let events = state.events.lock().unwrap().clone();
    if state.unconfigured_logo {
        assert_unconfigured_phases(&events, fixture);
    } else if mode.ends_with("-read") {
        assert_nested_phases(&events, fixture);
    } else {
        assert_eq!(json!(events), fixture["events"], "{fixture}");
    }
    state.enabled.store(false, Ordering::Relaxed);
    assert_eq!(stored::<S>(&*store).await, fixture["stored"], "{fixture}");
}
async fn create_tables(db: &DatabaseConnection) {
    migrator::run_migrations(db).await.unwrap();
    let schema = Schema::new(db.get_database_backend());
    for statement in [
        schema.create_table_from_entity(models::organization::Entity),
        schema.create_table_from_entity(models::member::Entity),
        schema.create_table_from_entity(models::invitation::Entity),
        schema.create_table_from_entity(models::team::Entity),
        schema.create_table_from_entity(models::team_member::Entity),
        schema.create_table_from_entity(models::organization_role::Entity),
    ] {
        let _ = db.execute(&statement).await.unwrap();
    }
}
async fn database() -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    create_tables(&db).await;
    db
}
#[tokio::test]
async fn memory_organization_joins_match_pinned_display_callbacks_and_live_references() {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/organization-native-joins-1.7.6.json"
    ))
    .unwrap();
    for row in fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["backend"] == "memory" && row["path"] != "team-members")
    {
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            check_case::<better_auth_core::store::StatelessSchema, _>(row, |config| {
                EphemeralStore::new(config.into())
            }),
        )
        .await
        .unwrap();
    }
}
#[tokio::test]
async fn sqlite_organization_joins_match_pinned_display_callbacks_and_statement_snapshots() {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/organization-native-joins-1.7.6.json"
    ))
    .unwrap();
    for row in fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["backend"] == "sqlite" && row["path"] != "team-members")
    {
        let db = database().await;
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            check_case::<BundledSchema, _>(row, |config| {
                SeaOrmStore::<BundledSchema>::new(config, db)
                    .with_organization_schema::<models::Models>()
            }),
        )
        .await
        .unwrap();
    }
}

fn assert_unconfigured_phases(events: &[Value], fixture: &Value) {
    let sorted = |rows: &[Value]| {
        let mut rows = rows.iter().map(Value::to_string).collect::<Vec<_>>();
        rows.sort();
        rows
    };
    assert_eq!(
        sorted(events),
        sorted(fixture["events"].as_array().unwrap())
    );
    let write = events
        .iter()
        .position(|event| event[0] == "display-write")
        .unwrap();
    let names = events
        .iter()
        .enumerate()
        .filter(|(_, event)| **event == json!(["organization.name", "O-A"]))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    assert_eq!(names.len(), 2);
    assert!(names[0] < names[1] && names[1] < write);
    for source in ["A", "B"] {
        let label = events
            .iter()
            .position(|event| *event == json!(["member.label", format!("M-{source}")]))
            .unwrap();
        let detail = events
            .iter()
            .position(|event| *event == json!(["member.detail", format!("M-{source}-detail")]))
            .unwrap();
        assert!(label < detail && detail < names[0]);
    }
}

#[tokio::test]
async fn unconfigured_organization_logo_is_read_in_its_native_field_phase() {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/organization-native-joins-unconfigured-1.7.6.json"
    ))
    .unwrap();
    for row in fixture["cases"].as_array().unwrap() {
        if row["backend"] == "memory" {
            check_case::<better_auth_core::store::StatelessSchema, _>(row, |config| {
                EphemeralStore::new(config.into())
            })
            .await;
        } else {
            let db = database().await;
            check_case::<BundledSchema, _>(row, |config| {
                SeaOrmStore::<BundledSchema>::new(config, db)
                    .with_organization_schema::<models::Models>()
            })
            .await;
        }
    }
}
