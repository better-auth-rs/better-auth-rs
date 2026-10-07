#![cfg(feature = "seaorm2")]
#![allow(
    unreachable_pub,
    reason = "SeaORM entity derives require public generated model types"
)]

#[path = "../compat-tests/rust-server/src/organization_fields/models.rs"]
mod models;

use better_auth_core::{
    AuthConfig, AuthError, AuthResult, AuthSchema, AuthStore, CreateInvitation, CreateMember,
    CreateOrganization, CreateOrganizationRole, CreateTeam, CreateUser, FieldMap,
    FieldValue as Value,
    organization_fields::OrganizationFields,
    store::EphemeralStore,
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform},
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Schema, Statement},
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};

#[derive(Clone, Copy, Debug)]
enum Model {
    Organization,
    Member,
    Invitation,
    Team,
    Role,
}

const MODELS: [Model; 5] = [
    Model::Organization,
    Model::Member,
    Model::Invitation,
    Model::Team,
    Model::Role,
];

fn fields(
    model: Model,
    input: Option<UserFieldTransform>,
    output: Option<UserFieldTransform>,
) -> OrganizationFields {
    let mut fields = OrganizationFields::default();
    let target = match model {
        Model::Organization => &mut fields.organization,
        Model::Member => &mut fields.member,
        Model::Invitation => &mut fields.invitation,
        Model::Team => &mut fields.team,
        Model::Role => &mut fields.organization_role,
    };
    let _ = target.fields_mut().insert(
        "label".into(),
        UserFieldConfig {
            field_name: Some("stored_label".into()),
            required: Some(false),
            transform: Some(FieldTransforms { input, output }),
            ..Default::default()
        },
    );
    fields
}

struct Call {
    phase: &'static str,
    value: Value,
    reply: oneshot::Sender<AuthResult<Value>>,
}

struct Gate {
    enabled: Arc<AtomicBool>,
    sender: mpsc::UnboundedSender<Call>,
}

impl Gate {
    fn new() -> (Self, mpsc::UnboundedReceiver<Call>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        (
            Self {
                enabled: Arc::new(AtomicBool::new(true)),
                sender,
            },
            receiver,
        )
    }

    fn callback(&self, phase: &'static str) -> UserFieldTransform {
        let enabled = self.enabled.clone();
        let sender = self.sender.clone();
        UserFieldTransform::new_async(move |value| {
            let enabled = enabled.clone();
            let sender = sender.clone();
            async move {
                if !enabled.load(Ordering::Relaxed) {
                    return Ok(value);
                }
                let (reply, result) = oneshot::channel();
                sender
                    .send(Call {
                        phase,
                        value,
                        reply,
                    })
                    .map_err(|_| AuthError::internal("Callback controller closed"))?;
                result
                    .await
                    .map_err(|_| AuthError::internal("Callback answer missing"))?
            }
        })
    }
}

async fn sqlite() -> (
    SeaOrmStore<BundledSchema, models::Models>,
    DatabaseConnection,
) {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&db).await.unwrap();
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
    let store = SeaOrmStore::<BundledSchema>::new(AuthConfig::default(), db.clone())
        .with_organization_schema::<models::Models>();
    (store, db)
}

async fn seed<S: AuthSchema>(store: &impl AuthStore<S>) -> (String, String) {
    let user = store
        .create_user(
            CreateUser::new()
                .with_name("Fixture User")
                .with_email("fixture@organization-async.test"),
        )
        .await
        .unwrap();
    let org = store
        .create_organization(CreateOrganization::new("Fixture Organization", "fixture"))
        .await
        .unwrap();
    (
        org.id.typed().unwrap().clone(),
        user.id.typed().unwrap().clone(),
    )
}

async fn create<S: AuthSchema>(
    store: &impl AuthStore<S>,
    model: Model,
    org: &str,
    user: &str,
) -> AuthResult<FieldMap> {
    let additional_fields = [("label".into(), Value::from("source"))]
        .into_iter()
        .collect();
    match model {
        Model::Organization => {
            let mut input = CreateOrganization::new("Organization", "organization");
            input.additional_fields = additional_fields;
            store
                .create_organization(input)
                .await
                .map(|row| row.additional_fields)
        }
        Model::Member => {
            let mut input = CreateMember::new(org, user, "member");
            input.additional_fields = additional_fields;
            store
                .create_member(input)
                .await
                .map(|row| row.additional_fields)
        }
        Model::Invitation => {
            let mut input = CreateInvitation::new(
                org,
                "invitee@organization-async.test",
                "member",
                user,
                (chrono::Utc::now() + chrono::Duration::hours(1)).into(),
            );
            input.additional_fields = additional_fields;
            store
                .create_invitation(input)
                .await
                .map(|row| row.additional_fields)
        }
        Model::Team => store
            .create_team(CreateTeam {
                name: "Fixture Team".into(),
                organization_id: org.into(),
                additional_fields,
                ..Default::default()
            })
            .await
            .map(|row| row.additional_fields),
        Model::Role => store
            .create_organization_role(CreateOrganizationRole {
                organization_id: org.into(),
                role: "reviewer".into(),
                permission: Value::from(FieldMap::from([(
                    "organization".into(),
                    Value::from(vec![Value::from("update")]),
                )])),
                additional_fields,
            })
            .await
            .map(|row| row.additional_fields),
    }
}

async fn read<S: AuthSchema>(
    store: &impl AuthStore<S>,
    model: Model,
    org: &str,
    user: &str,
) -> Option<FieldMap> {
    match model {
        Model::Organization => store
            .get_organization_by_slug("organization")
            .await
            .unwrap()
            .map(|row| row.additional_fields),
        Model::Member => store
            .get_member(org, user)
            .await
            .unwrap()
            .map(|row| row.additional_fields),
        Model::Invitation => store
            .get_pending_invitation(org, "invitee@organization-async.test")
            .await
            .unwrap()
            .map(|row| row.additional_fields),
        Model::Team => store
            .list_organization_teams(org)
            .await
            .unwrap()
            .into_iter()
            .next()
            .map(|row| row.additional_fields),
        Model::Role => store
            .list_organization_roles(org)
            .await
            .unwrap()
            .into_iter()
            .next()
            .map(|row| row.additional_fields),
    }
}

async fn check_writes<S: AuthSchema>(store: &impl AuthStore<S>) {
    let (org, user) = seed(store).await;
    for model in MODELS {
        let (gate, mut receiver) = Gate::new();
        store
            .configure_organization_fields(fields(
                model,
                Some(gate.callback("input")),
                Some(gate.callback("output")),
            ))
            .unwrap();
        let controller = async {
            let input = receiver.recv().await.unwrap();
            assert_eq!(
                (input.phase, input.value),
                ("input", Value::from("source")),
                "{model:?}"
            );
            gate.enabled.store(false, Ordering::Relaxed);
            assert!(
                read(store, model, &org, &user).await.is_none(),
                "{model:?}: input must precede storage"
            );
            gate.enabled.store(true, Ordering::Relaxed);
            input.reply.send(Ok(Value::from("stored"))).unwrap();
            let output = receiver.recv().await.unwrap();
            assert_eq!(
                (output.phase, output.value),
                ("output", Value::from("stored")),
                "{model:?}"
            );
            // The pending callback retains its reply channel while reads use identity projection.
            gate.enabled.store(false, Ordering::Relaxed);
            let raw = read(store, model, &org, &user).await.unwrap();
            assert_eq!(
                raw["label"],
                Value::from("stored"),
                "{model:?}: output must follow storage"
            );
            assert!(!raw.contains_key("stored_label"));
            output.reply.send(Ok(Value::from("visible"))).unwrap();
        };
        let (result, ()) = tokio::join!(create(store, model, &org, &user), controller);
        let returned = result.unwrap();
        assert_eq!(returned["label"], Value::from("visible"), "{model:?}");
        assert!(!returned.contains_key("stored_label"));
    }
}

async fn check_failures<S: AuthSchema>(store: &impl AuthStore<S>) {
    let (org, user) = seed(store).await;
    for phase in ["input", "output"] {
        let (gate, mut receiver) = Gate::new();
        store
            .configure_organization_fields(fields(
                Model::Team,
                Some(gate.callback("input")),
                Some(gate.callback("output")),
            ))
            .unwrap();
        let message = format!("{phase} application failure");
        let controller = async {
            let input = receiver.recv().await.unwrap();
            assert_eq!((input.phase, input.value), ("input", Value::from("source")));
            if phase == "input" {
                input
                    .reply
                    .send(Err(AuthError::internal(&message)))
                    .unwrap();
            } else {
                input.reply.send(Ok(Value::from("stored"))).unwrap();
                let output = receiver.recv().await.unwrap();
                assert_eq!(
                    (output.phase, output.value),
                    ("output", Value::from("stored"))
                );
                output
                    .reply
                    .send(Err(AuthError::internal(&message)))
                    .unwrap();
            }
        };
        let (result, ()) = tokio::join!(create(store, Model::Team, &org, &user), controller);
        assert!(matches!(result, Err(AuthError::Internal(actual)) if actual == message));
        gate.enabled.store(false, Ordering::Relaxed);
        let rows = store.list_organization_teams(&org).await.unwrap();
        assert_eq!(rows.len(), usize::from(phase == "output"));
        if phase == "output" {
            assert_eq!(rows[0].additional_fields["label"], Value::from("stored"));
        }
    }
}

async fn check_batch<S: AuthSchema>(store: &impl AuthStore<S>) {
    let (org, _) = seed(store).await;
    store
        .configure_organization_fields(fields(Model::Team, None, None))
        .unwrap();
    for name in ["A", "B"] {
        let _ = store
            .create_team(CreateTeam {
                name: name.into(),
                organization_id: org.clone().into(),
                additional_fields: [("label".into(), Value::from(name))].into_iter().collect(),
                ..Default::default()
            })
            .await
            .unwrap();
    }
    let baseline = store.list_organization_teams(&org).await.unwrap();
    let expected = baseline
        .iter()
        .map(|row| row.additional_fields["label"].clone())
        .collect::<Vec<_>>();
    let (sender, mut receiver) = mpsc::unbounded_channel();
    let (finished, mut completions) = mpsc::unbounded_channel();
    let output = UserFieldTransform::new_async(move |value| {
        let sender = sender.clone();
        let finished = finished.clone();
        async move {
            let (reply, result) = oneshot::channel();
            sender
                .send(Call {
                    phase: "output",
                    value: value.clone(),
                    reply,
                })
                .map_err(|_| AuthError::internal("Batch controller closed"))?;
            let result = result
                .await
                .map_err(|_| AuthError::internal("Batch answer missing"))??;
            finished
                .send(value)
                .map_err(|_| AuthError::internal("Batch observer closed"))?;
            Ok(result)
        }
    });
    store
        .configure_organization_fields(fields(Model::Team, None, Some(output)))
        .unwrap();
    let controller = async {
        let first = receiver.recv().await.unwrap();
        let second = receiver.recv().await.unwrap();
        assert_eq!(
            [first.value, second.value],
            [expected[0].clone(), expected[1].clone()]
        );
        second
            .reply
            .send(Ok(Value::from(format!(
                "{}:visible",
                expected[1].as_str().unwrap()
            ))))
            .unwrap();
        assert_eq!(completions.recv().await.unwrap(), expected[1].clone());
        first
            .reply
            .send(Ok(Value::from(format!(
                "{}:visible",
                expected[0].as_str().unwrap()
            ))))
            .unwrap();
        assert_eq!(completions.recv().await.unwrap(), expected[0].clone());
    };
    let (result, ()) = tokio::join!(store.list_organization_teams(&org), controller);
    let rows = result.unwrap();
    assert_eq!(
        rows.iter().map(|row| &row.name).collect::<Vec<_>>(),
        baseline.iter().map(|row| &row.name).collect::<Vec<_>>()
    );
    assert_eq!(
        rows.iter()
            .map(|row| row.additional_fields["label"].clone())
            .collect::<Vec<_>>(),
        expected
            .iter()
            .map(|value| Value::from(format!("{}:visible", value.as_str().unwrap())))
            .collect::<Vec<_>>()
    );
    store
        .configure_organization_fields(fields(Model::Team, None, None))
        .unwrap();
    assert_eq!(
        store
            .list_organization_teams(&org)
            .await
            .unwrap()
            .iter()
            .map(|row| row.additional_fields["label"].clone())
            .collect::<Vec<_>>(),
        expected
    );
}

#[tokio::test]
async fn ephemeral_awaits_five_organization_models_with_label_alias() {
    let store = EphemeralStore::new(AuthConfig::default().into());
    tokio::time::timeout(Duration::from_secs(10), check_writes(&store))
        .await
        .unwrap();
}

#[tokio::test]
async fn sqlite_awaits_five_organization_models_with_physical_label_alias() {
    let (store, db) = sqlite().await;
    tokio::time::timeout(Duration::from_secs(10), check_writes(&store))
        .await
        .unwrap();
    for table in [
        "app_organization",
        "app_member",
        "app_invitation",
        "app_team",
        "app_organization_role",
    ] {
        let rows = db
            .query_all_raw(Statement::from_string(
                DbBackend::Sqlite,
                format!("SELECT physical_label FROM {table} WHERE physical_label IS NOT NULL"),
            ))
            .await
            .unwrap();
        assert_eq!(rows.len(), 1, "{table}");
        assert_eq!(
            rows[0].try_get::<String>("", "physical_label").unwrap(),
            "stored",
            "{table}"
        );
    }
}

#[tokio::test]
async fn ephemeral_async_errors_preserve_ordinary_write_boundaries() {
    let store = EphemeralStore::new(AuthConfig::default().into());
    tokio::time::timeout(Duration::from_secs(10), check_failures(&store))
        .await
        .unwrap();
}

#[tokio::test]
async fn sqlite_async_errors_preserve_ordinary_write_boundaries() {
    let (store, _) = sqlite().await;
    tokio::time::timeout(Duration::from_secs(10), check_failures(&store))
        .await
        .unwrap();
}

#[tokio::test]
async fn ephemeral_batch_starts_both_rows_and_preserves_return_order() {
    let store = EphemeralStore::new(AuthConfig::default().into());
    tokio::time::timeout(Duration::from_secs(10), check_batch(&store))
        .await
        .unwrap();
}

#[tokio::test]
async fn sqlite_batch_starts_both_rows_and_preserves_return_order() {
    let (store, _) = sqlite().await;
    tokio::time::timeout(Duration::from_secs(10), check_batch(&store))
        .await
        .unwrap();
}
