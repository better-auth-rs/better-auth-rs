use super::*;
use better_auth::plugins::{
    organization::{OrganizationConfig, OrganizationPlugin, OrganizationTeamsConfig},
    passkey::PasskeyPlugin,
};
use better_auth_core::{
    AuthRecordFields, AuthSchema, AuthStore, FieldDate, FieldMap, FieldValue,
    id::{IdGeneration, IdGenerator},
    store::schema::EntityRole,
    user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform},
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Mutex};

#[path = "native_mapping_id.rs"]
mod id;
#[path = "native_mapping_order.rs"]
mod order;
#[path = "native_mapping_records.rs"]
mod records;
#[path = "native_mapping_sqlite.rs"]
mod sqlite;

const DATE: &str = "2030-01-01T00:00:00.000Z";
const EXPIRY: &str = "2100-01-01T00:00:00.000Z";
const ID: &str = "mapping-row";
type Events = Arc<Mutex<Vec<Value>>>;
type Snapshot = BTreeMap<String, Vec<Value>>;

#[path = "effective_organization_declarations.rs"]
mod effective_organization_declarations;

#[derive(Clone, Copy, Debug)]
enum Model {
    User,
    Session,
    Account,
    Verification,
    Team,
    Passkey,
}

impl Model {
    fn role(self) -> EntityRole {
        match self {
            Self::User => EntityRole::User,
            Self::Session => EntityRole::Session,
            Self::Account => EntityRole::Account,
            Self::Verification => EntityRole::Verification,
            Self::Team => EntityRole::Team,
            Self::Passkey => EntityRole::Passkey,
        }
    }

    fn mapping(self) -> (&'static str, &'static str, &'static str, &'static str) {
        match self {
            Self::User => ("users", "name", "image", "name"),
            Self::Session => ("sessions", "token", "userAgent", "token"),
            Self::Account => ("accounts", "accountId", "scope", "account_id"),
            Self::Verification => ("verifications", "value", "identifier", "value"),
            Self::Team => ("team", "organizationId", "name", "organization_id"),
            Self::Passkey => ("passkeys", "publicKey", "name", "public_key"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum OldColumn {
    Required,
    Nullable,
    Defaulted,
}

impl OldColumn {
    #[expect(
        clippy::panic,
        reason = "Required legacy columns must fail preflight before a stored row can exist"
    )]
    fn value(self) -> Value {
        match self {
            Self::Defaulted => json!("legacy-default"),
            Self::Nullable => Value::Null,
            Self::Required => panic!("Required old columns must fail before CRUD"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Create,
    Read,
    Update,
}

struct Fields(EntityRole, UserConfig);

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Fields {
    fn name(&self) -> &'static str {
        "preflight-native-mapping"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    fn schema(
        &self,
        context: &mut better_auth_core::plugin_runtime::ModelFields,
    ) -> AuthResult<()> {
        context.register_model_fields(self.0, self.1.clone())
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

fn callback(events: &Events, phase: &'static str, field: &'static str) -> UserFieldTransform {
    let events = events.clone();
    UserFieldTransform::new(move |value| {
        events
            .lock()
            .unwrap()
            .push(json!([phase, field, value.json()?]));
        Ok(format!(
            "{}:{}",
            if phase == "input" {
                "stored"
            } else {
                "visible"
            },
            better_auth_core::SchemaValue::<String>::from_field(value).display_string()?
        )
        .into())
    })
}

fn declaration(field: &'static str, destination: &str, events: &Events) -> UserConfig {
    UserConfig {
        additional_fields: Some(
            [(
                field.into(),
                UserFieldConfig {
                    field_name: Some(destination.into()),
                    required: Some(true),
                    transform: Some(FieldTransforms {
                        input: Some(callback(events, "input", field)),
                        output: Some(callback(events, "output", field)),
                    }),
                    ..Default::default()
                },
            )]
            .into(),
        ),
    }
}

fn settings() -> AuthConfig {
    let mut settings = config();
    settings.telemetry.enabled = false;
    settings.logger = better_auth_core::LoggerConfig {
        disabled: Some(true),
        ..Default::default()
    }
    .into();
    settings.advanced.database.generate_id = Some(IdGeneration::Custom(IdGenerator::new(|_| {
        Ok(Some(ID.into()))
    })));
    settings
}

fn assert_mismatch(error: &SchemaCheckError, finding: SchemaFinding, message: String) {
    assert_eq!(findings(error), std::slice::from_ref(&finding));
    let inner = mismatch_details(error);
    assert_eq!(
        serde_json::to_value(inner).unwrap(),
        json!({
            "code": "SCHEMA_MISMATCH", "source": "database", "findings": [finding],
        })
    );
    assert_eq!(error.to_string(), message);
}

async fn run(model: Model, old: OldColumn) {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    sqlite::prepare(&database, model, old).await;
    let original_schema = sqlite::catalog(&database).await;
    let empty = sqlite::snapshot(&database).await;
    let events = Events::default();
    let settings = settings();
    let store = SeaOrmStore::<BundledSchema>::new(settings.clone(), database.clone());
    let observer = Observe(Default::default());
    let (_, source, destination, physical) = model.mapping();
    let auth = AuthBuilder::new(settings)
        .store(store)
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            teams: OrganizationTeamsConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        }))
        .plugin(PasskeyPlugin::new())
        .plugin(Fields(
            model.role(),
            declaration(source, destination, &events),
        ))
        .plugin(observer.clone())
        .build()
        .await
        .unwrap();
    let outcome = http(&auth).await;
    assert!(
        events.lock().unwrap().is_empty(),
        "{model:?} {old:?} preflight callbacks"
    );
    assert_eq!(sqlite::snapshot(&database).await, empty);
    if matches!(old, OldColumn::Required) {
        let table = model.mapping().0;
        assert_mismatch(
            &mismatch(outcome.unwrap_err()),
            SchemaFinding::UnexpectedRequiredColumn {
                table: table.into(),
                column: physical.into(),
            },
            format!(
                "Database schema mismatch\n\n  Required columns Better Auth never writes\n    {table}.{physical}\n\n  Inserts into {table} will fail.\n\n  help: Make the listed columns nullable, give them defaults, or remove them."
            ),
        );
        assert_eq!(observer.0.load(Ordering::SeqCst), 0);
    } else {
        let response = outcome.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(
            serde_json::from_slice::<Value>(response.body.bytes().unwrap().as_ref()).unwrap(),
            json!({"ok":true})
        );
        assert_eq!(observer.0.load(Ordering::SeqCst), 1);
        sqlite::seed(&database, model).await;
        let seeded = sqlite::snapshot(&database).await;
        for (stage, input) in [
            (Stage::Create, "source"),
            (Stage::Read, "source"),
            (Stage::Update, "next"),
            (Stage::Read, "next"),
        ] {
            let actual = records::run(model, stage, input, auth.store().as_ref()).await;
            assert_eq!(
                Value::Object(actual.json().unwrap()),
                records::expected(model, input),
                "{model:?} {old:?} {stage:?}"
            );
            let mut expected_events = Vec::new();
            if stage != Stage::Read {
                expected_events.push(json!(["input", source, input]));
            }
            expected_events.push(json!(["output", source, format!("stored:{input}")]));
            assert_eq!(
                *events.lock().unwrap(),
                expected_events,
                "{model:?} {old:?} {stage:?}"
            );
            events.lock().unwrap().clear();
            let mut expected_storage = seeded.clone();
            expected_storage
                .get_mut(model.mapping().0)
                .unwrap()
                .push(records::stored(model, old, input));
            assert_eq!(
                sqlite::snapshot(&database).await,
                expected_storage,
                "{model:?} {old:?} {stage:?} complete storage"
            );
        }
        records::delete(model, auth.store().as_ref()).await;
        let delete_events = if matches!(model, Model::Team | Model::Passkey) {
            Vec::new()
        } else {
            vec![json!(["output", source, "stored:next"])]
        };
        assert_eq!(
            *events.lock().unwrap(),
            delete_events,
            "Internal core deletion projects its hook snapshot"
        );
        events.lock().unwrap().clear();
        assert!(
            records::read(model, "next", auth.store().as_ref())
                .await
                .is_none()
        );
        assert_eq!(sqlite::snapshot(&database).await, seeded);
    }
    assert!(events.lock().unwrap().is_empty());
    assert_eq!(sqlite::catalog(&database).await, original_schema);
}

macro_rules! mapping_test {
    ($name:ident, $model:ident) => {
        #[tokio::test]
        async fn $name() {
            for old in [
                OldColumn::Required,
                OldColumn::Nullable,
                OldColumn::Defaulted,
            ] {
                run(Model::$model, old).await;
            }
        }
    };
}

mapping_test!(user_mapping_checks_unwritten_original_column, User);
mapping_test!(session_mapping_checks_unwritten_original_column, Session);
mapping_test!(account_mapping_checks_unwritten_original_column, Account);
mapping_test!(
    verification_mapping_checks_unwritten_original_column,
    Verification
);
mapping_test!(team_mapping_checks_unwritten_original_column, Team);
mapping_test!(passkey_mapping_checks_unwritten_original_column, Passkey);

#[tokio::test]
async fn rust_organization_private_timestamp_replacement_leaves_original_column_unwritten() {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&database).await.unwrap();
    let before = sqlite::snapshot(&database).await;
    let schema = sqlite::catalog(&database).await;
    let events = Events::default();
    let settings = settings();
    let store = SeaOrmStore::<BundledSchema>::new(settings.clone(), database.clone());
    let auth = AuthBuilder::new(settings)
        .store(store)
        .plugin(OrganizationPlugin::new())
        .plugin(Fields(
            EntityRole::Organization,
            declaration("authUpdatedAt", "name", &events),
        ))
        .build()
        .await
        .unwrap();
    assert_mismatch(&mismatch(http(&auth).await.unwrap_err()), SchemaFinding::UnexpectedRequiredColumn {
        table: "organization".into(), column: "updated_at".into(),
    }, "Database schema mismatch\n\n  Required columns Better Auth never writes\n    organization.updated_at\n\n  Inserts into organization will fail.\n\n  help: Make the listed columns nullable, give them defaults, or remove them.".into());
    assert!(events.lock().unwrap().is_empty());
    assert_eq!(sqlite::snapshot(&database).await, before);
    assert_eq!(sqlite::catalog(&database).await, schema);
}
