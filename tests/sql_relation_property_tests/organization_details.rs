use super::*;
use better_auth_core::{
    organization_fields::OrganizationFields,
    store::{OrganizationDetailsQuery, OrganizationKey},
    user_fields::UserFieldReference,
};
use serde::Deserialize;
use tracing::{Subscriber, field::Visit, instrument::WithSubscriber};
use tracing_subscriber::{Layer, layer::Context, prelude::*};

#[path = "organization_differences.rs"]
mod differences;
#[path = "organization_models.rs"]
mod organization_models;
#[path = "../support/device_where_values.rs"]
mod values;

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Scenario {
    name: String,
    #[serde(default)]
    dependencies: bool,
    #[serde(default)]
    mapped: bool,
    #[serde(default)]
    source_alias: bool,
    #[serde(default)]
    target_alias: bool,
    owner: Option<String>,
    failure: Option<String>,
    singular: Option<String>,
    #[serde(rename = "empty")]
    _empty: Option<String>,
    #[serde(default, rename = "duplicateUsers")]
    _duplicate_users: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Case {
    scenario: String,
    before: serde_json::Map<String, Value>,
    events: Vec<Value>,
    returned: bool,
    result: Option<Value>,
    json: Option<Value>,
    key_order: Option<Vec<Value>>,
    error: Option<Value>,
    after: serde_json::Map<String, Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    version: String,
    backend: String,
    catalog: serde_json::Map<String, Value>,
    scenarios: Vec<Scenario>,
    cases: Vec<Case>,
}

#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<Value>>>);

impl Recorder {
    fn push(&self, value: Value) -> AuthResult<()> {
        self.0
            .lock()
            .map_err(|_| AuthError::internal("Full Organization recorder lock poisoned"))?
            .push(value);
        Ok(())
    }

    fn snapshot(&self) -> TestResult<Vec<Value>> {
        Ok(self.0.lock().map_err(|_| "Recorder lock poisoned")?.clone())
    }
}

#[derive(Default)]
struct SpanName(Option<String>);

impl Visit for SpanName {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "otel.name" {
            self.0 = Some(value.to_owned());
        }
    }
    fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
}

impl<S: Subscriber> Layer<S> for Recorder {
    #[expect(
        clippy::expect_used,
        reason = "Tracing callbacks cannot return errors; recorder failure must fail the contract."
    )]
    fn on_new_span(
        &self,
        attributes: &tracing::span::Attributes<'_>,
        _: &tracing::Id,
        _: Context<'_, S>,
    ) {
        if attributes.metadata().target() != "better-auth" {
            return;
        }
        let mut name = SpanName::default();
        attributes.record(&mut name);
        if let Some(name) = name.0
            && let Some(query) = name.strip_prefix("db ")
            && let Some((operation, model)) = query.split_once(' ')
        {
            self.push(json!(["query", operation, model]))
                .expect("Full Organization query recorder available");
        }
    }
}

fn trace_field(name: &'static str, scenario: &Scenario, events: &Recorder) -> UserFieldConfig {
    let scenario = scenario.clone();
    let input = events.clone();
    let output = events.clone();
    UserFieldConfig {
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                input.push(json!(["unexpected-input", name, values::observe(&value)?]))?;
                Ok(value)
            })),
            output: Some(UserFieldTransform::new(move |value| {
                output.push(json!(["output", name, values::observe(&value)?]))?;
                if scenario.failure.as_deref() == Some(name) {
                    return Err(AuthError::type_error(format!(
                        "full-fallback-output-rejected:{name}"
                    )));
                }
                Ok(if name == "member.userId" {
                    match scenario.owner.as_deref() {
                        Some("redirect") => "redirect".into(),
                        Some("null") => FieldValue::Null,
                        Some("number") => 7.0.into(),
                        _ => value,
                    }
                } else {
                    value
                })
            })),
        }),
        ..Default::default()
    }
}

fn reference(field: &str) -> UserFieldConfig {
    UserFieldConfig {
        references: Some(UserFieldReference {
            model: "organization".into(),
            field: field.into(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn policies(
    scenario: &Scenario,
    events: &Recorder,
) -> AuthResult<(AuthConfig, OrganizationFields)> {
    let mut config = AuthConfig::default();
    config.logger = better_auth_core::LoggerConfig {
        disabled: Some(true),
        ..Default::default()
    }
    .into();
    config.telemetry.enabled = false;
    config.advanced.database.joins = Some(false);
    let _ = config
        .user
        .fields_mut()
        .insert("name".into(), trace_field("user.name", scenario, events));
    let mut fields = OrganizationFields::default();
    for (schema, name, label) in [
        (&mut fields.organization, "name", "organization.name"),
        (&mut fields.invitation, "role", "invitation.role"),
        (&mut fields.team, "name", "team.name"),
    ] {
        let _ = schema
            .fields_mut()
            .insert(name.into(), trace_field(label, scenario, events));
    }
    fields.member.fields_mut().extend([
        (
            "userId".into(),
            trace_field("member.userId", scenario, events),
        ),
        ("role".into(), trace_field("member.role", scenario, events)),
    ]);
    if scenario.dependencies {
        for (name, label) in [
            ("invitation", "organization.invitation"),
            ("member", "organization.member"),
        ] {
            let _ = fields.organization.fields_mut().insert(
                name.into(),
                UserFieldConfig {
                    field_name: scenario.mapped.then(|| format!("stored_{name}")),
                    ..trace_field(label, scenario, events)
                },
            );
        }
        let _ = fields
            .member
            .fields_mut()
            .insert("organizationId".into(), reference("invitation"));
        let _ = fields
            .team
            .fields_mut()
            .insert("organizationId".into(), reference("member"));
    }
    if scenario.source_alias {
        for (name, physical, label) in [
            ("ownerRef", "lookup", "organization.ownerRef"),
            ("lookup", "stored_lookup", "organization.lookup"),
        ] {
            let _ = fields.organization.fields_mut().insert(
                name.into(),
                UserFieldConfig {
                    field_name: Some(physical.into()),
                    ..trace_field(label, scenario, events)
                },
            );
        }
        let _ = fields
            .member
            .fields_mut()
            .insert("organizationId".into(), reference("ownerRef"));
    }
    if scenario.target_alias {
        fields.member.fields_mut().extend([
            (
                "organizationId".into(),
                UserFieldConfig {
                    field_name: Some("lookup".into()),
                    ..reference("id")
                },
            ),
            (
                "lookup".into(),
                UserFieldConfig {
                    field_name: Some("stored_lookup".into()),
                    ..trace_field("member.lookup", scenario, events)
                },
            ),
        ]);
    }
    if let Some(model) = scenario.singular.as_deref() {
        let schema = match model {
            "member" => &mut fields.member,
            "invitation" => &mut fields.invitation,
            "team" => &mut fields.team,
            _ => {
                return Err(AuthError::internal(
                    "The pinned scenario must name a registered Organization relation",
                ));
            }
        };
        let _ = schema.fields_mut().insert(
            "organizationId".into(),
            UserFieldConfig {
                unique: Some(true),
                ..reference("id")
            },
        );
    }
    Ok((config, fields))
}

fn key_order(value: &FieldValue, path: Vec<String>) -> AuthResult<Vec<Value>> {
    let entries: Vec<(String, FieldValue)> = match value {
        FieldValue::Object(object) => object.snapshot_fields()?.into_iter().collect(),
        FieldValue::Array(values) => values
            .iter()?
            .enumerate()
            .map(|(index, value)| Ok((index.to_string(), value?)))
            .collect::<AuthResult<_>>()?,
        _ => return Ok(Vec::new()),
    };
    let mut result = vec![
        json!({"path": path, "keys": entries.iter().map(|(name, _)| name).collect::<Vec<_>>()}),
    ];
    for (name, value) in entries {
        let mut child_path = path.clone();
        child_path.push(name);
        result.extend(key_order(&value, child_path)?);
    }
    Ok(result)
}

async fn database(fixture: &Fixture, case: &Case) -> TestResult<DatabaseConnection> {
    let database = Database::connect("sqlite::memory:").await?;
    for (table, columns) in &fixture.catalog {
        let columns = columns.as_object().ok_or("Expected SQL catalog columns")?;
        let mut columns = columns
            .iter()
            .map(|(name, kind)| {
                Ok(format!(
                    "\"{name}\" {}",
                    kind.as_str().ok_or("Expected SQL type")?
                ))
            })
            .collect::<TestResult<Vec<_>>>()?;
        if table == "organization" {
            columns.push("\"updated_at\" TEXT NOT NULL".into());
        }
        let columns = columns.join(",");
        let _ = database
            .execute_raw(Statement::from_string(
                DbBackend::Sqlite,
                format!("CREATE TABLE \"{table}\" ({columns})"),
            ))
            .await?;
        for row in case
            .before
            .get(table)
            .and_then(Value::as_array)
            .ok_or("Missing physical seed table")?
        {
            let mut row = row.clone();
            if table == "organization" {
                let fields = row.as_object_mut().ok_or("Expected Organization seed")?;
                let updated = fields
                    .get("createdAt")
                    .cloned()
                    .ok_or("Missing Organization creation time")?;
                assert!(fields.insert("updated_at".into(), updated).is_none());
            }
            insert(&database, table, &row).await?;
        }
    }
    Ok(database)
}

async fn snapshot(
    database: &DatabaseConnection,
    fixture: &Fixture,
    case: &Case,
) -> TestResult<serde_json::Map<String, Value>> {
    let mut tables = serde_json::Map::new();
    for (table, columns) in &fixture.catalog {
        let _ = tables.insert(table.clone(), storage(database, table, columns).await?);
    }
    // The Rust-only update column is checked separately from the captured upstream rows.
    let expected = case
        .before
        .get("organization")
        .and_then(Value::as_array)
        .ok_or("Missing Organization seed table")?
        .iter()
        .map(|row| {
            Ok(json!({
                "id": row.get("id").ok_or("Missing Organization seed ID")?,
                "updated_at": row.get("createdAt").ok_or("Missing Organization creation time")?,
            }))
        })
        .collect::<TestResult<Vec<_>>>()?;
    assert_eq!(
        storage(
            database,
            "organization",
            &json!({"id": "TEXT", "updated_at": "TEXT"})
        )
        .await?,
        Value::Array(expected),
        "{}: internal Organization update column",
        case.scenario
    );
    Ok(tables)
}

async fn contract(name: &str) -> TestResult {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../fixtures/organization-full-fallback-1.7.6.json"
    ))?;
    assert_eq!(fixture.version, "1.7.6");
    assert_eq!(fixture.backend, "sqlite");
    assert_eq!(fixture.scenarios.len(), 19);
    assert_eq!(fixture.cases.len(), fixture.scenarios.len());
    let scenarios = fixture
        .scenarios
        .iter()
        .zip(&fixture.cases)
        .filter(|(scenario, _)| scenario.name == name)
        .collect::<Vec<_>>();
    assert_eq!(scenarios.len(), 1, "{name}");
    for (scenario, case) in scenarios {
        assert_eq!(scenario.name, case.scenario);
        assert_eq!(case.before, case.after, "{}", case.scenario);
        let database = database(&fixture, case).await?;
        assert_eq!(
            snapshot(&database, &fixture, case).await?,
            case.before,
            "{}",
            case.scenario
        );
        let events = Recorder::default();
        let (config, fields) = policies(scenario, &events)?;
        let config = Arc::new(config);
        let raw = Arc::new(
            SeaOrmStore::<models::Core>::new((*config).clone(), database.clone())
                .with_organization_schema::<organization_models::Organizations>(),
        );
        let mut model_fields = better_auth_core::plugin_runtime::ModelFields::default();
        model_fields.register_model_schema(
            EntityRole::User,
            Some("linked_user"),
            UserConfig::default(),
        )?;
        model_fields.register_organization_schema(&fields, true, false);
        let reader = raw.with_runtime(config, Vec::new(), model_fields)?;
        let result = async {
            reader
                .get_organization_details(OrganizationDetailsQuery {
                    organization: OrganizationKey::Id("organization"),
                    members_limit: None,
                    users_limit: 100.0,
                    include_teams: true,
                })
                .await?
                .ok_or_else(|| AuthError::internal("Expected full Organization"))?
                .into_public_value(&fields)
        }
        .with_subscriber(tracing_subscriber::registry().with(events.clone()))
        .await;
        assert_eq!(events.snapshot()?, case.events, "{}", case.scenario);
        if case.returned {
            let result = result?;
            assert_eq!(
                Some(values::observe(&result)?),
                case.result,
                "{}",
                case.scenario
            );
            assert_eq!(
                result,
                values::revive(case.result.as_ref().ok_or("Missing native result")?)?,
                "{}",
                case.scenario
            );
            assert_eq!(result.json()?, case.json, "{}", case.scenario);
            assert_eq!(
                Some(key_order(&result, Vec::new())?),
                case.key_order,
                "{}",
                case.scenario
            );
        } else {
            let error = result
                .err()
                .ok_or("The upstream Full Organization operation rejected")?;
            let expected = case.error.as_ref().ok_or("Missing captured error")?;
            differences::assert_error(&case.scenario, expected, &error)?;
            assert_eq!(
                expected.get("sameCallbackError").and_then(Value::as_bool),
                Some(scenario.failure.is_some()),
                "{}",
                case.scenario
            );
        }
        assert_eq!(
            snapshot(&database, &fixture, case).await?,
            case.after,
            "{}",
            case.scenario
        );
    }
    Ok(())
}

macro_rules! full_fallback_cases {
    ($($name:ident => $scenario:literal),+ $(,)?) => {
        $(
            #[tokio::test]
            async fn $name() -> TestResult {
                contract($scenario).await
            }
        )+
    };
}

full_fallback_cases! {
    ordinary => "ordinary",
    preceding_relations => "preceding-relations",
    mapped_preceding_relations => "mapped-preceding-relations",
    preceding_relation_error => "preceding-relation-error",
    source_alias_chain => "source-alias-chain",
    target_alias_chain => "target-alias-chain",
    projected_owner_redirect => "projected-owner-redirect",
    projected_owner_null => "projected-owner-null",
    projected_owner_number => "projected-owner-number",
    duplicate_user_id_last_wins => "duplicate-user-id-last-wins",
    member_singular_present => "member-singular-present",
    member_singular_empty => "member-singular-empty",
    invitation_singular_present => "invitation-singular-present",
    invitation_singular_empty => "invitation-singular-empty",
    team_singular_present => "team-singular-present",
    team_singular_empty => "team-singular-empty",
    member_output_error => "member.role-error",
    team_output_error => "team.name-error",
    user_output_error => "user.name-error",
}
