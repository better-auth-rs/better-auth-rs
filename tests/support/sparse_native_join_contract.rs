use super::{TestResult, models, values};
use async_trait::async_trait;
use better_auth::{AuthConfig, BetterAuth};
use better_auth_core::{
    AuthContext, AuthError, AuthPlugin, AuthRecordFields, AuthRequest, AuthResponse, AuthResult,
    AuthRoute, AuthSchema, FieldMap, FieldValue, ListUsersParams, SchemaValue,
    organization_fields::OrganizationFields,
    store::{OrganizationDetailsQuery, OrganizationKey, schema::EntityRole},
    user_fields::{
        FieldTransforms, UserConfig, UserFieldConfig, UserFieldReference, UserFieldTransform,
    },
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement},
    store::__private_test_support::bundled_schema::BundledSchema,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

type Events = Arc<Mutex<Vec<Value>>>;

struct Declarations(Vec<(EntityRole, UserConfig)>);

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Declarations {
    fn name(&self) -> &'static str {
        "sparse-native-fields"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    fn schema(
        &self,
        context: &mut better_auth_core::plugin_runtime::ModelFields,
    ) -> AuthResult<()> {
        for (role, fields) in &self.0 {
            context.register_model_fields(*role, fields.clone())?;
        }
        Ok(())
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

fn field(label: String, value: &Value, reject: Option<&str>, events: &Events) -> UserFieldConfig {
    let events = events.clone();
    let reject = reject == Some(label.as_str());
    UserFieldConfig {
        field_name: value["fieldName"].as_str().map(str::to_owned),
        references: value["references"]
            .as_str()
            .map(|model| UserFieldReference {
                model: model.into(),
                field: "id".into(),
                ..Default::default()
            }),
        transform: Some(FieldTransforms {
            output: Some(UserFieldTransform::new(move |value| {
                events
                    .lock()
                    .unwrap()
                    .push(json!([label, values::observe(&value)?]));
                if reject {
                    return Err(AuthError::internal("sparse-native-output-rejected"));
                }
                if label.ends_with(".name") {
                    assert!(matches!(value, FieldValue::Number(_)));
                    Ok(format!(
                        "visible:{}",
                        SchemaValue::<String>::from_field(value).display_string()?
                    )
                    .into())
                } else {
                    Ok(value)
                }
            })),
            ..Default::default()
        }),
        ..Default::default()
    }
}

pub(super) struct Fixture {
    pub(super) database: DatabaseConnection,
    pub(super) events: Events,
    auth: BetterAuth<BundledSchema>,
    tables: Vec<String>,
}

impl Fixture {
    pub(super) async fn new(
        cases: &Value,
        case: &Value,
        joins: bool,
        reject: bool,
    ) -> TestResult<Self> {
        let database = Database::connect("sqlite::memory:").await?;
        let mut tables = Vec::new();
        for table in cases["tables"].as_array().unwrap() {
            let name = table["table"].as_str().unwrap();
            tables.push(name.to_owned());
            let columns = table["columns"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(column, kind)| format!("\"{column}\" {}", kind.as_str().unwrap()))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = database
                .execute_unprepared(&format!("CREATE TABLE \"{name}\" ({columns})"))
                .await?;
            for row in table["rows"].as_array().unwrap() {
                let row = row.as_object().unwrap();
                let columns = row
                    .keys()
                    .map(|name| format!("\"{name}\""))
                    .collect::<Vec<_>>()
                    .join(", ");
                let markers = row.keys().map(|_| "?").collect::<Vec<_>>().join(", ");
                let values = row
                    .values()
                    .map(|value| {
                        Ok(match value {
                            Value::Null => Option::<String>::None.into(),
                            Value::Number(value) => value.as_i64().unwrap().into(),
                            Value::String(value) => value.clone().into(),
                            _ => return Err("The SQL seed contains a non-scalar field".into()),
                        })
                    })
                    .collect::<TestResult<Vec<better_auth_seaorm::sea_orm::Value>>>()?;
                let _ = database
                    .execute_raw(Statement::from_sql_and_values(
                        DbBackend::Sqlite,
                        format!("INSERT INTO \"{name}\" ({columns}) VALUES ({markers})"),
                        values,
                    ))
                    .await?;
            }
        }
        let events = Events::default();
        let reject = reject.then(|| case["rejectAt"].as_str().unwrap());
        let mut config =
            AuthConfig::new("sparse-native-join-contract-at-least-thirty-two-characters")
                .base_url("http://sparse-native.test");
        config.logger = better_auth_core::LoggerConfig {
            disabled: Some(true),
            ..Default::default()
        }
        .into();
        config.telemetry.enabled = false;
        config.advanced.database.joins = Some(joins);
        let _ = config.user.fields_mut().insert(
            "name".into(),
            field("user.name".into(), &Value::Null, reject, &events),
        );
        let mut declarations = Vec::new();
        for (model, role) in [
            ("organization", EntityRole::Organization),
            ("team", EntityRole::Team),
            ("teamMember", EntityRole::TeamMember),
            ("member", EntityRole::Member),
            ("invitation", EntityRole::Invitation),
            ("apikey", EntityRole::ApiKey),
            ("organizationRole", EntityRole::OrganizationRole),
        ] {
            let fields = cases["declarations"][model]
                .as_object()
                .unwrap()
                .iter()
                .map(|(name, value)| {
                    (
                        name.clone(),
                        field(format!("{model}.{name}"), value, reject, &events),
                    )
                })
                .collect();
            declarations.push((
                role,
                UserConfig {
                    additional_fields: Some(fields),
                },
            ));
        }
        let auth = BetterAuth::new(config.clone())
            .store(
                SeaOrmStore::<BundledSchema>::new(config, database.clone())
                    .with_organization_schema::<models::Models>(),
            )
            .plugin(Declarations(declarations))
            .build()
            .await?;
        Ok(Self {
            database,
            events,
            auth,
            tables,
        })
    }

    pub(super) async fn snapshot(&self) -> TestResult<Value> {
        let mut result = serde_json::Map::new();
        for table in &self.tables {
            let columns = self
                .database
                .query_all_raw(Statement::from_string(
                    DbBackend::Sqlite,
                    format!("PRAGMA table_info(\"{table}\")"),
                ))
                .await?
                .iter()
                .map(|row| row.try_get::<String>("", "name"))
                .collect::<Result<Vec<_>, _>>()?;
            let entries = columns
                .iter()
                .map(|name| format!("'{name}', \"{name}\""))
                .collect::<Vec<_>>()
                .join(", ");
            let rows = self
                .database
                .query_all_raw(Statement::from_string(
                    DbBackend::Sqlite,
                    format!("SELECT json_object({entries}) AS record FROM \"{table}\" ORDER BY id"),
                ))
                .await?
                .iter()
                .map(|row| {
                    Ok(serde_json::from_str::<Value>(
                        &row.try_get::<String>("", "record")?,
                    )?)
                })
                .collect::<TestResult<Vec<_>>>()?;
            let _ = result.insert(table.clone(), json!({"columns": columns, "rows": rows}));
        }
        Ok(Value::Object(result))
    }

    pub(super) async fn read(&self, path: &str) -> AuthResult<FieldValue> {
        let selector = match path {
            "team" => "team",
            "member" => "member",
            "full" => "organization",
            _ => return Err(AuthError::internal("Unknown sparse join operation")),
        };
        Ok(self.read_selected(path, &selector.into()).await?.unwrap())
    }

    pub(super) async fn read_users(&self, params: ListUsersParams) -> AuthResult<FieldValue> {
        let (users, total) = self.auth.store().list_users(params).await?;
        let users = users
            .into_iter()
            .map(|user| FieldValue::from(FieldMap::from(user)))
            .collect::<Vec<_>>();
        Ok(FieldMap::from([
            ("users".into(), users.into()),
            ("total".into(), total.into()),
        ])
        .into())
    }

    pub(super) async fn count(&self, model: &str, value: &FieldValue) -> AuthResult<FieldValue> {
        let store = self.auth.store();
        Ok(match model {
            "apikey" => store.count_api_keys_by_reference_value(value).await?.into(),
            "member" => store.count_organization_members_value(value).await?.into(),
            "teamMember" => store.count_team_members_value(value).await?.into(),
            "organizationRole" => store.count_organization_roles_value(value).await?.into(),
            _ => return Err(AuthError::internal("Unknown sparse count model")),
        })
    }

    pub(super) async fn read_api_keys(&self, reference: &FieldValue) -> AuthResult<FieldValue> {
        self.auth
            .store()
            .find_api_keys_by_reference_value(reference, None)
            .await?
            .into_iter()
            .map(|key| key.field_values().map(FieldValue::from))
            .collect::<AuthResult<Vec<_>>>()
            .map(Into::into)
    }

    pub(super) async fn read_selected(
        &self,
        path: &str,
        selector: &FieldValue,
    ) -> AuthResult<Option<FieldValue>> {
        let store = self.auth.store();
        match path {
            "team" => {
                let Some(details) = store.get_team_details_value(selector, None, true).await?
                else {
                    return Ok(None);
                };
                let (team, members) = details.into_public_parts(&UserConfig::default())?;
                let mut output = team.field_values()?;
                let members = members
                    .unwrap()
                    .into_iter()
                    .map(|row| row.field_values().map(FieldValue::from))
                    .collect::<AuthResult<Vec<_>>>()?;
                let _ = output.insert("members".into(), members.into());
                Ok(Some(output.into()))
            }
            "member" => {
                let Some(member) = store
                    .get_member_by_id_with_user(selector.as_str().ok_or_else(|| {
                        AuthError::internal("Member fixture selector must be a string")
                    })?)
                    .await?
                else {
                    return Ok(None);
                };
                let mut output = member.member.field_values()?;
                let _ = output.insert("user".into(), member.user.field_values()?.into());
                Ok(Some(output.into()))
            }
            "full" => store
                .get_organization_details(OrganizationDetailsQuery {
                    organization: OrganizationKey::IdValue(selector),
                    members_limit: None,
                    users_limit: 100.0,
                    include_teams: true,
                })
                .await?
                .map(|value| value.into_public_value(&OrganizationFields::default()))
                .transpose(),
            _ => Err(AuthError::internal("Unknown sparse join operation")),
        }
    }
}

pub(super) fn assert_value(actual: &FieldValue, expected: &Value) -> AuthResult<()> {
    assert_fields(actual, &values::revive(expected)?)
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions compare complete fields and key order; Result propagates field access errors"
)]
fn assert_fields(actual: &FieldValue, expected: &FieldValue) -> AuthResult<()> {
    assert_eq!(actual, expected);
    match expected {
        FieldValue::Object(expected) => {
            let actual = actual.enumerable_fields()?;
            let expected = expected.snapshot_fields()?;
            assert_eq!(
                actual.keys().collect::<Vec<_>>(),
                expected.keys().collect::<Vec<_>>()
            );
            for (key, value) in &expected {
                assert_fields(&actual[key], value)?;
            }
        }
        FieldValue::Array(expected) => {
            for (actual, expected) in actual.as_array().unwrap().iter()?.zip(expected.iter()?) {
                assert_fields(&actual?, &expected?)?;
            }
        }
        _ => {}
    }
    Ok(())
}
