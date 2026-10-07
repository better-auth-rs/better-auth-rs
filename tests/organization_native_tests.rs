#![cfg(feature = "seaorm2")]
#![expect(
    clippy::unwrap_used,
    reason = "contract fixtures fail immediately on invalid setup"
)]
#![expect(
    unreachable_pub,
    reason = "SeaORM derives require public generated fixture entities"
)]

#[path = "../compat-tests/rust-server/src/organization_fields/models.rs"]
mod models;

use async_trait::async_trait;
use better_auth::config::{FieldTransforms, UserFieldTransform};
use better_auth::plugins::{
    endpoint_context::EndpointContext,
    organization::{OrganizationConfig, OrganizationPlugin, hooks::*},
};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult, BetterAuth};
use better_auth_core::observability::{AfterEndpointHook, BeforeEndpointHook, EndpointHooks};
use better_auth_core::store::{StatelessSchema, transaction};
use better_auth_core::user_fields::UserFieldConfig;
use better_auth_core::{
    AuthContext, AuthRequest, AuthResponse, AuthSchema, BeforeRequestAction, CreateMember,
    CreateOrganization, CreateTeam, CreateUser, FieldValue,
};
use better_auth_seaorm::store::__private_test_support::{bundled_schema::BundledSchema, migrator};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, Schema},
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

const MODES: &[&str] = &[
    "normal",
    "patch",
    "stop",
    "replace",
    "invalid",
    "override",
    "before-error",
    "after-error",
    "member-error",
    "policy-error",
    "limit",
    "team",
    "team-limit",
    "team-disabled",
    "missing-org",
    "duplicate",
    "tx-commit",
    "tx-rollback",
    "org-number",
    "team-dynamic-limit",
    "tx-team-commit",
    "tx-team-rollback",
    "tx-team-catch",
    "team-reassign",
    "tx-team-reassign",
];

struct State {
    mode: &'static str,
    events: Mutex<Vec<Value>>,
}
impl State {
    fn record(&self, event: Value) {
        self.events.lock().unwrap().push(event);
    }
    fn endpoint(&self, phase: &str, request: &AuthRequest) -> AuthResult<()> {
        self.record(json!({"phase":phase,"path":request.path(),"ambient":ambient(),"body":request.input_body()?.unwrap_or_else(||json!({"$undefined":true}))}));
        Ok(())
    }
}
fn ambient() -> Value {
    better_auth_core::hooks::current_request_hook_context()
        .and_then(|context| context.path)
        .map(Value::String)
        .unwrap_or_else(|| json!({"$undefined":true}))
}
fn rejected() -> AuthError {
    AuthError::Upstream {
        status: 403,
        code: "FIXTURE_REJECTED",
        message: "fixture rejected",
    }
}
fn project(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(project).collect()),
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .filter(|(key, _)| !matches!(key.as_str(), "id" | "createdAt" | "updatedAt"))
                .map(|(key, value)| (key, project(value)))
                .collect(),
        ),
        value => value,
    }
}
#[async_trait]
impl<S: AuthSchema> BeforeEndpointHook<S> for State {
    async fn before(
        &self,
        request: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        self.endpoint("before", request)?;
        match self.mode {
            "before-error" => Err(rejected()),
            "stop" => Ok(Some(BeforeRequestAction::Respond(AuthResponse::json(
                200,
                &json!({"stopped":true}),
            )?))),
            "patch" => Ok(Some(BeforeRequestAction::MergeContext(
                better_auth_core::endpoint_input::EndpointInputPatch {
                    body: Some(json!({"role":"admin","label":"patched","ignored":"still unknown"})),
                    query: None,
                },
            ))),
            _ => Ok(None),
        }
    }
}
#[async_trait]
impl<S: AuthSchema> AfterEndpointHook<S> for State {
    async fn after(
        &self,
        request: &AuthRequest,
        response: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<()> {
        self.endpoint("after", request)?;
        if self.mode == "replace" {
            response.replace_returned(AuthResponse::json(200, &json!({"replaced":true}))?);
        }
        if self.mode == "after-error" {
            return Err(rejected());
        }
        Ok(())
    }
}
#[async_trait]
impl MembershipLimitPolicy for State {
    async fn membership_limit(&self, _: OrganizationUser<'_>) -> AuthResult<usize> {
        self.record(json!({"phase":"limit"}));
        if self.mode == "policy-error" {
            return Err(rejected());
        }
        Ok(100)
    }
}
#[async_trait]
impl TeamMemberLimitPolicy for State {
    async fn maximum_members_per_team(
        &self,
        _: OrganizationTeamMemberLimit<'_>,
    ) -> AuthResult<usize> {
        Ok(1)
    }
}
#[async_trait]
impl OrganizationHooks for State {
    async fn before_add_member(
        &self,
        member: &mut OrganizationMemberDraft,
        _: OrganizationUser<'_>,
    ) -> AuthResult<()> {
        let mut value = json!({"userId":member.user_id,"organizationId":member.organization_id,"role":member.role});
        let object = value.as_object_mut().unwrap();
        object.extend(member.additional_fields.json()?);
        if let Some(team) = &member.team_id {
            let _ = object.insert("teamId".into(), json!(team));
        }
        self.record(json!({"phase":"member-before","member":value,"ambient":ambient()}));
        if self.mode == "member-error" {
            return Err(rejected());
        }
        let label = member
            .additional_fields
            .get("label")
            .and_then(FieldValue::as_str)
            .unwrap_or("default");
        let _ = member
            .additional_fields
            .insert("label".into(), FieldValue::from(format!("{label}:hook")));
        if self.mode.ends_with("reassign") {
            member.user_id = "owner".into();
        }
        Ok(())
    }
    async fn after_add_member(&self, event: OrganizationMemberEvent<'_>) -> AuthResult<()> {
        self.record(json!({"phase":"member-after","member":project(serde_json::to_value(event.member)?),"ambient":ambient()}));
        Ok(())
    }
}

fn options(state: &Arc<State>) -> OrganizationConfig {
    let mut options = OrganizationConfig {
        hooks: Some(state.clone()),
        ..Default::default()
    };
    if state.mode == "limit" {
        options.membership_limit = Some(2);
    } else {
        options.membership_limit_callback = Some(state.clone());
    }
    options.teams.enabled = state.mode != "team-disabled";
    if matches!(
        state.mode,
        "team-limit" | "tx-team-catch" | "team-reassign" | "tx-team-reassign"
    ) {
        options.teams.maximum_members_per_team = Some(0);
    }
    if state.mode == "team-dynamic-limit" {
        options.teams.maximum_members_per_team_callback = Some(state.clone());
    }
    if state.mode == "org-number" {
        let _ = options.schema.member.fields_mut().insert(
            "organizationId".into(),
            UserFieldConfig {
                field_type: better_auth_core::user_fields::UserFieldType::Number,
                required: Some(true),
                ..Default::default()
            },
        );
    }
    options.schema.member.fields_mut().extend([
        (
            "label".into(),
            UserFieldConfig {
                required: Some(false),
                field_name: Some("storedLabel".into()),
                default_value: Some(FieldValue::from("default")),
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(|value| {
                        Ok(FieldValue::from(format!("{}:in", value.as_str().unwrap())))
                    })),
                    output: Some(UserFieldTransform::new(|value| {
                        Ok(FieldValue::from(format!("{}:out", value.as_str().unwrap())))
                    })),
                }),
                ..Default::default()
            },
        ),
        (
            "secret".into(),
            UserFieldConfig {
                required: Some(false),
                input: Some(false),
                returned: Some(false),
                default_value: Some(FieldValue::from("hidden")),
                ..Default::default()
            },
        ),
    ]);
    if state.mode == "override" {
        let _ = options.schema.member.fields_mut().insert(
            "role".into(),
            UserFieldConfig {
                required: Some(true),
                ..Default::default()
            },
        );
    }
    options
}

fn user(id: &str) -> CreateUser {
    CreateUser {
        id: Some(id.into()),
        name: Some(id.into()).into(),
        email: Some(format!("{id}@example.com")),
        email_verified: Some(true),
        ..Default::default()
    }
}
async fn scenario<S: AuthSchema>(auth: Arc<BetterAuth<S>>, state: Arc<State>) -> AuthResult<Value> {
    let mode = state.mode;
    let store = auth.store();
    let _ = store.create_user(user("owner")).await?;
    if !mode.starts_with("tx-") {
        let _ = store.create_user(user("target")).await?;
    }
    let mut organization = CreateOrganization::new("Org", "org");
    organization.id = Some("org".into());
    let _ = store.create_organization(organization).await?;
    let _ = store
        .create_member(CreateMember::new("org", "owner", "owner"))
        .await?;
    if mode == "limit" {
        let _ = store.create_user(user("other")).await?;
        let _ = store
            .create_member(CreateMember::new("org", "other", "member"))
            .await?;
    }
    if mode == "duplicate" {
        let _ = store
            .create_member(CreateMember::new("org", "target", "member"))
            .await?;
    }
    if mode != "team-disabled" {
        let _ = store
            .create_team(CreateTeam {
                id: Some("team".into()),
                name: "Team".into(),
                organization_id: "org".into(),
                ..Default::default()
            })
            .await?;
    }
    if mode.ends_with("reassign") {
        let _ = store.add_team_member(&"team".into(), "owner", None).await?;
    }
    let mut body = json!({"userId":"target","organizationId":if mode == "missing-org" {"missing"} else {"org"},"role":if mode == "override" {json!(["member"])} else {json!(["member","admin"])},"label":"sent","secret":"forged","unknown":true});
    if mode.starts_with("team") || mode.starts_with("tx-team") {
        let _ = body
            .as_object_mut()
            .unwrap()
            .insert("teamId".into(), json!("team"));
    }
    if mode == "org-number" {
        let _ = body
            .as_object_mut()
            .unwrap()
            .insert("organizationId".into(), json!(42));
    }
    if mode == "invalid" {
        let _ = body.as_object_mut().unwrap().remove("role");
    }
    state.events.lock().unwrap().clear();
    let result = if mode.starts_with("tx-") {
        let auth = auth.clone();
        let state = state.clone();
        transaction(store.as_ref(), move |tx| {
            Box::pin(async move {
                let _ = tx.create_user(user("target")).await?;
                let mut endpoint = EndpointContext::new(
                    None,
                    better_auth_core::FieldMap::new().into(),
                    auth.context(),
                );
                endpoint.transaction = Some(tx);
                let result = match endpoint.organization()?.add_member(Some(body)).await {
                    Ok(result) => result,
                    Err(error) if matches!(mode, "tx-team-catch" | "tx-team-reassign") => {
                        let response = error.to_auth_response();
                        let body: Value = serde_json::from_slice(&response.body.bytes()?)?;
                        json!({"caught":body.get("code")})
                    }
                    Err(error) => return Err(error),
                };
                let count = i64::from(
                    tx.get_member_value(&FieldValue::from("org"), &FieldValue::from("target"))
                        .await?
                        .is_some(),
                );
                state.record(json!({"phase":"transaction","members":count}));
                if matches!(mode, "tx-rollback" | "tx-team-rollback") {
                    return Err(AuthError::internal("rollback requested"));
                }
                Ok(result)
            })
        })
        .await
    } else {
        auth.organization()?.add_member(Some(body)).await
    };
    let mut output = match result {
        Ok(result) => json!({"result":project(result)}),
        Err(AuthError::Internal(message)) => json!({"error":{"message":message}}),
        Err(error) => {
            let response = error.to_auth_response();
            let mut error = json!({"status":response.status});
            if !response.body.is_empty() {
                let _ = error.as_object_mut().unwrap().insert(
                    "body".into(),
                    serde_json::from_slice(&response.body.bytes()?)?,
                );
            }
            json!({"error":error})
        }
    };
    let member = store.get_member("org", "target").await?;
    let members = member
        .map(|member| project(serde_json::to_value(member).unwrap()))
        .into_iter()
        .collect::<Vec<_>>();
    let teams = if mode == "team-disabled" {
        0
    } else {
        i64::from(store.get_team_member("team", "target").await?.is_some())
    };
    let object = output.as_object_mut().unwrap();
    let _ = object.insert("events".into(), json!(state.events.lock().unwrap().clone()));
    let _ = object.insert("members".into(), json!(members));
    let _ = object.insert("teams".into(), json!(teams));
    if mode.ends_with("reassign") {
        let _ = object.insert(
            "ownerTeams".into(),
            json!(i64::from(
                store.get_team_member("team", "owner").await?.is_some()
            )),
        );
    }
    Ok(output)
}

#[tokio::test]
async fn organization_native_dispatch_matches_memory_and_sqlite_upstream_contracts() {
    let expected: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/organization-native-upstream.json")).unwrap();
    for backend in ["memory", "sqlite"] {
        for &mode in MODES {
            let state = Arc::new(State {
                mode,
                events: Mutex::new(Vec::new()),
            });
            let mut config = AuthConfig::new("organization-native-fixture-secret-long-enough")
                .base_url("http://localhost:3000");
            config.advanced.database.default_find_many_limit =
                Some(if mode == "limit" { 1.0 } else { 100.0 });
            let options = options(&state);
            let actual = if backend == "memory" {
                let mut options = options;
                options
                    .schema
                    .member
                    .fields_mut()
                    .get_mut("label")
                    .unwrap()
                    .field_name = None;
                let auth = AuthBuilder::<StatelessSchema>::new(config.clone())
                    .store(better_auth_core::store::EphemeralStore::new(Arc::new(
                        config,
                    )))
                    .plugin(OrganizationPlugin::with_config(options))
                    .hooks(EndpointHooks {
                        before: Some(state.clone()),
                        after: Some(state.clone()),
                    })
                    .build()
                    .await
                    .unwrap();
                scenario(Arc::new(auth), state).await.unwrap()
            } else {
                let db = Database::connect("sqlite::memory:").await.unwrap();
                migrator::run_migrations(&db).await.unwrap();
                let schema = Schema::new(db.get_database_backend());
                for table in [
                    schema.create_table_from_entity(models::organization::Entity),
                    schema.create_table_from_entity(models::member::Entity),
                    schema.create_table_from_entity(models::invitation::Entity),
                    schema.create_table_from_entity(models::team::Entity),
                    schema.create_table_from_entity(models::team_member::Entity),
                    schema.create_table_from_entity(models::organization_role::Entity),
                ] {
                    let _ = db.execute(&table).await.unwrap();
                }
                let auth = AuthBuilder::new(config.clone())
                    .store(
                        SeaOrmStore::<BundledSchema>::new(config, db)
                            .with_organization_schema::<models::Models>(),
                    )
                    .plugin(OrganizationPlugin::with_config(options))
                    .hooks(EndpointHooks {
                        before: Some(state.clone()),
                        after: Some(state.clone()),
                    })
                    .build()
                    .await
                    .unwrap();
                scenario(Arc::new(auth), state).await.unwrap()
            };
            let expected = expected
                .iter()
                .find(|row| {
                    row.get("backend").and_then(Value::as_str) == Some(backend)
                        && row.get("mode").and_then(Value::as_str) == Some(mode)
                })
                .unwrap()
                .get("output")
                .unwrap();
            assert_eq!(&actual, expected, "{backend}/{mode}");
        }
    }
}

#[tokio::test]
async fn bundled_member_schema_keeps_membership_uniqueness_in_the_endpoint() {
    use better_auth_core::store::{MemberStore, OrganizationStore, UserStore};
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&db).await.unwrap();
    let config = AuthConfig::new("organization-native-fixture-secret-long-enough");
    let store = SeaOrmStore::<BundledSchema>::new(config, db);
    let _ = store.create_user(user("owner")).await.unwrap();
    let mut organization = CreateOrganization::new("Org", "org");
    organization.id = Some("org".into());
    let _ = store.create_organization(organization).await.unwrap();
    let _ = store
        .create_member(CreateMember::new("org", "owner", "owner"))
        .await
        .unwrap();
    let _ = store
        .create_member(CreateMember::new("org", "owner", "member"))
        .await
        .unwrap();
    assert_eq!(store.count_organization_members("org").await.unwrap(), 2);
}

async fn deletion_projection_failure<S: AuthSchema>(
    store: &dyn better_auth_core::store::AuthStore<S>,
) {
    use std::sync::atomic::{AtomicBool, Ordering};
    let reject = Arc::new(AtomicBool::new(false));
    let transform_reject = reject.clone();
    let mut fields = better_auth_core::organization_fields::OrganizationFields::default();
    let _ = fields.team.fields_mut().insert(
        "name".into(),
        UserFieldConfig {
            transform: Some(FieldTransforms {
                output: Some(UserFieldTransform::new(move |value| {
                    if transform_reject.load(Ordering::SeqCst) {
                        return Err(AuthError::internal("team projection rejected"));
                    }
                    Ok(value)
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    store.configure_organization_fields(fields).unwrap();
    let _ = store.create_user(user("owner")).await.unwrap();
    let mut organization = CreateOrganization::new("Org", "org");
    organization.id = Some("org".into());
    let _ = store.create_organization(organization).await.unwrap();
    let member = store
        .create_member(CreateMember::new("org", "owner", "owner"))
        .await
        .unwrap();
    let _ = store
        .create_team(CreateTeam {
            id: Some("team".into()),
            organization_id: "org".into(),
            name: "Team".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let _ = store
        .add_team_member(&"team".into(), "owner", None)
        .await
        .unwrap();
    for explicit_subject in [false, true] {
        reject.store(true, Ordering::SeqCst);
        let error = if explicit_subject {
            store
                .delete_member_for_user(member.id.typed().unwrap(), "org", "owner")
                .await
        } else {
            store.delete_member(member.id.typed().unwrap()).await
        }
        .unwrap_err();
        assert!(
            matches!(error, AuthError::Internal(message) if message == "team projection rejected")
        );
        reject.store(false, Ordering::SeqCst);
        assert!(store.get_member("org", "owner").await.unwrap().is_some());
        assert!(
            store
                .get_team_member("team", "owner")
                .await
                .unwrap()
                .is_some()
        );
    }
}

#[tokio::test]
async fn member_deletion_rolls_back_when_the_team_snapshot_projection_fails() {
    let config = AuthConfig::new("organization-native-fixture-secret-long-enough");
    deletion_projection_failure(&better_auth_core::store::EphemeralStore::new(Arc::new(
        config.clone(),
    )))
    .await;
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migrator::run_migrations(&db).await.unwrap();
    deletion_projection_failure(&SeaOrmStore::<BundledSchema>::new(config, db)).await;
}
