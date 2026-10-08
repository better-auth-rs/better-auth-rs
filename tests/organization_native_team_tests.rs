#![cfg(feature = "seaorm2")]
#![expect(
    unreachable_pub,
    reason = "SeaORM derives require public fixture entities"
)]

#[path = "../compat-tests/rust-server/src/organization_fields/models.rs"]
mod models;

use async_trait::async_trait;
use better_auth::config::{FieldTransforms, UserFieldTransform};
use better_auth::plugins::organization::{
    OrganizationConfig, OrganizationPlugin, hooks::*, types::OrganizationResponse,
};
use better_auth::server_api::EndpointInput;
use better_auth::{AuthConfig, AuthError, AuthResult, AuthSchema, BetterAuth};
use better_auth_core::observability::{AfterEndpointHook, BeforeEndpointHook, EndpointHooks};
use better_auth_core::store::EphemeralStore;
use better_auth_core::user_fields::UserFieldConfig;
use better_auth_core::wire::UserView;
use better_auth_core::{
    AuthContext, AuthRequest, AuthResponse, BeforeRequestAction, CreateInvitation, CreateMember,
    CreateOrganization, CreateSession, CreateTeam, CreateUser, FieldDate, FieldMap, FieldValue,
    HttpMethod, Team,
};
use better_auth_seaorm::store::__private_test_support::{bundled_schema::BundledSchema, migrator};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, Schema},
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct State {
    events: Mutex<Vec<Value>>,
    created_id: Mutex<String>,
}

impl State {
    fn record(&self, event: Value) -> AuthResult<()> {
        self.events
            .lock()
            .map_err(|error| AuthError::internal(error.to_string()))?
            .push(event);
        Ok(())
    }
    fn endpoint(&self, phase: &str, request: &AuthRequest) -> AuthResult<()> {
        let mut body = request.input_body()?.unwrap_or_default();
        let id = self
            .created_id
            .lock()
            .map_err(|error| AuthError::internal(error.to_string()))?;
        if body.get("teamId").and_then(Value::as_str) == Some(id.as_str())
            && let Some(object) = body.as_object_mut()
        {
            let _ = object.insert("teamId".into(), json!("created"));
        }
        self.record(json!({"phase":phase,"path":request.path(),"body":body}))
    }
    fn team(&self, phase: &str, event: OrganizationTeamEvent<'_>) -> AuthResult<()> {
        self.record(json!({"phase":phase,"user":event.user.map(|user| &user.id),"team":team_value(event.team)?}))
    }
}

fn team_value(team: &Team) -> AuthResult<Value> {
    Ok(
        json!({"name":team.name,"organizationId":team.organization_id,"label":team.additional_fields.get("label").map(FieldValue::json).transpose()?}),
    )
}
fn property<'a>(value: &'a Value, name: &str) -> AuthResult<&'a Value> {
    value
        .get(name)
        .ok_or_else(|| AuthError::internal(format!("Missing fixture property {name}")))
}
fn string<'a>(value: &'a Value, name: &str) -> AuthResult<&'a str> {
    property(value, name)?
        .as_str()
        .ok_or_else(|| AuthError::internal(format!("Expected fixture string {name}")))
}
fn date(value: &str) -> AuthResult<FieldDate> {
    value
        .parse::<chrono::DateTime<chrono::Utc>>()
        .map(FieldDate::from)
        .map_err(|error: chrono::ParseError| AuthError::internal(error.to_string()))
}

#[async_trait]
impl<S: AuthSchema> BeforeEndpointHook<S> for State {
    async fn before(
        &self,
        request: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeRequestAction>> {
        self.endpoint("before", request)?;
        Ok(None)
    }
}
#[async_trait]
impl<S: AuthSchema> AfterEndpointHook<S> for State {
    async fn after(
        &self,
        request: &AuthRequest,
        _: &mut AuthResponse,
        _: &AuthContext<S>,
    ) -> AuthResult<()> {
        self.endpoint("after", request)
    }
}
#[async_trait]
impl OrganizationPolicy for State {
    async fn maximum_teams(
        &self,
        data: OrganizationTeamLimit<'_>,
        _: OrganizationEndpoint<'_>,
    ) -> AuthResult<Option<usize>> {
        self.record(json!({"phase":"limit","organizationId":data.organization_id.json()?,"user":data.session.map(|session| &session.user.id)}))?;
        Ok(Some(100))
    }
}
#[async_trait]
impl OrganizationHooks for State {
    async fn before_create_team(
        &self,
        data: &mut OrganizationTeamDraft,
        _: &OrganizationResponse,
        user: Option<&UserView>,
    ) -> AuthResult<()> {
        self.record(json!({"phase":"create-before","user":user.map(|user| &user.id),"team":{"name":data.name,"organizationId":data.organization_id,"label":data.additional_fields.get("label").map(FieldValue::json).transpose()?}}))?;
        data.name = format!("{}:hook", data.name.typed()?).into();
        let label = data
            .additional_fields
            .get("label")
            .and_then(FieldValue::as_str)
            .ok_or_else(|| AuthError::internal("Missing team label"))?;
        let label = format!("{label}:hook").into();
        let _ = data.additional_fields.insert("label".into(), label);
        Ok(())
    }
    async fn after_create_team(&self, event: OrganizationTeamEvent<'_>) -> AuthResult<()> {
        self.team("create-after", event)
    }
    async fn before_delete_team(&self, event: OrganizationTeamEvent<'_>) -> AuthResult<()> {
        self.team("delete-before", event)
    }
    async fn after_delete_team(&self, event: OrganizationTeamEvent<'_>) -> AuthResult<()> {
        self.team("delete-after", event)
    }
}

fn options(state: &Arc<State>, sqlite: bool) -> OrganizationConfig {
    let mut options = OrganizationConfig {
        hooks: Some(state.clone()),
        policy: Some(state.clone()),
        ..Default::default()
    };
    options.teams.enabled = true;
    let _ = options.schema.team.fields_mut().insert(
        "label".into(),
        UserFieldConfig {
            required: Some(false),
            field_name: sqlite.then(|| "storedLabel".into()),
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(|value| {
                    let value = value
                        .as_str()
                        .ok_or_else(|| AuthError::internal("Expected label input"))?;
                    Ok(format!("{value}:in").into())
                })),
                output: Some(UserFieldTransform::new(|value| {
                    let value = value
                        .as_str()
                        .ok_or_else(|| AuthError::internal("Expected label output"))?;
                    Ok(format!("{value}:out").into())
                })),
            }),
            ..Default::default()
        },
    );
    options
}

async fn scenario<S: AuthSchema>(
    auth: BetterAuth<S>,
    state: &State,
    case: &Value,
) -> AuthResult<()> {
    let store = auth.store();
    let _ = store
        .create_user(CreateUser {
            id: Some("owner".into()),
            name: Some("Owner".into()).into(),
            email: Some("owner@example.test".into()),
            email_verified: Some(true),
            ..Default::default()
        })
        .await?;
    let mut organization = CreateOrganization::new("Organization", "organization");
    organization.id = Some("org".into());
    let _ = store.create_organization(organization).await?;
    let _ = store
        .create_member(CreateMember::new("org", "owner", "owner"))
        .await?;
    let _ = store
        .create_team(CreateTeam {
            id: Some("existing".into()),
            name: "Existing".into(),
            organization_id: "org".into(),
            additional_fields: FieldMap::from_iter([("label".into(), "seed".into())]),
            ..Default::default()
        })
        .await?;
    let session = store
        .create_session(CreateSession {
            inherited_fields: Default::default(),
            user_id: "owner".into(),
            expires_at: date("2099-01-01T00:00:00Z")?,
            active_organization_id: Some("org".into()),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            additional_fields: Default::default(),
        })
        .await?;
    let trusted = string(case, "mode")? == "trusted";
    let headers = (!trusted).then(|| {
        HashMap::from([(
            "cookie".into(),
            format!(
                "better-auth.session_token={}",
                better_auth_core::utils::cookie_utils::sign_cookie_value(
                    session.token.typed()?,
                    auth.config().signing_secret()
                )
            ),
        )])
    });
    let mut body = json!({"name":"New","label":"sent","ignored":true});
    if trusted && let Some(body) = body.as_object_mut() {
        let _ = body.insert("organizationId".into(), json!("org"));
    }
    state
        .events
        .lock()
        .map_err(|error| AuthError::internal(error.to_string()))?
        .clear();
    let created = auth
        .call_endpoint(
            HttpMethod::Post,
            "/organization/create-team",
            EndpointInput {
                body: Some(body),
                headers: headers.clone(),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(created.status, 200);
    let created: Value = serde_json::from_slice(&created.body.bytes()?)?;
    let created_id = string(&created, "id")?;
    assert!(!created_id.is_empty());
    let _ = date(string(&created, "createdAt")?)?;
    let _ = date(string(&created, "updatedAt")?)?;
    *state
        .created_id
        .lock()
        .map_err(|error| AuthError::internal(error.to_string()))? = created_id.into();
    let stored = store
        .get_team(created_id)
        .await?
        .ok_or_else(|| AuthError::internal("Created team was not persisted"))?;
    let mut invitation = CreateInvitation::new(
        "org",
        "invitee@example.test",
        "member",
        "owner",
        date("2099-01-01T00:00:00Z")?,
    );
    invitation.id = Some("invitation".into());
    invitation.team_id = Some(format!("{created_id},existing"));
    let _ = store.create_invitation(invitation).await?;
    let mut body = json!({"teamId":created_id});
    if trusted && let Some(body) = body.as_object_mut() {
        let _ = body.insert("organizationId".into(), json!("org"));
    }
    let removed = auth
        .call_endpoint(
            HttpMethod::Post,
            "/organization/remove-team",
            EndpointInput {
                body: Some(body),
                headers,
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(removed.status, 200);
    let removed: Value = serde_json::from_slice(&removed.body.bytes()?)?;
    let remaining: Vec<_> = store
        .list_organization_teams("org")
        .await?
        .into_iter()
        .map(|team| team.name)
        .collect();
    let invitation = store
        .get_invitation_by_id("invitation")
        .await?
        .ok_or_else(|| AuthError::internal("Invitation must survive team removal"))?;
    let created = json!({"name":property(&created,"name")?,"organizationId":property(&created,"organizationId")?,"label":property(&created,"label")?});
    let events = state
        .events
        .lock()
        .map_err(|error| AuthError::internal(error.to_string()))?
        .clone();
    assert_eq!(
        &json!({"backend":property(case,"backend")?,"mode":property(case,"mode")?,"created":created,"stored":team_value(&stored)?,"removed":removed,"remaining":remaining,"invitationTeam":invitation.team_id,"events":events}),
        case
    );
    Ok(())
}

#[tokio::test]
async fn trusted_and_owner_native_teams_match_pinned_memory_and_sqlite() -> AuthResult<()> {
    let cases: Vec<Value> = serde_json::from_str(include_str!(
        "fixtures/organization-native-teams-upstream.json"
    ))?;
    for case in cases {
        let state = Arc::new(State::default());
        let mut config = AuthConfig::new("native-team-contract-secret-at-least-thirty-two")
            .base_url("http://localhost:3000");
        config.logger.disabled = Some(true);
        let sqlite = string(&case, "backend")? == "sqlite";
        let plugin = OrganizationPlugin::with_config(options(&state, sqlite));
        if sqlite {
            let database = Database::connect("sqlite::memory:")
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?;
            migrator::run_migrations(&database)
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?;
            let schema = Schema::new(database.get_database_backend());
            for table in [
                schema.create_table_from_entity(models::organization::Entity),
                schema.create_table_from_entity(models::member::Entity),
                schema.create_table_from_entity(models::invitation::Entity),
                schema.create_table_from_entity(models::team::Entity),
                schema.create_table_from_entity(models::team_member::Entity),
                schema.create_table_from_entity(models::organization_role::Entity),
            ] {
                let _ = database
                    .execute(&table)
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
            }
            let auth = BetterAuth::<BundledSchema>::new(config.clone())
                .store(
                    SeaOrmStore::<BundledSchema>::new(config, database)
                        .with_organization_schema::<models::Models>(),
                )
                .plugin(plugin)
                .hooks(EndpointHooks {
                    before: Some(state.clone()),
                    after: Some(state.clone()),
                })
                .build()
                .await?;
            scenario(auth, &state, &case).await?;
        } else {
            let auth = BetterAuth::new(config)
                .store(EphemeralStore::default())
                .plugin(plugin)
                .hooks(EndpointHooks {
                    before: Some(state.clone()),
                    after: Some(state.clone()),
                })
                .build()
                .await?;
            scenario(auth, &state, &case).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn request_bearing_team_lifecycle_calls_still_require_a_session() -> AuthResult<()> {
    let config = AuthConfig::new("native-team-contract-secret-at-least-thirty-two")
        .base_url("http://localhost:3000");
    let mut options = OrganizationConfig::default();
    options.teams.enabled = true;
    let auth = BetterAuth::stateless(config)
        .plugin(OrganizationPlugin::with_config(options))
        .build()
        .await?;
    for (path, body) in [
        (
            "/organization/create-team",
            json!({"name":"New","organizationId":"org"}),
        ),
        (
            "/organization/remove-team",
            json!({"teamId":"team","organizationId":"org"}),
        ),
    ] {
        for source in [
            EndpointInput {
                headers: Some(HashMap::new()),
                ..Default::default()
            },
            EndpointInput {
                request: Some(AuthRequest::new(HttpMethod::Get, "/source")),
                ..Default::default()
            },
        ] {
            let response = auth
                .call_endpoint(
                    HttpMethod::Post,
                    path,
                    EndpointInput {
                        body: Some(body.clone()),
                        ..source
                    },
                )
                .await
                .unwrap_or_else(AuthError::to_auth_response);
            assert_empty_unauthorized(&response);
        }
        let request = AuthRequest::from_parts(
            HttpMethod::Post,
            path.into(),
            HashMap::from([("content-type".into(), "application/json".into())]),
            Some(serde_json::to_vec(&body)?),
            None,
        );
        let response = auth
            .handle_request(request)
            .await
            .unwrap_or_else(AuthError::to_auth_response);
        assert_empty_unauthorized(&response);
    }
    Ok(())
}

fn assert_empty_unauthorized(response: &AuthResponse) {
    assert_eq!(response.status, 401);
    assert!(response.body.is_empty());
}
