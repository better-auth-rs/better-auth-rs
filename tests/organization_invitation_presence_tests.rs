#![cfg(feature = "seaorm2")]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "The pinned ordinary invitation fixture requires exact seeded rows and response shapes."
)]

use async_trait::async_trait;
use better_auth::plugins::organization::{
    InvitationEmail, OrganizationConfig, OrganizationPlugin, SendInvitationEmail,
    hooks::{OrganizationHooks, OrganizationInvitationEvent},
};
use better_auth::{AuthConfig, AuthError, AuthResult, AuthSchema, BetterAuth};
use better_auth_core::store::EphemeralStore;
use better_auth_core::user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform};
use better_auth_core::{
    AuthRequest, CreateMember, CreateOrganization, CreateSession, CreateUser, FieldValue,
    HttpMethod,
};
use better_auth_seaorm::store::__private_test_support::{bundled_schema::BundledSchema, migrator};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, DbBackend, Statement},
};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

const ORIGIN: &str = "http://invitation-presence.test";
const SECRET: &str = "ordinary-invitation-presence-secret-at-least-thirty-two-characters";

fn invitation(value: &impl Serialize) -> AuthResult<Value> {
    let mut value = serde_json::to_value(value)?;
    let object = value.as_object_mut().unwrap();
    for key in ["id", "createdAt", "expiresAt"] {
        let _ = object.remove(key);
    }
    Ok(value)
}

#[derive(Default)]
struct State {
    events: Mutex<Vec<Value>>,
}
impl State {
    fn record(&self, phase: &str, value: &impl Serialize) -> AuthResult<()> {
        self.events
            .lock()
            .unwrap()
            .push(json!([phase, invitation(value)?]));
        Ok(())
    }
    fn take(&self) -> Vec<Value> {
        std::mem::take(&mut *self.events.lock().unwrap())
    }
}
#[async_trait]
impl SendInvitationEmail for State {
    async fn send(&self, email: &InvitationEmail) -> AuthResult<()> {
        self.record("sender", &email.invitation)
    }
}
#[async_trait]
impl OrganizationHooks for State {
    async fn after_create_invitation(
        &self,
        event: OrganizationInvitationEvent<'_>,
    ) -> AuthResult<()> {
        self.record("after-create", event.invitation)
    }
}

fn options(mode: &str, state: &Arc<State>) -> OrganizationConfig {
    let mut options = OrganizationConfig {
        send_invitation_email: Some(state.clone()),
        hooks: Some(state.clone()),
        ..Default::default()
    };
    options.teams.enabled = mode == "teams";
    if matches!(mode, "declared" | "display") {
        let _ = options.schema.invitation.fields_mut().insert(
            "teamId".into(),
            UserFieldConfig {
                required: Some(false),
                transform: (mode == "display").then(|| FieldTransforms {
                    output: Some(UserFieldTransform::new(|value| {
                        Ok(if value.is_null() {
                            FieldValue::from("team-display")
                        } else {
                            value
                        })
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
    }
    options
}

async fn request<S: AuthSchema>(
    auth: &BetterAuth<S>,
    cookie: &str,
    path: &str,
    body: Option<Value>,
    query: Option<Value>,
) -> AuthResult<(u16, Value)> {
    let path = format!("/api/auth/organization/{path}");
    let response = auth
        .handle_request(
            AuthRequest::from_parts(
                if body.is_some() {
                    HttpMethod::Post
                } else {
                    HttpMethod::Get
                },
                path.clone(),
                HashMap::from([
                    ("content-type".into(), "application/json".into()),
                    ("origin".into(), ORIGIN.into()),
                    ("cookie".into(), cookie.into()),
                ]),
                body.map(|body| serde_json::to_vec(&body)).transpose()?,
                query,
            )
            .with_url(format!("{ORIGIN}{path}").parse().unwrap()),
        )
        .await?;
    Ok((
        response.status,
        serde_json::from_slice(&response.body.bytes()?)?,
    ))
}

async fn scenario<S: AuthSchema>(
    auth: BetterAuth<S>,
    state: &State,
    case: &Value,
) -> AuthResult<()> {
    let store = &auth.context().database;
    for (id, name) in [
        ("owner", "Ordinary Owner"),
        ("recipient", "Ordinary Recipient"),
    ] {
        let _ = store
            .create_user(CreateUser {
                id: Some(id.into()),
                name: Some(name.to_owned()).into(),
                email: Some(format!("{id}@invitation-presence.test")),
                email_verified: Some(true),
                ..Default::default()
            })
            .await?;
    }
    let mut organization =
        CreateOrganization::new("Ordinary Organization", "ordinary-organization");
    organization.id = Some("org".into());
    let _ = store.create_organization(organization).await?;
    let mut cookies = HashMap::new();
    for id in ["owner", "recipient"] {
        let session = store
            .create_session(CreateSession {
                inherited_fields: Default::default(),
                user_id: id.into(),
                expires_at: "2099-01-01T00:00:00Z"
                    .parse::<chrono::DateTime<chrono::Utc>>()
                    .unwrap()
                    .into(),
                active_organization_id: Some("org".into()),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                additional_fields: Default::default(),
            })
            .await?;
        let _ = cookies.insert(
            id,
            format!(
                "better-auth.session_token={}",
                better_auth_core::utils::cookie_utils::sign_cookie_value(
                    session.token.typed().unwrap(),
                    auth.config().signing_secret()
                )
            ),
        );
    }
    let _ = store
        .create_member(CreateMember::new("org", "owner", "owner"))
        .await?;
    let body = json!({"organizationId":"org","email":"recipient@invitation-presence.test","role":"member"});
    let (created_status, created) = request(
        &auth,
        &cookies["owner"],
        "invite-member",
        Some(body.clone()),
        None,
    )
    .await?;
    let create_events = state.take();
    let mut resend_body = body;
    resend_body["resend"] = json!(true);
    let (resent_status, resent) = request(
        &auth,
        &cookies["owner"],
        "invite-member",
        Some(resend_body),
        None,
    )
    .await?;
    let resend_events = state.take();
    let (found_status, found) = request(
        &auth,
        &cookies["recipient"],
        "get-invitation",
        None,
        Some(json!({"id":created["id"]})),
    )
    .await?;
    let (listed_status, listed) = request(
        &auth,
        &cookies["owner"],
        "list-invitations",
        None,
        Some(json!({"organizationId":"org"})),
    )
    .await?;
    let (received_status, received) = request(
        &auth,
        &cookies["recipient"],
        "list-user-invitations",
        None,
        None,
    )
    .await?;
    let (full_status, full) = request(
        &auth,
        &cookies["owner"],
        "get-full-organization",
        None,
        Some(json!({"organizationId":"org"})),
    )
    .await?;
    let rows = store.list_organization_invitations("org").await?;
    let result = json!({
        "backend":case["backend"],"mode":case["mode"],
        "create":{"status":created_status,"body":invitation(&created)?,"events":create_events},
        "resend":{"status":resent_status,"body":invitation(&resent)?,"events":resend_events},
        "get":{"status":found_status,"body":invitation(&found)?},
        "list":{"status":listed_status,"body":listed.as_array().unwrap().iter().map(invitation).collect::<AuthResult<Vec<_>>>()?},
        "received":{"status":received_status,"body":received.as_array().unwrap().iter().map(invitation).collect::<AuthResult<Vec<_>>>()?},
        "full":{"status":full_status,"invitations":full["invitations"].as_array().unwrap().iter().map(invitation).collect::<AuthResult<Vec<_>>>()?},
        "onePersistedInvitation":rows.len()==1,
        "sameInvitation":rows.len()==1 && rows[0].id.json()?.as_ref()==Some(&created["id"]) && resent["id"]==created["id"],
    });
    assert_eq!(&result, case);
    Ok(())
}

#[tokio::test]
async fn invitation_display_presence_matches_pinned_normal_flows() -> AuthResult<()> {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/organization-invitation-presence-1.7.6.json"
    ))?;
    for case in fixture["cases"].as_array().unwrap() {
        let state = Arc::new(State::default());
        let config = AuthConfig::new(SECRET).base_url(ORIGIN);
        let plugin =
            OrganizationPlugin::with_config(options(case["mode"].as_str().unwrap(), &state));
        if case["backend"] == "sqlite" {
            let database = Database::connect("sqlite::memory:")
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?;
            migrator::run_migrations(&database)
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?;
            let auth = BetterAuth::<BundledSchema>::new(config.clone())
                .store(SeaOrmStore::<BundledSchema>::new(config, database.clone()))
                .plugin(plugin)
                .rate_limit(better_auth_core::middleware::RateLimitConfig {
                    enabled: Some(false),
                    ..Default::default()
                })
                .build()
                .await?;
            scenario(auth, &state, case).await?;
            let row = database
                .query_one_raw(Statement::from_string(
                    DbBackend::Sqlite,
                    "SELECT team_id FROM invitation".to_owned(),
                ))
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?
                .unwrap();
            assert_eq!(row.try_get::<Option<String>>("", "team_id").unwrap(), None);
        } else {
            let auth = BetterAuth::new(config)
                .store(EphemeralStore::default())
                .plugin(plugin)
                .rate_limit(better_auth_core::middleware::RateLimitConfig {
                    enabled: Some(false),
                    ..Default::default()
                })
                .build()
                .await?;
            scenario(auth, &state, case).await?;
        }
    }
    Ok(())
}
