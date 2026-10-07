#![cfg(feature = "seaorm2")]

use better_auth::config::{FieldTransforms, UserFieldTransform};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use better_auth::plugins::organization::{OrganizationConfig, OrganizationPlugin};
use better_auth::server_api::EndpointInput;
use better_auth::{AuthConfig, AuthError, AuthResult, AuthSchema, BetterAuth};
use better_auth_core::store::{EphemeralStore, OrganizationRoleKey};
use better_auth_core::user_fields::UserFieldConfig;
use better_auth_core::{
    CreateInvitation, CreateMember, CreateOrganization, CreateOrganizationRole, CreateSession,
    CreateTeam, CreateUser, FieldDate, FieldMap, HttpMethod, InvitationStatus,
};
use better_auth_seaorm::store::__private_test_support::{bundled_schema::BundledSchema, migrator};
use better_auth_seaorm::{SeaOrmStore, sea_orm::Database};
use serde_json::{Value, json};

type Events = Arc<Mutex<Vec<String>>>;

fn take(events: &Events) -> AuthResult<Vec<String>> {
    Ok(std::mem::take(
        &mut *events
            .lock()
            .map_err(|error| AuthError::internal(error.to_string()))?,
    ))
}

fn field(events: &Events, kind: &'static str, required: bool) -> UserFieldConfig {
    let events = events.clone();
    UserFieldConfig {
        required: Some(required),
        transform: Some(FieldTransforms {
            output: Some(UserFieldTransform::new(move |value| {
                let label = value.as_str().unwrap_or("undefined");
                events
                    .lock()
                    .map_err(|error| AuthError::internal(error.to_string()))?
                    .push(format!("{kind}:{label}"));
                Ok(value)
            })),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn configuration(limit: Option<f64>, events: &Events) -> (AuthConfig, OrganizationPlugin) {
    let mut config = AuthConfig::new("organization-list-contract-secret-at-least-thirty-two")
        .base_url("http://localhost:3000");
    config.logger.disabled = Some(true);
    config.advanced.database.default_find_many_limit = limit;
    let _ = config
        .user
        .fields_mut()
        .insert("username".into(), field(events, "user", false));
    let mut plugin = OrganizationConfig::default();
    plugin.teams.enabled = true;
    plugin.dynamic_access_control = true;
    for (fields, name, kind, required) in [
        (
            &mut plugin.schema.organization,
            "name",
            "organization",
            true,
        ),
        (&mut plugin.schema.member, "role", "member", true),
        (&mut plugin.schema.team, "name", "team", true),
        (&mut plugin.schema.invitation, "role", "invitation", false),
        (&mut plugin.schema.organization_role, "role", "role", true),
    ] {
        let _ = fields
            .fields_mut()
            .insert(name.into(), field(events, kind, required));
    }
    (config, OrganizationPlugin::with_config(plugin))
}

fn date(value: &str) -> AuthResult<FieldDate> {
    value
        .parse::<chrono::DateTime<chrono::Utc>>()
        .map(FieldDate::from)
        .map_err(|error: chrono::ParseError| AuthError::internal(error.to_string()))
}

async fn seed<S: AuthSchema>(auth: &BetterAuth<S>) -> AuthResult<HashMap<String, String>> {
    let store = auth.store();
    for name in ["alice", "bob", "carol"] {
        let _ = store
            .create_user(CreateUser {
                id: Some(name.into()),
                name: Some(name.into()).into(),
                email: Some(format!("{name}@example.test")),
                email_verified: Some(true),
                username: Some(Some(name.into())),
                ..Default::default()
            })
            .await?;
    }
    for suffix in ["a", "b"] {
        let id = format!("org-{suffix}");
        let mut input = CreateOrganization::new(&id, &id);
        input.id = Some(id.clone());
        let _ = store.create_organization(input).await?;
        let _ = store
            .create_member(CreateMember::new(&id, "alice", "owner"))
            .await?;
    }
    let _ = store
        .create_member(CreateMember::new("org-a", "bob", "member"))
        .await?;
    for suffix in ["a", "b"] {
        let id = format!("team-{suffix}");
        let _ = store
            .create_team(CreateTeam {
                id: Some(id.clone()),
                name: id.into(),
                organization_id: "org-a".into(),
                created_at: Some(date("2025-01-01T00:00:00Z")?),
                ..Default::default()
            })
            .await?;
    }
    for (team, user) in [("team-b", "alice"), ("team-a", "alice"), ("team-b", "bob")] {
        let _ = store.add_team_member(&team.into(), user, None).await?;
    }
    for (id, status, role, expiry) in [
        (
            "accepted",
            InvitationStatus::Accepted,
            "member",
            "2099-01-01T00:00:00Z",
        ),
        (
            "expired",
            InvitationStatus::Pending,
            "admin",
            "2020-01-01T00:00:00Z",
        ),
        (
            "fresh",
            InvitationStatus::Pending,
            "member",
            "2099-01-01T00:00:00Z",
        ),
    ] {
        let mut input =
            CreateInvitation::new("org-a", "carol@example.test", role, "alice", date(expiry)?);
        input.id = Some(id.into());
        input.status = Some(status);
        input.created_at = Some(date("2025-01-01T00:00:00Z")?);
        let _ = store.create_invitation(input).await?;
    }
    for role in ["first", "second"] {
        let _ = store
            .create_organization_role(CreateOrganizationRole {
                organization_id: "org-a".into(),
                role: role.into(),
                permission: FieldMap::new().into(),
                additional_fields: Default::default(),
            })
            .await?;
    }
    let mut cookies = HashMap::new();
    for name in ["alice", "carol"] {
        let session = store
            .create_session(CreateSession {
                user_id: name.into(),
                expires_at: date("2099-01-01T00:00:00Z")?,
                active_organization_id: Some("org-a".into()),
                additional_fields: Default::default(),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
            })
            .await?;
        let cookie = format!(
            "better-auth.session_token={}",
            better_auth_core::utils::cookie_utils::sign_cookie_value(
                &session.token,
                auth.config().signing_secret()
            )
        );
        let _ = cookies.insert(name.into(), cookie);
    }
    Ok(cookies)
}

fn property<'a>(value: &'a Value, key: &str) -> AuthResult<&'a Value> {
    value
        .get(key)
        .ok_or_else(|| AuthError::internal(format!("Expected fixture property {key}")))
}

fn full_projection(body: &Value) -> AuthResult<Value> {
    let values = |key: &str, field: &str| -> AuthResult<Vec<Value>> {
        property(body, key)?
            .as_array()
            .ok_or_else(|| AuthError::internal("Expected full organization list"))?
            .iter()
            .map(|row| property(row, field).cloned())
            .collect()
    };
    let members = values("members", "user")?
        .iter()
        .map(|user| property(user, "name").cloned())
        .collect::<AuthResult<Vec<_>>>()?;
    Ok(json!({"name":property(body, "name")?, "members":members,
        "invitations":values("invitations", "id")?, "teams":values("teams", "name")?}))
}

async fn check<S: AuthSchema>(
    auth: BetterAuth<S>,
    case: &Value,
    events: &Events,
) -> AuthResult<()> {
    let cookies = seed(&auth).await?;
    let store = auth.store();
    let record = |name: &str, result: Value| -> AuthResult<()> {
        let actual = json!({"result":result,"events":take(events)?});
        assert_eq!(
            &actual,
            property(property(case, "operations")?, name)?,
            "{} {:?} {name}",
            property(case, "backend")?,
            property(case, "limit")?
        );
        Ok(())
    };
    let _ = take(events)?;
    record(
        "organizations",
        json!(
            store
                .list_user_organizations("alice")
                .await?
                .into_iter()
                .map(|row| row.name)
                .collect::<Vec<_>>()
        ),
    )?;
    record(
        "teams",
        json!(
            store
                .list_organization_teams("org-a")
                .await?
                .into_iter()
                .map(|row| row.name)
                .collect::<Vec<_>>()
        ),
    )?;
    record(
        "userTeams",
        json!(
            store
                .list_user_teams("alice")
                .await?
                .into_iter()
                .map(|row| row.name)
                .collect::<Vec<_>>()
        ),
    )?;
    record(
        "teamMembers",
        json!(
            store
                .list_team_members("team-b")
                .await?
                .into_iter()
                .map(|row| row.user_id)
                .collect::<Vec<_>>()
        ),
    )?;
    record(
        "roles",
        json!(
            store
                .list_organization_roles("org-a")
                .await?
                .into_iter()
                .map(|row| row.role)
                .collect::<Vec<_>>()
        ),
    )?;
    record(
        "invitations",
        json!(
            store
                .list_organization_invitations("org-a")
                .await?
                .into_iter()
                .map(|row| row.id)
                .collect::<Vec<_>>()
        ),
    )?;
    let call = |path, name: &str, query| -> AuthResult<_> {
        let cookie = cookies
            .get(name)
            .cloned()
            .ok_or_else(|| AuthError::internal("Fixture session cookie is missing"))?;
        Ok(auth.call_endpoint(
            HttpMethod::Get,
            path,
            EndpointInput {
                headers: Some(HashMap::from([("cookie".into(), cookie)])),
                query,
                ..Default::default()
            },
        ))
    };
    let response = call("/organization/list-user-invitations", "carol", None)?.await?;
    let result: Vec<Value> = serde_json::from_slice(&response.body.bytes()?)?;
    record(
        "received",
        json!(
            result
                .into_iter()
                .map(|row| Ok(
                    json!({"id":property(&row, "id")?,"name":property(&row, "organizationName")?})
                ))
                .collect::<AuthResult<Vec<_>>>()?
        ),
    )?;
    let response = call(
        "/organization/get-full-organization",
        "alice",
        Some(json!({"organizationId":"org-a"})),
    )?
    .await?;
    let body: Value = serde_json::from_slice(&response.body.bytes()?)?;
    record("full", full_projection(&body)?)?;
    let response = call(
        "/organization/get-full-organization",
        "alice",
        Some(json!({"organizationSlug":"org-a"})),
    )?
    .await?;
    let body: Value = serde_json::from_slice(&response.body.bytes()?)?;
    record("fullSlug", full_projection(&body)?)?;

    assert_eq!(store.count_organization_teams("org-a").await?, 2);
    assert_eq!(store.count_team_members("team-b").await?, 2);
    assert_eq!(store.count_organization_roles("org-a").await?, 2);
    assert!(take(events)?.is_empty(), "Counts must not project records");
    let second = store
        .find_organization_role("org-a", OrganizationRoleKey::Name("second"))
        .await?
        .ok_or_else(|| AuthError::internal("Second role must be found beyond the list page"))?;
    assert_eq!(second.role, "second");
    assert_eq!(take(events)?, ["role:second"]);
    let roles = store
        .query_organization_roles("org-a", &["second".into()])
        .await?;
    assert_eq!(
        roles.into_iter().map(|role| role.role).collect::<Vec<_>>(),
        vec![better_auth_core::SchemaValue::from("second")]
    );
    assert_eq!(take(events)?, ["role:second"]);
    Ok(())
}

#[tokio::test]
async fn normal_organization_lists_match_pinned_memory_and_sqlite() -> AuthResult<()> {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/organization-lists-upstream.json"))?;
    for case in cases {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (config, plugin) = configuration(property(&case, "limit")?.as_f64(), &events);
        if property(&case, "backend")? == "sqlite" {
            let database = Database::connect("sqlite::memory:")
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?;
            migrator::run_migrations(&database)
                .await
                .map_err(|error| AuthError::internal(error.to_string()))?;
            let auth = BetterAuth::<BundledSchema>::new(config.clone())
                .store(SeaOrmStore::<BundledSchema>::new(config, database))
                .plugin(plugin)
                .build()
                .await?;
            check(auth, &case, &events).await?;
        } else {
            let auth = BetterAuth::new(config)
                .store(EphemeralStore::default())
                .plugin(plugin)
                .build()
                .await?;
            check(auth, &case, &events).await?;
        }
    }
    Ok(())
}
