#![cfg(all(feature = "axum", feature = "seaorm2"))]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "Captured fixture keys and local SQLite setup must exist; failures stop the contract."
)]

use better_auth::plugins::organization::{
    InvitationEmail, OrganizationCallbacks, OrganizationPlugin, OrganizationTeamsConfig,
};
use better_auth::{AuthBuilder, AuthConfig};
use better_auth_core::{
    AuthRequest, CreateInvitation, CreateMember, CreateOrganization, CreateSession, CreateUser,
    HttpMethod, utils::cookie_utils::sign_cookie_value,
};
use better_auth_seaorm::{
    SeaOrmStore,
    sea_orm::{ConnectionTrait, Database, DbBackend, Statement},
    store::__private_test_support::{bundled_schema::BundledSchema, migrator},
};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

const ORIGIN: &str = "http://organization-duration.test";
const PATH: &str = "/organization/invite-member";

fn timestamp(value: &Value) -> i64 {
    DateTime::parse_from_rfc3339(value.as_str().unwrap())
        .unwrap()
        .timestamp_millis()
}

fn record(row: &Value, issued_at: i64) -> Value {
    let mut fields: serde_json::Map<_, _> = [
        "email",
        "role",
        "status",
        "organizationId",
        "inviterId",
        "teamId",
    ]
    .into_iter()
    .filter_map(|field| {
        row.get(field)
            .map(|value| (field.to_owned(), value.clone()))
    })
    .collect();
    let _ = fields.insert(
        "lifetimeMillis".into(),
        json!(timestamp(&row["expiresAt"]) - issued_at),
    );
    fields.into()
}

#[tokio::test]
async fn invitation_creation_and_resend_preserve_pinned_fractional_lifetimes() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/organization-duration-1.7.6.json")).unwrap();
    let created_at: DateTime<Utc> = "2025-01-01T00:00:00Z".parse().unwrap();
    let valid_until: DateTime<Utc> = "2099-01-01T00:00:00Z".parse().unwrap();
    for expected in fixture["cases"].as_array().unwrap() {
        let name = expected["name"].as_str().unwrap();
        let operation = expected["operation"].as_str().unwrap();
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrator::run_migrations(&db).await.unwrap();
        let config =
            AuthConfig::new("ordinary-organization-duration-secret-longer-than-32-characters")
                .base_url(ORIGIN);
        let sent = Arc::new(Mutex::new(Vec::<InvitationEmail>::new()));
        let messages = sent.clone();
        let mut plugin = OrganizationPlugin::new().teams(OrganizationTeamsConfig {
            enabled: true,
            ..Default::default()
        });
        if let Some(seconds) = expected.get("configured").and_then(Value::as_f64) {
            plugin = plugin.invitation_expires_in(seconds);
        }
        let auth = AuthBuilder::new(config.clone())
            .store(SeaOrmStore::<BundledSchema>::new(config, db.clone()))
            .rate_limit(better_auth_core::middleware::RateLimitConfig {
                enabled: Some(false),
                ..Default::default()
            })
            .plugin(
                plugin.callbacks(OrganizationCallbacks::<BundledSchema>::invitation_email(
                    move |message, _| {
                        messages.lock().unwrap().push(message.clone());
                        Ok(None)
                    },
                )),
            )
            .build()
            .await
            .unwrap();
        let store = &auth.context().database;
        let _ = store
            .create_user(CreateUser {
                id: Some("owner".into()),
                name: Some("Ordinary Owner".into()).into(),
                email: Some("owner@organization-duration.test".into()),
                email_verified: Some(true),
                ..Default::default()
            })
            .await
            .unwrap();
        let mut organization =
            CreateOrganization::new("Ordinary Organization", "ordinary-organization");
        organization.id = Some("org".into());
        let _ = store.create_organization(organization).await.unwrap();
        let _ = store
            .create_member(CreateMember::new("org", "owner", "owner"))
            .await
            .unwrap();
        let session = store
            .create_session(CreateSession {
                inherited_fields: Default::default(),
                user_id: "owner".into(),
                expires_at: valid_until.into(),
                additional_fields: Default::default(),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
            })
            .await
            .unwrap();
        if operation == "resend" {
            let mut invitation = CreateInvitation::new(
                "org",
                "invitee@organization-duration.test",
                "member",
                "owner",
                valid_until.into(),
            );
            invitation.id = Some("existing-invitation".into());
            invitation.created_at = Some(created_at.into());
            let _ = store.create_invitation(invitation).await.unwrap();
        }
        let cookie = format!(
            "better-auth.session_token={}",
            sign_cookie_value(
                session.token.typed().unwrap(),
                auth.config().signing_secret(),
            )
        );
        let mut body = json!({"organizationId":"org", "email":"invitee@organization-duration.test", "role":"member"});
        if operation == "resend" {
            body["resend"] = true.into();
        }
        let request = AuthRequest::from_parts(
            HttpMethod::Post,
            format!("/api/auth{PATH}"),
            [
                ("content-type".into(), "application/json".into()),
                ("origin".into(), ORIGIN.into()),
                ("cookie".into(), cookie),
            ]
            .into(),
            Some(serde_json::to_vec(&body).unwrap()),
            None,
        )
        .with_url(format!("{ORIGIN}/api/auth{PATH}").parse().unwrap());
        let before = Utc::now().timestamp_millis();
        let response = auth.handle_request(request).await.unwrap();
        let after = Utc::now().timestamp_millis();
        assert_eq!(
            json!(response.status),
            expected["status"],
            "{name}/{operation}"
        );
        let body: Value = serde_json::from_slice(&response.body.bytes().unwrap()).unwrap();
        let rows = db.query_all_raw(Statement::from_string(DbBackend::Sqlite,
            "SELECT id, email, role, status, organization_id, inviter_id, team_id, expires_at, created_at FROM invitation".to_owned(),
        )).await.unwrap();
        assert_eq!(
            rows.len(),
            expected["records"].as_array().unwrap().len(),
            "{name}/{operation}"
        );
        let row = &rows[0];
        let expires_at: DateTime<Utc> = row.try_get("", "expires_at").unwrap();
        let lifetime = expected["records"][0]["lifetimeMillis"].as_i64().unwrap();
        assert!(
            (before + lifetime..=after + lifetime).contains(&expires_at.timestamp_millis()),
            "{name}/{operation}: expiry must equal the issuance clock plus {lifetime} milliseconds"
        );
        let issued_at = expires_at.timestamp_millis() - lifetime;
        let stored = json!({
            "id": row.try_get::<String>("", "id").unwrap(),
            "email": row.try_get::<String>("", "email").unwrap(),
            "role": row.try_get::<String>("", "role").unwrap(),
            "status": row.try_get::<String>("", "status").unwrap(),
            "organizationId": row.try_get::<String>("", "organization_id").unwrap(),
            "inviterId": row.try_get::<String>("", "inviter_id").unwrap(),
            "teamId": row.try_get::<Option<String>>("", "team_id").unwrap(),
            "expiresAt": expires_at,
            "createdAt": row.try_get::<DateTime<Utc>>("", "created_at").unwrap(),
        });
        assert_eq!(
            record(&body, issued_at),
            expected["body"],
            "{name}/{operation}"
        );
        assert_eq!(
            json!([record(&stored, issued_at)]),
            expected["records"],
            "{name}/{operation}"
        );
        assert_eq!(
            json!(
                body["id"] == stored["id"]
                    && timestamp(&body["expiresAt"]) == expires_at.timestamp_millis()
            ),
            expected["responseMatchesStored"],
            "{name}/{operation}"
        );
        let preserved = (operation == "resend").then(|| {
            stored["id"] == "existing-invitation"
                && timestamp(&stored["createdAt"]) == created_at.timestamp_millis()
        });
        assert_eq!(
            json!(preserved),
            expected["resendPreservedRecord"],
            "{name}/{operation}"
        );
        let sender: Vec<_> = sent.lock().unwrap().iter().map(|message| {
            let invitation = serde_json::to_value(&message.invitation).unwrap();
            json!({
                "invitation": record(&invitation, issued_at),
                "matchesResponse": invitation["id"] == body["id"],
                "organizationName": message.organization.name,
                "inviterName": message.inviter.name,
                "method": message.request.as_ref().map(|request| format!("{:?}", request.method).to_uppercase()),
                "path": message.request.as_ref().and_then(AuthRequest::url).map(|url| url.path()),
            })
        }).collect();
        assert_eq!(json!(sender), expected["sender"], "{name}/{operation}");
    }
}
