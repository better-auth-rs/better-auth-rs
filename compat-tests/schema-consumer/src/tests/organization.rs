use std::{collections::HashMap, sync::Arc};

use axum::{Router, http::StatusCode};
use better_auth::{
    AuthConfig, BetterAuth,
    config::{UserFieldConfig, UserFieldType},
    integrations::axum::AxumIntegration,
    plugins::{
        EmailPasswordPlugin, SessionManagementPlugin,
        organization::{OrganizationConfig, OrganizationPlugin, OrganizationTeamsConfig},
    },
    seaorm::{
        Database, SeaOrmStore,
        sea_orm::{ConnectionTrait, EntityTrait, PaginatorTrait},
    },
};
use serde_json::{Value, json};

use super::request;

mod generated {
    include!(env!("BETTER_AUTH_ORGANIZATION_SCHEMA"));
}

fn optional(field_type: UserFieldType) -> UserFieldConfig {
    UserFieldConfig {
        field_type,
        required: Some(false),
        ..Default::default()
    }
}

async fn post(router: &Router, path: &str, body: Value, token: &str) -> Value {
    let (status, response) = request(router, path, Some(body), Some(token)).await;
    assert_eq!(status, StatusCode::OK, "{path}: {response}");
    response
}

#[tokio::test]
async fn generated_organization_models_persist_mapped_fields_and_enforce_constraints() {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    generated::create_auth_tables(&database).await.unwrap();
    let mut organization = OrganizationConfig {
        teams: OrganizationTeamsConfig {
            enabled: true,
            ..Default::default()
        },
        dynamic_access_control: true,
        ac: Some(HashMap::from([(
            "organization".to_owned(),
            vec!["update".to_owned()],
        )])),
        ..Default::default()
    };
    organization.schema.organization.additional_fields = [
        ("label", UserFieldType::String),
        (
            "category",
            UserFieldType::Enum(vec!["small".into(), "large".into()]),
        ),
        ("joinedAt", UserFieldType::Date),
        ("tags", UserFieldType::StringArray),
        ("scores", UserFieldType::NumberArray),
        ("payload", UserFieldType::Json),
        ("enabled", UserFieldType::Boolean),
        ("score", UserFieldType::Number),
    ]
    .into_iter()
    .map(|(name, field_type)| (name.to_owned(), optional(field_type)))
    .collect();
    organization.schema.organization.additional_fields.insert(
        "name".to_owned(),
        UserFieldConfig {
            field_name: Some("organization_name".to_owned()),
            required: Some(true),
            ..Default::default()
        },
    );
    organization.schema.organization.additional_fields.insert(
        "logo".to_owned(),
        UserFieldConfig {
            field_name: Some("logo_url".to_owned()),
            ..optional(UserFieldType::String)
        },
    );
    organization
        .schema
        .organization
        .additional_fields
        .get_mut("label")
        .unwrap()
        .field_name = Some("stored_label".to_owned());
    organization
        .schema
        .organization
        .additional_fields
        .get_mut("joinedAt")
        .unwrap()
        .default_value = Some(json!("2026-01-02T03:04:05.000Z"));
    organization.schema.member.additional_fields.insert(
        "badge".to_owned(),
        UserFieldConfig {
            default_value: Some(json!("founder")),
            ..optional(UserFieldType::String)
        },
    );
    organization
        .schema
        .invitation
        .additional_fields
        .insert("note".to_owned(), optional(UserFieldType::String));
    organization
        .schema
        .team
        .additional_fields
        .insert("region".to_owned(), optional(UserFieldType::String));
    organization
        .schema
        .organization_role
        .additional_fields
        .insert("description".to_owned(), optional(UserFieldType::String));
    let mut config = AuthConfig::new("organization-consumer-secret-at-least-32-characters")
        .base_url("http://localhost:3000");
    config.session.bearer = Some(Default::default());
    let store = SeaOrmStore::<generated::AppAuthSchema>::new(config.clone(), database.clone())
        .with_organization_schema::<generated::AppOrganizationSchema>();
    let auth = Arc::new(
        BetterAuth::<generated::AppAuthSchema>::new(config)
            .store(store)
            .plugin(EmailPasswordPlugin::new().enable_signup(true))
            .plugin(SessionManagementPlugin::new())
            .plugin(OrganizationPlugin::with_config(organization))
            .build()
            .await
            .unwrap(),
    );
    let router = Router::new()
        .nest("/auth", auth.clone().axum_router())
        .with_state(auth);
    let (status, signup) = request(
        &router,
        "/auth/sign-up/email",
        Some(json!({"email":"organization@example.com","password":"test-password-123","name":"Owner"})),
        None,
    ).await;
    assert_eq!(status, StatusCode::OK, "{signup}");
    let token = signup["token"].as_str().unwrap();
    let created = post(
        &router,
        "/auth/organization/create",
        json!({
            "name":"Mapped organization", "slug":"mapped", "label":"stored", "logo":"https://example.com/logo.svg",
        "category":"small",
            "tags":["one","two"], "scores":[1.25,2.5], "payload":{"nested":true},
            "enabled":true, "score":4.5
        }),
        token,
    )
    .await;
    let id = created["id"].as_str().unwrap();
    assert_eq!(created["label"], "stored");
    let row = generated::organization::Entity::find_by_id(id)
        .one(&database)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.name, "Mapped organization");
    assert_eq!(row.logo.as_deref(), Some("https://example.com/logo.svg"));
    assert_eq!(row.label.as_deref(), Some("stored"));
    assert_eq!(row.category.as_deref(), Some("small"));
    assert_eq!(
        row.joined_at.unwrap().to_rfc3339(),
        "2026-01-02T03:04:05+00:00"
    );
    assert_eq!(row.tags.unwrap().0, ["one", "two"]);
    assert_eq!(row.scores.unwrap().0, [1.25, 2.5]);
    assert_eq!(row.payload, Some(json!({"nested":true})));
    assert_eq!(row.enabled, Some(true));
    assert_eq!(row.score, Some(4.5));
    assert_eq!(row.metadata, None);
    let session = generated::session::Entity::find()
        .one(&database)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.active_organization_id.as_deref(), Some(id));
    let member = generated::member::Entity::find()
        .one(&database)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(member.badge.as_deref(), Some("founder"));
    assert_eq!(
        generated::team_member::Entity::find()
            .count(&database)
            .await
            .unwrap(),
        1
    );

    post(
        &router,
        "/auth/organization/update",
        json!({"organizationId":id,"data":{"label":"updated","metadata":{}}}),
        token,
    )
    .await;
    let row = generated::organization::Entity::find_by_id(id)
        .one(&database)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.label.as_deref(), Some("updated"));
    assert_eq!(row.tags.unwrap().0, ["one", "two"]);
    assert_eq!(row.metadata, Some(json!({})));
    let team = post(
        &router,
        "/auth/organization/create-team",
        json!({"organizationId":id,"name":"Engineering","region":"east"}),
        token,
    )
    .await;
    let team_id = team["id"].as_str().unwrap();
    assert_eq!(
        generated::team::Entity::find_by_id(team_id)
            .one(&database)
            .await
            .unwrap()
            .unwrap()
            .region
            .as_deref(),
        Some("east")
    );
    let invitation = post(
        &router,
        "/auth/organization/invite-member",
        json!({"organizationId":id,"email":"invitee@example.com","role":"member","note":"welcome"}),
        token,
    )
    .await;
    assert_eq!(
        generated::invitation::Entity::find_by_id(invitation["id"].as_str().unwrap())
            .one(&database)
            .await
            .unwrap()
            .unwrap()
            .note
            .as_deref(),
        Some("welcome")
    );
    let role = post(&router, "/auth/organization/create-role", json!({"organizationId":id,"role":"editor","permission":{"organization":["update"]},"additionalFields":{"description":"Can edit"}}), token).await;
    assert_eq!(
        generated::organization_role::Entity::find_by_id(role["roleData"]["id"].as_str().unwrap())
            .one(&database)
            .await
            .unwrap()
            .unwrap()
            .description
            .as_deref(),
        Some("Can edit")
    );
    post(
        &router,
        "/auth/organization/update-role",
        json!({"organizationId":id,"roleId":role["roleData"]["id"],"data":{"description":null}}),
        token,
    )
    .await;
    assert_eq!(
        generated::organization_role::Entity::find_by_id(role["roleData"]["id"].as_str().unwrap())
            .one(&database)
            .await
            .unwrap()
            .unwrap()
            .description,
        None,
    );

    for (statement, expected) in [
        (
            "INSERT INTO app_organizations (id, organization_name, slug, created_at, updated_at) SELECT 'duplicate-name', organization_name, 'different-slug', created_at, updated_at FROM app_organizations LIMIT 1",
            "UNIQUE constraint failed: app_organizations.organization_name",
        ),
        (
            "UPDATE app_members SET workspace_id = 'missing'",
            "FOREIGN KEY constraint failed",
        ),
        (
            "INSERT INTO app_team_members (id, group_id, subject_id, created_at, link_key) SELECT 'duplicate', group_id, subject_id, created_at, link_key FROM app_team_members LIMIT 1",
            "UNIQUE constraint failed",
        ),
    ] {
        let error = database.execute_unprepared(statement).await.unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
    }
    database.execute_unprepared("INSERT INTO app_organizations (id, organization_name, slug, created_at, updated_at) SELECT 'duplicate-slug', 'Different name', slug, created_at, updated_at FROM app_organizations LIMIT 1").await.unwrap();
    database
        .execute_unprepared("DELETE FROM app_organizations WHERE id = 'duplicate-slug'")
        .await
        .unwrap();
    post(
        &router,
        "/auth/organization/delete",
        json!({"organizationId":id}),
        token,
    )
    .await;
    assert_eq!(
        generated::organization::Entity::find()
            .count(&database)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        generated::member::Entity::find()
            .count(&database)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        generated::invitation::Entity::find()
            .count(&database)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        generated::team::Entity::find()
            .count(&database)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        generated::team_member::Entity::find()
            .count(&database)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        generated::organization_role::Entity::find()
            .count(&database)
            .await
            .unwrap(),
        0
    );
    database.close().await.unwrap();
}
