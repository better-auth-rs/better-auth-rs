#![cfg(feature = "seaorm2")]
#![allow(
    unreachable_pub,
    reason = "SeaORM entity derives require public generated model types"
)]

#[path = "../compat-tests/rust-server/src/organization_fields.rs"]
mod fixture;

use better_auth::__private_core::{
    store::{
        InvitationStore, MemberStore, OrganizationRoleStore, OrganizationStore, TeamStore,
        UserStore,
    },
    types::{
        CreateInvitation, CreateMember, CreateOrganization, CreateOrganizationRole, CreateTeam,
        CreateUser, UpdateOrganization, UpdateOrganizationRole, UpdateTeam,
    },
};
use better_auth::seaorm::{Database, SeaOrmStore, sea_orm::EntityTrait};
use better_auth::{
    AuthConfig,
    config::{UserFieldConfig, UserFieldType},
    plugins::organization::OrganizationConfig,
};
use better_auth_seaorm::store::__private_test_support::{
    bundled_schema::BundledSchema, migrator::run_migrations,
};
use serde_json::{Value, json};
use std::sync::Arc;

type Store = SeaOrmStore<BundledSchema, fixture::models::Models>;

fn text_policy() -> UserFieldConfig {
    UserFieldConfig {
        required: Some(true),
        input_transform: Some(Arc::new(|value| {
            Ok(value.map(|value| json!(format!("{}:in", value.as_str().unwrap()))))
        })),
        output_transform: Some(Arc::new(|value| {
            Ok(value.map(|value| json!(format!("{}:out", value.as_str().unwrap()))))
        })),
        ..Default::default()
    }
}

async fn store(config: OrganizationConfig) -> Store {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    run_migrations(&db).await.unwrap();
    fixture::create_tables(&db).await.unwrap();
    let store = SeaOrmStore::<BundledSchema>::new(
        AuthConfig::new("builtin-policies-test-secret-at-least-32-characters"),
        db,
    )
    .with_organization_schema::<fixture::models::Models>();
    store.configure_organization_fields(config.schema).unwrap();
    for id in ["owner", "recipient"] {
        let _ = store
            .create_user(CreateUser {
                id: Some(id.into()),
                email: Some(format!("{id}@example.com")),
                ..Default::default()
            })
            .await
            .unwrap();
    }
    store
}

#[tokio::test]
async fn builtin_policies_update_typed_fields_once_and_preserve_storage_mappings() {
    let mut config = OrganizationConfig::default();
    fixture::configure(&mut config);
    let _ = config.schema.organization.additional_fields.insert(
        "name".into(),
        UserFieldConfig {
            field_name: Some("name".into()),
            ..text_policy()
        },
    );
    let _ = config.schema.organization.additional_fields.insert(
        "logo".into(),
        UserFieldConfig {
            required: Some(false),
            default_value: Some(json!("default-logo")),
            ..Default::default()
        },
    );
    let _ = config
        .schema
        .member
        .additional_fields
        .insert("role".into(), text_policy());
    let _ = config
        .schema
        .invitation
        .additional_fields
        .insert("role".into(), text_policy());
    let _ = config
        .schema
        .team
        .additional_fields
        .insert("name".into(), text_policy());
    let _ = config
        .schema
        .organization_role
        .additional_fields
        .insert("role".into(), text_policy());
    let timestamp = UserFieldConfig {
        field_type: UserFieldType::Date,
        required: Some(false),
        field_name: Some("updated_at".into()),
        default_value: Some(json!("2020-01-02T03:04:05.000Z")),
        ..Default::default()
    };
    let _ = config
        .schema
        .team
        .additional_fields
        .insert("updatedAt".into(), timestamp.clone());
    let _ = config
        .schema
        .organization_role
        .additional_fields
        .insert("updatedAt".into(), timestamp);
    let _ = config.schema.organization.additional_fields.insert(
        "id".into(),
        UserFieldConfig {
            field_name: Some("ignored_id_mapping".into()),
            default_value: Some(json!("ignored-id-default")),
            input_transform: Some(Arc::new(|_| {
                Err(better_auth::AuthError::config(
                    "id input policy must not run",
                ))
            })),
            output_transform: Some(Arc::new(|_| {
                Err(better_auth::AuthError::config(
                    "id output policy must not run",
                ))
            })),
            ..Default::default()
        },
    );
    let store = store(config.clone()).await;
    let mut input = CreateOrganization::new("Acme", "acme");
    input.id = Some("actual-organization".into());
    let organization = store.create_organization(input).await.unwrap();
    assert_eq!(organization.id, "actual-organization");
    assert_eq!(organization.name, "Acme:in:out");
    assert_eq!(organization.logo.as_deref(), Some("default-logo"));
    assert!(!organization.additional_fields.contains_key("name"));
    assert_eq!(
        fixture::models::organization::Entity::find_by_id(&organization.id)
            .one(store.connection())
            .await
            .unwrap()
            .unwrap()
            .name,
        "Acme:in"
    );
    let organization = store
        .update_organization(
            &organization.id,
            UpdateOrganization {
                name: Some("Updated".into()),
                logo: Some(None),
                metadata: Some(Value::Null),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(organization.name, "Updated:in:out");
    assert_eq!(organization.logo, None);
    assert_eq!(organization.metadata, Some(Value::Null));
    let member = store
        .create_member(CreateMember::new(&organization.id, "owner", "owner"))
        .await
        .unwrap();
    assert_eq!(member.role, "owner:in:out");
    assert!(!member.additional_fields.contains_key("role"));
    assert_eq!(
        store
            .update_member_role(&member.id, "admin")
            .await
            .unwrap()
            .role,
        "admin:in:out"
    );
    let invitation = store
        .create_invitation(CreateInvitation::new(
            &organization.id,
            "recipient@example.com",
            "member",
            "owner",
            chrono::Utc::now() + chrono::Duration::days(1),
        ))
        .await
        .unwrap();
    assert_eq!(invitation.role, "member:in:out");
    assert!(!invitation.additional_fields.contains_key("role"));
    assert_eq!(
        store
            .get_invitation_by_id(&invitation.id)
            .await
            .unwrap()
            .unwrap()
            .role,
        invitation.role
    );
    let team = store
        .create_team(CreateTeam {
            name: "Engineering".into(),
            organization_id: organization.id.clone(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(team.name, "Engineering:in:out");
    assert!(!team.additional_fields.contains_key("name"));
    let default_date: chrono::DateTime<chrono::Utc> = "2020-01-02T03:04:05Z".parse().unwrap();
    assert_eq!(team.updated_at, Some(default_date));
    let team = store
        .update_team(
            &team.id,
            UpdateTeam {
                name: Some("Platform".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(team.name, "Platform:in:out");
    assert_eq!(team.updated_at, Some(default_date));
    let role = store
        .create_organization_role(CreateOrganizationRole {
            organization_id: organization.id.clone(),
            role: "editor".into(),
            permission: json!({"project":["read"]}),
            additional_fields: Default::default(),
        })
        .await
        .unwrap();
    assert_eq!(role.role, "editor:in:out");
    assert!(!role.additional_fields.contains_key("role"));
    assert_eq!(role.updated_at, Some(default_date));
    let role = store
        .update_organization_role(
            &role.id,
            UpdateOrganizationRole {
                role: Some("writer".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(role.role, "writer:in:out");
    assert_eq!(role.updated_at, Some(default_date));
    let date: chrono::DateTime<chrono::Utc> = "2022-03-04T05:06:07Z".parse().unwrap();
    config
        .schema
        .team
        .additional_fields
        .get_mut("updatedAt")
        .unwrap()
        .on_update = Some(Arc::new(move || json!(date)));
    store.configure_organization_fields(config.schema).unwrap();
    assert_eq!(
        store
            .update_team(&team.id, UpdateTeam::default())
            .await
            .unwrap()
            .updated_at,
        Some(date)
    );
    fixture::reset(store.connection()).await.unwrap();
}

#[tokio::test]
async fn builtin_output_type_errors_and_core_column_remaps_fail_explicitly() {
    let mut config = OrganizationConfig::default();
    fixture::configure(&mut config);
    let store = store(config.clone()).await;
    for (name, target) in [("name", "slug"), ("name", "storedLabel"), ("extra", "name")] {
        let mut invalid = config.clone();
        let _ = invalid.schema.organization.additional_fields.insert(
            name.into(),
            UserFieldConfig {
                required: Some(true),
                field_name: Some(target.into()),
                ..Default::default()
            },
        );
        let error = store
            .configure_organization_fields(invalid.schema)
            .unwrap_err();
        assert!(
            error.to_string().contains("different typed field"),
            "{error}"
        );
    }
    let _ = config.schema.organization.additional_fields.insert(
        "name".into(),
        UserFieldConfig {
            required: Some(true),
            output_transform: Some(Arc::new(|_| Ok(Some(json!(12))))),
            ..Default::default()
        },
    );
    store
        .configure_organization_fields(config.schema.clone())
        .unwrap();
    let error = store
        .create_organization(CreateOrganization::new("Saved", "saved"))
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("name output is incompatible"),
        "{error}"
    );
    let _ = config.schema.organization.additional_fields.remove("name");
    store
        .configure_organization_fields(config.schema.clone())
        .unwrap();
    let organization = store
        .get_organization_by_slug("saved")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(organization.name, "Saved");
    let _ = config.schema.organization.additional_fields.insert(
        "logo".into(),
        UserFieldConfig {
            required: Some(false),
            output_transform: Some(Arc::new(|_| Ok(None))),
            ..Default::default()
        },
    );
    store
        .configure_organization_fields(config.schema.clone())
        .unwrap();
    let error = store.get_organization_by_slug("saved").await.unwrap_err();
    assert!(
        error.to_string().contains("logo output is undefined"),
        "{error}"
    );
    let _ = config.schema.organization.additional_fields.remove("logo");
    let _ = config.schema.invitation.additional_fields.insert(
        "status".into(),
        UserFieldConfig {
            required: Some(true),
            output_transform: Some(Arc::new(|_| Ok(Some(json!("unrecognized"))))),
            ..Default::default()
        },
    );
    store.configure_organization_fields(config.schema).unwrap();
    let error = store
        .create_invitation(CreateInvitation::new(
            &organization.id,
            "recipient@example.com",
            "member",
            "owner",
            chrono::Utc::now() + chrono::Duration::days(1),
        ))
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("status output is incompatible"),
        "{error}"
    );
    fixture::reset(store.connection()).await.unwrap();
}
