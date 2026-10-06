use super::*;
use better_auth::config::{FieldTransforms, UserFieldTransform};
use better_auth::{
    __private_core::{
        CreateApiKey, CreateDeviceCode, Member, UpdateDeviceCode, UpdateTeam,
        organization_fields::OrganizationFields, store::OrganizationStore,
    },
    prelude::{CreateMember, CreateOrganization, CreateTeam, CreateTwoFactor},
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

pub(super) async fn reference_writes<
    S: AuthSchema,
    O: SeaOrmOrganizationSchema,
    P: SeaOrmPluginSchema,
>(
    database: DatabaseConnection,
    generation: IdGeneration,
) where
    S::User: SeaOrmUserModel,
    S::Session: SeaOrmSessionModel,
    S::Account: SeaOrmAccountModel,
    S::Verification: SeaOrmVerificationModel,
{
    let serial = matches!(generation, IdGeneration::Serial);
    let database_ids = matches!(generation, IdGeneration::Database);
    let mut config = AuthConfig::new("serial-reference-writes-secret-at-least-32-characters");
    config.advanced.database.generate_id = Some(generation);
    let auth = BetterAuth::<S>::new(config.clone())
        .store(
            SeaOrmStore::<S>::new(config, database)
                .with_organization_schema::<O>()
                .with_plugin_schema::<P>(),
        )
        .build()
        .await
        .unwrap();
    let store = auth.store();
    let user = store
        .create_user(
            CreateUser::new()
                .with_name("Reference owner")
                .with_email("reference-owner@catalog.test"),
        )
        .await
        .unwrap();
    let owner = user.id.typed().unwrap();
    let alias = if serial {
        format!("0x{:x}", owner.parse::<u64>().unwrap())
    } else {
        owner.clone()
    };
    let factor = store
        .create_two_factor(CreateTwoFactor {
            additional_fields: Default::default(),
            user_id: alias.clone(),
            secret: "0x10".into(),
            backup_codes: "1e1".into(),
            verified: false,
        })
        .await
        .unwrap();
    assert_eq!(factor.user_id, *owner);
    assert_eq!(factor.secret, "0x10");
    assert_eq!(factor.backup_codes, "1e1");
    for invalid in ["", "invalid-id", "2147483647"] {
        assert!(
            store
                .create_two_factor(CreateTwoFactor {
                    additional_fields: Default::default(),
                    user_id: invalid.into(),
                    secret: "invalid".into(),
                    backup_codes: "unused".into(),
                    verified: false,
                })
                .await
                .is_err()
        );
    }
    if database_ids {
        assert!(
            store
                .create_two_factor(CreateTwoFactor {
                    additional_fields: Default::default(),
                    user_id: format!("0x{:x}", owner.parse::<u64>().unwrap()),
                    secret: "literal".into(),
                    backup_codes: "unused".into(),
                    verified: false,
                })
                .await
                .is_err()
        );
    }
    let organization = store
        .create_organization(CreateOrganization::new("Alias A", "alias-a"))
        .await
        .unwrap();
    let destination = store
        .create_organization(CreateOrganization::new("Alias B", "alias-b"))
        .await
        .unwrap();
    let org_id = organization.id.typed().unwrap();
    let org_alias = if serial {
        format!(" {org_id} ")
    } else {
        org_id.clone()
    };
    let target_id = destination.id.typed().unwrap();
    let target_alias = if serial {
        format!("{target_id}e0")
    } else {
        target_id.clone()
    };
    let team = store
        .create_team(CreateTeam {
            name: "Alias team".into(),
            organization_id: org_alias.clone().into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(team.organization_id, organization.id);
    let changed = store
        .update_team(
            team.id.typed().unwrap(),
            UpdateTeam {
                organization_id: Some(target_alias),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(changed.organization_id, destination.id);
    let member_alias = if serial {
        format!("{owner}e0")
    } else {
        owner.clone()
    };
    let transforms = Arc::new(AtomicUsize::new(0));
    let observed = transforms.clone();
    let transformed_owner = alias.clone();
    let mut fields = OrganizationFields::default();
    fields.member.fields_mut().insert(
        "sponsor".into(),
        UserFieldConfig {
            required: Some(false),
            field_name: Some("sponsor_id".into()),
            references: Some(UserFieldReference {
                model: "user".into(),
                field: "id".into(),
            }),
            transform: Some(FieldTransforms {
                input: Some(UserFieldTransform::new(move |value| {
                    if value == Some(json!("@owner")) {
                        observed.fetch_add(1, Ordering::SeqCst);
                        Ok(Some(json!(transformed_owner)))
                    } else {
                        Ok(value)
                    }
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    fields.member.fields_mut().insert(
        "externalId".into(),
        UserFieldConfig {
            required: Some(false),
            field_name: Some("external_id".into()),
            ..Default::default()
        },
    );
    store.configure_organization_fields(fields.clone()).unwrap();
    let mut create = CreateMember::new(&org_alias, &member_alias, "member");
    create.additional_fields = [
        ("sponsor".into(), json!("@owner")),
        ("externalId".into(), json!("0x10")),
    ]
    .into_iter()
    .collect();
    let member = store.create_member(create).await.unwrap();
    assert_eq!(member.organization_id, organization.id);
    assert_eq!(member.user_id, user.id);
    assert_eq!(member.additional_fields["sponsor"], json!(owner));
    assert_eq!(member.additional_fields["externalId"], json!("0x10"));
    assert_eq!(transforms.load(Ordering::SeqCst), 1);
    let mut missing = CreateMember::new(&org_alias, owner, "member");
    missing.user_id = Default::default();
    assert!(store.create_member(missing).await.is_err());
    if serial {
        fields.member.fields_mut().insert(
            "userId".into(),
            UserFieldConfig {
                field_name: Some("user_id".into()),
                ..Default::default()
            },
        );
        store.configure_organization_fields(fields).unwrap();
        assert!(
            store
                .create_member(CreateMember::new(target_id, &alias, "member"))
                .await
                .is_err()
        );
    }
    let device = store
        .create_device_code(CreateDeviceCode {
            additional_fields: Default::default(),
            device_code: "alias-device".into(),
            user_code: "0x10".into(),
            user_id: None,
            expires_at: user.created_at + std::time::Duration::from_secs(300),
            status: "pending".into(),
            last_polled_at: None,
            polling_interval: Some(5.0),
            client_id: None,
            scope: Default::default(),
        })
        .await
        .unwrap();
    assert_eq!(device.user_id, None);
    let changed = store
        .update_device_code(
            &device.id,
            UpdateDeviceCode {
                user_id: Some(Some(alias.clone())),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(changed.user_id.as_ref(), Some(owner));
    assert_eq!(changed.user_code, "0x10");
    assert!(
        store
            .update_device_code_if_status(
                &device.id,
                "pending",
                UpdateDeviceCode {
                    user_id: Some(None),
                    ..Default::default()
                }
            )
            .await
            .unwrap()
    );
    assert!(
        store
            .update_device_code_if_status(
                &device.id,
                "pending",
                UpdateDeviceCode {
                    user_id: Some(Some(alias)),
                    ..Default::default()
                }
            )
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .get_device_code_by_device_code("alias-device")
            .await
            .unwrap()
            .unwrap()
            .user_id
            .as_ref(),
        Some(owner)
    );
    let key = store
        .create_api_key(CreateApiKey {
            reference_id: "0x10".into(),
            config_id: "default".into(),
            name: None,
            prefix: None,
            key_hash: "literal-owner-key".into(),
            start: None,
            expires_at: None,
            remaining: None,
            rate_limit_enabled: false,
            rate_limit_time_window: None,
            rate_limit_max: None,
            refill_interval: None,
            refill_amount: None,
            permissions: None,
            metadata: None,
            enabled: true,
        })
        .await
        .unwrap();
    assert_eq!(key.reference_id, "0x10");
}

#[tokio::test]
async fn database_mode_preserves_distinct_text_reference_ids() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    database::create_auth_tables(&db).await.unwrap();
    let mut config = AuthConfig::new("database-literal-reference-secret-at-least-32-characters");
    config.advanced.database.generate_id = Some(IdGeneration::Database);
    let store = SeaOrmStore::<database::AppAuthSchema>::new(config, db)
        .with_organization_schema::<database::AppOrganizationSchema>()
        .with_plugin_schema::<database::AppPluginSchema>();
    use better_auth::__private_core::store::{MemberStore, UserStore};
    for id in ["1", "0x1"] {
        let mut user = CreateUser::new()
            .with_name("Literal")
            .with_email(format!("literal-{id}@catalog.test"));
        user.id = Some(id.into());
        assert_eq!(
            store.create_user(user).await.unwrap().id.typed().unwrap(),
            id
        );
    }
    for id in ["2", "0x2"] {
        let mut organization = CreateOrganization::new("Literal", id);
        organization.id = Some(id.into());
        store.create_organization(organization).await.unwrap();
    }
    let member = store
        .insert_member(Member {
            id: "literal-member".into(),
            organization_id: "0x2".into(),
            user_id: "0x1".into(),
            role: "member".into(),
            created_at: better_auth::seaorm::__private_chrono::Utc::now().into(),
            additional_fields: Default::default(),
        })
        .await
        .unwrap();
    assert_eq!(member.user_id.typed().unwrap(), "0x1");
    assert_eq!(member.organization_id.typed().unwrap(), "0x2");
    assert!(store.get_member("0x2", "0x1").await.unwrap().is_some());
    assert!(store.get_member("2", "1").await.unwrap().is_none());
}
