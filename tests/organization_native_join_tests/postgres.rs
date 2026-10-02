use super::*;
use better_auth_core::CreateMember;
use better_auth_core::store::{
    InvitationStore, MemberStore, OrganizationStore, TeamStore, UserStore,
};
use better_auth_core::user_fields::UserConfig;
use better_auth_seaorm::sea_orm::ConnectOptions;

async fn check_full_read(db: DatabaseConnection) {
    let mut config = AuthConfig::default();
    config.advanced.database.joins = Some(true);
    let store =
        SeaOrmStore::<BundledSchema>::new(config, db).with_organization_schema::<models::Models>();
    let fields = UserConfig {
        additional_fields: Some(
            [(
                "label".into(),
                UserFieldConfig {
                    required: Some(false),
                    field_name: Some("stored_label".into()),
                    ..Default::default()
                },
            )]
            .into(),
        ),
    };
    store
        .configure_organization_fields(OrganizationFields {
            member: fields.clone(),
            invitation: fields.clone(),
            team: fields,
            ..Default::default()
        })
        .unwrap();
    let owner = store
        .create_user(
            CreateUser::new()
                .with_name("PG Owner")
                .with_email("owner@ordinary-native-org.test"),
        )
        .await
        .unwrap();
    let organization = store
        .create_organization(
            CreateOrganization::new("PG Organization", "pg-ordinary").with_logo("PG Logo"),
        )
        .await
        .unwrap();
    let org_id = organization.id.typed().unwrap().clone();
    let owner_id = owner.id.typed().unwrap().clone();
    let mut input = CreateMember::new(&org_id, &owner_id, "member");
    let _ = input
        .additional_fields
        .insert("label".into(), json!("PG Member"));
    let member = store.create_member(input).await.unwrap();
    let mut input = CreateInvitation::new(
        &org_id,
        "recipient@ordinary-native-org.test",
        "member",
        &owner_id,
        "2099-01-01T00:00:00Z".parse().unwrap(),
    );
    let _ = input
        .additional_fields
        .insert("label".into(), json!("PG Invitation"));
    let invitation = store.create_invitation(input).await.unwrap();
    let team = store
        .create_team(CreateTeam {
            name: "PG Team".into(),
            organization_id: org_id.clone().into(),
            additional_fields: [("label".into(), json!("PG Team Label"))]
                .into_iter()
                .collect(),
            ..Default::default()
        })
        .await
        .unwrap();
    let details = store
        .get_organization_details(OrganizationDetailsQuery {
            organization: OrganizationKey::Id(&org_id),
            members_limit: Some(1.0),
            users_limit: 100.0,
            include_teams: true,
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(details.organization, organization);
    assert_eq!(details.invitations, vec![invitation]);
    assert_eq!(details.teams, Some(vec![team]));
    assert_eq!(details.members.len(), 1);
    assert_eq!(details.members[0].member, member);
    assert_eq!(details.members[0].user.id, owner.id);
    assert_eq!(details.members[0].user.name, owner.name);
    assert_eq!(details.members[0].user.email, owner.email);
}

#[tokio::test]
#[ignore = "Requires BETTER_AUTH_TEST_POSTGRES_URL and permission to create an isolated test schema"]
async fn live_postgres_full_organization_joins_decode_all_typed_children()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut options = ConnectOptions::new(std::env::var("BETTER_AUTH_TEST_POSTGRES_URL")?);
    let _ = options.max_connections(1).sqlx_logging(false);
    let database = Database::connect(options).await?;
    let schema = format!("ba_native_org_{}", uuid::Uuid::new_v4().simple());
    let _ = database
        .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
        .await?;
    let worker = database.clone();
    let worker_schema = schema.clone();
    let result = tokio::spawn(async move {
        let _ = worker
            .execute_unprepared(&format!("SET search_path TO {worker_schema}"))
            .await?;
        create_tables(&worker).await;
        check_full_read(worker).await;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await;
    let cleanup = database
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await;
    database.close().await?;
    let _ = cleanup?;
    result??;
    Ok(())
}
