use better_auth::config::{UserFieldConfig, UserFieldType};
use better_auth::plugins::organization::OrganizationConfig;
use better_auth::plugins::organization::hooks::{
    OrganizationHooks, OrganizationInvitationDraft, OrganizationUser,
};
use better_auth_seaorm::sea_orm::{
    ConnectionTrait, DatabaseConnection, DbErr, EntityTrait, Schema,
};

struct Hooks {
    invitation_teams: bool,
}
#[async_trait::async_trait]
impl OrganizationHooks for Hooks {
    async fn before_create_invitation(
        &self,
        data: &mut OrganizationInvitationDraft,
        _event: OrganizationUser<'_>,
    ) -> better_auth::AuthResult<()> {
        let mut snapshot =
            serde_json::Map::from_iter([("inviterId".into(), serde_json::json!(data.inviter_id))]);
        for (name, value) in [
            ("status", data.status.json()?),
            ("createdAt", data.created_at.json()?),
            ("expiresAt", data.expires_at.json()?),
        ] {
            if let Some(value) = value {
                let _ = snapshot.insert(name.into(), value);
            }
        }
        if self.invitation_teams {
            for (name, value) in [
                ("teamIds", data.team_ids.json()?),
                ("teamId", data.team_id.json()?),
            ] {
                if let Some(value) = value {
                    let _ = snapshot.insert(name.into(), value);
                }
            }
        }
        let _ = data
            .additional_fields
            .insert("hookState".into(), snapshot.into());
        Ok(())
    }
}

pub fn enabled(profile: &str) -> bool {
    matches!(
        profile,
        "organization-member-fields" | "organization-invitation-teams"
    )
}

pub fn configure(config: &mut OrganizationConfig, profile: &str) {
    config.teams.enabled = true;
    config.teams.default_team = false;
    let invitation_teams = profile == "organization-invitation-teams";
    config.hooks = Some(std::sync::Arc::new(Hooks { invitation_teams }));
    let unconstrained = UserFieldConfig {
        field_type: UserFieldType::Enum(vec!["unconstrained".into()]),
        required: Some(false),
        ..Default::default()
    };
    let json = UserFieldConfig {
        field_type: UserFieldType::Json,
        required: Some(false),
        input_transform: Some(std::sync::Arc::new(|value| {
            Ok(value.map(|value| {
                if value.is_string() {
                    serde_json::json!(value.to_string())
                } else {
                    value
                }
            }))
        })),
        ..Default::default()
    };
    config.schema.member.additional_fields.extend([
        (
            "role".into(),
            UserFieldConfig {
                default_value: Some(serde_json::json!("member")),
                ..json.clone()
            },
        ),
        ("organizationId".into(), unconstrained.clone()),
        ("userId".into(), unconstrained.clone()),
        ("teamId".into(), unconstrained.clone()),
    ]);
    config.schema.invitation.additional_fields.extend([
        ("email".into(), json.clone()),
        ("role".into(), json),
        ("organizationId".into(), unconstrained.clone()),
        (
            "status".into(),
            UserFieldConfig {
                required: Some(false),
                ..Default::default()
            },
        ),
        (
            "createdAt".into(),
            UserFieldConfig {
                required: Some(false),
                ..Default::default()
            },
        ),
        (
            "expiresAt".into(),
            UserFieldConfig {
                required: Some(false),
                ..Default::default()
            },
        ),
        (
            "inviterId".into(),
            UserFieldConfig {
                required: Some(false),
                ..Default::default()
            },
        ),
        (
            "hookState".into(),
            UserFieldConfig {
                field_type: UserFieldType::Json,
                input: false,
                required: Some(false),
                ..Default::default()
            },
        ),
    ]);
    for fields in [
        &mut config.schema.member.additional_fields,
        &mut config.schema.invitation.additional_fields,
    ] {
        fields.extend([
            (
                "zetaText".into(),
                UserFieldConfig {
                    required: Some(false),
                    ..Default::default()
                },
            ),
            (
                "alphaCount".into(),
                UserFieldConfig {
                    field_type: UserFieldType::Number,
                    required: Some(false),
                    ..Default::default()
                },
            ),
        ]);
    }
    if invitation_teams {
        let _ = config
            .schema
            .invitation
            .additional_fields
            .insert("teamId".into(), unconstrained);
    }
}

pub mod member {
    use better_auth_seaorm::sea_orm::{self, entity::prelude::*};
    #[derive(
        Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, better_auth_seaorm::AuthEntity,
    )]
    #[auth(role = "member")]
    #[sea_orm(table_name = "dynamic_member")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub organization_id: String,
        pub user_id: String,
        pub role: Option<Json>,
        pub created_at: DateTimeUtc,
        #[serde(rename = "teamId")]
        pub team_id: Option<String>,
        #[serde(rename = "zetaText")]
        pub zeta_text: Option<String>,
        #[serde(rename = "alphaCount")]
        pub alpha_count: Option<f64>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
pub mod invitation {
    use better_auth_seaorm::sea_orm::{self, entity::prelude::*};
    #[derive(
        Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, better_auth_seaorm::AuthEntity,
    )]
    #[auth(role = "invitation")]
    #[sea_orm(table_name = "dynamic_invitation")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub organization_id: String,
        pub email: Option<Json>,
        pub role: Option<Json>,
        pub status: Option<String>,
        pub inviter_id: Option<String>,
        pub expires_at: Option<String>,
        pub created_at: Option<String>,
        pub team_id: Option<String>,
        #[serde(rename = "zetaText")]
        pub zeta_text: Option<String>,
        #[serde(rename = "alphaCount")]
        pub alpha_count: Option<f64>,
        #[serde(rename = "hookState")]
        pub hook_state: Option<Json>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
type Base = better_auth_seaorm::OrganizationModels;
pub type Models = better_auth_seaorm::OrganizationModels<
    <Base as better_auth_seaorm::SeaOrmOrganizationSchema>::Organization,
    member::Model,
    invitation::Model,
    <Base as better_auth_seaorm::SeaOrmOrganizationSchema>::Team,
    <Base as better_auth_seaorm::SeaOrmOrganizationSchema>::TeamMember,
    <Base as better_auth_seaorm::SeaOrmOrganizationSchema>::OrganizationRole,
>;
pub async fn create_tables(database: &DatabaseConnection) -> Result<(), DbErr> {
    let schema = Schema::new(database.get_database_backend());
    for statement in [
        schema.create_table_from_entity(member::Entity),
        schema.create_table_from_entity(invitation::Entity),
    ] {
        let _ = database.execute(&statement).await?;
    }
    Ok(())
}
pub async fn reset(database: &DatabaseConnection) -> Result<(), DbErr> {
    let _ = invitation::Entity::delete_many().exec(database).await?;
    let _ = member::Entity::delete_many().exec(database).await?;
    Ok(())
}
