use better_auth::seaorm::{SeaOrmSessionModel, SqlNumber, sea_orm};
use better_auth::{FieldMap, FieldValue, SchemaField, prelude::AuthSession};
use sea_orm::{TryIntoModel, entity::prelude::*};
use serde_json::json;

mod session {
    use super::*;

    #[derive(
        better_auth::seaorm::AuthEntity,
        Clone,
        Debug,
        PartialEq,
        serde::Serialize,
        DeriveEntityModel,
    )]
    #[auth(role = "session")]
    #[sea_orm(table_name = "native_session_values")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub token: Option<SqlNumber>,
        pub expires_at: String,
        pub created_at: DateTimeUtc,
        pub updated_at: Option<bool>,
        pub ip_address: Json,
        pub user_agent: bool,
        pub user_id: String,
        pub impersonated_by: Option<SqlNumber>,
        pub active_organization_id: Option<String>,
        pub active_team_id: Option<Json>,
        pub active: bool,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[test]
fn derived_session_fields_preserve_native_replacements_until_typed_operations()
-> Result<(), Box<dyn std::error::Error>> {
    let now: DateTimeUtc = "2030-01-02T03:04:05Z".parse()?;
    let fields = FieldMap::from([
        ("token".into(), 17.5.into()),
        ("expiresAt".into(), "schema-expiry".into()),
        ("createdAt".into(), now.into_field()),
        ("updatedAt".into(), false.into()),
        (
            "ipAddress".into(),
            FieldValue::from_json(json!({"network": [1, null]}))?,
        ),
        ("userAgent".into(), true.into()),
        ("userId".into(), "owner".into()),
        ("impersonatedBy".into(), 23.5.into()),
        ("activeOrganizationId".into(), FieldValue::Null),
        ("activeTeamId".into(), FieldValue::from_json(json!(false))?),
    ]);
    let mut active = session::Model::new_active_from_fields(Some("session".into()), &fields)?;
    session::Model::apply_fields(&mut active, fields.clone())?;
    let row = active.clone().try_into_model()?;
    for (name, actual) in [
        ("token", row.token().into_field_value()),
        ("expiresAt", row.expires_at().into_field_value()),
        ("createdAt", row.created_at().into_field_value()),
        ("updatedAt", row.updated_at().into_field_value()),
        ("ipAddress", row.ip_address().into_field_value()),
        ("userAgent", row.user_agent().into_field_value()),
        ("impersonatedBy", row.impersonated_by().into_field_value()),
        (
            "activeOrganizationId",
            row.active_organization_id().into_field_value(),
        ),
        ("activeTeamId", row.active_team_id().into_field_value()),
    ] {
        assert_eq!(Some(&actual), fields.get(name), "{name}");
    }
    assert!(row.active());
    assert!(session::Model::set_updated_at(&mut active, now).is_err());
    assert_eq!(active.updated_at, sea_orm::ActiveValue::Set(Some(false)));
    Ok(())
}
