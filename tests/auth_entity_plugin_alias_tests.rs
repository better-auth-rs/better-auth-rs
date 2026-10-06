#![cfg(feature = "seaorm2")]
#![allow(
    unreachable_pub,
    reason = "SeaORM DeriveEntityModel requires public entity types"
)]

use better_auth::{
    __private_core::user_fields::{UserConfig, UserFieldConfig},
    seaorm::{
        AuthEntity, SeaOrmPluginModel,
        sea_orm::{self, IntoActiveModel, TryIntoModel, entity::prelude::*},
    },
};
use serde_json::json;

mod mapped {
    use super::*;

    #[derive(Clone, Debug, PartialEq, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "rate_limit")]
    #[sea_orm(table_name = "mapped_limits")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        #[sea_orm(column_name = "stored_key", unique)]
        pub key: String,
        pub count: i32,
        #[sea_orm(column_name = "stored_time")]
        #[serde(rename = "serializedTime")]
        pub last_request: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[tokio::test]
async fn plugin_physical_columns_support_writes_and_projection_without_serde_renaming()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use sea_orm::ActiveValue::Set;

    assert!(matches!(
        mapped::Model::column("stored_key")?,
        mapped::Column::Key
    ));
    let mut active = mapped::Model {
        id: "limit".into(),
        key: "before".into(),
        count: 1,
        last_request: 0,
    }
    .into_active_model();
    mapped::Model::apply_fields(&mut active, [("stored_key".into(), json!("after"))].into())?;
    assert_eq!(active.key, Set("after".into()));
    for alias in [
        "last_request",
        "lastRequest",
        "serializedTime",
        "stored_time",
    ] {
        assert!(matches!(
            mapped::Model::column(alias)?,
            mapped::Column::LastRequest
        ));
        mapped::Model::apply_fields(&mut active, [(alias.into(), json!(42))].into())?;
        assert_eq!(active.last_request, Set(42));
    }
    let model = active.try_into_model()?;
    assert_eq!(
        serde_json::to_value(&model)?,
        json!({"id":"limit", "key":"after", "count":1, "serializedTime":42})
    );
    let fields = UserConfig {
        additional_fields: Some(
            [(
                "key".into(),
                UserFieldConfig {
                    field_name: Some("stored_key".into()),
                    ..Default::default()
                },
            )]
            .into(),
        ),
    };
    let output = fields
        .project_adapter_records(vec![model.record_fields(&fields)?], false, true)
        .await?;
    assert_eq!(serde_json::to_value(output)?, json!([{"key":"after"}]));
    Ok(())
}
