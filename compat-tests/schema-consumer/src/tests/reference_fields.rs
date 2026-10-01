use better_auth::{
    AuthConfig, AuthSchema, BetterAuth,
    config::{UserFieldConfig, UserFieldReference, UserFieldType},
    prelude::{CreateSession, CreateUser, SessionView, UpdateUser, UserView},
    seaorm::{
        AuthEntity, Database, ReferenceId, SeaOrmStore,
        sea_orm::{self, ConnectionTrait, Schema, entity::prelude::*},
    },
};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

mod user {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "user")]
    #[sea_orm(table_name = "reference_users")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub email: Option<String>,
        pub name: Option<String>,
        pub email_verified: bool,
        pub image: Option<String>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
        #[serde(rename = "storedOwner")]
        #[sea_orm(column_name = "physical_owner")]
        pub owner: Option<ReferenceId>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

mod session {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
    #[auth(role = "session")]
    #[sea_orm(table_name = "reference_sessions")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub expires_at: DateTimeUtc,
        pub token: String,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
        pub ip_address: Option<String>,
        pub user_agent: Option<String>,
        pub user_id: String,
        pub active: bool,
        #[serde(rename = "storedOwner")]
        #[sea_orm(column_name = "physical_owner")]
        pub owner: Option<ReferenceId>,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

struct AppSchema;
impl AuthSchema for AppSchema {
    type User = user::Model;
    type Session = session::Model;
    type Account = super::generated::account::Model;
    type Verification = super::generated::verification::Model;
}

#[tokio::test]
async fn user_and_session_references_keep_aliases_bindings_and_single_output_transform() {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    let schema = Schema::new(database.get_database_backend());
    database
        .execute(&schema.create_table_from_entity(user::Entity))
        .await
        .unwrap();
    database
        .execute(&schema.create_table_from_entity(session::Entity))
        .await
        .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let field = UserFieldConfig {
        field_type: UserFieldType::Number,
        field_name: Some("storedOwner".into()),
        required: Some(false),
        references: Some(UserFieldReference {
            model: "user".into(),
            field: "id".into(),
        }),
        default_value: Some(json!(1)),
        output_transform: Some(Arc::new(move |value| {
            count.fetch_add(1, Ordering::SeqCst);
            assert!(value.as_ref().unwrap().is_string());
            Ok(value)
        })),
        ..Default::default()
    };
    let mut config = AuthConfig::new("reference-fields-consumer-secret-at-least-32-chars");
    config
        .user
        .additional_fields
        .insert("owner".into(), field.clone());
    let mut session_field = field;
    session_field.on_update = Some(Arc::new(|| json!(-0.0)));
    config
        .session
        .additional_fields
        .insert("owner".into(), session_field);
    let auth = BetterAuth::<AppSchema>::new(config.clone())
        .store(SeaOrmStore::<AppSchema>::new(config.clone(), database))
        .build()
        .await
        .unwrap();
    let store = auth.store();
    let user = store.create_user(CreateUser::new()).await.unwrap();
    let session = store
        .create_session(CreateSession {
            user_id: user.id.clone(),
            expires_at: user.created_at + std::time::Duration::from_secs(3600),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await
        .unwrap();
    assert_eq!(user.owner, Some(ReferenceId::Text("1".into())));
    assert_eq!(session.owner, Some(ReferenceId::Text("1".into())));
    let updated_user = store
        .update_user(
            &user.id,
            UpdateUser {
                additional_fields: [("owner".into(), json!(1e20))].into_iter().collect(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let updated_session = store
        .update_session_fields(
            &session.token,
            [("owner".into(), json!(1e20))].into_iter().collect(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        updated_user.owner,
        Some(ReferenceId::Text("1.0e+20".into()))
    );
    assert_eq!(
        updated_session.owner,
        Some(ReferenceId::Text("1.0e+20".into()))
    );
    let user_view =
        UserView::with_fields_for_adapter(&updated_user, &config.user, &Default::default(), false)
            .unwrap();
    let session_view =
        SessionView::with_fields_for_adapter(&updated_session, &config.session, false).unwrap();
    assert_eq!(serde_json::to_value(user_view).unwrap()["owner"], "1.0e+20");
    assert_eq!(
        serde_json::to_value(session_view).unwrap()["owner"],
        "1.0e+20"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let refreshed = store
        .update_session_expiry(&session.token, session.expires_at)
        .await
        .unwrap();
    assert_eq!(refreshed.owner, Some(ReferenceId::Text("0.0".into())));
}
