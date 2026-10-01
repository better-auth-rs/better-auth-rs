use super::{Capture, config};
use better_auth::{AuthError, AuthResult};
use better_auth_core::{
    AuthConfig, AuthSchema, CreateUser, ListUsersParams,
    store::{EphemeralStore, StatelessSchema, UserStore},
    user_fields::UserFieldConfig,
};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tracing::Instrument;

struct Projection {
    options: AuthConfig,
    fail: Arc<AtomicBool>,
    calls: Arc<AtomicUsize>,
}
impl Projection {
    fn new() -> Self {
        let fail = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicUsize::new(0));
        let (should_fail, counter) = (fail.clone(), calls.clone());
        let mut options = config();
        options.experimental.instrumentation.enabled = true;
        let _ = options.user.additional_fields.insert(
            "note".into(),
            UserFieldConfig {
                required: Some(false),
                output_transform: Some(Arc::new(move |value| {
                    let _ = counter.fetch_add(1, Ordering::SeqCst);
                    if should_fail.load(Ordering::SeqCst) {
                        return Err(AuthError::internal("list projection failed"));
                    }
                    Ok(value)
                })),
                ..Default::default()
            },
        );
        Self {
            options,
            fail,
            calls,
        }
    }
}
fn names(capture: &Capture) -> AuthResult<Vec<String>> {
    Ok(capture
        .0
        .lock()
        .map_err(|_| AuthError::internal("capture poisoned"))?
        .iter()
        .filter_map(|record| record.fields.get("otel.name").and_then(Value::as_str))
        .filter(|name| name.starts_with("db "))
        .map(str::to_owned)
        .collect())
}
async fn check<S: AuthSchema>(
    store: &impl UserStore<S>,
    projection: &Projection,
    collection: &str,
) -> AuthResult<()> {
    for (name, note) in [
        ("Included A", "one"),
        ("Included B", "two"),
        ("Excluded", "three"),
    ] {
        let mut user = CreateUser::new();
        user.email = Some(format!(
            "{}@count.example",
            name.replace(' ', "-").to_lowercase()
        ));
        user.name = Some(name.into());
        let _ = user.additional_fields.insert("note".into(), json!(note));
        let _ = store.create_user(user).await?;
    }
    projection.calls.store(0, Ordering::SeqCst);
    let params = ListUsersParams {
        search_field: Some("name".into()),
        search_value: Some("Included".into()),
        limit: Some(1.0),
        offset: Some(1.0),
        sort_by: Some("name".into()),
        ..Default::default()
    };
    let capture = Capture::default();
    let (users, total) = store
        .list_users(params.clone())
        .instrument(capture.span())
        .await?;
    assert_eq!(users.len(), 1);
    assert_eq!(
        users.first().and_then(|user| user.name.as_deref()),
        Some("Included B")
    );
    assert_eq!(total, 2);
    assert_eq!(projection.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        names(&capture)?,
        [
            format!("db findMany {collection}"),
            format!("db count {collection}")
        ]
    );
    projection.calls.store(0, Ordering::SeqCst);
    projection.fail.store(true, Ordering::SeqCst);
    let capture = Capture::default();
    assert!(
        store
            .list_users(params)
            .instrument(capture.span())
            .await
            .is_err()
    );
    assert_eq!(projection.calls.load(Ordering::SeqCst), 1);
    assert_eq!(names(&capture)?, [format!("db findMany {collection}")]);
    Ok(())
}
#[tokio::test]
async fn memory_list_projects_only_the_page_then_counts_without_projection() -> AuthResult<()> {
    let projection = Projection::new();
    check::<StatelessSchema>(
        &EphemeralStore::new(projection.options.clone().into()),
        &projection,
        "user",
    )
    .await
}
#[cfg(feature = "seaorm2")]
mod sqlite {
    use super::*;
    use better_auth::seaorm::{
        AuthEntity, SeaOrmStore,
        sea_orm::{self, ConnectionTrait, Database, Schema, entity::prelude::*},
    };
    use better_auth_seaorm::store::entities;
    #[expect(unreachable_pub, reason = "SeaORM derives require public model items")]
    mod user {
        use super::*;
        #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
        #[sea_orm(table_name = "counted_people")]
        #[auth(role = "user")]
        pub struct Model {
            #[sea_orm(primary_key, auto_increment = false)]
            pub id: String,
            pub name: Option<String>,
            pub email: Option<String>,
            pub email_verified: bool,
            pub image: Option<String>,
            pub created_at: DateTimeUtc,
            pub updated_at: DateTimeUtc,
            pub note: Option<String>,
        }
        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {}
        impl ActiveModelBehavior for ActiveModel {}
    }
    struct Tables;
    impl AuthSchema for Tables {
        type User = user::Model;
        type Account = entities::account::Model;
        type Session = entities::session::Model;
        type Verification = entities::verification::Model;
    }
    #[tokio::test]
    async fn sqlite_list_projects_only_the_page_then_counts_without_projection() -> AuthResult<()> {
        let projection = Projection::new();
        let db = Database::connect("sqlite::memory:")
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let _ = db
            .execute(&Schema::new(db.get_database_backend()).create_table_from_entity(user::Entity))
            .await
            .map_err(|error| AuthError::internal(error.to_string()))?;
        check(
            &SeaOrmStore::<Tables>::new(projection.options.clone(), db),
            &projection,
            "counted_people",
        )
        .await
    }
}
