use better_auth::seaorm::{
    Database, SeaOrmStore,
    sea_orm::{ConnectionTrait, EntityTrait},
};
use better_auth::{AuthConfig, middleware::EndpointRateLimit, store::RateLimitStore};

mod generated {
    include!(env!("BETTER_AUTH_RATE_LIMIT_SCHEMA"));
}

#[tokio::test]
async fn generated_rate_limit_schema_uses_mapped_table_columns_and_unique_keys() {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    generated::create_auth_tables(&database).await.unwrap();
    let store =
        SeaOrmStore::<generated::AppAuthSchema>::new(AuthConfig::default(), database.clone())
            .with_plugin_schema::<generated::AppPluginSchema>();
    let rule = EndpointRateLimit {
        window: 60.0,
        max_requests: 1.5,
    };
    for allowed in [true, true, false] {
        assert_eq!(
            store
                .consume_rate_limit("mapped", rule, 60.0)
                .await
                .unwrap()
                .allowed,
            allowed
        );
    }
    let rows = generated::rate_limit::Entity::find()
        .all(&database)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(f64::from(rows.first().unwrap().count), 2.0);
    assert!(database.execute_unprepared("INSERT INTO app_request_limits (id, request_bucket, request_total, requested_at_ms) SELECT 'duplicate', request_bucket, request_total, requested_at_ms FROM app_request_limits").await.is_err());
    database
        .execute_unprepared("UPDATE app_request_limits SET request_total = 0.5")
        .await
        .unwrap();
    assert!(
        store
            .consume_rate_limit("mapped", rule, 60.0)
            .await
            .unwrap()
            .allowed
    );
    assert_eq!(
        f64::from(
            generated::rate_limit::Entity::find()
                .one(&database)
                .await
                .unwrap()
                .unwrap()
                .count
        ),
        1.5
    );
    assert!(
        !store
            .consume_rate_limit("mapped", rule, 60.0)
            .await
            .unwrap()
            .allowed
    );
    assert!(
        database
            .execute_unprepared("SELECT * FROM rate_limit")
            .await
            .is_err()
    );
}
