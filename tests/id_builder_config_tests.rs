use std::sync::Arc;

use better_auth::config::{IdGeneration, IdGenerator};
use better_auth::{AuthBuilder, AuthConfig, AuthResult};
use better_auth_core::CreateUser;
use better_auth_core::store::{EphemeralStore, UserStore};

#[tokio::test]
async fn builder_binds_distinct_id_policies_to_shared_storage_without_plugins() -> AuthResult<()> {
    let store = Arc::new(EphemeralStore::default());
    let mut instances = Vec::new();
    for prefix in ["first", "second"] {
        let mut config = AuthConfig::new("builder-id-policy-secret-at-least-thirty-two-characters")
            .base_url("http://localhost:3000");
        config.advanced.database.generate_id =
            Some(IdGeneration::Custom(IdGenerator::new(move |request| {
                Ok(Some(format!("{prefix}-{}", request.model)))
            })));
        instances.push(
            AuthBuilder::new(config)
                .store_arc(store.clone())
                .build()
                .await?,
        );
    }
    for (auth, prefix) in instances.iter().zip(["first", "second"]) {
        let user = auth
            .store()
            .create_user(CreateUser::new().with_email(format!("{prefix}@example.com")))
            .await?;
        assert_eq!(user.id.typed()?, &format!("{prefix}-user"));
        assert!(store.get_user_by_id(user.id.typed()?).await?.is_some());
    }
    let original = store
        .create_user(CreateUser::new().with_email("original@example.com"))
        .await?;
    assert_eq!(original.id.typed()?.len(), 32);
    Ok(())
}
