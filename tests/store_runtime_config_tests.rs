use std::sync::Arc;

use better_auth::{AuthBuilder, AuthConfig, AuthResult};
use better_auth_core::{
    CreateUser, ListUsersParams,
    store::{EphemeralStore, UserStore},
};

#[tokio::test]
async fn builder_installs_final_adapter_config_without_plugins_and_isolates_shared_storage()
-> AuthResult<()> {
    let store = Arc::new(EphemeralStore::default());
    for name in ["First", "Second", "Third"] {
        let _ = store
            .create_user(
                CreateUser::new()
                    .with_name(name)
                    .with_email(format!("{name}@example.test")),
            )
            .await?;
    }
    let mut instances = Vec::new();
    for limit in [1.0, 2.0] {
        let mut config = AuthConfig::new("runtime-config-isolation-secret-at-least-32-characters")
            .base_url("http://runtime.test");
        config.logger.disabled = Some(true);
        config.advanced.database.default_find_many_limit = Some(limit);
        instances.push(
            AuthBuilder::new(config)
                .store_arc(store.clone())
                .build()
                .await?,
        );
    }
    for (index, auth) in instances.iter().enumerate() {
        let (users, total) = auth.store().list_users(ListUsersParams::default()).await?;
        assert_eq!(users.len(), index + 1);
        assert_eq!(total, 3);
    }
    let (original, total) = store.list_users(ListUsersParams::default()).await?;
    assert_eq!(original.len(), 3);
    assert_eq!(total, 3);
    Ok(())
}
