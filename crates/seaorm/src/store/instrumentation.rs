use std::future::Future;

use better_auth_core::{AuthConfig, AuthResult};
use sea_orm::EntityTrait;

pub(super) async fn database_operation<E: EntityTrait, T>(
    config: &AuthConfig,
    operation: &str,
    future: impl Future<Output = AuthResult<T>>,
) -> AuthResult<T> {
    let entity = E::default();
    better_auth_core::observability::database::with_database_operation(
        config,
        sea_orm::EntityName::table_name(&entity),
        operation,
        future,
    )
    .await
}
