//! SeaORM integration re-exports, gated behind the `seaorm2` feature.

pub use better_auth_seaorm::schema::{
    SeaOrmAccountModel, SeaOrmSessionModel, SeaOrmUserModel, SeaOrmVerificationModel,
};
pub use better_auth_seaorm::{
    AuthEntity, Database, DatabaseConnection, HookControl, SeaOrmHookContext, SeaOrmHooks,
    SeaOrmStore, current_request_hook_context, sea_orm,
};
