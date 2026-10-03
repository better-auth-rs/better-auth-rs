//! SeaORM integration re-exports, gated behind the `seaorm2` feature.

pub use better_auth_seaorm::schema::{
    SeaOrmAccountModel, SeaOrmSessionModel, SeaOrmUserModel, SeaOrmVerificationModel,
};
pub use better_auth_seaorm::{
    AuthEntity, Database, DatabaseConnection, DatabaseHookUpdate, HookControl, OrganizationModels,
    PluginModels, ReferenceId, SeaOrmHookContext, SeaOrmHooks, SeaOrmOrganizationModel,
    SeaOrmOrganizationSchema, SeaOrmPluginModel, SeaOrmPluginSchema, SeaOrmStore, SessionUpdate,
    SqlNumber, SqlText, VerificationUpdate, current_request_hook_context, sea_orm,
};

#[doc(hidden)]
pub use better_auth_seaorm::__private_chrono;
