//! SeaORM integration for Better Auth.

extern crate self as better_auth_seaorm;

mod config;
mod conversions;
mod error;
mod reference_id;
pub use reference_id::ReferenceId;
mod sql_number;
pub use sql_number::SqlNumber;
pub mod hooks;
pub mod organization_schema;
pub mod plugin_schema;
pub use plugin_schema::{PluginModels, SeaOrmPluginModel, SeaOrmPluginSchema};
pub mod schema;
pub use organization_schema::{
    OrganizationModels, SeaOrmOrganizationModel, SeaOrmOrganizationSchema,
};
pub mod store;
mod types;
mod types_org;
mod utils;

pub use better_auth_seaorm_macros::AuthEntity;
pub use hooks::{
    DatabaseHookUpdate, HookControl, SeaOrmHookContext, SeaOrmHooks, SessionUpdate,
    VerificationUpdate, current_request_hook_context,
};
pub use schema::{
    SeaOrmAccountModel, SeaOrmSessionModel, SeaOrmUserModel, SeaOrmVerificationModel,
};
pub use sea_orm;
pub use sea_orm::{Database, DatabaseConnection};
pub use store::SeaOrmStore;

#[doc(hidden)]
pub use better_auth_core as __private_core;
#[doc(hidden)]
pub use sea_orm as __private_seaorm;

#[doc(hidden)]
pub use chrono as __private_chrono;
