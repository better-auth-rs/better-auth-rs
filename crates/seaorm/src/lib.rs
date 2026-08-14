//! SeaORM integration for Better Auth.

extern crate self as better_auth_seaorm;

mod config;
mod conversions;
mod entity;
mod error;
pub mod hooks;
pub mod schema;
pub mod store;
mod types;
mod types_org;
mod utils;

pub use better_auth_seaorm_macros::AuthEntity;
pub use hooks::{HookControl, SeaOrmHookContext, SeaOrmHooks, current_request_hook_context};
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
