//! Plugin authoring interfaces and shared runtime types.

pub use better_auth_core::openapi::{OpenApiBuilder, OpenApiSpec};
pub use better_auth_core::plugin::{
    AuthContext, AuthInitContext, AuthPlugin, AuthRoute, BeforeRequestAction,
};
