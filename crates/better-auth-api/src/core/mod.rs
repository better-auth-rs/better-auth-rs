pub mod auth;
pub mod session;
pub mod plugin;
pub mod config;

pub use auth::{BetterAuth, AuthBuilder};
pub use config::AuthConfig;
pub use plugin::{
    AuthPlugin, AuthRoute, AuthContext, PluginCapabilities, RuntimeCapabilities, RouteSpec,
    HookDispatcher,
};
pub use session::SessionManager; 
