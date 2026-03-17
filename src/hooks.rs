//! Database hook interfaces and request-hook utilities.

pub use better_auth_core::hooks::{
    DatabaseHookContext, DatabaseHooks, HookControl, RequestHookContext, with_request_hook_context,
    with_request_hook_context_value,
};
