//! Proc macros for the Better Auth SeaORM integration.

mod auth_entity;

use proc_macro::TokenStream;
use syn::{DeriveInput, parse_macro_input};

/// Derive macro that generates `Auth*` trait impls and `SeaOrm*Model` impls
/// for a SeaORM entity.
///
/// # Usage
///
/// Annotate a SeaORM `Model` struct with `#[derive(AuthEntity)]` and
/// `#[auth(role = "...")]`. Core roles are `user`, `session`, `account`, and `verification`.
/// Organization roles are `organization`, `member`, `invitation`, `team`, `team_member`, and `organization_role`.
/// Plugin roles are `api_key`, `device_code`, `passkey`, `two_factor`, `jwk`, and `wallet_address`.
/// Table and column mappings use SeaORM's `table_name` and `column_name` attributes.
/// IDs use the declared field types. Absent IDs remain unset for database defaults.
/// Mark additional fields that reference an ID with `#[auth(reference)]` to parse string identifiers into integer or UUID storage.
/// Use `#[auth(reference = false)]` to keep a native field independent of the registry's ID-reference conversion.
///
/// ```ignore
/// #[derive(DeriveEntityModel, AuthEntity)]
/// #[auth(role = "user")]
/// #[sea_orm(table_name = "users")]
/// pub struct Model {
///     #[sea_orm(primary_key, auto_increment = false)]
///     pub id: String,
///     // ... core fields ...
/// }
/// ```
///
/// # Session representation
///
/// Session models require `active` unless they explicitly use `#[auth(role = "session", row_presence)]`.
/// The marker rejects fields whose Rust or serialized alias is `active` and returns no independent active column.
/// Existing active-backed models retain their stored state and predicates. Row-presence models retain expiry checks.
/// Use the marker for a fresh table or an application-owned migration; derive does not validate historical state.
/// Runtime declarations that map logical `active` require an active-column model.
///
/// # Extra fields
///
/// The struct may contain fields beyond the core set required by the auth
/// role.  These are accepted by the macro and set to `ActiveValue::NotSet`
/// in the generated `new_active()`.  Use database defaults or
/// `ActiveModelBehavior::before_save` to populate them.
///
/// ```ignore
/// #[derive(DeriveEntityModel, AuthEntity)]
/// #[auth(role = "user")]
/// #[sea_orm(table_name = "users")]
/// pub struct Model {
///     // ... core fields ...
///     pub locale: String,     // extra — gets NotSet in new_active
///     pub tenant_id: i64,     // extra — gets NotSet in new_active
/// }
/// ```
#[proc_macro_derive(AuthEntity, attributes(auth))]
pub fn derive_auth_entity(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    auth_entity::derive_auth_entity(&input).into()
}
