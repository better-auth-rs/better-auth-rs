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
/// `#[auth(role = "...")]` where role is one of `user`, `session`, `account`,
/// or `verification`.
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
