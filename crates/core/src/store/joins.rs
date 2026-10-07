//! Runtime projections returned by the core adapter's ordinary joins.

use crate::{
    AuthConfig, AuthError, AuthResult, SchemaValue,
    plugin_runtime::ModelFields,
    store::schema::{EntityRole, resolve_field_name},
    user_fields::{USER_FIELDS, UserConfig, UserFieldConfig, UserFieldReference},
    wire::{AccountView, UserView},
};

/// An account and its persisted owner. A missing owner is an orphaned account, not a new identity.
#[derive(Debug, Clone)]
pub struct AccountOwner {
    pub account: AccountView,
    pub user: Option<UserView>,
}

impl AccountOwner {
    /// Validate final Account/User references before reading either model.
    pub fn validate_schema(
        config: &AuthConfig,
        schema: &ModelFields,
        table_matches: impl Fn(EntityRole, &str) -> bool,
    ) -> AuthResult<()> {
        resolve_references(
            (
                EntityRole::Account,
                "account",
                &config.account.field_schema(),
            ),
            (EntityRole::User, "user", &config.user),
            schema,
            table_matches,
        )
        .map(|_| ())
    }

    /// Check projections against the canonical owner ID captured before output policies run.
    pub fn new(
        account: AccountView,
        user: Option<UserView>,
        stored_owner_id: &SchemaValue<String>,
    ) -> AuthResult<Self> {
        if account.user_id != *stored_owner_id
            || user
                .as_ref()
                .is_some_and(|user| user.id != *stored_owner_id)
        {
            return Err(AuthError::internal(
                "Account projection changed its owner binding",
            ));
        }
        Ok(Self { account, user })
    }
}

/// A user and the adapter-limited account page joined to that user.
#[derive(Debug, Clone)]
pub struct UserAccounts {
    pub user: UserView,
    pub accounts: Vec<AccountView>,
}

impl UserAccounts {
    /// Validate final User/Account references before reading either model.
    pub fn validate_schema(
        config: &AuthConfig,
        schema: &ModelFields,
        table_matches: impl Fn(EntityRole, &str) -> bool,
    ) -> AuthResult<()> {
        resolve_references(
            (EntityRole::User, "user", &config.user),
            (
                EntityRole::Account,
                "account",
                &config.account.field_schema(),
            ),
            schema,
            table_matches,
        )
        .map(|_| ())
    }

    /// Check a stored user and its account page without trusting projected identity fields.
    pub fn new(
        user: UserView,
        accounts: Vec<AccountView>,
        stored_user_id: &SchemaValue<String>,
    ) -> AuthResult<Self> {
        if user.id != *stored_user_id
            || accounts
                .iter()
                .any(|account| account.user_id != *stored_user_id)
        {
            return Err(AuthError::internal(
                "User projection changed its account binding",
            ));
        }
        Ok(Self { user, accounts })
    }
}

fn ordered_fields<'a>(model: &str, fields: &'a UserConfig) -> Vec<(&'a str, &'a UserFieldConfig)> {
    fields.ordered_fields(if model == "user" { USER_FIELDS } else { &[] })
}

fn matching_references<'a>(
    fields: &'a UserConfig,
    source: &str,
    target: &str,
    schema: &ModelFields,
    table_matches: &impl Fn(EntityRole, &str) -> bool,
) -> AuthResult<Vec<(&'a str, &'a UserFieldReference)>> {
    let mut matching = Vec::new();
    for (name, field) in ordered_fields(source, fields) {
        if let Some(reference) = &field.references
            && schema.resolve_model_name(&reference.model, table_matches)? == target
        {
            matching.push((name, reference));
        }
    }
    Ok(matching)
}

fn resolve_field<'a>(model: &str, fields: &'a UserConfig, name: &'a str) -> AuthResult<&'a str> {
    let name = if name == "_id" { "id" } else { name };
    let configured = fields.fields().get(name);
    if name == "id" || (model == "user" && USER_FIELDS.contains(&name)) || configured.is_some() {
        return Ok(resolve_field_name(
            configured.and_then(|field| field.field_name.as_deref()),
            name,
        ));
    }
    ordered_fields(model, fields)
        .into_iter()
        .find(|(_, field)| field.field_name.as_deref() == Some(name))
        .map(|(logical, field)| resolve_field_name(field.field_name.as_deref(), logical))
        .ok_or_else(|| AuthError::config(format!("Field {name} not found in model {model}")))
}

fn resolve_references(
    (base_role, base, base_fields): (EntityRole, &str, &UserConfig),
    (model_role, model, model_fields): (EntityRole, &str, &UserConfig),
    schema: &ModelFields,
    table_matches: impl Fn(EntityRole, &str) -> bool,
) -> AuthResult<(String, String)> {
    // Where conversion changes adapter metadata before join validation, including failed joins.
    schema.begin_id_input(base_role)?;
    let base_fields = schema.runtime_fields(base_role, base_fields)?;
    let model_fields = schema.runtime_fields(model_role, model_fields)?;
    let forward = matching_references(&model_fields, model, base, schema, &table_matches)?;
    let is_forward = !forward.is_empty();
    let selected = if is_forward {
        forward
    } else {
        matching_references(&base_fields, base, model, schema, &table_matches)?
    };
    match selected.as_slice() {
        [] => Err(AuthError::config(format!(
            "No foreign key found for model {model} and base model {base} while performing join operation."
        ))),
        [(foreign_key, reference)] => {
            let (from, to) = if is_forward {
                (
                    resolve_field(base, &base_fields, &reference.field)?,
                    resolve_field(model, &model_fields, foreign_key)?,
                )
            } else {
                (
                    resolve_field(base, &base_fields, foreign_key)?,
                    resolve_field(model, &model_fields, &reference.field)?,
                )
            };
            Ok((from.to_owned(), to.to_owned()))
        }
        _ => Err(AuthError::config(format!(
            "Multiple foreign keys found for model {model} and base model {base} while performing join operation. Only one foreign key is supported."
        ))),
    }
}

#[cfg(test)]
mod history_tests;
#[cfg(test)]
mod reference_fields_tests;

/// An invitation and the organization selected by its persisted foreign key.
#[derive(Debug, Clone)]
pub struct InvitationOrganization {
    pub invitation: crate::Invitation,
    pub organization: Option<crate::Organization>,
}

/// A member and the user selected by the member's persisted foreign key.
#[derive(Debug, Clone)]
pub struct MemberUser {
    /// Projected member fields.
    pub member: crate::Member,
    /// Projected fields from the stored user, before the endpoint selects its summary.
    pub user: UserView,
}

/// Select the organization before loading its related records.
#[derive(Debug, Clone, Copy)]
pub enum OrganizationKey<'a> {
    /// Match the stored organization ID.
    Id(&'a str),
    /// Match the stored organization slug.
    Slug(&'a str),
}

/// The independently limited pages used by a full organization response.
#[derive(Debug, Clone, Copy)]
pub struct OrganizationDetailsQuery<'a> {
    /// Organization selector.
    pub organization: OrganizationKey<'a>,
    /// Member page limit; omission uses the adapter default.
    pub members_limit: Option<f64>,
    /// Limit of the separate user query after the organization and child projections.
    pub users_limit: f64,
    /// Include the organization's team page.
    pub include_teams: bool,
}

/// Projected organization records and the users loaded after the related pages.
#[derive(Debug, Clone)]
pub struct OrganizationDetails {
    /// Organization fields.
    pub organization: crate::Organization,
    /// Adapter-limited invitation page.
    pub invitations: Vec<crate::Invitation>,
    /// Adapter-limited member page with its separately loaded users.
    pub members: Vec<MemberUser>,
    /// Team page when requested; omission remains distinct from an empty page.
    pub teams: Option<Vec<crate::Team>>,
}
