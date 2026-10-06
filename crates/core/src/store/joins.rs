//! Runtime projections returned by the core adapter's ordinary joins.

use crate::{
    AuthConfig, AuthError, AuthResult, SchemaValue,
    plugin_runtime::ModelFields,
    store::schema::EntityRole,
    user_fields::UserConfig,
    utils::json::array_index,
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
        validate_references(
            ("account", &config.account.field_schema()),
            ("user", &config.user),
            schema,
            table_matches,
        )
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
        validate_references(
            ("user", &config.user),
            ("account", &config.account.field_schema()),
            schema,
            table_matches,
        )
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

fn validate_references(
    (base, base_fields): (&str, &UserConfig),
    (model, model_fields): (&str, &UserConfig),
    schema: &ModelFields,
    table_matches: impl Fn(EntityRole, &str) -> bool,
) -> AuthResult<()> {
    let references = |fields: &UserConfig, source: &str, target: &str| {
        let mut references = fields
            .fields()
            .iter()
            .filter_map(|(name, field)| {
                field.references.as_ref().map(|reference| (name, reference))
            })
            .collect::<Vec<_>>();
        // Native replacements retain schema positions. Integer keys use JavaScript property order.
        references.sort_by_key(|(name, _)| {
            let native = if source == "user" {
                let names = [
                    "name",
                    "email",
                    "emailVerified",
                    "image",
                    "createdAt",
                    "updatedAt",
                ];
                names
                    .iter()
                    .position(|field| *field == name.as_str())
                    .unwrap_or(names.len())
            } else {
                0
            };
            array_index(name).map_or((true, 0, native), |index| (false, index, 0))
        });
        references.into_iter().try_fold(0, |count, (_, reference)| {
            let model = schema.resolve_model_name(&reference.model, &table_matches)?;
            Ok::<_, AuthError>(count + usize::from(model == target))
        })
    };
    let forward = references(model_fields, model, base)?;
    let count = if forward == 0 {
        references(base_fields, base, model)?
    } else {
        forward
    };
    match count {
        0 => Err(AuthError::config(format!(
            "No foreign key found for model {model} and base model {base} while performing join operation."
        ))),
        1 => Ok(()),
        _ => Err(AuthError::config(format!(
            "Multiple foreign keys found for model {model} and base model {base} while performing join operation. Only one foreign key is supported."
        ))),
    }
}

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
