//! Runtime projections returned by the core adapter's ordinary joins.

use crate::{
    AuthConfig, AuthError, AuthResult, SchemaValue,
    plugin_runtime::ModelFields,
    store::schema::{EntityRole, resolve_field_name},
    user_fields::{USER_FIELDS, UserConfig, UserFieldConfig, UserFieldReference, UserFieldType},
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
) -> AuthResult<Vec<(&'a str, &'a UserFieldReference, bool)>> {
    let mut matching = Vec::new();
    for (name, field) in ordered_fields(source, fields) {
        if let Some(reference) = &field.references
            && schema.resolve_model_name(&reference.model, table_matches)? == target
        {
            matching.push((name, reference, field.unique == Some(true)));
        }
    }
    Ok(matching)
}

fn resolve_field<'a>(
    model: &str,
    fields: &'a UserConfig,
    name: &'a str,
) -> AuthResult<(&'a str, &'a str)> {
    let name = if name == "_id" { "id" } else { name };
    let configured = fields.fields().get(name);
    if name == "id" || (model == "user" && USER_FIELDS.contains(&name)) || configured.is_some() {
        return Ok((
            name,
            resolve_field_name(
                configured.and_then(|field| field.field_name.as_deref()),
                name,
            ),
        ));
    }
    ordered_fields(model, fields)
        .into_iter()
        .find(|(_, field)| field.field_name.as_deref() == Some(name))
        .map(|(logical, field)| {
            (
                logical,
                resolve_field_name(field.field_name.as_deref(), logical),
            )
        })
        .ok_or_else(|| AuthError::config(format!("Field {name} not found in model {model}")))
}

fn resolve_references(
    (base_role, base, base_fields): (EntityRole, &str, &UserConfig),
    (model_role, model, model_fields): (EntityRole, &str, &UserConfig),
    schema: &ModelFields,
    table_matches: impl Fn(EntityRole, &str) -> bool,
) -> AuthResult<MemberUserJoin> {
    // Where conversion changes adapter metadata before join validation, including failed joins.
    schema.begin_id_query(base_role)?;
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
        [(foreign_key, reference, unique)] => {
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
            Ok(MemberUserJoin {
                from: from.1.to_owned(),
                to: to.1.to_owned(),
                logical_from: from.0.to_owned(),
                logical_to: to.0.to_owned(),
                many: to.1 != "id" && !*unique,
            })
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

/// A member and the user summary selected by the final schema relationship.
#[derive(Debug, Clone)]
pub struct MemberUser {
    /// Projected member fields.
    pub member: crate::Member,
    /// Organization adapter summary after all related user output policies complete.
    pub user: crate::MemberUserView,
}

/// Selected Member/User join fields and result cardinality.
#[derive(Debug, Clone)]
pub struct MemberUserJoin {
    /// Physical field on Member.
    pub from: String,
    /// Physical field on User.
    pub to: String,
    /// Original logical Member field corresponding to the native source column.
    pub logical_from: String,
    /// Original logical User field corresponding to the native target column.
    pub logical_to: String,
    /// Whether the selected foreign key returns a page instead of one user.
    pub many: bool,
}

impl MemberUser {
    fn field_schema(configured: &UserConfig) -> UserConfig {
        let mut defaults = ModelFields::default();
        defaults.register_organization_schema(&Default::default(), true);
        let mut fields = defaults.fields(EntityRole::Member).clone();
        for (name, target) in better_auth_schema_registry::entity_foreign_keys("member") {
            let mut parts = name.split('_');
            let mut logical = parts.next().unwrap_or_default().to_owned();
            for part in parts {
                let mut characters = part.chars();
                if let Some(first) = characters.next() {
                    logical.extend(first.to_uppercase());
                    logical.extend(characters);
                }
            }
            fields.fields_mut().entry(logical).or_default().references = Some(UserFieldReference {
                model: if *target == "users" { "user" } else { target }.into(),
                field: "id".into(),
            });
        }
        fields.fields_mut().extend(configured.fields().clone());
        fields
    }

    /// Resolve final Member/User references before reading either model.
    pub fn resolve_schema(
        config: &AuthConfig,
        member_fields: &UserConfig,
        schema: &ModelFields,
        table_matches: impl Fn(EntityRole, &str) -> bool,
    ) -> AuthResult<MemberUserJoin> {
        let schema = schema.organization_join_schema(config);
        let fields = Self::field_schema(member_fields);
        resolve_references(
            (EntityRole::Member, "member", &fields),
            (EntityRole::User, "user", &config.user),
            &schema,
            table_matches,
        )
    }
}

impl MemberUserJoin {
    /// Resolve User query attributes without changing creation or output policies.
    pub fn target_field(config: &AuthConfig, logical: &str) -> UserFieldConfig {
        if logical == "id" {
            return UserFieldConfig::default();
        }
        config
            .user
            .fields()
            .get(logical)
            .cloned()
            .unwrap_or_else(|| UserFieldConfig {
                field_type: match logical {
                    "emailVerified" => UserFieldType::Boolean,
                    "createdAt" | "updatedAt" => UserFieldType::Date,
                    _ => UserFieldType::String,
                },
                ..Default::default()
            })
    }

    /// Resolve the native source column again against the projected Member field names.
    pub fn fallback_from(
        &self,
        member_fields: &UserConfig,
        schema: &ModelFields,
    ) -> AuthResult<String> {
        let fields =
            schema.runtime_fields(EntityRole::Member, &MemberUser::field_schema(member_fields))?;
        Ok(resolve_field("member", &fields, &self.from)?.0.to_owned())
    }

    /// Resolve the fallback query column before installing the User ID query policy.
    pub fn fallback_target(
        &self,
        config: &AuthConfig,
        schema: &ModelFields,
    ) -> AuthResult<(String, String)> {
        let fields = schema.runtime_fields(EntityRole::User, &config.user)?;
        let (logical, physical) = resolve_field("user", &fields, &self.to)?;
        schema.begin_id_query(EntityRole::User)?;
        Ok((logical.to_owned(), physical.to_owned()))
    }

    /// Select the organization summary after every joined user output callback completes.
    pub fn finish(
        &self,
        member: crate::Member,
        users: Vec<UserView>,
        require_user: bool,
    ) -> AuthResult<Option<MemberUser>> {
        let user = if self.many {
            // JavaScript reads the four summary properties from the array, including an empty array.
            crate::MemberUserView::default()
        } else if let Some(user) = users.first() {
            crate::MemberUserView::from_user(user)
        } else if require_user {
            return Err(AuthError::internal("User not found for member"));
        } else {
            return Ok(None);
        };
        Ok(Some(MemberUser { member, user }))
    }
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
