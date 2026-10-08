//! Runtime projections returned by the core adapter's ordinary joins.

use crate::{
    AuthConfig, AuthError, AuthResult,
    plugin_runtime::ModelFields,
    store::schema::{EntityRole, resolve_field_name},
    user_fields::{USER_FIELDS, UserConfig, UserFieldConfig, UserFieldReference, UserFieldType},
    wire::{AccountView, UserView},
};

/// The selected relationship preserves a single record, a missing record, or a record page.
#[derive(Debug, Clone)]
pub enum JoinValue<T> {
    /// A relationship that selects at most one record.
    One(Option<T>),
    /// A relationship that selects a record page, including an empty page.
    Many(Vec<T>),
}

/// An account and the User relationship selected by the active schema.
#[derive(Debug, Clone)]
pub struct AccountOwner {
    pub account: AccountView,
    pub user: JoinValue<UserView>,
}

impl AccountOwner {
    /// Validate final Account/User references before reading either model.
    pub fn validate_schema(
        config: &AuthConfig,
        schema: &ModelFields,
        table_matches: impl Fn(EntityRole, &str) -> bool,
    ) -> AuthResult<()> {
        Self::resolve_schema(config, schema, table_matches).map(|_| ())
    }

    /// Resolve final Account/User references before reading either model.
    pub fn resolve_schema(
        config: &AuthConfig,
        schema: &ModelFields,
        table_matches: impl Fn(EntityRole, &str) -> bool,
    ) -> AuthResult<ResolvedJoin> {
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
    }
}

impl crate::session::SessionData {
    /// Validate final Session/User references before reading either model.
    #[doc(hidden)]
    pub fn validate_schema(
        config: &AuthConfig,
        schema: &ModelFields,
        table_matches: impl Fn(EntityRole, &str) -> bool,
    ) -> AuthResult<()> {
        Self::resolve_schema(config, schema, table_matches).map(|_| ())
    }

    /// Resolve the Session/User relationship before reading either model.
    #[doc(hidden)]
    pub fn resolve_schema(
        config: &AuthConfig,
        schema: &ModelFields,
        table_matches: impl Fn(EntityRole, &str) -> bool,
    ) -> AuthResult<ResolvedJoin> {
        let fields = super::session_create_schema(&config.session, &crate::FieldMap::new());
        resolve_references(
            (EntityRole::Session, "session", &fields),
            (EntityRole::User, "user", &config.user),
            schema,
            table_matches,
        )
    }
}

/// A user and the Account relationship selected by the active schema.
#[derive(Debug, Clone)]
pub struct UserAccounts {
    pub user: UserView,
    pub accounts: JoinValue<AccountView>,
}

impl UserAccounts {
    /// Validate final User/Account references before reading either model.
    pub fn validate_schema(
        config: &AuthConfig,
        schema: &ModelFields,
        table_matches: impl Fn(EntityRole, &str) -> bool,
    ) -> AuthResult<()> {
        Self::resolve_schema(config, schema, table_matches).map(|_| ())
    }

    /// Resolve final User/Account references before reading either model.
    pub fn resolve_schema(
        config: &AuthConfig,
        schema: &ModelFields,
        table_matches: impl Fn(EntityRole, &str) -> bool,
    ) -> AuthResult<ResolvedJoin> {
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
    }

    /// The internal adapter replaces a null Account relationship with an empty page.
    pub fn new(user: UserView, accounts: JoinValue<AccountView>) -> Self {
        let accounts = match accounts {
            JoinValue::One(None) => JoinValue::Many(Vec::new()),
            accounts => accounts,
        };
        Self { user, accounts }
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
) -> AuthResult<ResolvedJoin> {
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
            Ok(ResolvedJoin {
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

/// Selected join fields and result cardinality.
#[derive(Debug, Clone)]
pub struct ResolvedJoin {
    /// Physical field on the parent model.
    pub from: String,
    /// Physical field on the child model.
    pub to: String,
    /// Original logical parent field corresponding to the native source column.
    pub logical_from: String,
    /// Original logical child field corresponding to the native target column.
    pub logical_to: String,
    /// Whether the selected foreign key returns a page instead of one record.
    pub many: bool,
}

impl MemberUser {
    #[doc(hidden)]
    pub fn field_schema(configured: &UserConfig) -> UserConfig {
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
                ..Default::default()
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
    ) -> AuthResult<ResolvedJoin> {
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

impl ResolvedJoin {
    /// Resolve User query attributes without changing creation or output policies.
    pub fn user_field(config: &AuthConfig, logical: &str) -> UserFieldConfig {
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
                    "emailVerified"
                    | "isAnonymous"
                    | "phoneNumberVerified"
                    | "twoFactorEnabled"
                    | "banned" => UserFieldType::Boolean,
                    "createdAt" | "updatedAt" | "banExpires" => UserFieldType::Date,
                    _ => UserFieldType::String,
                },
                ..Default::default()
            })
    }

    /// Resolve the native source column again against the projected parent field names.
    pub fn fallback_from(
        &self,
        (role, model, fields): (EntityRole, &str, &UserConfig),
        schema: &ModelFields,
    ) -> AuthResult<String> {
        let fields = schema.runtime_fields(role, fields)?;
        Ok(resolve_field(model, &fields, &self.from)?.0.to_owned())
    }

    /// Resolve the fallback query column before installing the child ID query policy.
    pub fn fallback_target(
        &self,
        (role, model, fields): (EntityRole, &str, &UserConfig),
        schema: &ModelFields,
    ) -> AuthResult<(String, String)> {
        let fields = schema.runtime_fields(role, fields)?;
        let (logical, physical) = resolve_field(model, &fields, &self.to)?;
        schema.begin_id_query(role)?;
        Ok((logical.to_owned(), physical.to_owned()))
    }
}

impl MemberUser {
    /// Select the organization summary after every joined user output callback completes.
    pub fn finish(
        relation: &ResolvedJoin,
        member: crate::Member,
        users: Vec<crate::MemberUserView>,
        require_user: bool,
    ) -> AuthResult<Option<MemberUser>> {
        let user = if relation.many {
            // JavaScript reads the four summary properties from the array, including an empty array.
            crate::MemberUserView::default()
        } else if let Some(user) = users.first() {
            user.clone()
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
    /// Match a native session organization ID.
    IdValue(&'a crate::FieldValue),
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
