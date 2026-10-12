//! Runtime projections returned by the core adapter's ordinary joins.

mod organization;

use crate::{
    AuthConfig, AuthError, AuthResult,
    plugin_runtime::ModelFields,
    store::schema::{EntityRole, resolve_field_name},
    user_fields::{USER_FIELDS, UserConfig, UserFieldConfig, UserFieldReference},
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

impl<T> JoinValue<T> {
    /// Consume a relationship at the JavaScript array-operation boundary.
    pub fn into_required_page(self, name: &str) -> AuthResult<Vec<T>> {
        match self {
            Self::Many(rows) => Ok(rows),
            Self::One(None) => Err(AuthError::type_error(
                "Cannot read properties of null (reading 'map')",
            )),
            Self::One(Some(_)) => Err(AuthError::type_error(format!(
                "{name}.map is not a function"
            ))),
        }
    }
}

impl From<JoinValue<crate::FieldMap>> for crate::FieldValue {
    fn from(value: JoinValue<crate::FieldMap>) -> Self {
        match value {
            JoinValue::One(row) => row.map_or(Self::Null, Self::from),
            JoinValue::Many(rows) => rows.into_iter().map(Self::from).collect::<Vec<_>>().into(),
        }
    }
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
            && schema
                .resolve_model_key(&reference.model, table_matches)?
                .logical_name()?
                == target
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

/// An invitation and the Organization relationship selected by the final field declarations.
#[derive(Debug, Clone)]
pub struct InvitationOrganization {
    pub invitation: crate::Invitation,
    /// Complete projected child fields, including null and page relationships.
    pub organization: JoinValue<crate::FieldMap>,
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
    /// Resolve final Member/User references before reading either model.
    pub fn resolve_schema(
        config: &AuthConfig,
        member_fields: &UserConfig,
        schema: &ModelFields,
        table_matches: impl Fn(EntityRole, &str) -> bool,
    ) -> AuthResult<ResolvedJoin> {
        let schema = schema.organization_join_schema();
        resolve_references(
            (EntityRole::Member, "member", member_fields),
            (EntityRole::User, "user", &config.user),
            &schema,
            table_matches,
        )
    }
}

impl ResolvedJoin {
    /// Resolve an adapter relationship from the complete registered declarations.
    #[doc(hidden)]
    pub fn resolve(
        base: (EntityRole, &str, &UserConfig),
        model: (EntityRole, &str, &UserConfig),
        schema: &ModelFields,
        table_matches: impl Fn(EntityRole, &str) -> bool,
    ) -> AuthResult<Self> {
        resolve_references(base, model, schema, table_matches)
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
        use crate::{AuthRecordFields, FromFieldMap};

        let user = if relation.many {
            // JavaScript reads the four summary properties from the array, including an empty array.
            crate::MemberUserView::default()
        } else if let Some(user) = users.first() {
            user.clone()
        } else if require_user {
            return Err(AuthError::type_error(
                "null is not an object (evaluating 'user.id')",
            ));
        } else {
            return Ok(None);
        };
        let mut fields = member.field_values()?;
        let _ = fields.remove("user");
        let member = crate::Member::from_field_values(fields)?;
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

/// Adapter output retained until the Organization plugin consumes public fields.
#[derive(Debug, Clone)]
pub struct OrganizationDetails {
    /// Ordered parent fields, including projected relationship properties.
    pub organization: crate::FieldMap,
    /// Invitation cardinality remains unchecked until public member and parent output complete.
    pub invitations: JoinValue<crate::FieldMap>,
    /// Member page after the plugin's first array operation.
    pub members: Vec<crate::FieldMap>,
    /// Users loaded from the projected member selectors, in adapter order.
    pub users: Vec<UserView>,
    /// Preserve omitted and singular team relationships until public consumption.
    pub teams: Option<JoinValue<crate::FieldMap>>,
}

/// A projected team and its requested membership relationship.
#[derive(Debug, Clone)]
pub struct TeamDetails {
    pub team: crate::Team,
    /// Preserve omission and singular relationships until the public consumer runs.
    pub members: Option<JoinValue<crate::TeamMember>>,
}

impl TeamDetails {
    #[doc(hidden)]
    pub fn from_adapter_output(
        mut output: crate::FieldMap,
        members: Option<(Vec<crate::FieldMap>, bool)>,
    ) -> AuthResult<Self> {
        use crate::FromFieldMap;
        let _ = output.shift_remove("teamMember");
        let _ = output.shift_remove("memberCount");
        let members = members
            .map(|(rows, many)| -> AuthResult<_> {
                let rows = rows
                    .into_iter()
                    .map(crate::TeamMember::from_field_values)
                    .collect::<AuthResult<Vec<_>>>()?;
                Ok(if many {
                    JoinValue::Many(rows)
                } else {
                    JoinValue::One(rows.into_iter().next())
                })
            })
            .transpose()?;
        Ok(Self {
            team: crate::Team::from_field_values(output)?,
            members,
        })
    }

    /// Apply public Team output before consuming the membership relationship as an array.
    pub fn into_public_parts(
        self,
        schema: &UserConfig,
    ) -> AuthResult<(crate::Team, Option<Vec<crate::TeamMember>>)> {
        let team = self.team.filter_output_fields(schema)?;
        let members = self
            .members
            .map(|members| match members {
                JoinValue::Many(members) => Ok(members),
                JoinValue::One(None) => Ok(Vec::new()),
                JoinValue::One(Some(_)) => {
                    Err(AuthError::type_error("members.map is not a function"))
                }
            })
            .transpose()?;
        Ok((team, members))
    }
}
