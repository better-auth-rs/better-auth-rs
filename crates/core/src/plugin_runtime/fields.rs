mod api_key;
mod device;
mod jwk;
mod passkey;
mod two_factor;
mod wallet;

use crate::store::schema::{EntityRole, resolve_field_name};
use crate::user_fields::{AdapterRecord, UserConfig, UserFieldType};
use crate::{AuthConfig, AuthError, AuthResult, SchemaValue};
use indexmap::{IndexMap, IndexSet};
use serde_json::{Map, Value};
use std::sync::LazyLock;

/// Plugin field policies consumed by the selected adapter during auth initialization.
#[derive(Clone, Default)]
pub struct ModelFields {
    models: IndexMap<EntityRole, UserConfig>,
    schema_models: Option<Vec<(EntityRole, &'static str)>>,
    native_fields: IndexMap<EntityRole, IndexSet<String>>,
    organization_output_order: IndexMap<EntityRole, Vec<String>>,
    organization: Option<crate::organization_fields::OrganizationFields>,
}

fn optional_string(
    fields: &mut Map<String, Value>,
    name: &str,
) -> AuthResult<Option<Option<String>>> {
    fields
        .remove(name)
        .map(serde_json::from_value)
        .transpose()
        .map_err(Into::into)
}

impl ModelFields {
    /// Retain the same active logical models used by runtime schema validation.
    pub fn set_schema_configuration(&mut self, config: &crate::store::schema::SchemaConfiguration) {
        self.schema_models = Some(config.models());
    }

    pub(crate) fn resolve_model_name(
        &self,
        candidate: &str,
        table_matches: &impl Fn(EntityRole, &str) -> bool,
    ) -> AuthResult<&'static str> {
        let models = self.schema_models.as_deref().unwrap_or(&[
            (EntityRole::User, "user"),
            (EntityRole::Session, "session"),
            (EntityRole::Account, "account"),
            (EntityRole::Verification, "verification"),
        ]);
        // Logical model names take precedence over every physical table alias.
        models
            .iter()
            .find(|(_, name)| *name == candidate)
            .or_else(|| {
                models
                    .iter()
                    .find(|(role, _)| table_matches(*role, candidate))
            })
            .map(|(_, name)| *name)
            .ok_or_else(|| AuthError::config(format!("Model \"{candidate}\" not found in schema")))
    }

    pub(crate) fn register(&mut self, role: EntityRole, fields: UserConfig) -> AuthResult<()> {
        match role {
            EntityRole::ApiKey => {
                let mut combined = self.fields(role).clone();
                combined.fields_mut().extend(fields.fields().clone());
                api_key::validate_fields(&combined)?;
            }
            EntityRole::DeviceCode => device::validate_fields(&fields)?,
            EntityRole::Jwk => jwk::validate_fields(&fields)?,
            EntityRole::Passkey => {
                let mut combined = self.fields(role).clone();
                combined.fields_mut().extend(fields.fields().clone());
                passkey::validate_fields(&combined)?;
            }
            EntityRole::TwoFactor => two_factor::validate_fields(&fields)?,
            EntityRole::WalletAddress => wallet::validate_fields(&fields)?,
            EntityRole::User
            | EntityRole::Session
            | EntityRole::Account
            | EntityRole::Verification
            | EntityRole::Organization
            | EntityRole::Team => {}
            _ => {
                return Err(AuthError::config(format!(
                    "Plugin field registration does not support {role:?}"
                )));
            }
        }
        self.extend(role, fields);
        if role == EntityRole::Passkey
            && let Some(fields) = self.models.get_mut(&role)
        {
            // Replacing an upstream field policy retains the field's schema position.
            fields.fields_mut().sort_by(|left, _, right, _| {
                passkey::field_order(left).cmp(&passkey::field_order(right))
            });
        }
        if role == EntityRole::ApiKey
            && let Some(fields) = self.models.get_mut(&role)
        {
            fields
                .fields_mut()
                .sort_by(|left, _, right, _| (left != "name").cmp(&(right != "name")));
        }
        Ok(())
    }

    pub(crate) fn extend(&mut self, role: EntityRole, fields: UserConfig) {
        if let Some(fields) = fields.additional_fields {
            if let Some(native) = self.native_fields.get_mut(&role) {
                native.retain(|name| !fields.contains_key(name));
            }
            self.models
                .entry(role)
                .or_default()
                .fields_mut()
                .extend(fields);
        }
    }

    pub(crate) fn register_organization_schema(
        &mut self,
        fields: &crate::organization_fields::OrganizationFields,
        teams_enabled: bool,
    ) {
        self.organization = Some(fields.clone());
        self.declare_native_fields(
            EntityRole::Organization,
            &["name", "slug", "logo", "createdAt", "metadata"],
            fields.organization.clone(),
        );
        if teams_enabled {
            self.declare_native_fields(
                EntityRole::Team,
                &[
                    "name",
                    "memberCount",
                    "organizationId",
                    "createdAt",
                    "updatedAt",
                ],
                fields.team.clone(),
            );
        }
        self.declare_native_fields(
            EntityRole::Member,
            &["organizationId", "userId", "role", "createdAt"],
            fields.member.clone(),
        );
        self.declare_native_fields(
            EntityRole::Invitation,
            &[
                "organizationId",
                "email",
                "role",
                "teamId",
                "status",
                "expiresAt",
                "createdAt",
                "inviterId",
            ],
            fields.invitation.clone(),
        );
        self.declare_native_fields(
            EntityRole::OrganizationRole,
            &[
                "organizationId",
                "role",
                "permission",
                "createdAt",
                "updatedAt",
            ],
            fields.organization_role.clone(),
        );
    }

    fn declare_native_fields(&mut self, role: EntityRole, names: &[&str], fields: UserConfig) {
        let registered = self.models.entry(role).or_default().fields_mut();
        let native = self.native_fields.entry(role).or_default();
        for name in names {
            // Reserve the schema position; the adapter already implements native field defaults.
            let _ = registered.insert((*name).into(), Default::default());
            let _ = native.insert((*name).into());
        }
        self.extend(role, fields);
    }

    /// Resolve Organization model policies without replacing adapter-owned native defaults.
    pub fn organization_fields(
        &self,
        fields: crate::organization_fields::OrganizationFields,
    ) -> crate::organization_fields::OrganizationFields {
        let mut fields = self.organization.clone().unwrap_or(fields);
        for (role, schema) in [
            (EntityRole::Organization, &mut fields.organization),
            (EntityRole::Team, &mut fields.team),
            (EntityRole::Member, &mut fields.member),
            (EntityRole::Invitation, &mut fields.invitation),
            (EntityRole::OrganizationRole, &mut fields.organization_role),
        ] {
            let Some(registered) = self.models.get(&role) else {
                continue;
            };
            let mut resolved = registered.clone();
            for (name, field) in schema.fields() {
                let _ = resolved
                    .fields_mut()
                    .entry(name.clone())
                    .or_insert_with(|| field.clone());
            }
            if let Some(native) = self.native_fields.get(&role) {
                resolved
                    .fields_mut()
                    .retain(|name, _| !native.contains(name));
            }
            *schema = resolved;
        }
        // Upstream initializes the dynamic-role update schema eagerly as partial.
        for field in fields.organization_role.fields_mut().values_mut() {
            field.required = Some(false);
        }
        fields
    }

    /// Read the adapter policies for one supported model.
    pub fn fields(&self, role: EntityRole) -> &UserConfig {
        static EMPTY: LazyLock<UserConfig> = LazyLock::new(UserConfig::default);
        self.models.get(&role).unwrap_or(&EMPTY)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (EntityRole, &UserConfig)> {
        self.models.iter().map(|(role, fields)| (*role, fields))
    }

    pub(crate) fn organization_output_field_names(
        &self,
        role: EntityRole,
        policies: &UserConfig,
    ) -> Vec<String> {
        let mut names = self
            .organization_output_order
            .get(&role)
            .cloned()
            .unwrap_or_else(|| {
                let mut fields = Self::default();
                fields.register_organization_schema(&Default::default(), true);
                fields.fields(role).fields().keys().cloned().collect()
            });
        for name in policies.fields().keys() {
            if !names.contains(name) {
                names.push(name.clone());
            }
        }
        names.retain(|name| name != "id");
        names.push("id".into());
        names
    }

    /// Merge core policies and retain plugin-table policies for `RuntimeStore::with_runtime`.
    /// Application fields win at the adapter; plugin fields win at existing endpoint parsers.
    pub fn resolve(mut self, application: &AuthConfig) -> (AuthConfig, AuthConfig, Self) {
        let mut adapter = application.clone();
        let mut endpoint = application.clone();
        let mut resolve = |role, configured| {
            let fields = self.models.shift_remove(&role).unwrap_or_default();
            super::resolve_user_fields(&configured, fields)
        };
        (adapter.user, endpoint.user) = resolve(EntityRole::User, application.user.clone());
        let (stored, public) = resolve(EntityRole::Session, application.session.field_schema());
        adapter.session.additional_fields = stored.additional_fields;
        endpoint.session.additional_fields = public.additional_fields;
        let (stored, public) = resolve(
            EntityRole::Account,
            UserConfig {
                additional_fields: Some(application.account.additional_fields.clone()),
            },
        );
        adapter.account.additional_fields = stored.additional_fields.unwrap_or_default();
        endpoint.account.additional_fields = public.additional_fields.unwrap_or_default();
        let (stored, public) = resolve(
            EntityRole::Verification,
            UserConfig {
                additional_fields: Some(application.verification.additional_fields.clone()),
            },
        );
        adapter.verification.additional_fields = stored.additional_fields.unwrap_or_default();
        endpoint.verification.additional_fields = public.additional_fields.unwrap_or_default();
        for (role, native) in &self.native_fields {
            if let Some(fields) = self.models.get_mut(role) {
                // Native slots determine read timing but are not configured adapter policies.
                let _ = self
                    .organization_output_order
                    .insert(*role, fields.fields().keys().cloned().collect());
                fields.fields_mut().retain(|name, _| !native.contains(name));
            }
        }
        (adapter, endpoint, self)
    }
}
