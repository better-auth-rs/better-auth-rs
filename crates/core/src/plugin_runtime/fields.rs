mod device;
mod jwk;
mod two_factor;
mod wallet;

use crate::store::schema::{EntityRole, resolve_field_name};
use crate::user_fields::{AdapterRecord, UserConfig, UserFieldType};
use crate::{ApiKey, AuthConfig, AuthError, AuthResult, Passkey, SchemaValue};
use indexmap::{IndexMap, IndexSet};
use serde_json::{Map, Value};
use std::sync::LazyLock;

/// Plugin field policies consumed by the selected adapter during auth initialization.
#[derive(Clone, Default)]
pub struct ModelFields {
    models: IndexMap<EntityRole, UserConfig>,
    native_fields: IndexMap<EntityRole, IndexSet<String>>,
    organization_output_order: IndexMap<EntityRole, Vec<String>>,
    organization: Option<crate::organization_fields::OrganizationFields>,
}

type StringFields<'a, const N: usize> = [(&'static str, &'a mut SchemaValue<Option<String>>); N];

pub(crate) struct PasskeyFieldPatch {
    pub name: Option<Option<String>>,
    pub aaguid: Option<Option<String>>,
}

impl PasskeyFieldPatch {
    pub(crate) fn apply(self, row: &mut Passkey) {
        if let Some(name) = self.name {
            row.name = name.into();
        }
        if let Some(aaguid) = self.aaguid {
            row.aaguid = aaguid.into();
        }
    }
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
    pub(crate) fn register(&mut self, role: EntityRole, fields: UserConfig) -> AuthResult<()> {
        match role {
            EntityRole::DeviceCode => device::validate_fields(&fields)?,
            EntityRole::Jwk => jwk::validate_fields(&fields)?,
            EntityRole::TwoFactor => two_factor::validate_fields(&fields)?,
            EntityRole::WalletAddress => wallet::validate_fields(&fields)?,
            EntityRole::User
            | EntityRole::Session
            | EntityRole::Account
            | EntityRole::Verification
            | EntityRole::Organization
            | EntityRole::Team => {}
            EntityRole::Passkey | EntityRole::ApiKey => {
                for (name, field) in fields.fields() {
                    if !matches!(
                        (role, name.as_str()),
                        (EntityRole::Passkey, "name" | "aaguid") | (EntityRole::ApiKey, "name")
                    ) || !matches!(field.field_type, UserFieldType::String)
                        || field.references.is_some()
                        || resolve_field_name(field.field_name.as_deref(), name) != name
                    {
                        return Err(AuthError::config(format!(
                            "{role:?} field registration supports only its ordinary string fields (Passkey name/aaguid, ApiKey name) without reference or field-name replacement",
                        )));
                    }
                }
            }
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

    /// Prepare an optional API Key name patch.
    /// `None` omits the supplied name; defaults or `on_update` may still supply it.
    /// `Some(None)` supplies a null value.
    pub async fn api_key_name_for_storage(
        &self,
        name: Option<Option<String>>,
        create: bool,
    ) -> AuthResult<Option<Option<String>>> {
        let core = name
            .into_iter()
            .map(|name| {
                (
                    "name".to_owned(),
                    name.map(Value::String).unwrap_or(Value::Null),
                )
            })
            .collect();
        let mut fields = self
            .fields(EntityRole::ApiKey)
            .organization_storage_fields(core, Map::new(), create)
            .await?;
        optional_string(&mut fields, "name")
    }

    pub(crate) async fn passkey_fields_for_storage(
        &self,
        name: SchemaValue<Option<String>>,
        aaguid: SchemaValue<Option<String>>,
        create: bool,
    ) -> AuthResult<PasskeyFieldPatch> {
        let mut core = Map::new();
        for (name, value) in [("name", name), ("aaguid", aaguid)] {
            if let Some(value) = value.json()? {
                let _ = core.insert(name.into(), value);
            }
        }
        let mut fields = self
            .fields(EntityRole::Passkey)
            .organization_storage_fields(core, Map::new(), create)
            .await?;
        Ok(PasskeyFieldPatch {
            name: optional_string(&mut fields, "name")?,
            aaguid: optional_string(&mut fields, "aaguid")?,
        })
    }

    /// Project passkey display fields together while retaining the other typed record fields.
    pub async fn project_passkeys(&self, rows: Vec<Passkey>) -> AuthResult<Vec<Passkey>> {
        self.project_strings(EntityRole::Passkey, rows, |row| {
            [("name", &mut row.name), ("aaguid", &mut row.aaguid)]
        })
        .await
    }

    /// Project API Key names together while retaining credentials, owners, and counters.
    pub async fn project_api_keys(&self, rows: Vec<ApiKey>) -> AuthResult<Vec<ApiKey>> {
        self.project_strings(EntityRole::ApiKey, rows, |row| [("name", &mut row.name)])
            .await
    }

    async fn project_strings<T: Send, const N: usize>(
        &self,
        role: EntityRole,
        mut rows: Vec<T>,
        columns: fn(&mut T) -> StringFields<'_, N>,
    ) -> AuthResult<Vec<T>> {
        let fields = self.fields(role);
        if fields.fields().is_empty() {
            return Ok(rows);
        }
        let records = rows
            .iter_mut()
            .map(|row| {
                let mut core = Map::new();
                for (name, value) in columns(row) {
                    if let Some(value) = value.json()? {
                        let _ = core.insert(name.into(), value);
                    }
                }
                Ok(AdapterRecord::new(Map::new(), core))
            })
            .collect::<AuthResult<Vec<_>>>()?;
        let output = fields.project_adapter_records(records, true, true).await?;
        for (row, mut output) in rows.iter_mut().zip(output) {
            for (name, value) in columns(row)
                .into_iter()
                .filter(|(name, _)| fields.fields().contains_key(*name))
            {
                *value = output
                    .shift_remove(name)
                    .map(|value| value.json())
                    .transpose()?
                    .flatten()
                    .map(serde_json::from_value)
                    .transpose()?
                    .map(SchemaValue::Typed)
                    .unwrap_or_default();
            }
        }
        Ok(rows)
    }
}
