use crate::store::schema::EntityRole;
use crate::user_fields::{AdapterRecord, UserConfig, UserFieldType};
use crate::{ApiKey, AuthConfig, AuthError, AuthResult, Passkey};
use indexmap::IndexMap;
use serde_json::{Map, Value};
use std::sync::LazyLock;

/// Plugin field policies consumed by the selected adapter during auth initialization.
#[derive(Clone, Default)]
pub struct ModelFields(IndexMap<EntityRole, UserConfig>);

impl ModelFields {
    pub(crate) fn register(&mut self, role: EntityRole, fields: UserConfig) -> AuthResult<()> {
        match role {
            EntityRole::User
            | EntityRole::Session
            | EntityRole::Account
            | EntityRole::Verification => {}
            EntityRole::Passkey | EntityRole::ApiKey => {
                for (name, field) in fields.fields() {
                    if name != "name"
                        || !matches!(field.field_type, UserFieldType::String)
                        || field.references.is_some()
                        || field
                            .field_name
                            .as_deref()
                            .is_some_and(|name| name != "name")
                    {
                        return Err(AuthError::config(format!(
                            "{role:?} field registration supports only the ordinary string field name without reference or field-name replacement",
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
        Ok(())
    }

    pub(crate) fn extend(&mut self, role: EntityRole, fields: UserConfig) {
        if let Some(fields) = fields.additional_fields {
            self.0.entry(role).or_default().fields_mut().extend(fields);
        }
    }

    /// Read the adapter policies for one supported model.
    pub fn fields(&self, role: EntityRole) -> &UserConfig {
        static EMPTY: LazyLock<UserConfig> = LazyLock::new(UserConfig::default);
        self.0.get(&role).unwrap_or(&EMPTY)
    }

    /// Merge core policies and retain plugin-table policies for `RuntimeStore::with_runtime`.
    /// Application fields win at the adapter; plugin fields win at existing endpoint parsers.
    pub fn resolve(mut self, application: &AuthConfig) -> (AuthConfig, AuthConfig, Self) {
        let mut adapter = application.clone();
        let mut endpoint = application.clone();
        let mut resolve = |role, configured| {
            let fields = self.0.shift_remove(&role).unwrap_or_default();
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
        (adapter, endpoint, self)
    }

    /// Prepare an optional name patch for the supported Passkey or API Key model.
    /// `None` omits the supplied name; defaults or `on_update` may still supply it.
    /// `Some(None)` supplies a null value.
    pub async fn name_for_storage(
        &self,
        role: EntityRole,
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
        self.fields(role)
            .organization_storage_fields(core, Map::new(), create)
            .await?
            .remove("name")
            .map(serde_json::from_value)
            .transpose()
            .map_err(Into::into)
    }

    /// Project passkey names together while retaining the other typed record fields.
    pub async fn project_passkeys(&self, rows: Vec<Passkey>) -> AuthResult<Vec<Passkey>> {
        self.project_names(EntityRole::Passkey, rows, |row| &mut row.name)
            .await
    }

    /// Project API Key names together while retaining credentials, owners, and counters.
    pub async fn project_api_keys(&self, rows: Vec<ApiKey>) -> AuthResult<Vec<ApiKey>> {
        self.project_names(EntityRole::ApiKey, rows, |row| &mut row.name)
            .await
    }

    async fn project_names<T: Send>(
        &self,
        role: EntityRole,
        mut rows: Vec<T>,
        name: impl Fn(&mut T) -> &mut Option<String> + Send + Sync,
    ) -> AuthResult<Vec<T>> {
        let fields = self.fields(role);
        if fields.fields().is_empty() {
            return Ok(rows);
        }
        let records = rows
            .iter_mut()
            .map(|row| {
                AdapterRecord::new(
                    Map::new(),
                    Map::from_iter([(
                        "name".into(),
                        name(row).clone().map(Value::String).unwrap_or(Value::Null),
                    )]),
                )
            })
            .collect();
        let output = fields.project_adapter_records(records, true, true).await?;
        for (row, mut output) in rows.iter_mut().zip(output) {
            *name(row) = output
                .shift_remove("name")
                .map(|value| value.json())
                .transpose()?
                .flatten()
                .map(serde_json::from_value)
                .transpose()?
                .flatten();
        }
        Ok(rows)
    }
}
