//! Entity traits for the Better Auth framework.
//!
//! These traits define the interface that entity types must implement.
//! The framework uses trait methods and native field extraction to read entity fields.
//! Custom models may use their own field names and additional fields.
//!
//! Implement these traits manually for any custom types used inside the auth
//! runtime.

use std::borrow::Cow;

use chrono::Utc;
use serde::Serialize;

use crate::{SchemaValue, types::InvitationStatus};

/// Extract native adapter fields without converting object values to JSON.
pub trait AuthRecordFields {
    fn field_values(&self) -> crate::AuthResult<crate::FieldMap>;

    /// Deep-copy runtime objects through one graph context while retaining record state.
    fn structured_clone(
        &self,
        context: &mut crate::StructuredCloneContext,
    ) -> crate::AuthResult<Self>
    where
        Self: FromFieldMap,
    {
        Self::from_field_values(context.clone_map(&self.field_values()?))
    }
}

/// Reconstruct a runtime record from native adapter fields.
pub trait FromFieldMap: Sized {
    fn from_field_values(fields: crate::FieldMap) -> crate::AuthResult<Self>;
}

impl AuthRecordFields for crate::FieldMap {
    fn field_values(&self) -> crate::AuthResult<Self> {
        Ok(self.clone())
    }

    fn structured_clone(
        &self,
        context: &mut crate::StructuredCloneContext,
    ) -> crate::AuthResult<Self> {
        Ok(context.clone_map(self))
    }
}

impl FromFieldMap for crate::FieldMap {
    fn from_field_values(fields: Self) -> crate::AuthResult<Self> {
        Ok(fields)
    }
}

/// Trait representing a user entity.
///
/// The framework reads `name`, `image`, and nullable `twoFactorEnabled` from native field extraction.
/// Other core fields use getters. The `two_factor_enabled` getter supplies truthiness to runtime guards.
/// Custom types must provide all framework fields and may have additional fields.
/// If serialized keys differ, override [`Self::serialized_field_name`].
/// `AuthEntity` generates the serialized field mapping for derived models.
pub trait AuthUser:
    AuthRecordFields + Clone + Send + Sync + Serialize + std::fmt::Debug + 'static
{
    /// Preserve the source property order for native runtime records.
    fn field_order(&self) -> Option<&[String]> {
        None
    }
    /// Field presence for runtime records and signed snapshots. Database models use `None`.
    /// A missing optional core field differs from a present field containing JSON null.
    fn field_presence(&self) -> Option<&std::collections::BTreeSet<String>> {
        None
    }
    /// Already projected application fields, for views reconstructed from session caches.
    /// Storage models return `None` so the output transform runs exactly once per database read.
    fn projected_fields(&self) -> Option<&crate::FieldMap> {
        None
    }
    /// Plugin fields that the entity and store can read and persist.
    ///
    /// `AuthEntity` derives this list. Manual implementations must declare each
    /// supported field by its Rust name. An empty list supports core fields only.
    const PLUGIN_FIELDS: &'static [&'static str] = &[];

    /// Reject a plugin whose required fields are absent from this entity.
    fn require_plugin_fields(plugin: &str, required: &[&str]) -> crate::AuthResult<()> {
        require_plugin_fields(plugin, "user", Self::PLUGIN_FIELDS, required)
    }

    /// Resolve canonical field names to serialized application model fields.
    fn serialized_field_name(name: &str) -> &str {
        name
    }

    fn id(&self) -> SchemaValue<Cow<'_, str>>;
    fn email(&self) -> Option<&str>;
    fn email_verified(&self) -> bool;
    fn created_at(&self) -> crate::FieldDate;
    fn updated_at(&self) -> crate::FieldDate;
    fn is_anonymous(&self) -> Option<bool> {
        None
    }
    fn phone_number(&self) -> Option<&str> {
        None
    }
    fn phone_number_verified(&self) -> Option<bool> {
        None
    }
    fn username(&self) -> Option<&str>;
    fn display_username(&self) -> Option<&str>;
    fn two_factor_enabled(&self) -> bool;
    fn role(&self) -> Option<&str>;
    fn banned(&self) -> bool;
    fn ban_reason(&self) -> Option<&str>;
    fn ban_expires(&self) -> Option<crate::FieldDate>;
}

/// Trait representing a session entity.
pub trait AuthSession:
    AuthRecordFields + Clone + Send + Sync + Serialize + std::fmt::Debug + 'static
{
    /// Preserve the source property order for native runtime records.
    fn field_order(&self) -> Option<&[String]> {
        None
    }
    /// Optional field presence for runtime records; database models expose every mapped column.
    fn field_presence(&self) -> Option<&std::collections::BTreeSet<String>> {
        None
    }
    /// Resolve an application field alias to the model's serialized key.
    fn serialized_field_name(name: &str) -> &str {
        name
    }
    /// Already projected fields from a cached session view.
    fn projected_fields(&self) -> Option<&crate::FieldMap> {
        None
    }

    /// Plugin fields that the entity and store can read and persist.
    ///
    /// `AuthEntity` derives this list. Manual implementations must declare each
    /// supported field by its Rust name. An empty list supports core fields only.
    const PLUGIN_FIELDS: &'static [&'static str] = &[];

    /// Reject a plugin whose required fields are absent from this entity.
    fn require_plugin_fields(plugin: &str, required: &[&str]) -> crate::AuthResult<()> {
        require_plugin_fields(plugin, "session", Self::PLUGIN_FIELDS, required)
    }

    fn id(&self) -> SchemaValue<Cow<'_, str>>;
    fn expires_at(&self) -> SchemaValue<crate::FieldDate>;
    fn token(&self) -> SchemaValue<Cow<'_, str>>;
    fn created_at(&self) -> SchemaValue<crate::FieldDate>;
    fn updated_at(&self) -> SchemaValue<crate::FieldDate>;
    fn ip_address(&self) -> SchemaValue<Option<Cow<'_, str>>>;
    fn user_agent(&self) -> SchemaValue<Option<Cow<'_, str>>>;
    fn user_id(&self) -> SchemaValue<Cow<'_, str>>;
    fn impersonated_by(&self) -> SchemaValue<Option<Cow<'_, str>>>;
    fn active_organization_id(&self) -> SchemaValue<Option<Cow<'_, str>>>;
    /// Active team selected for this session.
    fn active_team_id(&self) -> SchemaValue<Option<Cow<'_, str>>> {
        SchemaValue::Typed(None)
    }
    fn active(&self) -> bool;
}

fn require_plugin_fields(
    plugin: &str,
    entity: &str,
    available: &[&str],
    required: &[&str],
) -> crate::AuthResult<()> {
    for field in required {
        if !available.contains(field) {
            return Err(crate::AuthError::config(format!(
                "Plugin `{plugin}` requires {entity} field `{field}`; add the field and migrate the database"
            )));
        }
    }
    Ok(())
}

/// Trait representing an account entity (OAuth provider linking).
pub trait AuthAccount:
    AuthRecordFields + Clone + Send + Sync + Serialize + std::fmt::Debug + 'static
{
    /// Optional field presence for runtime records; database models expose every mapped column.
    fn field_presence(&self) -> Option<&std::collections::BTreeSet<String>> {
        None
    }
    fn id(&self) -> Cow<'_, str>;
    fn account_id(&self) -> &str;
    fn provider_id(&self) -> &str;
    fn user_id(&self) -> Cow<'_, str>;
    fn access_token(&self) -> Option<&str>;
    fn refresh_token(&self) -> Option<&str>;
    fn id_token(&self) -> Option<&str>;
    fn access_token_expires_at(&self) -> Option<crate::FieldDate>;
    fn refresh_token_expires_at(&self) -> Option<crate::FieldDate>;
    fn scope(&self) -> Option<&str>;
    fn password(&self) -> Option<&str>;
    fn created_at(&self) -> crate::FieldDate;
    fn updated_at(&self) -> crate::FieldDate;
}

/// Trait representing an organization entity.
pub trait AuthOrganization:
    AuthRecordFields + Clone + Send + Sync + Serialize + std::fmt::Debug + 'static
{
    /// Application fields already projected by the adapter.
    fn projected_fields(&self) -> Option<&crate::FieldMap> {
        None
    }

    fn id(&self) -> SchemaValue<Cow<'_, str>>;
    fn name(&self) -> &SchemaValue<String>;
    fn slug(&self) -> &SchemaValue<String>;
    fn logo(&self) -> &SchemaValue<Option<String>>;
    fn metadata(&self) -> &SchemaValue<Option<crate::FieldValue>>;
    fn created_at(&self) -> &SchemaValue<crate::FieldDate>;
}

/// Trait representing an organization member entity.
pub trait AuthMember:
    AuthRecordFields + Clone + Send + Sync + Serialize + std::fmt::Debug + 'static
{
    /// Application fields already projected by the adapter.
    fn projected_fields(&self) -> Option<&crate::FieldMap> {
        None
    }

    fn id(&self) -> SchemaValue<Cow<'_, str>>;
    fn organization_id(&self) -> &SchemaValue<String>;
    fn user_id(&self) -> &SchemaValue<String>;
    fn role(&self) -> &SchemaValue<String>;
    fn created_at(&self) -> &SchemaValue<crate::FieldDate>;
}

/// Trait representing an invitation entity.
pub trait AuthInvitation:
    AuthRecordFields + Clone + Send + Sync + Serialize + std::fmt::Debug + 'static
{
    /// Application fields already projected by the adapter.
    fn projected_fields(&self) -> Option<&crate::FieldMap> {
        None
    }

    fn id(&self) -> SchemaValue<Cow<'_, str>>;
    fn organization_id(&self) -> &SchemaValue<String>;
    fn email(&self) -> &SchemaValue<String>;
    fn role(&self) -> &SchemaValue<String>;
    fn status(&self) -> &SchemaValue<InvitationStatus>;
    fn inviter_id(&self) -> &SchemaValue<String>;
    fn expires_at(&self) -> &SchemaValue<crate::FieldDate>;
    fn created_at(&self) -> &SchemaValue<crate::FieldDate>;

    /// Check if the invitation is still pending.
    fn is_pending(&self) -> bool {
        self.status() == &SchemaValue::Typed(InvitationStatus::Pending)
    }

    /// Check if the invitation has expired.
    fn is_expired(&self) -> crate::AuthResult<bool> {
        self.expires_at().is_before(Utc::now())
    }
    /// Comma-separated invited team identifiers.
    fn team_id(&self) -> &SchemaValue<Option<String>>;
}

/// Trait representing a verification token entity.
pub trait AuthVerification:
    AuthRecordFields + Clone + Send + Sync + Serialize + std::fmt::Debug + 'static
{
    fn id(&self) -> Cow<'_, str>;
    fn identifier(&self) -> &str;
    fn value(&self) -> &str;
    fn expires_at(&self) -> crate::FieldDate;
    fn created_at(&self) -> crate::FieldDate;
    fn updated_at(&self) -> crate::FieldDate;
}

/// Trait representing a two-factor authentication entity.
pub trait AuthTwoFactor:
    AuthRecordFields + Clone + Send + Sync + Serialize + std::fmt::Debug + 'static
{
    /// Return application fields when the entity already contains an adapter projection.
    fn additional_fields(&self) -> Option<&crate::FieldMap> {
        None
    }
    fn id(&self) -> SchemaValue<Cow<'_, str>>;
    fn secret(&self) -> &SchemaValue<String>;
    fn backup_codes(&self) -> &SchemaValue<String>;
    fn user_id(&self) -> SchemaValue<Cow<'_, str>>;
    fn verified(&self) -> &SchemaValue<Option<bool>>;
    fn failed_verification_count(&self) -> &SchemaValue<Option<f64>>;
    fn locked_until(&self) -> &SchemaValue<Option<crate::FieldDate>>;
    fn created_at(&self) -> &SchemaValue<crate::FieldDate>;
    fn updated_at(&self) -> &SchemaValue<crate::FieldDate>;
}

/// Trait representing an API key entity.
pub trait AuthApiKey:
    AuthRecordFields + Clone + Send + Sync + Serialize + std::fmt::Debug + 'static
{
    /// Return application fields when the entity already contains an adapter projection.
    fn additional_fields(&self) -> Option<&crate::FieldMap> {
        None
    }
    fn id(&self) -> SchemaValue<Cow<'_, str>>;
    fn name(&self) -> &SchemaValue<Option<String>>;
    fn start(&self) -> &SchemaValue<Option<crate::ApiKeyStart>>;
    fn prefix(&self) -> &SchemaValue<Option<String>>;
    fn key_hash(&self) -> &SchemaValue<String>;
    /// Owner of the key — a user id, or an organization id when the key's
    /// configuration references organizations.
    fn reference_id(&self) -> &SchemaValue<String>;
    /// Name of the API-key configuration this key belongs to (`"default"`
    /// unless the application registers named configurations).
    fn config_id(&self) -> &SchemaValue<String>;
    fn refill_interval(&self) -> &SchemaValue<Option<f64>>;
    fn refill_amount(&self) -> &SchemaValue<Option<f64>>;
    fn last_refill_at(&self) -> &SchemaValue<Option<crate::FieldDate>>;
    fn enabled(&self) -> &SchemaValue<bool>;
    fn rate_limit_enabled(&self) -> &SchemaValue<bool>;
    fn rate_limit_time_window(&self) -> &SchemaValue<Option<f64>>;
    fn rate_limit_max(&self) -> &SchemaValue<Option<f64>>;
    fn request_count(&self) -> &SchemaValue<Option<f64>>;
    fn remaining(&self) -> &SchemaValue<Option<f64>>;
    fn last_request(&self) -> &SchemaValue<Option<crate::FieldDate>>;
    fn expires_at(&self) -> &SchemaValue<Option<crate::FieldDate>>;
    fn created_at(&self) -> &SchemaValue<crate::FieldDate>;
    fn updated_at(&self) -> &SchemaValue<crate::FieldDate>;
    fn permissions(&self) -> &SchemaValue<Option<String>>;
    fn metadata(&self) -> &SchemaValue<Option<String>>;
}

/// Trait representing a passkey entity.
pub trait AuthPasskey:
    AuthRecordFields + Clone + Send + Sync + Serialize + std::fmt::Debug + 'static
{
    /// Return application fields when the entity already contains an adapter projection.
    fn additional_fields(&self) -> Option<&crate::FieldMap> {
        None
    }
    fn id(&self) -> SchemaValue<Cow<'_, str>>;
    fn name(&self) -> &SchemaValue<Option<String>>;
    fn public_key(&self) -> &SchemaValue<String>;
    fn user_id(&self) -> SchemaValue<Cow<'_, str>>;
    fn credential_id(&self) -> &SchemaValue<String>;
    fn counter(&self) -> &SchemaValue<u64>;
    fn device_type(&self) -> &SchemaValue<String>;
    fn backed_up(&self) -> &SchemaValue<bool>;
    fn transports(&self) -> &SchemaValue<Option<String>>;
    fn created_at(&self) -> &SchemaValue<Option<crate::FieldDate>>;
    fn updated_at(&self) -> &SchemaValue<crate::FieldDate>;
    fn aaguid(&self) -> &SchemaValue<Option<String>>;
    fn credential(&self) -> &SchemaValue<String>;
}

/// Minimal user info for member-related API responses.
///
/// This is a concrete framework type (not generic) used to project
/// user fields into member responses.
#[derive(Debug, Clone, Default)]
pub struct MemberUserView {
    pub id: SchemaValue<String>,
    pub email: SchemaValue<Option<String>>,
    pub name: SchemaValue<Option<String>>,
    pub image: SchemaValue<Option<String>>,
}

mod member_user_view;
mod record_fields;

impl MemberUserView {
    /// Retain the runtime identity fields used in organization member responses.
    pub fn from_user(user: &crate::UserView) -> Self {
        Self {
            id: SchemaValue::from_field(user.native_field_value("id").unwrap_or_default()),
            email: SchemaValue::from_field(user.native_field_value("email").unwrap_or_default()),
            name: SchemaValue::from_field(user.native_field_value("name").unwrap_or_default()),
            image: SchemaValue::from_field(user.native_field_value("image").unwrap_or_default()),
        }
    }
}
