//! Concrete auth types for API responses and framework callbacks.
//!
//! These types decouple JSON response shapes from app-owned SeaORM entities.
//! Account and verification views retain adapter replacement types and field omission.
//! Persistence traits describe application models; runtime readers consume projected views.

use crate::SchemaValue;
#[cfg(test)]
use chrono::Utc;
use serde::{Deserialize, Serialize, Serializer};
use std::borrow::Cow;

use crate::entity::{
    AuthApiKey, AuthInvitation, AuthOrganization, AuthPasskey, AuthSession, AuthUser,
};
use crate::types::InvitationStatus;

mod account_view;
mod session_projection;
mod verification_view;
pub use account_view::AccountView;
pub use verification_view::VerificationView;

/// Public user response shape.
#[derive(Debug, Clone, PartialEq)]
pub struct UserView {
    /// Configured application fields after output transforms.
    pub additional_fields: crate::FieldMap,
    /// Present optional core fields and enabled plugin fields. `None` preserves an unconfigured view.
    pub visible_fields: Option<std::collections::BTreeSet<String>>,
    pub id: SchemaValue<String>,
    pub name: SchemaValue<Option<String>>,
    pub email: Option<String>,
    pub email_verified: bool,
    pub image: SchemaValue<Option<String>>,
    pub created_at: crate::FieldDate,
    pub updated_at: crate::FieldDate,
    pub is_anonymous: Option<bool>,
    pub phone_number: Option<String>,
    pub phone_number_verified: Option<bool>,
    pub username: Option<String>,
    pub display_username: Option<String>,
    pub two_factor_enabled: Option<bool>,
    pub role: Option<String>,
    pub banned: bool,
    pub ban_reason: Option<String>,
    pub ban_expires: Option<crate::FieldDate>,
    pub metadata: crate::FieldValue,
}

/// Public session response shape.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionView {
    /// Plugin field presence in the database projection or signed cache.
    pub visible_fields: Option<std::collections::BTreeSet<String>>,
    pub id: SchemaValue<String>,
    pub expires_at: crate::FieldDate,
    pub token: String,
    pub created_at: crate::FieldDate,
    pub updated_at: crate::FieldDate,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub user_id: SchemaValue<String>,
    pub impersonated_by: Option<String>,
    pub active_organization_id: Option<String>,
    pub active_team_id: Option<String>,
    pub active: bool,
    pub additional_fields: crate::FieldMap,
}

impl UserView {
    /// Read an application model without applying adapter output transforms.
    pub fn from_model<T: AuthUser>(user: &T) -> crate::AuthResult<Self> {
        let model = user.field_values()?;
        Ok(Self {
            additional_fields: user.projected_fields().cloned().unwrap_or_default(),
            visible_fields: user.field_presence().cloned(),
            id: user.id().into_owned(),
            name: SchemaValue::from_field(
                model
                    .get(T::serialized_field_name("name"))
                    .cloned()
                    .unwrap_or_default(),
            ),
            email: user.email().map(str::to_owned),
            email_verified: user.email_verified(),
            image: SchemaValue::from_field(
                model
                    .get(T::serialized_field_name("image"))
                    .cloned()
                    .unwrap_or_default(),
            ),
            created_at: user.created_at(),
            updated_at: user.updated_at(),
            is_anonymous: user.is_anonymous(),
            phone_number: user.phone_number().map(str::to_owned),
            phone_number_verified: user.phone_number_verified(),
            username: user.username().map(str::to_owned),
            display_username: user.display_username().map(str::to_owned),
            two_factor_enabled: match model.get(T::serialized_field_name("twoFactorEnabled")) {
                Some(value) => value.decode()?,
                None => Some(user.two_factor_enabled()),
            },
            role: user.role().map(str::to_owned),
            banned: user.banned(),
            ban_reason: user.ban_reason().map(str::to_owned),
            ban_expires: user.ban_expires(),
            metadata: model
                .get(T::serialized_field_name("metadata"))
                .cloned()
                .unwrap_or(crate::FieldValue::Null),
        })
    }
}

impl From<&UserView> for UserView {
    fn from(user: &UserView) -> Self {
        user.clone()
    }
}

impl<T: AuthSession> From<&T> for SessionView {
    fn from(session: &T) -> Self {
        Self {
            visible_fields: Some(session.field_presence().cloned().unwrap_or_else(|| {
                [
                    ("impersonated_by", "impersonatedBy"),
                    ("active_organization_id", "activeOrganizationId"),
                    ("active_team_id", "activeTeamId"),
                ]
                .into_iter()
                .filter(|(field, _)| T::PLUGIN_FIELDS.contains(field))
                .map(|(_, name)| name.to_owned())
                .collect()
            })),
            id: session.id().into_owned(),
            expires_at: session.expires_at(),
            token: session.token().to_owned(),
            created_at: session.created_at(),
            updated_at: session.updated_at(),
            ip_address: session.ip_address().map(str::to_owned),
            user_agent: session.user_agent().map(str::to_owned),
            user_id: session.user_id().into_owned(),
            impersonated_by: session.impersonated_by().map(str::to_owned),
            active_organization_id: session.active_organization_id().map(str::to_owned),
            active_team_id: session.active_team_id().map(str::to_owned),
            active: session.active(),
            additional_fields: Default::default(),
        }
    }
}

impl SessionView {
    /// Apply current public visibility without materializing absent cached fields.
    pub fn filter_returned_fields(&mut self, config: &crate::config::SessionConfig) {
        self.additional_fields.retain(|name, _| {
            config
                .fields()
                .get(name)
                .is_none_or(|field| field.returned())
        });
    }

    /// Apply configured field visibility to a serialized application session model.
    pub async fn with_fields<T: AuthSession>(
        session: &T,
        config: &crate::config::SessionConfig,
    ) -> crate::AuthResult<Self> {
        Self::with_fields_for_adapter(session, config, true).await
    }

    pub async fn with_fields_for_adapter<T: AuthSession>(
        session: &T,
        config: &crate::config::SessionConfig,
        supports_native_json: bool,
    ) -> crate::AuthResult<Self> {
        let mut view =
            Self::with_internal_fields_for_adapter(session, config, supports_native_json).await?;
        view.filter_returned_fields(config);
        Ok(view)
    }

    /// Include hidden application fields for trusted callbacks, never for public responses.
    pub async fn with_internal_fields_for_adapter<T: AuthSession>(
        session: &T,
        config: &crate::config::SessionConfig,
        supports_native_json: bool,
    ) -> crate::AuthResult<Self> {
        // Projection preserves the one input row.
        Ok(Self::with_internal_fields_many_for_adapter(
            std::slice::from_ref(session),
            config,
            supports_native_json,
        )
        .await?
        .remove(0))
    }

    /// Project a database result in row order, interleaving synchronous callbacks by field.
    pub async fn with_internal_fields_many_for_adapter<T: AuthSession>(
        sessions: &[T],
        config: &crate::config::SessionConfig,
        supports_native_json: bool,
    ) -> crate::AuthResult<Vec<Self>> {
        Self::with_internal_fields_many_for_adapter_then(
            sessions,
            config,
            supports_native_json,
            |_, session| std::future::ready(Ok(session)),
        )
        .await
    }

    /// Continue each projected session while other rows retain their pending field callbacks.
    /// Preserve the original row index for adapter-owned association data.
    pub async fn with_internal_fields_many_for_adapter_then<T: AuthSession, R: Send, F>(
        sessions: &[T],
        config: &crate::config::SessionConfig,
        supports_native_json: bool,
        complete: impl Fn(usize, Self) -> F + Sync,
    ) -> crate::AuthResult<Vec<R>>
    where
        F: std::future::Future<Output = crate::AuthResult<R>> + Send,
    {
        let mut rows = session_projection::rows(sessions, config)?;
        crate::user_fields::project_fields_then(
            &mut rows,
            config.fields(),
            |row, name, field| Box::pin(row.project(name, field, supports_native_json)),
            |index, row| complete(index, row.view.clone()),
        )
        .await
    }

    /// Continue ready session projections together, retaining their original row indices.
    pub async fn with_internal_fields_many_for_adapter_batches_then<T: AuthSession, R: Send, F>(
        sessions: &[T],
        config: &crate::config::SessionConfig,
        supports_native_json: bool,
        complete: impl Fn(Vec<(usize, Self)>) -> F + Sync,
    ) -> crate::AuthResult<Vec<R>>
    where
        F: std::future::Future<Output = crate::AuthResult<Vec<(usize, R)>>> + Send,
    {
        let mut rows = session_projection::rows(sessions, config)?;
        crate::user_fields::project_fields_batches_then(
            &mut rows,
            config.fields(),
            |row, name, field| Box::pin(row.project(name, field, supports_native_json)),
            |_, row| Ok(row.view.clone()),
            complete,
        )
        .await
    }
}

impl AuthUser for UserView {
    fn field_presence(&self) -> Option<&std::collections::BTreeSet<String>> {
        self.visible_fields.as_ref()
    }
    fn projected_fields(&self) -> Option<&crate::FieldMap> {
        Some(&self.additional_fields)
    }
    const PLUGIN_FIELDS: &'static [&'static str] = &[
        "is_anonymous",
        "phone_number",
        "phone_number_verified",
        "username",
        "display_username",
        "two_factor_enabled",
        "role",
        "banned",
        "ban_reason",
        "ban_expires",
        "metadata",
    ];
    fn id(&self) -> SchemaValue<Cow<'_, str>> {
        self.id.as_ref().map(|id| Cow::Borrowed(id.as_str()))
    }
    fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }
    fn email_verified(&self) -> bool {
        self.email_verified
    }
    fn created_at(&self) -> crate::FieldDate {
        self.created_at.clone()
    }
    fn updated_at(&self) -> crate::FieldDate {
        self.updated_at.clone()
    }
    fn is_anonymous(&self) -> Option<bool> {
        self.is_anonymous
    }
    fn phone_number(&self) -> Option<&str> {
        self.phone_number.as_deref()
    }
    fn phone_number_verified(&self) -> Option<bool> {
        self.phone_number_verified
    }
    fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }
    fn display_username(&self) -> Option<&str> {
        self.display_username.as_deref()
    }
    fn two_factor_enabled(&self) -> bool {
        self.two_factor_enabled == Some(true)
    }
    fn role(&self) -> Option<&str> {
        self.role.as_deref()
    }
    fn banned(&self) -> bool {
        self.banned
    }
    fn ban_reason(&self) -> Option<&str> {
        self.ban_reason.as_deref()
    }
    fn ban_expires(&self) -> Option<crate::FieldDate> {
        self.ban_expires.clone()
    }
}

impl AuthSession for SessionView {
    fn field_presence(&self) -> Option<&std::collections::BTreeSet<String>> {
        self.visible_fields.as_ref()
    }
    fn projected_fields(&self) -> Option<&crate::FieldMap> {
        Some(&self.additional_fields)
    }

    const PLUGIN_FIELDS: &'static [&'static str] = &[
        "impersonated_by",
        "active_organization_id",
        "active_team_id",
    ];
    fn id(&self) -> SchemaValue<Cow<'_, str>> {
        self.id.as_ref().map(|id| Cow::Borrowed(id.as_str()))
    }
    fn expires_at(&self) -> crate::FieldDate {
        self.expires_at.clone()
    }
    fn token(&self) -> &str {
        &self.token
    }
    fn created_at(&self) -> crate::FieldDate {
        self.created_at.clone()
    }
    fn updated_at(&self) -> crate::FieldDate {
        self.updated_at.clone()
    }
    fn ip_address(&self) -> Option<&str> {
        self.ip_address.as_deref()
    }
    fn user_agent(&self) -> Option<&str> {
        self.user_agent.as_deref()
    }
    fn user_id(&self) -> SchemaValue<Cow<'_, str>> {
        self.user_id.as_ref().map(|id| Cow::Borrowed(id.as_str()))
    }
    fn impersonated_by(&self) -> Option<&str> {
        self.impersonated_by.as_deref()
    }
    fn active_team_id(&self) -> Option<&str> {
        self.active_team_id.as_deref()
    }
    fn active_organization_id(&self) -> Option<&str> {
        self.active_organization_id.as_deref()
    }
    fn active(&self) -> bool {
        self.active
    }
}

// ---------------------------------------------------------------------------
// Plugin entity views
// ---------------------------------------------------------------------------

/// Public organization response shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OrganizationView {
    #[serde(with = "crate::field_value::serde::map", flatten)]
    pub additional_fields: crate::FieldMap,

    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub id: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub name: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub slug: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub logo: SchemaValue<Option<String>>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub metadata: SchemaValue<Option<crate::FieldValue>>,
    #[serde(rename = "createdAt")]
    #[serde(with = "crate::field_value::serde::schema_date")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub created_at: SchemaValue<crate::FieldDate>,
}

impl<T: AuthOrganization> From<&T> for OrganizationView {
    fn from(org: &T) -> Self {
        Self {
            additional_fields: org.projected_fields().cloned().unwrap_or_default(),
            id: org.id().into_owned(),
            name: org.name().clone(),
            slug: org.slug().clone(),
            logo: org.logo().clone(),
            metadata: org.metadata().clone(),
            created_at: org.created_at().clone(),
        }
    }
}

/// Public invitation response shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InvitationView {
    #[serde(with = "crate::field_value::serde::map", flatten)]
    pub additional_fields: crate::FieldMap,

    #[serde(rename = "teamId")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub team_id: SchemaValue<Option<String>>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub id: SchemaValue<String>,
    #[serde(rename = "organizationId")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub organization_id: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub email: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub role: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub status: SchemaValue<InvitationStatus>,
    #[serde(rename = "inviterId")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub inviter_id: SchemaValue<String>,
    #[serde(rename = "expiresAt")]
    #[serde(with = "crate::field_value::serde::schema_date")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub expires_at: SchemaValue<crate::FieldDate>,
    #[serde(rename = "createdAt")]
    #[serde(with = "crate::field_value::serde::schema_date")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub created_at: SchemaValue<crate::FieldDate>,
}

impl<T: AuthInvitation> From<&T> for InvitationView {
    fn from(inv: &T) -> Self {
        Self {
            additional_fields: inv.projected_fields().cloned().unwrap_or_default(),
            id: inv.id().into_owned(),
            organization_id: inv.organization_id().clone(),
            email: inv.email().clone(),
            role: inv.role().clone(),
            status: inv.status().clone(),
            inviter_id: inv.inviter_id().clone(),
            team_id: inv.team_id().clone(),
            expires_at: inv.expires_at().clone(),
            created_at: inv.created_at().clone(),
        }
    }
}

/// Public passkey response shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PasskeyView {
    /// Declared application fields after adapter output projection.
    #[serde(with = "crate::field_value::serde::map", flatten, default)]
    pub additional_fields: crate::FieldMap,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub id: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    #[serde(deserialize_with = "crate::types_plugin::deserialize_display_string")]
    pub name: SchemaValue<Option<String>>,
    #[serde(rename = "credentialID")]
    pub credential_id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    pub counter: u64,
    #[serde(rename = "deviceType")]
    pub device_type: String,
    #[serde(rename = "backedUp")]
    pub backed_up: bool,
    pub transports: Option<String>,
    #[serde(rename = "createdAt")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    #[serde(with = "crate::field_value::serde::optional_schema_date")]
    pub created_at: SchemaValue<Option<crate::FieldDate>>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    #[serde(deserialize_with = "crate::types_plugin::deserialize_display_string")]
    pub aaguid: SchemaValue<Option<String>>,
}

impl<T: AuthPasskey> From<&T> for PasskeyView {
    fn from(pk: &T) -> Self {
        Self {
            additional_fields: pk.additional_fields().cloned().unwrap_or_default(),
            id: pk.id().into_owned(),
            name: pk.name().clone(),
            credential_id: pk.credential_id().to_owned(),
            user_id: pk.user_id().into_owned(),
            public_key: pk.public_key().to_owned(),
            counter: pk.counter(),
            device_type: pk.device_type().to_owned(),
            backed_up: pk.backed_up(),
            transports: pk.transports().map(str::to_owned),
            created_at: pk.created_at().clone(),
            aaguid: pk.aaguid().clone(),
        }
    }
}

/// Public API key response shape.
///
/// Intentionally omits `key_hash` — the hashed key value is never returned
/// over the wire (matches upstream TS behavior).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiKeyView {
    /// Declared application fields after adapter output projection.
    #[serde(with = "crate::field_value::serde::map", flatten, default)]
    pub additional_fields: crate::FieldMap,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub id: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    #[serde(deserialize_with = "crate::types_plugin::deserialize_display_string")]
    pub name: SchemaValue<Option<String>>,
    pub start: Option<crate::ApiKeyStart>,
    pub prefix: Option<String>,
    #[serde(rename = "referenceId")]
    pub reference_id: String,
    #[serde(rename = "configId")]
    pub config_id: String,
    #[serde(rename = "refillInterval")]
    #[serde(serialize_with = "serialize_optional_number")]
    pub refill_interval: Option<f64>,
    #[serde(rename = "refillAmount")]
    #[serde(serialize_with = "serialize_optional_number")]
    pub refill_amount: Option<f64>,
    #[serde(rename = "lastRefillAt")]
    #[serde(default, with = "crate::field_value::serde::optional_date")]
    pub last_refill_at: Option<crate::FieldDate>,
    pub enabled: bool,
    #[serde(rename = "rateLimitEnabled")]
    pub rate_limit_enabled: bool,
    #[serde(rename = "rateLimitTimeWindow")]
    #[serde(serialize_with = "serialize_optional_number")]
    pub rate_limit_time_window: Option<f64>,
    #[serde(rename = "rateLimitMax")]
    #[serde(serialize_with = "serialize_optional_number")]
    pub rate_limit_max: Option<f64>,
    #[serde(rename = "requestCount")]
    #[serde(serialize_with = "serialize_optional_number")]
    pub request_count: Option<f64>,
    #[serde(serialize_with = "serialize_optional_number")]
    pub remaining: Option<f64>,
    #[serde(rename = "lastRequest")]
    #[serde(default, with = "crate::field_value::serde::optional_date")]
    pub last_request: Option<crate::FieldDate>,
    #[serde(rename = "expiresAt")]
    #[serde(default, with = "crate::field_value::serde::optional_date")]
    pub expires_at: Option<crate::FieldDate>,
    #[serde(rename = "createdAt")]
    #[serde(with = "crate::field_value::serde::date")]
    pub created_at: crate::FieldDate,
    #[serde(rename = "updatedAt")]
    #[serde(with = "crate::field_value::serde::date")]
    pub updated_at: crate::FieldDate,
    pub permissions: Option<serde_json::Value>,
    pub metadata: Option<serde_json::Value>,
}

/// Serialize optional JavaScript numbers, preserving whole-number JSON representation.
pub fn serialize_optional_number<S: Serializer>(
    value: &Option<f64>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) if value.fract() == 0.0 && value.abs() <= 9_007_199_254_740_991.0 => {
            serializer.serialize_i64(*value as i64)
        }
        value => value.serialize(serializer),
    }
}

impl<T: AuthApiKey> From<&T> for ApiKeyView {
    fn from(ak: &T) -> Self {
        Self {
            additional_fields: ak.additional_fields().cloned().unwrap_or_default(),
            id: ak.id().into_owned(),
            name: ak.name().clone(),
            start: ak.start().map(std::borrow::Cow::into_owned),
            prefix: ak.prefix().map(str::to_owned),
            reference_id: ak.reference_id().into_owned(),
            config_id: ak.config_id().into_owned(),
            refill_interval: ak.refill_interval(),
            refill_amount: ak.refill_amount(),
            last_refill_at: ak.last_refill_at(),
            enabled: ak.enabled(),
            rate_limit_enabled: ak.rate_limit_enabled(),
            rate_limit_time_window: ak.rate_limit_time_window(),
            rate_limit_max: ak.rate_limit_max(),
            request_count: ak.request_count(),
            remaining: ak.remaining(),
            last_request: ak.last_request(),
            expires_at: ak.expires_at(),
            created_at: ak.created_at().to_owned(),
            updated_at: ak.updated_at().to_owned(),
            permissions: ak.permissions().and_then(|s| serde_json::from_str(s).ok()),
            metadata: ak.metadata().and_then(|s| serde_json::from_str(s).ok()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_view_serializes_camel_case() {
        let user = UserView {
            visible_fields: None,
            additional_fields: Default::default(),
            id: "user-1".to_string().into(),
            name: Some("Ada".to_string()).into(),
            email: Some("ada@example.com".to_string()),
            email_verified: true,
            image: Default::default(),
            created_at: Utc::now().into(),
            updated_at: Utc::now().into(),
            is_anonymous: None,
            phone_number: None,
            phone_number_verified: None,
            username: Some("ada".to_string()),
            display_username: Some("Ada".to_string()),
            two_factor_enabled: Some(true),
            role: Some("admin".to_string()),
            banned: false,
            ban_reason: None,
            ban_expires: None,
            metadata: crate::FieldMap::new().into(),
        };

        let json = serde_json::to_value(UserView::from(&user)).expect("serialize user view");
        assert_eq!(json["emailVerified"], true);
        assert_eq!(json["displayUsername"], "Ada");
        assert_eq!(json["twoFactorEnabled"], true);
    }

    #[tokio::test]
    async fn two_factor_enabled_preserves_null_through_projection_and_cache() {
        let metadata = crate::plugin::MetadataMap::from_iter([(
            "two_factor.enabled".to_owned(),
            serde_json::json!(true),
        )]);
        for value in [None, Some(false), Some(true)] {
            let user: UserView = serde_json::from_value(serde_json::json!({
                "id": "owner",
                "name": "Owner",
                "email": "owner@example.com",
                "emailVerified": true,
                "createdAt": "2026-10-07T00:00:00.000Z",
                "updatedAt": "2026-10-07T00:00:00.000Z",
                "twoFactorEnabled": value,
            }))
            .expect("user response");
            let projected = UserView::with_fields(&user, &Default::default(), &metadata)
                .await
                .expect("project nullable plugin field");
            let cached: UserView = serde_json::from_value(
                serde_json::to_value(&projected).expect("serialize signed cache user"),
            )
            .expect("deserialize signed cache user");
            let projected = UserView::with_fields(&cached, &Default::default(), &metadata)
                .await
                .expect("reproject cached user");
            assert_eq!(projected.two_factor_enabled, value);
            assert_eq!(projected.two_factor_enabled(), value == Some(true));
            assert_eq!(
                serde_json::to_value(projected)
                    .expect("serialize public user")
                    .get("twoFactorEnabled"),
                Some(&serde_json::json!(value)),
            );
        }
    }

    #[test]
    fn session_view_serializes_camel_case() {
        let session = SessionView {
            visible_fields: None,
            id: "session-1".to_string().into(),
            expires_at: Utc::now().into(),
            token: "token".to_string(),
            created_at: Utc::now().into(),
            updated_at: Utc::now().into(),
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: Some("agent".to_string()),
            user_id: "user-1".to_string().into(),
            impersonated_by: Some("admin-1".to_string()),
            active_organization_id: Some("org-1".to_string()),
            active_team_id: None,
            active: true,
            additional_fields: Default::default(),
        };

        let json =
            serde_json::to_value(SessionView::from(&session)).expect("serialize session view");
        assert_eq!(json["expiresAt"].is_string(), true);
        assert_eq!(json["ipAddress"], "127.0.0.1");
        assert_eq!(json["activeOrganizationId"], "org-1");
    }

    #[test]
    fn account_view_omits_password_on_serialize() {
        let account = AccountView {
            additional_fields: Default::default(),
            id: "acc-1".to_string().into(),
            account_id: "account-id".to_string().into(),
            provider_id: "credential".to_string().into(),
            user_id: "user-1".to_string().into(),
            access_token: None.into(),
            refresh_token: None.into(),
            id_token: None.into(),
            access_token_expires_at: None.into(),
            refresh_token_expires_at: None.into(),
            scope: None.into(),
            password: Some("$2a$hash".to_string()).into(),
            created_at: Utc::now().into(),
            updated_at: Utc::now().into(),
        };

        let json = serde_json::to_value(&account).expect("serialize account view");
        assert!(
            json.get("password").is_none(),
            "password field must not appear in serialized output"
        );
    }
}
