//! Concrete auth types for API responses and framework callbacks.
//!
//! These types decouple JSON response shapes from app-owned SeaORM entities.
//! Account and verification views retain adapter replacement types and field omission.
//! Persistence traits describe application models; runtime readers consume projected views.

use crate::SchemaValue;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer};
use std::borrow::Cow;

use crate::entity::{
    AuthApiKey, AuthInvitation, AuthOrganization, AuthPasskey, AuthSession, AuthUser,
};
use crate::types::InvitationStatus;

mod account_view;
mod verification_view;
pub use account_view::AccountView;
pub use verification_view::VerificationView;

/// Public user response shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(
    into = "serde_json::Map<String, serde_json::Value>",
    try_from = "serde_json::Map<String, serde_json::Value>"
)]
pub struct UserView {
    /// Configured application fields after output transforms.
    #[serde(flatten)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
    /// Present optional core fields and enabled plugin fields. `None` preserves an unconfigured view.
    #[serde(skip)]
    pub visible_fields: Option<std::collections::BTreeSet<String>>,
    pub id: SchemaValue<String>,
    pub name: SchemaValue<Option<String>>,
    pub email: Option<String>,
    #[serde(rename = "emailVerified")]
    pub email_verified: bool,
    pub image: SchemaValue<Option<String>>,
    #[serde(rename = "createdAt")]
    #[serde(serialize_with = "crate::utils::date::serialize")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    #[serde(serialize_with = "crate::utils::date::serialize")]
    pub updated_at: DateTime<Utc>,
    #[serde(
        rename = "isAnonymous",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub is_anonymous: Option<bool>,
    #[serde(
        rename = "phoneNumber",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub phone_number: Option<String>,
    #[serde(
        rename = "phoneNumberVerified",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub phone_number_verified: Option<bool>,
    pub username: Option<String>,
    #[serde(rename = "displayUsername")]
    pub display_username: Option<String>,
    #[serde(rename = "twoFactorEnabled", default)]
    pub two_factor_enabled: bool,
    pub role: Option<String>,
    #[serde(default)]
    pub banned: bool,
    #[serde(rename = "banReason")]
    pub ban_reason: Option<String>,
    #[serde(rename = "banExpires")]
    #[serde(serialize_with = "crate::utils::date::serialize_option")]
    pub ban_expires: Option<DateTime<Utc>>,
    #[serde(skip)]
    pub metadata: serde_json::Value,
}

/// Public session response shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(
    into = "serde_json::Map<String, serde_json::Value>",
    try_from = "serde_json::Map<String, serde_json::Value>"
)]
pub struct SessionView {
    /// Plugin field presence in the database projection or signed cache.
    #[serde(skip)]
    pub visible_fields: Option<std::collections::BTreeSet<String>>,
    pub id: SchemaValue<String>,
    #[serde(rename = "expiresAt")]
    #[serde(serialize_with = "crate::utils::date::serialize")]
    pub expires_at: DateTime<Utc>,
    pub token: String,
    #[serde(rename = "createdAt")]
    #[serde(serialize_with = "crate::utils::date::serialize")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    #[serde(serialize_with = "crate::utils::date::serialize")]
    pub updated_at: DateTime<Utc>,
    #[serde(rename = "ipAddress")]
    pub ip_address: Option<String>,
    #[serde(rename = "userAgent")]
    pub user_agent: Option<String>,
    #[serde(rename = "userId")]
    pub user_id: SchemaValue<String>,
    #[serde(rename = "impersonatedBy")]
    pub impersonated_by: Option<String>,
    #[serde(rename = "activeOrganizationId")]
    pub active_organization_id: Option<String>,
    #[serde(
        rename = "activeTeamId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub active_team_id: Option<String>,
    #[serde(skip)]
    pub active: bool,
    #[serde(flatten)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
}

impl UserView {
    /// Read an application model without applying adapter output transforms.
    pub fn from_model<T: AuthUser>(user: &T) -> crate::AuthResult<Self> {
        let model = serde_json::to_value(user)?;
        Ok(Self {
            additional_fields: user.projected_fields().cloned().unwrap_or_default(),
            visible_fields: user.field_presence().cloned(),
            id: user.id().into_owned(),
            name: SchemaValue::from_json(model.get(T::serialized_field_name("name")).cloned()),
            email: user.email().map(str::to_owned),
            email_verified: user.email_verified(),
            image: SchemaValue::from_json(model.get(T::serialized_field_name("image")).cloned()),
            created_at: user.created_at(),
            updated_at: user.updated_at(),
            is_anonymous: user.is_anonymous(),
            phone_number: user.phone_number().map(str::to_owned),
            phone_number_verified: user.phone_number_verified(),
            username: user.username().map(str::to_owned),
            display_username: user.display_username().map(str::to_owned),
            two_factor_enabled: user.two_factor_enabled(),
            role: user.role().map(str::to_owned),
            banned: user.banned(),
            ban_reason: user.ban_reason().map(str::to_owned),
            ban_expires: user.ban_expires(),
            metadata: user.metadata().clone(),
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
            visible_fields: session.field_presence().cloned(),
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
        let mut rows = sessions
            .iter()
            .map(|session| {
                let view = Self::from(session);
                // Core getters retain public names when models serialize application field names.
                let core: serde_json::Map<String, serde_json::Value> = view.clone().into();
                Ok((
                    session,
                    view,
                    core,
                    if config.fields().is_empty() {
                        serde_json::Value::Null
                    } else {
                        serde_json::to_value(session)?
                    },
                ))
            })
            .collect::<crate::AuthResult<Vec<_>>>()?;
        crate::user_fields::project_fields_then(
            &mut rows,
            config.fields(),
            |(session, view, core, model), name, field| {
                Box::pin(async move {
                    let value = if let Some(fields) = session.projected_fields() {
                        fields.get(name).cloned()
                    } else {
                        let value = model
                            .get(T::serialized_field_name(
                                field.field_name.as_deref().unwrap_or(name),
                            ))
                            .or_else(|| model.get(name))
                            .or_else(|| core.get(name))
                            .cloned();
                        field.adapter_output(value, supports_native_json).await?
                    };
                    if let Some(mut value) = value {
                        if !field.references_id() {
                            field.normalize_date(&mut value)?;
                        }
                        let _ = view.additional_fields.insert(name.to_owned(), value);
                    }
                    Ok(())
                })
            },
            |index, (_, view, _, _)| complete(index, view.clone()),
        )
        .await
    }
}

impl AuthUser for UserView {
    fn field_presence(&self) -> Option<&std::collections::BTreeSet<String>> {
        self.visible_fields.as_ref()
    }
    fn projected_fields(&self) -> Option<&serde_json::Map<String, serde_json::Value>> {
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
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
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
        self.two_factor_enabled
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
    fn ban_expires(&self) -> Option<DateTime<Utc>> {
        self.ban_expires
    }
    fn metadata(&self) -> &serde_json::Value {
        &self.metadata
    }
}

impl AuthSession for SessionView {
    fn field_presence(&self) -> Option<&std::collections::BTreeSet<String>> {
        self.visible_fields.as_ref()
    }
    fn projected_fields(&self) -> Option<&serde_json::Map<String, serde_json::Value>> {
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
    fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
    fn token(&self) -> &str {
        &self.token
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
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

fn serialize_json_option_as_string<S>(
    value: &SchemaValue<Option<serde_json::Value>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        SchemaValue::Typed(Some(inner)) => serializer
            .serialize_some(&serde_json::to_string(inner).map_err(serde::ser::Error::custom)?),
        value => value.serialize(serializer),
    }
}

/// Public organization response shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OrganizationView {
    #[serde(flatten)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,

    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub id: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub name: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub slug: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub logo: SchemaValue<Option<String>>,
    #[serde(serialize_with = "serialize_json_option_as_string")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub metadata: SchemaValue<Option<serde_json::Value>>,
    #[serde(rename = "createdAt")]
    #[serde(serialize_with = "crate::schema_value::serialize_date")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub created_at: SchemaValue<DateTime<Utc>>,
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
    #[serde(flatten)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,

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
    #[serde(serialize_with = "crate::schema_value::serialize_date")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub expires_at: SchemaValue<DateTime<Utc>>,
    #[serde(rename = "createdAt")]
    #[serde(serialize_with = "crate::schema_value::serialize_date")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub created_at: SchemaValue<DateTime<Utc>>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    #[serde(deserialize_with = "crate::types_plugin::deserialize_display_string")]
    pub aaguid: SchemaValue<Option<String>>,
}

impl<T: AuthPasskey> From<&T> for PasskeyView {
    fn from(pk: &T) -> Self {
        Self {
            id: pk.id().into_owned(),
            name: pk.name().clone(),
            credential_id: pk.credential_id().to_owned(),
            user_id: pk.user_id().into_owned(),
            public_key: pk.public_key().to_owned(),
            counter: pk.counter(),
            device_type: pk.device_type().to_owned(),
            backed_up: pk.backed_up(),
            transports: pk.transports().map(str::to_owned),
            created_at: pk
                .created_at()
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
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
    pub last_refill_at: Option<String>,
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
    pub last_request: Option<String>,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
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
            id: ak.id().into_owned(),
            name: ak.name().clone(),
            start: ak.start().map(std::borrow::Cow::into_owned),
            prefix: ak.prefix().map(str::to_owned),
            reference_id: ak.reference_id().into_owned(),
            config_id: ak.config_id().into_owned(),
            refill_interval: ak.refill_interval(),
            refill_amount: ak.refill_amount(),
            last_refill_at: ak.last_refill_at().map(str::to_owned),
            enabled: ak.enabled(),
            rate_limit_enabled: ak.rate_limit_enabled(),
            rate_limit_time_window: ak.rate_limit_time_window(),
            rate_limit_max: ak.rate_limit_max(),
            request_count: ak.request_count(),
            remaining: ak.remaining(),
            last_request: ak.last_request().map(str::to_owned),
            expires_at: ak.expires_at().map(str::to_owned),
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
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_anonymous: None,
            phone_number: None,
            phone_number_verified: None,
            username: Some("ada".to_string()),
            display_username: Some("Ada".to_string()),
            two_factor_enabled: true,
            role: Some("admin".to_string()),
            banned: false,
            ban_reason: None,
            ban_expires: None,
            metadata: serde_json::json!({}),
        };

        let json = serde_json::to_value(UserView::from(&user)).expect("serialize user view");
        assert_eq!(json["emailVerified"], true);
        assert_eq!(json["displayUsername"], "Ada");
        assert_eq!(json["twoFactorEnabled"], true);
    }

    #[test]
    fn session_view_serializes_camel_case() {
        let session = SessionView {
            visible_fields: None,
            id: "session-1".to_string().into(),
            expires_at: Utc::now(),
            token: "token".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
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
