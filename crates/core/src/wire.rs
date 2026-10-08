//! Concrete auth types for API responses and framework callbacks.
//!
//! These types decouple JSON response shapes from app-owned SeaORM entities.
//! Account and verification views retain adapter replacement types and field omission.
//! Persistence traits describe application models; runtime readers consume projected views.

use crate::SchemaValue;
#[cfg(test)]
use chrono::Utc;
use futures_util::future::BoxFuture;
use serde::{Deserialize, Serialize, Serializer};
use std::borrow::Cow;

use crate::entity::{AuthInvitation, AuthOrganization, AuthPasskey, AuthSession, AuthUser};
use crate::types::InvitationStatus;

mod account_view;
mod api_key_view;
mod session_projection;
mod verification_view;
pub use account_view::AccountView;
pub use api_key_view::ApiKeyView;
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
#[derive(Debug, Clone, Default)]
pub struct SessionView {
    /// Source property order, independent of the current typed values.
    pub field_order: Vec<String>,
    /// Plugin field presence in the database projection or signed cache.
    pub visible_fields: Option<std::collections::BTreeSet<String>>,
    pub id: SchemaValue<String>,
    pub expires_at: SchemaValue<crate::FieldDate>,
    pub token: SchemaValue<String>,
    pub created_at: SchemaValue<crate::FieldDate>,
    pub updated_at: SchemaValue<crate::FieldDate>,
    pub ip_address: SchemaValue<Option<String>>,
    pub user_agent: SchemaValue<Option<String>>,
    pub user_id: SchemaValue<String>,
    pub impersonated_by: SchemaValue<Option<String>>,
    pub active_organization_id: SchemaValue<Option<String>>,
    pub active_team_id: SchemaValue<Option<String>>,
    pub active: bool,
    pub additional_fields: crate::FieldMap,
}

impl From<crate::session::SessionData> for crate::FieldMap {
    fn from(data: crate::session::SessionData) -> Self {
        Self::from([
            ("session".into(), Self::from(data.session).into()),
            ("user".into(), Self::from(data.user).into()),
        ])
    }
}

impl crate::FromFieldMap for crate::session::SessionData {
    fn from_field_values(fields: crate::FieldMap) -> crate::AuthResult<Self> {
        fn record<T: crate::FromFieldMap>(
            fields: &crate::FieldMap,
            name: &str,
        ) -> crate::AuthResult<T> {
            let fields = fields
                .get(name)
                .and_then(crate::FieldValue::as_object)
                .ok_or_else(|| {
                    crate::AuthError::internal(format!(
                        "Session response must contain a `{name}` object"
                    ))
                })?;
            T::from_field_values(fields.clone())
        }
        Ok(Self {
            session: record(&fields, "session")?,
            user: record(&fields, "user")?,
        })
    }
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
            field_order: session.field_order().unwrap_or_default().to_vec(),
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
            token: session.token().into_owned(),
            created_at: session.created_at(),
            updated_at: session.updated_at(),
            ip_address: session.ip_address().map(|value| value.map(Cow::into_owned)),
            user_agent: session.user_agent().map(|value| value.map(Cow::into_owned)),
            user_id: session.user_id().into_owned(),
            impersonated_by: session
                .impersonated_by()
                .map(|value| value.map(Cow::into_owned)),
            active_organization_id: session
                .active_organization_id()
                .map(|value| value.map(Cow::into_owned)),
            active_team_id: session
                .active_team_id()
                .map(|value| value.map(Cow::into_owned)),
            active: session.active(),
            additional_fields: Default::default(),
        }
    }
}

impl SessionView {
    pub(crate) fn active_plugin_fields(
        metadata: &crate::plugin::MetadataMap,
    ) -> impl Iterator<Item = &'static str> + '_ {
        [
            ("admin.enabled", "impersonatedBy"),
            ("organization.enabled", "activeOrganizationId"),
            ("organization.teams_enabled", "activeTeamId"),
        ]
        .into_iter()
        .filter(move |(plugin, _)| {
            metadata.get(*plugin).and_then(serde_json::Value::as_bool) == Some(true)
        })
        .map(|(_, field)| field)
    }

    /// Apply current public visibility without materializing absent cached fields.
    pub fn filter_returned_fields(&mut self, config: &crate::config::SessionConfig) {
        macro_rules! hide {
            ($($field:ident => $name:literal),* $(,)?) => {$(
                if config.fields().get($name).is_some_and(|field| !field.returned()) {
                    self.$field = SchemaValue::Undefined;
                    self.field_order.retain(|name| name != $name);
                }
            )*};
        }
        hide!(
            token => "token", user_id => "userId", expires_at => "expiresAt",
            created_at => "createdAt", updated_at => "updatedAt", ip_address => "ipAddress",
            user_agent => "userAgent", impersonated_by => "impersonatedBy",
            active_organization_id => "activeOrganizationId", active_team_id => "activeTeamId",
        );
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
    pub fn with_internal_fields_many_for_adapter_then<'a, T: AuthSession, R: Send + 'a, F>(
        sessions: &'a [T],
        config: &'a crate::config::SessionConfig,
        supports_native_json: bool,
        complete: impl Fn(usize, Self) -> F + Send + Sync + 'a,
    ) -> BoxFuture<'a, crate::AuthResult<Vec<R>>>
    where
        F: std::future::Future<Output = crate::AuthResult<R>> + Send + 'a,
    {
        // Erase the entry future so callers do not expand the nested projection's Send obligations.
        Box::pin(async move {
            let mut rows = session_projection::rows(sessions, config)?;
            let schema = config.adapter_schema();
            crate::user_fields::project_fields_then(
                &mut rows,
                schema.fields(),
                |row, name, field| Box::pin(row.project(name, field, supports_native_json)),
                |index, row| complete(index, row.view.clone().into_projected_fields()),
            )
            .await
        })
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
        let schema = config.adapter_schema();
        crate::user_fields::project_fields_batches_then(
            &mut rows,
            schema.fields(),
            |row, name, field| Box::pin(row.project(name, field, supports_native_json)),
            |_, row| Ok(row.view.clone().into_projected_fields()),
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
    fn field_order(&self) -> Option<&[String]> {
        Some(&self.field_order)
    }
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
    fn expires_at(&self) -> SchemaValue<crate::FieldDate> {
        self.expires_at.clone()
    }
    fn token(&self) -> SchemaValue<Cow<'_, str>> {
        self.token
            .as_ref()
            .map(|value| Cow::Borrowed(value.as_str()))
    }
    fn created_at(&self) -> SchemaValue<crate::FieldDate> {
        self.created_at.clone()
    }
    fn updated_at(&self) -> SchemaValue<crate::FieldDate> {
        self.updated_at.clone()
    }
    fn ip_address(&self) -> SchemaValue<Option<Cow<'_, str>>> {
        self.ip_address
            .as_ref()
            .map(|value| value.as_deref().map(Cow::Borrowed))
    }
    fn user_agent(&self) -> SchemaValue<Option<Cow<'_, str>>> {
        self.user_agent
            .as_ref()
            .map(|value| value.as_deref().map(Cow::Borrowed))
    }
    fn user_id(&self) -> SchemaValue<Cow<'_, str>> {
        self.user_id.as_ref().map(|id| Cow::Borrowed(id.as_str()))
    }
    fn impersonated_by(&self) -> SchemaValue<Option<Cow<'_, str>>> {
        self.impersonated_by
            .as_ref()
            .map(|value| value.as_deref().map(Cow::Borrowed))
    }
    fn active_team_id(&self) -> SchemaValue<Option<Cow<'_, str>>> {
        self.active_team_id
            .as_ref()
            .map(|value| value.as_deref().map(Cow::Borrowed))
    }
    fn active_organization_id(&self) -> SchemaValue<Option<Cow<'_, str>>> {
        self.active_organization_id
            .as_ref()
            .map(|value| value.as_deref().map(Cow::Borrowed))
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
    pub name: SchemaValue<Option<String>>,
    #[serde(rename = "credentialID")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub credential_id: SchemaValue<String>,
    #[serde(rename = "userId")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub user_id: SchemaValue<String>,
    #[serde(rename = "publicKey")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub public_key: SchemaValue<String>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub counter: SchemaValue<u64>,
    #[serde(rename = "deviceType")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub device_type: SchemaValue<String>,
    #[serde(rename = "backedUp")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub backed_up: SchemaValue<bool>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub transports: SchemaValue<Option<String>>,
    #[serde(rename = "createdAt")]
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    #[serde(with = "crate::field_value::serde::optional_schema_date")]
    pub created_at: SchemaValue<Option<crate::FieldDate>>,
    #[serde(default, skip_serializing_if = "SchemaValue::is_undefined")]
    pub aaguid: SchemaValue<Option<String>>,
}

impl<T: AuthPasskey> From<&T> for PasskeyView {
    fn from(pk: &T) -> Self {
        Self {
            additional_fields: pk.additional_fields().cloned().unwrap_or_default(),
            id: pk.id().into_owned(),
            name: pk.name().clone(),
            credential_id: pk.credential_id().clone(),
            user_id: pk.user_id().into_owned(),
            public_key: pk.public_key().clone(),
            counter: pk.counter().clone(),
            device_type: pk.device_type().clone(),
            backed_up: pk.backed_up().clone(),
            transports: pk.transports().clone(),
            created_at: pk.created_at().clone(),
            aaguid: pk.aaguid().clone(),
        }
    }
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
            field_order: Default::default(),
            visible_fields: None,
            id: "session-1".to_string().into(),
            expires_at: Utc::now().into(),
            token: "token".to_string().into(),
            created_at: Utc::now().into(),
            updated_at: Utc::now().into(),
            ip_address: Some("127.0.0.1".to_string()).into(),
            user_agent: Some("agent".to_string()).into(),
            user_id: "user-1".to_string().into(),
            impersonated_by: Some("admin-1".to_string()).into(),
            active_organization_id: Some("org-1".to_string()).into(),
            active_team_id: None.into(),
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
