use better_auth_core::{
    ApiKey, DeviceCode, Invitation, InvitationStatus, Member, Organization, Passkey, TwoFactor,
};
use chrono::{DateTime, Utc};

use crate::store::entities;

fn to_rfc3339(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

impl From<&entities::organization::Model> for Organization {
    fn from(model: &entities::organization::Model) -> Self {
        Self {
            additional_fields: Default::default(),
            id: model.id.clone().into(),
            name: model.name.clone().into(),
            slug: model.slug.clone().into(),
            logo: model.logo.clone().into(),
            metadata: better_auth_core::SchemaValue::Dynamic(
                model
                    .metadata
                    .clone()
                    .map(serde_json::Value::String)
                    .unwrap_or(serde_json::Value::Null),
            ),
            created_at: model.created_at.into(),
        }
    }
}

impl From<&entities::member::Model> for Member {
    fn from(model: &entities::member::Model) -> Self {
        Self {
            additional_fields: Default::default(),
            id: model.id.clone().into(),
            organization_id: model.organization_id.clone().into(),
            user_id: model.user_id.clone().into(),
            role: model.role.clone().into(),
            created_at: model.created_at.into(),
        }
    }
}

impl From<&entities::invitation::Model> for Invitation {
    fn from(model: &entities::invitation::Model) -> Self {
        Self {
            additional_fields: Default::default(),
            id: model.id.clone().into(),
            organization_id: model.organization_id.clone().into(),
            email: model.email.clone().into(),
            role: model.role.clone().into(),
            status: InvitationStatus::from(model.status.clone()).into(),
            inviter_id: model.inviter_id.clone().into(),
            team_id: model.team_id.clone().into(),
            expires_at: model.expires_at.into(),
            created_at: model.created_at.into(),
        }
    }
}

impl From<&entities::two_factor::Model> for TwoFactor {
    fn from(model: &entities::two_factor::Model) -> Self {
        Self {
            id: model.id.clone().into(),
            secret: model.secret.clone(),
            backup_codes: model.backup_codes.clone(),
            user_id: model.user_id.clone(),
            verified: model.verified,
            failed_verification_count: model.failed_verification_count,
            locked_until: model.locked_until,
            created_at: model.created_at,
            updated_at: model.updated_at,
        }
    }
}

impl From<&entities::api_key::Model> for ApiKey {
    fn from(model: &entities::api_key::Model) -> Self {
        Self {
            id: model.id.clone().into(),
            name: model.name.clone().into(),
            start: model.start.clone().map(Into::into),
            prefix: model.prefix.clone(),
            key_hash: model.key_hash.clone(),
            reference_id: model.reference_id.clone(),
            config_id: model.config_id.clone(),
            refill_interval: model.refill_interval,
            refill_amount: model.refill_amount,
            last_refill_at: model.last_refill_at.map(to_rfc3339),
            enabled: model.enabled,
            rate_limit_enabled: model.rate_limit_enabled,
            rate_limit_time_window: model.rate_limit_time_window,
            rate_limit_max: model.rate_limit_max,
            request_count: model.request_count,
            remaining: model.remaining,
            last_request: model.last_request.map(to_rfc3339),
            expires_at: model.expires_at.map(to_rfc3339),
            created_at: to_rfc3339(model.created_at),
            updated_at: to_rfc3339(model.updated_at),
            permissions: model.permissions.clone(),
            metadata: model.metadata.clone(),
        }
    }
}

impl From<&entities::passkey::Model> for Passkey {
    fn from(model: &entities::passkey::Model) -> Self {
        Self {
            id: model.id.clone().into(),
            name: model.name.clone().into(),
            public_key: model.public_key.clone(),
            user_id: model.user_id.clone(),
            credential_id: model.credential_id.clone(),
            counter: u64::try_from(model.counter).unwrap_or_default(),
            device_type: model.device_type.clone(),
            backed_up: model.backed_up,
            transports: model.transports.clone(),
            created_at: model.created_at,
            updated_at: model.updated_at,
            aaguid: model.aaguid.clone().into(),
            credential: model.credential.clone(),
        }
    }
}

impl From<&entities::device_code::Model> for DeviceCode {
    fn from(model: &entities::device_code::Model) -> Self {
        Self {
            id: model.id.clone().into(),
            device_code: model.device_code.clone(),
            user_code: model.user_code.clone(),
            user_id: model.user_id.clone(),
            expires_at: model.expires_at,
            status: model.status.clone(),
            last_polled_at: model.last_polled_at,
            polling_interval: model.polling_interval.map(f64::from),
            client_id: model.client_id.clone().into(),
            scope: model.scope.clone().into(),
        }
    }
}
