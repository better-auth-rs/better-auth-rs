use better_auth_core::{
    ApiKey, DeviceCode, Invitation, InvitationStatus, Member, Organization, Passkey, TwoFactor,
};
use chrono::{DateTime, Utc};

use crate::store::entities;

fn to_rfc3339(value: DateTime<Utc>) -> String {
    value.to_rfc3339()
}

impl From<&entities::organization::Model> for Organization {
    fn from(model: &entities::organization::Model) -> Self {
        Self {
            id: model.id.clone(),
            name: model.name.clone(),
            slug: model.slug.clone(),
            logo: model.logo.clone(),
            metadata: Some(model.metadata.clone()),
            created_at: model.created_at,
            updated_at: model.updated_at,
        }
    }
}

impl From<&entities::member::Model> for Member {
    fn from(model: &entities::member::Model) -> Self {
        Self {
            id: model.id.clone(),
            organization_id: model.organization_id.clone(),
            user_id: model.user_id.clone(),
            role: model.role.clone(),
            created_at: model.created_at,
        }
    }
}

impl From<&entities::invitation::Model> for Invitation {
    fn from(model: &entities::invitation::Model) -> Self {
        Self {
            id: model.id.clone(),
            organization_id: model.organization_id.clone(),
            email: model.email.clone(),
            role: model.role.clone(),
            status: InvitationStatus::from(model.status.clone()),
            inviter_id: model.inviter_id.clone(),
            expires_at: model.expires_at,
            created_at: model.created_at,
        }
    }
}

impl From<&entities::two_factor::Model> for TwoFactor {
    fn from(model: &entities::two_factor::Model) -> Self {
        Self {
            id: model.id.clone(),
            secret: model.secret.clone(),
            backup_codes: model.backup_codes.clone(),
            user_id: model.user_id.clone(),
            created_at: model.created_at,
            updated_at: model.updated_at,
        }
    }
}

impl From<&entities::api_key::Model> for ApiKey {
    fn from(model: &entities::api_key::Model) -> Self {
        Self {
            id: model.id.clone(),
            name: model.name.clone(),
            start: model.start.clone(),
            prefix: model.prefix.clone(),
            key_hash: model.key_hash.clone(),
            user_id: model.user_id.clone(),
            refill_interval: model.refill_interval.map(i64::from),
            refill_amount: model.refill_amount.map(i64::from),
            last_refill_at: model.last_refill_at.map(to_rfc3339),
            enabled: model.enabled,
            rate_limit_enabled: model.rate_limit_enabled,
            rate_limit_time_window: model.rate_limit_time_window.map(i64::from),
            rate_limit_max: model.rate_limit_max.map(i64::from),
            request_count: model.request_count.map(i64::from),
            remaining: model.remaining.map(i64::from),
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
            id: model.id.clone(),
            name: model.name.clone(),
            public_key: model.public_key.clone(),
            user_id: model.user_id.clone(),
            credential_id: model.credential_id.clone(),
            counter: u64::try_from(model.counter).unwrap_or_default(),
            device_type: model.device_type.clone(),
            backed_up: model.backed_up,
            transports: model.transports.clone(),
            created_at: model.created_at,
            updated_at: model.updated_at,
            aaguid: model.aaguid.clone(),
            credential: model.credential.clone(),
        }
    }
}

impl From<&entities::device_code::Model> for DeviceCode {
    fn from(model: &entities::device_code::Model) -> Self {
        Self {
            id: model.id.clone(),
            device_code: model.device_code.clone(),
            user_code: model.user_code.clone(),
            user_id: model.user_id.clone(),
            expires_at: model.expires_at,
            status: model.status.clone(),
            last_polled_at: model.last_polled_at,
            polling_interval: model.polling_interval,
            client_id: model.client_id.clone(),
            scope: model.scope.clone(),
        }
    }
}
