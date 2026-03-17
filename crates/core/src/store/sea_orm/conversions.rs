//! Conversions between internal SeaORM models and public auth types.

use chrono::{DateTime, Utc};

use crate::types::{Account, ApiKey, Passkey, Session, TwoFactor, User, Verification};
use crate::types_org::{Invitation, InvitationStatus, Member, Organization};

use super::entities;

fn to_rfc3339(value: DateTime<Utc>) -> String {
    value.to_rfc3339()
}

impl From<entities::user::Model> for User {
    fn from(model: entities::user::Model) -> Self {
        Self {
            id: model.id,
            name: model.name,
            email: model.email,
            email_verified: model.email_verified,
            image: model.image,
            created_at: model.created_at,
            updated_at: model.updated_at,
            username: model.username,
            display_username: model.display_username,
            two_factor_enabled: model.two_factor_enabled,
            role: model.role,
            banned: model.banned,
            ban_reason: model.ban_reason,
            ban_expires: model.ban_expires,
            metadata: model.metadata,
        }
    }
}

impl From<entities::session::Model> for Session {
    fn from(model: entities::session::Model) -> Self {
        Self {
            id: model.id,
            expires_at: model.expires_at,
            token: model.token,
            created_at: model.created_at,
            updated_at: model.updated_at,
            ip_address: model.ip_address,
            user_agent: model.user_agent,
            user_id: model.user_id,
            impersonated_by: model.impersonated_by,
            active_organization_id: model.active_organization_id,
            active: model.active,
        }
    }
}

impl From<entities::account::Model> for Account {
    fn from(model: entities::account::Model) -> Self {
        Self {
            id: model.id,
            account_id: model.account_id,
            provider_id: model.provider_id,
            user_id: model.user_id,
            access_token: model.access_token,
            refresh_token: model.refresh_token,
            id_token: model.id_token,
            access_token_expires_at: model.access_token_expires_at,
            refresh_token_expires_at: model.refresh_token_expires_at,
            scope: model.scope,
            password: model.password,
            created_at: model.created_at,
            updated_at: model.updated_at,
        }
    }
}

impl From<entities::verification::Model> for Verification {
    fn from(model: entities::verification::Model) -> Self {
        Self {
            id: model.id,
            identifier: model.identifier,
            value: model.value,
            expires_at: model.expires_at,
            created_at: model.created_at,
            updated_at: model.updated_at,
        }
    }
}

impl From<entities::organization::Model> for Organization {
    fn from(model: entities::organization::Model) -> Self {
        Self {
            id: model.id,
            name: model.name,
            slug: model.slug,
            logo: model.logo,
            metadata: Some(model.metadata),
            created_at: model.created_at,
            updated_at: model.updated_at,
        }
    }
}

impl From<entities::member::Model> for Member {
    fn from(model: entities::member::Model) -> Self {
        Self {
            id: model.id,
            organization_id: model.organization_id,
            user_id: model.user_id,
            role: model.role,
            created_at: model.created_at,
        }
    }
}

impl From<entities::invitation::Model> for Invitation {
    fn from(model: entities::invitation::Model) -> Self {
        Self {
            id: model.id,
            organization_id: model.organization_id,
            email: model.email,
            role: model.role,
            status: InvitationStatus::from(model.status),
            inviter_id: model.inviter_id,
            expires_at: model.expires_at,
            created_at: model.created_at,
        }
    }
}

impl From<entities::two_factor::Model> for TwoFactor {
    fn from(model: entities::two_factor::Model) -> Self {
        Self {
            id: model.id,
            secret: model.secret,
            backup_codes: model.backup_codes,
            user_id: model.user_id,
            created_at: model.created_at,
            updated_at: model.updated_at,
        }
    }
}

impl From<entities::passkey::Model> for Passkey {
    fn from(model: entities::passkey::Model) -> Self {
        Self {
            id: model.id,
            name: model.name,
            public_key: model.public_key,
            user_id: model.user_id,
            credential_id: model.credential_id,
            counter: u64::try_from(model.counter).unwrap_or_default(),
            device_type: model.device_type,
            backed_up: model.backed_up,
            transports: model.transports,
            created_at: model.created_at,
        }
    }
}

impl From<entities::api_key::Model> for ApiKey {
    fn from(model: entities::api_key::Model) -> Self {
        Self {
            id: model.id,
            name: model.name,
            start: model.start,
            prefix: model.prefix,
            key_hash: model.key_hash,
            user_id: model.user_id,
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
            permissions: model.permissions,
            metadata: model.metadata,
        }
    }
}
