use better_auth_core::{
    ApiKey, DeviceCode, FieldMap, Invitation, InvitationStatus, Member, Organization, Passkey,
    SchemaField, SchemaValue, TwoFactor,
};

use crate::store::entities;

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
                    .map(better_auth_core::FieldValue::String)
                    .unwrap_or(better_auth_core::FieldValue::Null),
            ),
            created_at: better_auth_core::FieldDate::from(model.created_at).into(),
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
            created_at: better_auth_core::FieldDate::from(model.created_at).into(),
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
            expires_at: better_auth_core::FieldDate::from(model.expires_at).into(),
            created_at: better_auth_core::FieldDate::from(model.created_at).into(),
        }
    }
}

impl From<&entities::two_factor::Model> for TwoFactor {
    fn from(model: &entities::two_factor::Model) -> Self {
        Self {
            additional_fields: Default::default(),
            id: model.id.clone().into(),
            secret: model.secret.clone(),
            backup_codes: model.backup_codes.clone(),
            user_id: model.user_id.clone().into(),
            verified: Some(model.verified),
            failed_verification_count: Some(model.failed_verification_count),
            locked_until: model.locked_until.map(Into::into),
            created_at: better_auth_core::FieldDate::from(model.created_at).into(),
            updated_at: better_auth_core::FieldDate::from(model.updated_at).into(),
        }
    }
}

impl From<&entities::api_key::Model> for ApiKey {
    fn from(model: &entities::api_key::Model) -> Self {
        Self {
            additional_fields: Default::default(),
            id: model.id.clone().into(),
            name: model.name.clone().into(),
            start: model.start.clone().map(Into::into).into(),
            prefix: model.prefix.clone().into(),
            key_hash: model.key_hash.clone().into(),
            reference_id: model.reference_id.clone().into(),
            config_id: model.config_id.clone().into(),
            refill_interval: model.refill_interval.into(),
            refill_amount: model.refill_amount.into(),
            last_refill_at: model.last_refill_at.map(Into::into).into(),
            enabled: model.enabled.into(),
            rate_limit_enabled: model.rate_limit_enabled.into(),
            rate_limit_time_window: model.rate_limit_time_window.into(),
            rate_limit_max: model.rate_limit_max.into(),
            request_count: model.request_count.into(),
            remaining: model.remaining.into(),
            last_request: model.last_request.map(Into::into).into(),
            expires_at: model.expires_at.map(Into::into).into(),
            created_at: model.created_at.into(),
            updated_at: model.updated_at.into(),
            permissions: model.permissions.clone().into(),
            metadata: model.metadata.clone().into(),
        }
    }
}

impl From<&entities::passkey::Model> for Passkey {
    fn from(model: &entities::passkey::Model) -> Self {
        Self {
            additional_fields: Default::default(),
            id: model.id.clone().into(),
            name: model.name.clone().into(),
            public_key: model.public_key.clone().into(),
            user_id: model.user_id.clone().into(),
            credential_id: model.credential_id.clone().into(),
            counter: SchemaValue::from_field(model.counter.into()),
            device_type: model.device_type.clone().into(),
            backed_up: model.backed_up.into(),
            transports: model.transports.clone().into(),
            created_at: Some(better_auth_core::FieldDate::from(model.created_at)).into(),
            updated_at: better_auth_core::FieldDate::from(model.updated_at).into(),
            aaguid: model.aaguid.clone().into(),
            credential: model.credential.clone().into(),
        }
    }
}

impl From<&entities::device_code::Model> for DeviceCode {
    fn from(model: &entities::device_code::Model) -> Self {
        Self::from(FieldMap::from([
            ("id".into(), model.id.clone().into()),
            ("deviceCode".into(), model.device_code.clone().into()),
            ("userCode".into(), model.user_code.clone().into()),
            ("userId".into(), model.user_id.clone().into_field()),
            ("expiresAt".into(), model.expires_at.into()),
            ("status".into(), model.status.clone().into()),
            (
                "lastPolledAt".into(),
                model
                    .last_polled_at
                    .map(better_auth_core::FieldDate::from)
                    .into_field(),
            ),
            (
                "pollingInterval".into(),
                model.polling_interval.map(f64::from).into_field(),
            ),
            ("clientId".into(), model.client_id.clone().into_field()),
            ("scope".into(), model.scope.clone().into_field()),
        ]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_passkey_conversion_preserves_negative_counter() {
        let at = chrono::Utc::now();
        let model = entities::passkey::Model {
            id: "passkey".into(),
            name: None,
            public_key: "public-key".into(),
            user_id: "owner".into(),
            credential_id: "credential-id".into(),
            counter: -7,
            device_type: "singleDevice".into(),
            backed_up: false,
            transports: None,
            credential: "credential".into(),
            aaguid: None,
            created_at: at,
            updated_at: at,
        };

        let passkey = Passkey::from(&model);
        assert_eq!(
            passkey.counter.field_value(),
            better_auth_core::FieldValue::Number(-7.0)
        );
    }
}
