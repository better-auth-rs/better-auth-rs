use crate::{AuthRecordFields, AuthResult, FieldMap, FromFieldMap, SchemaField};

fn field<T: SchemaField>(value: &T) -> crate::FieldValue {
    value.clone().into_field()
}

/// Restore native slots and maps from the same prepared graph without narrowing schema variants.
pub(crate) struct ClonedFields(std::vec::IntoIter<crate::FieldValue>);

impl ClonedFields {
    pub(crate) fn new(fields: Vec<crate::FieldValue>) -> Self {
        Self(fields.into_iter())
    }

    fn next(&mut self) -> AuthResult<crate::FieldValue> {
        self.0
            .next()
            .ok_or_else(|| crate::AuthError::internal("Native record clone state is incomplete"))
    }

    pub(crate) fn field<T: SchemaField>(&mut self, source: &T) -> AuthResult<T> {
        source.restore_cloned_field(self.next()?)
    }

    pub(crate) fn map_values(source: &FieldMap) -> impl Iterator<Item = crate::FieldValue> {
        let mut fields = source.clone();
        fields.sort_property_order();
        fields.into_iter().map(|(_, value)| value)
    }

    pub(crate) fn map(&mut self, source: &FieldMap) -> AuthResult<FieldMap> {
        let mut fields = source.clone();
        fields.sort_property_order();
        fields
            .keys()
            .map(|name| Ok((name.clone(), self.next()?)))
            .collect()
    }
}

macro_rules! record {
    (serde $type:ty, [$($field:ident => $name:literal $([$json:ident])?),* $(,)?], $($extra:ident)? $(; order: $order:ident)? $(; omit: [$($omit:literal),*])? $(; serde_omit: [$($private:literal),*])? $(; state: $state:ident => $capture_state:ident, $restore_state:ident)? $(; from: $constructor:ident)?) => {
        record!(serialize $type, [$($field => $name),*], $($extra)? $(; order: $order)? $(; omit: [$($omit),*])? $(; serde_omit: [$($private),*])? $(; state: $state => $capture_state, $restore_state)? $(; from: $constructor)?);

        impl<'de> serde::Deserialize<'de> for $type {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let mut fields = crate::field_value::serde::map::deserialize(deserializer)?;
                $($(let _ = fields.remove($private);)*)?
                fields.sort_property_order();
                $($(record!(@json_field fields, $name, $json);)?)*
                Self::from_field_values(fields).map_err(serde::de::Error::custom)
            }
        }
    };
    (@json_field $fields:ident, $name:literal, date) => {
        if let Some(value) = $fields.get_mut($name) {
            crate::field_value::serde::revive_schema_date(value);
        }
    };
    (serialize $type:ty, [$($field:ident => $name:literal),* $(,)?], $($extra:ident)? $(; order: $order:ident)? $(; omit: [$($omit:literal),*])? $(; serde_omit: [$($private:literal),*])? $(; state: $state:ident => $capture_state:ident, $restore_state:ident)? $(; from: $constructor:ident)?) => {
        record!($type, [$($field => $name),*], $($extra)? $(; order: $order)? $(; omit: [$($omit),*])? $(; state: $state => $capture_state, $restore_state)? $(; from: $constructor)?);

        impl serde::Serialize for $type {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let fields = self.field_values().map_err(serde::ser::Error::custom)?;
                $(let fields = {
                    let mut fields = fields;
                    $(let _ = fields.remove($private);)*
                    fields
                };)?
                crate::field_value::serde::map::serialize(
                    &fields,
                    serializer,
                )
            }
        }
    };
    (@visible $source:ident, $fields:expr, $($extra:ident)? $(; order: $order:ident)? $(; omit: [$($omit:literal),*])?) => {{
        let mut fields = $fields;
        $(fields.retain(|name, value| !value.is_undefined() || $source.$order.contains(name));)?
        $(fields.extend($source.$extra.clone());)?
        $($(let _ = fields.remove($omit);)*)?
        $(let fields = fields.in_field_order(&$source.$order);)?
        fields
    }};
    (@constructor infallible $type:ty, [$($field:ident => $name:literal),*], $($extra:ident)? $(; order: $order:ident)? $(; omit: [$($omit:literal),*])? $(; state: $state:ident)?) => {
        impl From<FieldMap> for $type {
            fn from(mut fields: FieldMap) -> Self {
                $($(let _ = fields.remove($omit);)*)?
                $(let $order = fields.keys().cloned().collect();)?
                Self {
                    $($field: crate::SchemaValue::from_field(fields.remove($name).unwrap_or_default()),)*
                    $($extra: fields,)?
                    $($order,)?
                    $($state: Default::default(),)?
                }
            }
        }
        impl FromFieldMap for $type {
            fn from_field_values(fields: FieldMap) -> AuthResult<Self> {
                Ok(fields.into())
            }
        }
    };
    (@constructor $type:ty, [$($field:ident => $name:literal),*], $($extra:ident)? $(; order: $order:ident)? $(; omit: [$($omit:literal),*])? $(; state: $state:ident)?) => {
        impl FromFieldMap for $type {
            fn from_field_values(mut fields: FieldMap) -> AuthResult<Self> {
                $($(let _ = fields.remove($omit);)*)?
                $(let $order = fields.keys().cloned().collect();)?
                Ok(Self {
                    $($field: fields.remove($name).unwrap_or_default().decode()?,)*
                    $($extra: fields,)?
                    $($order,)?
                    $($state: Default::default(),)?
                })
            }
        }
    };
    ($type:ty, [$($field:ident => $name:literal),* $(,)?], $($extra:ident)? $(; order: $order:ident)? $(; omit: [$($omit:literal),*])? $(; state: $state:ident => $capture_state:ident, $restore_state:ident)? $(; from: $constructor:ident)?) => {
        impl AuthRecordFields for $type {
            fn field_values(&self) -> AuthResult<FieldMap> {
                let fields = FieldMap::from_iter([
                    $(($name.to_owned(), field(&self.$field))),*
                ]);
                Ok(record!(@visible self, fields, $($extra)? $(; order: $order)? $(; omit: [$($omit),*])?))
            }

            fn structured_clone(&self, context: &mut crate::StructuredCloneContext) -> AuthResult<Self> {
                let native = FieldMap::from_iter([
                    $(($name.to_owned(), field(&self.$field))),*
                ]);
                let fields = record!(@visible self, native.clone(), $($extra)? $(; order: $order)? $(; omit: [$($omit),*])?);
                let mut state: Vec<_> = native.into_iter().map(|(_, value)| value).collect();
                $(state.extend(ClonedFields::map_values(&self.$extra));)?
                $(state.extend(self.$capture_state());)?
                context.clone_with(&fields, &state, |fields, state| {
                    let mut state = ClonedFields::new(state);
                    let mut record = self.clone();
                    $(record.$field = state.field(&self.$field)?;)*
                    $(record.$extra = state.map(&self.$extra)?;)?
                    $(record.$state = self.$restore_state(&mut state)?;)?
                    $(record.$order = fields.keys().cloned().collect();)?
                    Ok(record)
                })
            }
        }

        record!(@constructor $($constructor)? $type, [$($field => $name),*], $($extra)? $(; order: $order)? $(; omit: [$($omit),*])? $(; state: $state)?);
    };

}

record!(serde crate::types::Organization, [
    id => "id",
    name => "name",
    slug => "slug",
    logo => "logo",
    metadata => "metadata",
    created_at => "createdAt" [date],
], additional_fields; order: field_order);

record!(serde crate::types::Member, [
    id => "id",
    organization_id => "organizationId",
    user_id => "userId",
    role => "role",
    created_at => "createdAt" [date],
], additional_fields; order: field_order);

record!(serde crate::types::Invitation, [
    team_id => "teamId",
    id => "id",
    organization_id => "organizationId",
    email => "email",
    role => "role",
    status => "status",
    inviter_id => "inviterId",
    expires_at => "expiresAt" [date],
    created_at => "createdAt" [date],
], additional_fields; order: field_order);

record!(serde crate::wire::InvitationView, [
    team_id => "teamId",
    id => "id",
    organization_id => "organizationId",
    email => "email",
    role => "role",
    status => "status",
    inviter_id => "inviterId",
    expires_at => "expiresAt" [date],
    created_at => "createdAt" [date],
], additional_fields; order: field_order);

record!(serde crate::types::Team, [
    id => "id",
    name => "name",
    organization_id => "organizationId",
    created_at => "createdAt" [date],
    updated_at => "updatedAt" [date],
], additional_fields; order: field_order);

record!(serde crate::types::TeamMember, [
    id => "id",
    team_id => "teamId",
    user_id => "userId",
    created_at => "createdAt" [date],
], additional_fields; order: field_order; omit: ["membershipKey"]);

record!(serde crate::types::OrganizationRole, [
    id => "id",
    organization_id => "organizationId",
    role => "role",
    permission => "permission",
    created_at => "createdAt" [date],
    updated_at => "updatedAt" [date],
], additional_fields; order: field_order);

record!(serde crate::types::DeviceCode, [
    id => "id",
    device_code => "deviceCode",
    user_code => "userCode",
    user_id => "userId",
    expires_at => "expiresAt",
    status => "status",
    last_polled_at => "lastPolledAt",
    polling_interval => "pollingInterval",
    client_id => "clientId",
    scope => "scope",
], additional_fields; order: field_order; state: consumption => consumption_clone_fields, restore_consumption; from: infallible);

record!(serde crate::types::TwoFactor, [
    id => "id",
    secret => "secret",
    backup_codes => "backupCodes",
    user_id => "userId",
    verified => "verified",
    failed_verification_count => "failedVerificationCount",
    locked_until => "lockedUntil" [date],
    created_at => "createdAt" [date],
    updated_at => "updatedAt" [date],
], additional_fields; order: field_order);

record!(serde crate::types::Passkey, [
    id => "id",
    name => "name",
    public_key => "publicKey",
    user_id => "userId",
    credential_id => "credentialID",
    counter => "counter",
    device_type => "deviceType",
    backed_up => "backedUp",
    transports => "transports",
    created_at => "createdAt" [date],
    updated_at => "updatedAt" [date],
    aaguid => "aaguid",
    credential => "credential",
], additional_fields; order: field_order; serde_omit: ["credential"]);

record!(serde crate::wire::PasskeyView, [
    id => "id",
    name => "name",
    credential_id => "credentialID",
    user_id => "userId",
    public_key => "publicKey",
    counter => "counter",
    device_type => "deviceType",
    backed_up => "backedUp",
    transports => "transports",
    created_at => "createdAt" [date],
    aaguid => "aaguid",
], additional_fields; order: field_order);

record!(serde crate::types::ApiKey, [
    id => "id",
    name => "name",
    start => "start",
    prefix => "prefix",
    key_hash => "key",
    reference_id => "referenceId",
    config_id => "configId",
    refill_interval => "refillInterval",
    refill_amount => "refillAmount",
    last_refill_at => "lastRefillAt" [date],
    enabled => "enabled",
    rate_limit_enabled => "rateLimitEnabled",
    rate_limit_time_window => "rateLimitTimeWindow",
    rate_limit_max => "rateLimitMax",
    request_count => "requestCount",
    remaining => "remaining",
    last_request => "lastRequest" [date],
    expires_at => "expiresAt" [date],
    created_at => "createdAt" [date],
    updated_at => "updatedAt" [date],
    permissions => "permissions",
    metadata => "metadata",
], additional_fields; order: field_order);

record!(crate::wire::ApiKeyView, [
    id => "id",
    name => "name",
    start => "start",
    prefix => "prefix",
    reference_id => "referenceId",
    config_id => "configId",
    refill_interval => "refillInterval",
    refill_amount => "refillAmount",
    last_refill_at => "lastRefillAt",
    enabled => "enabled",
    rate_limit_enabled => "rateLimitEnabled",
    rate_limit_time_window => "rateLimitTimeWindow",
    rate_limit_max => "rateLimitMax",
    request_count => "requestCount",
    remaining => "remaining",
    last_request => "lastRequest",
    expires_at => "expiresAt",
    created_at => "createdAt",
    updated_at => "updatedAt",
    permissions => "permissions",
    metadata => "metadata",
], additional_fields; order: field_order; omit: ["key"]);

record!(serde crate::types::WalletAddress, [
    id => "id",
    user_id => "userId",
    address => "address",
    chain_id => "chainId",
    is_primary => "isPrimary",
    created_at => "createdAt" [date],
], additional_fields; order: field_order);

record!(crate::types_jwt::Jwk, [
    id => "id",
    public_key => "publicKey",
    private_key => "privateKey",
    created_at => "createdAt",
    expires_at => "expiresAt",
    alg => "alg",
    crv => "crv",
], additional_fields; order: field_order);

record!(crate::wire::AccountView, [
    id => "id",
    account_id => "accountId",
    provider_id => "providerId",
    user_id => "userId",
    access_token => "accessToken",
    refresh_token => "refreshToken",
    id_token => "idToken",
    access_token_expires_at => "accessTokenExpiresAt",
    refresh_token_expires_at => "refreshTokenExpiresAt",
    scope => "scope",
    password => "password",
    created_at => "createdAt",
    updated_at => "updatedAt",
], additional_fields; order: field_order);

record!(crate::wire::VerificationView, [
    id => "id",
    identifier => "identifier",
    value => "value",
    expires_at => "expiresAt",
    created_at => "createdAt",
    updated_at => "updatedAt",
], additional_fields; order: field_order);

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract. Fixture indexing must fail when an expected record or property is missing. Assertions report exact contract mismatches while Result propagates fixture errors."
)]
mod tests {
    use super::*;
    use crate::{FieldDate, FieldValue, SchemaValue};

    #[test]
    fn passkey_projection_preserves_presence_and_order_without_exposing_credentials()
    -> AuthResult<()> {
        let input = FieldMap::from([
            ("counter".into(), "dynamic-count".into()),
            ("name".into(), 7.0.into()),
            ("publicKey".into(), FieldValue::Undefined),
            ("id".into(), "passkey".into()),
        ]);
        let mut passkey = crate::Passkey::from_field_values(input.clone())?;
        assert_eq!(passkey.field_values()?, input);
        assert_eq!(
            passkey.field_order,
            input.keys().cloned().collect::<Vec<_>>()
        );
        passkey.credential = "private-envelope".into();
        passkey.updated_at = FieldDate::from_milliseconds(0.0).into();
        let view = crate::wire::PasskeyView::from(&passkey);
        let expected = FieldMap::from([
            ("counter".into(), "dynamic-count".into()),
            ("name".into(), 7.0.into()),
            ("publicKey".into(), FieldValue::Undefined),
            ("id".into(), "passkey".into()),
        ]);
        assert_eq!(view.field_values()?, expected);
        assert_eq!(
            view.field_values()?.keys().collect::<Vec<_>>(),
            expected.keys().collect::<Vec<_>>(),
        );
        assert_eq!(
            serde_json::to_string(&view)?,
            r#"{"counter":"dynamic-count","name":7,"id":"passkey"}"#
        );
        assert_eq!(
            serde_json::to_string(&passkey)?,
            r#"{"counter":"dynamic-count","name":7,"id":"passkey","updatedAt":"1970-01-01T00:00:00.000Z"}"#
        );
        let restored: crate::Passkey =
            serde_json::from_str(r#"{"name":"restored","credential":"untrusted","counter":null}"#)?;
        let declared = crate::Passkey::from_field_values(FieldMap::from([
            ("updatedAt".into(), "declared-update".into()),
            ("credential".into(), "declared-value".into()),
        ]))?;
        assert_eq!(
            crate::wire::PasskeyView::from(&declared).field_values()?,
            declared.field_values()?,
        );
        assert!(restored.credential.is_undefined());
        assert_eq!(
            restored
                .field_values()?
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["name", "counter"]
        );
        Ok(())
    }

    #[test]
    fn account_field_roundtrip_retains_handles_and_private_password() -> AuthResult<()> {
        let date = FieldDate::invalid();
        let object = FieldValue::from(FieldMap::from_iter([
            ("date".into(), FieldValue::Date(date.clone())),
            ("omitted".into(), FieldValue::Undefined),
        ]));
        let account = crate::wire::AccountView {
            password: Some("private-password".to_owned()).into(),
            created_at: date.clone().into(),
            updated_at: date.clone().into(),
            additional_fields: FieldMap::from_iter([("payload".into(), object.clone())]),
            ..Default::default()
        };
        let restored = crate::wire::AccountView::from_field_values(account.field_values()?)?;
        assert_eq!(restored.password, account.password);
        assert!(restored.created_at.typed()?.same_object(&date));
        assert!(restored.updated_at.typed()?.same_object(&date));
        assert!(
            restored
                .additional_fields
                .get("payload")
                .unwrap()
                .strict_equals(&object)
        );
        let json = serde_json::to_value(&restored)?;
        assert!(json.get("password").is_none());
        assert!(json["payload"].get("omitted").is_none());
        assert_eq!(json["payload"]["date"], serde_json::Value::Null);
        assert!(matches!(restored.created_at, SchemaValue::Typed(_)));
        Ok(())
    }

    #[test]
    fn structured_user_clone_preserves_native_state_and_shared_dates() -> AuthResult<()> {
        let mut user: crate::UserView = serde_json::from_value(serde_json::json!({
            "id": "user", "name": "native-name", "emailVerified": false,
            "createdAt": "2026-10-07T00:00:00.000Z",
            "updatedAt": "2026-10-07T00:00:00.000Z"
        }))?;
        user.visible_fields = None;
        user.is_anonymous = None.into();
        user.created_at = crate::FieldDate::from_milliseconds(123.0).into();
        user.email = SchemaValue::from_field(user.created_at.field_value());
        let cloned = user.structured_clone(&mut crate::StructuredCloneContext::new())?;
        assert_eq!(cloned.visible_fields, None);
        assert_eq!(cloned.is_anonymous, None);
        assert_eq!(cloned.name, user.name);
        assert!(
            !cloned
                .created_at
                .typed()?
                .same_object(user.created_at.typed()?)
        );
        assert!(
            cloned
                .email
                .field_value()
                .as_date()
                .unwrap()
                .same_object(cloned.created_at.typed()?)
        );
        Ok(())
    }
}
