use crate::{AuthRecordFields, AuthResult, FieldMap, FromFieldMap, SchemaField};

fn field<T: SchemaField>(value: &T) -> crate::FieldValue {
    value.clone().into_field()
}

macro_rules! record {
    ($type:ty, [$($field:ident => $name:literal),* $(,)?], $($extra:ident)?) => {
        impl AuthRecordFields for $type {
            fn field_values(&self) -> AuthResult<FieldMap> {
                let fields = FieldMap::from_iter([
                    $(($name.to_owned(), field(&self.$field))),*
                ]);
                $(let fields = {
                    let mut fields = fields;
                    fields.extend(self.$extra.clone());
                    fields
                };)?
                Ok(fields)
            }

            fn structured_clone(&self, context: &mut crate::StructuredCloneContext) -> AuthResult<Self> {
                let mut record = self.clone();
                $(record.$field = context.clone_field(&self.$field)?;)*
                $(record.$extra = context.clone_map(&self.$extra);)?
                Ok(record)
            }
        }
        impl FromFieldMap for $type {
            fn from_field_values(mut fields: FieldMap) -> AuthResult<Self> {
                Ok(Self {
                    $($field: fields.remove($name).unwrap_or_default().decode()?,)*
                    $($extra: fields,)?
                })
            }
        }
    };
}

record!(crate::types::Organization, [
    id => "id",
    name => "name",
    slug => "slug",
    logo => "logo",
    metadata => "metadata",
    created_at => "createdAt",
], additional_fields);

record!(crate::types::Member, [
    id => "id",
    organization_id => "organizationId",
    user_id => "userId",
    role => "role",
    created_at => "createdAt",
], additional_fields);

record!(crate::types::Invitation, [
    team_id => "teamId",
    id => "id",
    organization_id => "organizationId",
    email => "email",
    role => "role",
    status => "status",
    inviter_id => "inviterId",
    expires_at => "expiresAt",
    created_at => "createdAt",
], additional_fields);

record!(crate::types::Team, [
    id => "id",
    name => "name",
    organization_id => "organizationId",
    created_at => "createdAt",
    updated_at => "updatedAt",
], additional_fields);

record!(crate::types::TeamMember, [
    id => "id",
    team_id => "teamId",
    user_id => "userId",
    created_at => "createdAt",
], );

record!(crate::types::OrganizationRole, [
    id => "id",
    organization_id => "organizationId",
    role => "role",
    permission => "permission",
    created_at => "createdAt",
    updated_at => "updatedAt",
], additional_fields);

record!(crate::types::TwoFactor, [
    id => "id",
    secret => "secret",
    backup_codes => "backupCodes",
    user_id => "userId",
    verified => "verified",
    failed_verification_count => "failedVerificationCount",
    locked_until => "lockedUntil",
    created_at => "createdAt",
    updated_at => "updatedAt",
], additional_fields);

record!(crate::types::Passkey, [
    id => "id",
    name => "name",
    public_key => "publicKey",
    user_id => "userId",
    credential_id => "credentialID",
    counter => "counter",
    device_type => "deviceType",
    backed_up => "backedUp",
    transports => "transports",
    created_at => "createdAt",
    updated_at => "updatedAt",
    aaguid => "aaguid",
    credential => "credential",
], additional_fields);

record!(crate::types::DeviceCode, [
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
], additional_fields);

record!(crate::types::ApiKey, [
    id => "id",
    name => "name",
    start => "start",
    prefix => "prefix",
    key_hash => "key",
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
], additional_fields);

record!(crate::types::WalletAddress, [
    id => "id",
    user_id => "userId",
    address => "address",
    chain_id => "chainId",
    is_primary => "isPrimary",
    created_at => "createdAt",
], additional_fields);

record!(crate::types_jwt::Jwk, [
    id => "id",
    public_key => "publicKey",
    private_key => "privateKey",
    created_at => "createdAt",
    expires_at => "expiresAt",
    alg => "alg",
    crv => "crv",
], additional_fields);

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
], additional_fields);

record!(crate::wire::VerificationView, [
    id => "id",
    identifier => "identifier",
    value => "value",
    expires_at => "expiresAt",
    created_at => "createdAt",
    updated_at => "updatedAt",
], additional_fields);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FieldDate, FieldValue, SchemaValue};

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
        user.is_anonymous = None;
        let _ = user
            .additional_fields
            .insert("name".into(), user.created_at.clone().into());
        let cloned = user.structured_clone(&mut crate::StructuredCloneContext::new())?;
        assert_eq!(cloned.visible_fields, None);
        assert_eq!(cloned.is_anonymous, None);
        assert_eq!(cloned.name, user.name);
        assert!(!cloned.created_at.same_object(&user.created_at));
        assert!(
            cloned
                .additional_fields
                .get("name")
                .unwrap()
                .as_date()
                .unwrap()
                .same_object(&cloned.created_at)
        );
        Ok(())
    }
}
