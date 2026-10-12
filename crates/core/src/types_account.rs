//! Native adapter inputs preserve explicit null, replacement types, and omission.
use crate::{AuthResult, SchemaValue};

/// Creation input passed to database hooks before adapter field policies.
#[derive(Debug, Clone, Default)]
pub struct CreateAccount {
    /// Source property order, independent of the current field values.
    pub field_order: Vec<String>,
    pub id: SchemaValue<String>,
    pub account_id: SchemaValue<String>,
    pub provider_id: SchemaValue<String>,
    pub user_id: SchemaValue<String>,
    pub access_token: SchemaValue<Option<String>>,
    pub refresh_token: SchemaValue<Option<String>>,
    pub id_token: SchemaValue<Option<String>>,
    pub access_token_expires_at: SchemaValue<Option<crate::FieldDate>>,
    pub refresh_token_expires_at: SchemaValue<Option<crate::FieldDate>>,
    pub scope: SchemaValue<Option<String>>,
    pub password: SchemaValue<Option<String>>,
    pub created_at: SchemaValue<crate::FieldDate>,
    pub updated_at: SchemaValue<crate::FieldDate>,
    pub additional_fields: crate::FieldMap,
}

impl CreateAccount {
    /// Return logical input fields without applying adapter policies.
    pub fn fields(&self) -> AuthResult<crate::FieldMap> {
        Ok(self.native_fields())
    }

    fn native_fields(&self) -> crate::FieldMap {
        ordered_input_fields(
            &self.additional_fields,
            &self.field_order,
            [
                input_slot("id", &self.id),
                input_slot("accountId", &self.account_id),
                input_slot("providerId", &self.provider_id),
                input_slot("userId", &self.user_id),
                input_slot("accessToken", &self.access_token),
                input_slot("refreshToken", &self.refresh_token),
                input_slot("idToken", &self.id_token),
                input_slot("accessTokenExpiresAt", &self.access_token_expires_at),
                input_slot("refreshTokenExpiresAt", &self.refresh_token_expires_at),
                input_slot("scope", &self.scope),
                input_slot("password", &self.password),
                input_slot("createdAt", &self.created_at),
                input_slot("updatedAt", &self.updated_at),
            ],
        )
    }

    /// Match the internal adapter timestamps present before create hooks.
    pub fn with_timestamps(mut self, now: crate::FieldDate) -> Self {
        input_timestamps(
            self.native_fields(),
            &mut self.field_order,
            &mut self.created_at,
            &mut self.updated_at,
            now,
        );
        self
    }
}

/// Typed update converted to logical fields before database hooks and adapter policies.
#[derive(Debug, Clone, Default)]
pub struct UpdateAccount {
    pub id: SchemaValue<String>,
    pub account_id: SchemaValue<String>,
    pub provider_id: SchemaValue<String>,
    pub user_id: SchemaValue<String>,
    pub access_token: SchemaValue<Option<String>>,
    pub refresh_token: SchemaValue<Option<String>>,
    pub id_token: SchemaValue<Option<String>>,
    pub access_token_expires_at: SchemaValue<Option<crate::FieldDate>>,
    pub refresh_token_expires_at: SchemaValue<Option<crate::FieldDate>>,
    pub scope: SchemaValue<Option<String>>,
    pub password: SchemaValue<Option<String>>,
    pub created_at: SchemaValue<crate::FieldDate>,
    pub updated_at: SchemaValue<crate::FieldDate>,
    pub additional_fields: crate::FieldMap,
}

impl UpdateAccount {
    /// Return logical input fields without applying adapter policies.
    pub fn fields(&self) -> AuthResult<crate::FieldMap> {
        Ok(ordered_input_fields(
            &self.additional_fields,
            &[],
            [
                input_slot("id", &self.id),
                input_slot("accountId", &self.account_id),
                input_slot("providerId", &self.provider_id),
                input_slot("userId", &self.user_id),
                input_slot("accessToken", &self.access_token),
                input_slot("refreshToken", &self.refresh_token),
                input_slot("idToken", &self.id_token),
                input_slot("accessTokenExpiresAt", &self.access_token_expires_at),
                input_slot("refreshTokenExpiresAt", &self.refresh_token_expires_at),
                input_slot("scope", &self.scope),
                input_slot("password", &self.password),
                input_slot("createdAt", &self.created_at),
                input_slot("updatedAt", &self.updated_at),
            ],
        ))
    }
}

/// Creation input passed to database hooks before adapter field policies.
#[derive(Debug, Clone, Default)]
pub struct CreateVerification {
    /// Source property order, independent of the current field values.
    pub field_order: Vec<String>,
    pub id: SchemaValue<String>,
    pub identifier: SchemaValue<String>,
    pub value: SchemaValue<String>,
    pub expires_at: SchemaValue<crate::FieldDate>,
    pub created_at: SchemaValue<crate::FieldDate>,
    pub updated_at: SchemaValue<crate::FieldDate>,
    pub additional_fields: crate::FieldMap,
}

impl CreateVerification {
    /// Return logical input fields without applying adapter policies.
    pub fn fields(&self) -> AuthResult<crate::FieldMap> {
        Ok(self.native_fields())
    }

    fn native_fields(&self) -> crate::FieldMap {
        ordered_input_fields(
            &self.additional_fields,
            &self.field_order,
            [
                input_slot("id", &self.id),
                input_slot("identifier", &self.identifier),
                input_slot("value", &self.value),
                input_slot("expiresAt", &self.expires_at),
                input_slot("createdAt", &self.created_at),
                input_slot("updatedAt", &self.updated_at),
            ],
        )
    }

    /// Match the internal adapter timestamps present before create hooks.
    pub fn with_timestamps(mut self, now: crate::FieldDate) -> Self {
        input_timestamps(
            self.native_fields(),
            &mut self.field_order,
            &mut self.created_at,
            &mut self.updated_at,
            now,
        );
        self
    }
    /// Construct the internal reservation input before adapter field policies.
    #[doc(hidden)]
    pub fn into_reservation(self, id: &str) -> Self {
        Self {
            field_order: [
                "id",
                "identifier",
                "value",
                "expiresAt",
                "createdAt",
                "updatedAt",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            id: id.into(),
            identifier: self.identifier,
            value: self.value,
            expires_at: self.expires_at,
            created_at: chrono::Utc::now().into(),
            updated_at: chrono::Utc::now().into(),
            ..Default::default()
        }
    }
}

/// Partial update passed to database hooks before adapter field policies.
#[derive(Debug, Clone, Default)]
pub struct VerificationUpdate {
    pub id: SchemaValue<String>,
    pub identifier: SchemaValue<String>,
    pub value: SchemaValue<String>,
    pub expires_at: SchemaValue<crate::FieldDate>,
    pub created_at: SchemaValue<crate::FieldDate>,
    pub updated_at: SchemaValue<crate::FieldDate>,
    pub additional_fields: crate::FieldMap,
}

impl VerificationUpdate {
    /// Return logical input fields without applying adapter policies.
    pub fn fields(&self) -> AuthResult<crate::FieldMap> {
        Ok(ordered_input_fields(
            &self.additional_fields,
            &[],
            [
                input_slot("id", &self.id),
                input_slot("identifier", &self.identifier),
                input_slot("value", &self.value),
                input_slot("expiresAt", &self.expires_at),
                input_slot("createdAt", &self.created_at),
                input_slot("updatedAt", &self.updated_at),
            ],
        ))
    }
}

fn input_slot<T: crate::SchemaField>(
    name: &'static str,
    value: &SchemaValue<T>,
) -> (&'static str, bool, crate::FieldValue) {
    (name, !value.is_undefined(), value.field_value())
}

fn ordered_input_fields<const N: usize>(
    additional: &crate::FieldMap,
    order: &[String],
    native: [(&str, bool, crate::FieldValue); N],
) -> crate::FieldMap {
    additional.clone().with_schema_fields(
        order,
        native.map(|(name, present, value)| {
            let present = present
                || (!additional.contains_key(name) && order.iter().any(|field| field == name));
            (name, present.then_some(value))
        }),
    )
}

fn input_timestamps(
    original: crate::FieldMap,
    order: &mut Vec<String>,
    created_at: &mut SchemaValue<crate::FieldDate>,
    updated_at: &mut SchemaValue<crate::FieldDate>,
    now: crate::FieldDate,
) {
    if !original.contains_key("createdAt") {
        *created_at = crate::FieldDate::from_milliseconds(now.milliseconds()).into();
    }
    if !original.contains_key("updatedAt") {
        *updated_at = crate::FieldDate::from_milliseconds(now.milliseconds()).into();
    }
    *order = ["createdAt", "updatedAt"]
        .into_iter()
        .map(str::to_owned)
        .chain(
            original
                .keys()
                .filter(|name| !matches!(name.as_str(), "createdAt" | "updatedAt"))
                .cloned(),
        )
        .collect();
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]
mod create_input_tests {
    use super::*;

    #[test]
    fn verification_hook_values_keep_timestamp_prefix_and_own_undefined() -> AuthResult<()> {
        let mut input = CreateVerification {
            id: "explicit".into(),
            identifier: "lookup".into(),
            value: "proof".into(),
            expires_at: crate::FieldDate::from_milliseconds(10_000.0).into(),
            ..Default::default()
        }
        .with_timestamps(crate::FieldDate::from_milliseconds(1_000.0));
        input.value = SchemaValue::Undefined;
        input.expires_at = SchemaValue::from_field(crate::FieldValue::Null);
        let fields = input.fields()?;
        assert_eq!(
            fields.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "createdAt",
                "updatedAt",
                "id",
                "identifier",
                "value",
                "expiresAt"
            ]
        );
        assert_eq!(fields.get("value"), Some(&crate::FieldValue::Undefined));
        assert_eq!(fields.get("expiresAt"), Some(&crate::FieldValue::Null));
        Ok(())
    }

    #[test]
    fn account_hooks_retain_input_order_presence_and_typed_mutations() -> AuthResult<()> {
        let mut input = CreateAccount {
            field_order: [
                "providerId",
                "accountId",
                "userId",
                "accessToken",
                "idToken",
            ]
            .map(str::to_owned)
            .into(),
            provider_id: "google".into(),
            account_id: "subject".into(),
            user_id: "owner".into(),
            access_token: Some("token".to_owned()).into(),
            ..Default::default()
        }
        .with_timestamps(crate::FieldDate::from_milliseconds(1_000.0));
        assert!(
            !input
                .created_at
                .field_value()
                .strict_equals(&input.updated_at.field_value())
        );
        assert_eq!(input.access_token.typed()?, &Some("token".to_owned()));
        input.access_token = SchemaValue::Undefined;
        input.id_token = SchemaValue::from_field(crate::FieldValue::Null);
        input.scope = Some("profile".to_owned()).into();
        let fields = input.fields()?;
        assert_eq!(
            fields.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "createdAt",
                "updatedAt",
                "providerId",
                "accountId",
                "userId",
                "accessToken",
                "idToken",
                "scope"
            ]
        );
        assert_eq!(
            fields.get("accessToken"),
            Some(&crate::FieldValue::Undefined)
        );
        assert_eq!(fields.get("idToken"), Some(&crate::FieldValue::Null));
        assert_eq!(fields.get("scope"), Some(&"profile".into()));
        assert!(!fields.contains_key("refreshToken"));
        Ok(())
    }

    #[test]
    fn dynamic_undefined_overrides_additional_fields_without_timestamp_defaults() -> AuthResult<()>
    {
        let additional = crate::FieldMap::from([
            ("createdAt".into(), "raw timestamp".into()),
            ("id".into(), "raw id".into()),
        ]);
        let account = CreateAccount {
            id: SchemaValue::Dynamic(crate::FieldValue::Undefined),
            created_at: SchemaValue::Dynamic(crate::FieldValue::Undefined),
            additional_fields: additional.clone(),
            ..Default::default()
        }
        .with_timestamps(crate::FieldDate::from_milliseconds(1_000.0));
        let verification = CreateVerification {
            id: SchemaValue::Dynamic(crate::FieldValue::Undefined),
            created_at: SchemaValue::Dynamic(crate::FieldValue::Undefined),
            additional_fields: additional.clone(),
            ..Default::default()
        }
        .with_timestamps(crate::FieldDate::from_milliseconds(1_000.0));
        let account_update = UpdateAccount {
            id: SchemaValue::Dynamic(crate::FieldValue::Undefined),
            created_at: SchemaValue::Dynamic(crate::FieldValue::Undefined),
            additional_fields: additional.clone(),
            ..Default::default()
        };
        let verification_update = VerificationUpdate {
            id: SchemaValue::Dynamic(crate::FieldValue::Undefined),
            created_at: SchemaValue::Dynamic(crate::FieldValue::Undefined),
            additional_fields: additional,
            ..Default::default()
        };
        for fields in [
            account.fields()?,
            verification.fields()?,
            account_update.fields()?,
            verification_update.fields()?,
        ] {
            assert_eq!(fields.get("createdAt"), Some(&crate::FieldValue::Undefined));
            assert_eq!(fields.get("id"), Some(&crate::FieldValue::Undefined));
        }
        assert_eq!(account.updated_at.typed()?.milliseconds(), 1_000.0);
        assert_eq!(verification.updated_at.typed()?.milliseconds(), 1_000.0);
        Ok(())
    }

    #[test]
    fn create_timestamp_defaults_preserve_present_undefined_and_raw_values() -> AuthResult<()> {
        let updated: crate::FieldValue =
            crate::FieldMap::from([("clock".into(), true.into())]).into();
        let account = CreateAccount {
            field_order: vec!["createdAt".into()],
            additional_fields: crate::FieldMap::from([("updatedAt".into(), updated.clone())]),
            ..Default::default()
        }
        .with_timestamps(crate::FieldDate::from_milliseconds(1_000.0));
        let verification = CreateVerification {
            field_order: vec!["createdAt".into()],
            additional_fields: crate::FieldMap::from([("updatedAt".into(), updated.clone())]),
            ..Default::default()
        }
        .with_timestamps(crate::FieldDate::from_milliseconds(1_000.0));
        for fields in [account.fields()?, verification.fields()?] {
            assert_eq!(
                fields.keys().map(String::as_str).collect::<Vec<_>>(),
                ["createdAt", "updatedAt"]
            );
            assert_eq!(fields.get("createdAt"), Some(&crate::FieldValue::Undefined));
            assert!(
                fields
                    .get("updatedAt")
                    .is_some_and(|value| value.strict_equals(&updated))
            );
        }
        Ok(())
    }
}
