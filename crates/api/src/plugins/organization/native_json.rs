use better_auth_core::utils::json::parse_client_json;
pub(super) use better_auth_core::utils::json::parse_native_json as parse_json;
use better_auth_core::{
    AuthRecordFields, AuthResult, FieldValue, FromFieldMap, Organization, SchemaValue,
};

pub(super) fn metadata(organization: Organization, create: bool) -> AuthResult<Organization> {
    let mut fields = organization.field_values()?;
    let raw = fields.get("metadata").cloned().unwrap_or_default();
    let parsed = if !raw.is_truthy() || (create && !raw.is_string()) {
        FieldValue::Undefined
    } else if create {
        parse_json(&raw)?
    } else {
        parse_client_json(raw)?
    };
    let _ = fields.insert("metadata".into(), parsed);
    Organization::from_field_values(fields)
}

pub(super) fn permission(value: &SchemaValue<FieldValue>) -> AuthResult<FieldValue> {
    parse_json(&value.field_value())
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract. Fixture indexing must fail when an expected record or property is missing. Assertions report exact contract mismatches while Result propagates fixture errors."
)]
mod tests {
    use super::*;
    use better_auth_core::Utf16String;
    use serde_json::{Value, json};

    fn parsed_metadata(value: FieldValue, create: bool) -> AuthResult<FieldValue> {
        let organization = Organization::from_field_values([("metadata".into(), value)].into())?;
        Ok(metadata(organization, create)?.metadata.field_value())
    }

    #[test]
    fn metadata_dates_follow_the_upstream_component_parser() -> AuthResult<()> {
        let parsed = parsed_metadata(
            r#"{"fraction":"2026-01-02T03:04:05.1234Z","overflow":"2026-02-30T25:00:00+02:00","year":"0099-01-01T00:00:00Z","untouched":"2026-01-02T03:04:05.12345678Z"}"#.into(),
            false,
        )?;
        let fields = parsed.as_object().unwrap().snapshot_fields()?;
        assert!(fields["fraction"].as_date().is_some());
        assert!(fields["overflow"].as_date().is_some());
        assert!(fields["year"].as_date().is_some());
        assert!(fields["untouched"].as_str().is_some());
        assert_eq!(
            parsed.json()?,
            Some(
                json!({"fraction":"2026-01-02T03:04:06.234Z","overflow":"2026-03-02T23:00:00.000Z","year":"1999-01-01T00:00:00.000Z","untouched":"2026-01-02T03:04:05.12345678Z"})
            )
        );
        Ok(())
    }

    #[test]
    fn metadata_parser_preserves_nonfinite_values_until_serialization() -> AuthResult<()> {
        for (text, expected) in [
            ("NaN", f64::NAN),
            ("Infinity", f64::INFINITY),
            ("-Infinity", f64::NEG_INFINITY),
        ] {
            let parsed = parsed_metadata(text.into(), false)?;
            let number = parsed.as_f64().unwrap();
            assert!(number == expected || number.is_nan() && expected.is_nan());
            assert_eq!(parsed.json()?, Some(Value::Null));
        }
        Ok(())
    }

    #[test]
    fn metadata_and_permission_preserve_native_json_values_and_errors() -> AuthResult<()> {
        let raw: FieldValue = Utf16String::from_units(vec![34, 0xd800, 34]).into();
        let expected: FieldValue = Utf16String::from_units(vec![0xd800]).into();
        for create in [true, false] {
            assert_eq!(parsed_metadata(raw.clone(), create)?, expected);
            assert_eq!(
                parsed_metadata("1e400".into(), create)?.as_f64(),
                Some(f64::INFINITY),
            );
            let error = parsed_metadata("invalid".into(), create).unwrap_err();
            assert!(!error.is_api_error()?);
        }
        assert_eq!(permission(&SchemaValue::from_field(raw))?, expected);
        assert!(
            !permission(&SchemaValue::from_field("invalid".into()))
                .unwrap_err()
                .is_api_error()?
        );
        Ok(())
    }
}
