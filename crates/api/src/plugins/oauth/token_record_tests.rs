#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]

use super::*;
use better_auth_core::{FieldDate, FieldFunction};

#[test]
fn token_record_preserves_presence_order_and_slot_mutation() {
    let mut tokens = OAuthTokenSet::from_fields(FieldMap::from([
        ("extension".into(), 7.0.into()),
        ("idToken".into(), FieldValue::Undefined),
        ("accessToken".into(), FieldValue::Null),
        ("scopes".into(), vec!["openid".into()].into()),
    ]));
    assert!(!tokens.additional_fields.contains_key("accessToken"));
    assert!(!tokens.additional_fields.contains_key("idToken"));
    assert!(tokens.refresh_token.is_undefined());
    assert!(matches!(
        tokens.id_token,
        SchemaValue::Dynamic(FieldValue::Undefined)
    ));
    assert!(tokens.access_token.field_value().is_null());
    let fields = tokens.fields();
    assert_eq!(
        fields.keys().map(String::as_str).collect::<Vec<_>>(),
        ["extension", "idToken", "accessToken", "scopes"]
    );
    assert!(fields.get("idToken").is_some_and(FieldValue::is_undefined));
    tokens.access_token = Some("replacement".to_owned()).into();
    tokens.id_token = SchemaValue::Undefined;
    tokens.field_order.push("refreshToken".into());
    let fields = tokens.fields();
    assert_eq!(fields.get("accessToken"), Some(&"replacement".into()));
    assert!(!fields.contains_key("idToken"));
    assert!(!fields.contains_key("refreshToken"));
    assert_eq!(fields.get("extension"), Some(&7.0.into()));
}

#[test]
fn native_token_handles_survive_request_conversion() {
    let object: FieldValue = FieldMap::from([("claim".into(), true.into())]).into();
    let array: FieldValue = vec!["openid".into(), FieldValue::Null, 3.0.into()].into();
    let date: FieldValue = FieldDate::from_milliseconds(1_700_000_000_000.0).into();
    let fields = FieldMap::from([
        ("accessToken".into(), object.clone()),
        ("refreshToken".into(), 42.0.into()),
        ("accessTokenExpiresAt".into(), date.clone()),
        ("scopes".into(), array.clone()),
        ("raw".into(), object.clone()),
        ("custom".into(), array.clone()),
    ]);
    let tokens = OAuthTokenSet::from_fields(fields);
    let request = OAuthUserInfoRequest::from(tokens.clone());
    for actual in [tokens.fields(), request.fields()] {
        for (name, expected) in [
            ("accessToken", &object),
            ("raw", &object),
            ("scopes", &array),
            ("custom", &array),
            ("accessTokenExpiresAt", &date),
        ] {
            assert!(
                actual
                    .get(name)
                    .is_some_and(|value| value.strict_equals(expected)),
                "{name}"
            );
        }
        assert_eq!(actual.get("refreshToken"), Some(&42.0.into()));
    }
}

#[test]
fn scope_consumers_apply_join_and_trim_at_their_own_boundaries() -> AuthResult<()> {
    let scopes = SchemaValue::Dynamic(vec![" openid ".into(), FieldValue::Null, 7.0.into()].into());
    assert_eq!(
        joined_scopes(&scopes.field_value())?.display_utf16()?,
        " openid ,,7".into()
    );
    assert!(merge_scopes(&"email".into(), &scopes).is_err());
    let scopes =
        SchemaValue::Dynamic(vec![" openid ".into(), "email".into(), "profile".into()].into());
    assert_eq!(
        merge_scopes(&"email, openid".into(), &scopes)?.display_utf16()?,
        "email,openid,profile".into()
    );
    assert!(joined_scopes(&7.0.into()).is_err());
    assert!(joined_scopes(&FieldValue::Null)?.is_undefined());
    Ok(())
}

#[test]
fn callback_metadata_preserves_real_presence_order_and_extension_fields() -> AuthResult<()> {
    let tokens = OAuthTokenSet::from_fields(FieldMap::from([
        ("accessToken".into(), "access".into()),
        ("user".into(), "overridden".into()),
    ]));
    let request = crate::plugins::oauth::handlers::callback_user_request(
        &tokens.fields().into(),
        &FieldValue::Undefined,
        None,
    )?;
    assert!(request.user.field_value().is_undefined());
    assert!(request.fields().contains_key("user"));
    assert!(!request.fields().contains_key("expectedIdTokenNonce"));
    for input in [Some("null"), Some("invalid JSON")] {
        let request = crate::plugins::oauth::handlers::callback_user_request(
            &tokens.fields().into(),
            &input.map(FieldValue::from).unwrap_or_default(),
            None,
        )?;
        assert!(
            request
                .fields()
                .get("user")
                .is_some_and(FieldValue::is_undefined)
        );
    }
    let tokens =
        OAuthTokenSet::from_fields(FieldMap::from([("accessToken".into(), "access".into())]));
    let request = crate::plugins::oauth::handlers::callback_user_request(
        &tokens.fields().into(),
        &r#"{"name":{"firstName":"Ada"},"custom":{"retained":true}}"#.into(),
        Some("nonce"),
    )?;
    let fields = request.fields();
    assert_eq!(
        fields.keys().map(String::as_str).collect::<Vec<_>>(),
        ["accessToken", "expectedIdTokenNonce", "user"]
    );
    assert!(
        request
            .user
            .field_value()
            .model_property("custom")?
            .model_property("retained")?
            .is_truthy()
    );
    assert!(
        fields
            .get("user")
            .is_some_and(|value| value.strict_equals(&request.user.field_value()))
    );
    let existing = OAuthTokenSet::from_fields(FieldMap::from([
        ("user".into(), "old user".into()),
        ("custom".into(), true.into()),
        ("expectedIdTokenNonce".into(), "old nonce".into()),
    ]));
    let request = crate::plugins::oauth::handlers::callback_user_request(
        &existing.fields().into(),
        &"false".into(),
        Some("new nonce"),
    )?;
    assert_eq!(
        request
            .fields()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["user", "custom", "expectedIdTokenNonce"]
    );
    assert_eq!(request.user.field_value(), false.into());
    assert_eq!(
        request.expected_id_token_nonce.field_value(),
        "new nonce".into()
    );
    Ok(())
}

#[test]
fn scope_join_ignores_to_string_and_retains_custom_method_results() -> AuthResult<()> {
    let scopes: FieldValue = vec!["openid".into(), "email".into()].into();
    scopes.set_model_property(
        "toString",
        FieldFunction::contextual(|_, _| {
            Err(AuthError::internal("Scope joining must not call toString"))
        })
        .into(),
    )?;
    assert_eq!(joined_scopes(&scopes)?, "openid,email".into());

    for scopes in [
        scopes,
        FieldMap::new().into(),
        FieldDate::from_milliseconds(0.0).into(),
        FieldFunction::contextual(|_, _| Ok(FieldValue::Undefined)).into(),
    ] {
        let result: FieldValue = FieldMap::from([("native".into(), true.into())]).into();
        let expected_receiver = scopes.clone();
        let expected_result = result.clone();
        scopes.set_model_property(
            "join",
            FieldFunction::contextual(move |receiver, arguments| {
                assert!(receiver.strict_equals(&expected_receiver));
                assert_eq!(arguments, &[FieldValue::from(",")]);
                Ok(expected_result.clone())
            })
            .into(),
        )?;
        let joined = joined_scopes(&scopes);
        scopes.set_model_property("join", FieldValue::Undefined)?;
        assert!(joined?.strict_equals(&result));
    }
    Ok(())
}

#[test]
fn scope_join_rejects_noncallable_array_overrides_and_preserves_original_errors() -> AuthResult<()>
{
    let scopes: FieldValue = vec!["openid".into(), "email".into()].into();
    for method in [FieldValue::Undefined, FieldValue::Null, false.into()] {
        scopes.set_model_property("join", method)?;
        assert!(
            matches!(joined_scopes(&scopes), Err(AuthError::TypeError(message)) if message == "tokens.scopes?.join is not a function")
        );
    }
    let original: FieldValue = FieldMap::from([("message".into(), "join error".into())]).into();
    let error = original.clone();
    scopes.set_model_property(
        "join",
        FieldFunction::contextual(move |_, _| Err(AuthError::from_thrown(error.clone()))).into(),
    )?;
    let result = joined_scopes(&scopes);
    assert!(
        matches!(result, Err(error) if error.raw_value().is_some_and(|value| value.strict_equals(&original)))
    );
    for nullish in [FieldValue::Undefined, FieldValue::Null] {
        assert!(joined_scopes(&nullish)?.is_undefined());
    }
    Ok(())
}
