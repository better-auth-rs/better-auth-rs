use super::*;
use fixture::Operation;

fn error_field<'a>(error: &'a Value, name: &str) -> AuthResult<&'a Value> {
    error
        .get(name)
        .ok_or_else(|| AuthError::internal(format!("Missing captured error field: {name}")))
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "The test helper propagates observation errors and asserts the complete captured error contract."
)]
fn assert_error(error: AuthError, expected: &Value) -> AuthResult<()> {
    match error_field(expected, "name")?.as_str() {
        Some("BetterAuthError") => {
            assert!(matches!(error, AuthError::Config(_)), "{error:?}");
            assert_eq!(
                Value::String(error.instrumentation_message()),
                *error_field(expected, "message")?
            );
            assert_eq!(
                error_field(expected, "sameCallbackError")?,
                &Value::Bool(false)
            );
        }
        Some("TypeError") => {
            assert!(
                matches!(&error, AuthError::Internal(message) if message == "User not found for member"),
                "{error:?}"
            );
            assert_eq!(
                error_field(expected, "sameCallbackError")?,
                &Value::Bool(false)
            );
        }
        Some("APIError") => {
            assert!(matches!(error, AuthError::Response(_)), "{error:?}");
            let response = error.to_auth_response();
            let properties = error_field(expected, "properties")?;
            assert_eq!(
                json!(response.status),
                *error_field(properties, "statusCode")?
            );
            assert_eq!(
                response
                    .headers
                    .get("x-member-join-callback")
                    .map(String::as_str),
                Some("original")
            );
            let body: Value = serde_json::from_slice(&response.body.bytes()?)?;
            assert_eq!(body, *error_field(properties, "body")?);
            assert_eq!(body.get("message"), Some(error_field(expected, "message")?));
            assert_eq!(
                error_field(expected, "sameCallbackError")?,
                &Value::Bool(true)
            );
        }
        name => {
            return Err(AuthError::internal(format!(
                "Unknown captured error class: {name:?}"
            )));
        }
    }
    Ok(())
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "The test helper propagates decoding errors and asserts complete results, JSON output, and property order."
)]
pub(super) fn assert_result(
    result: AuthResult<Option<MemberUser>>,
    expected: &Operation,
    case: &Case,
) -> AuthResult<()> {
    match result {
        Err(error) => {
            assert!(!expected.returned, "{case:?}: {error:?}");
            assert_error(
                error,
                expected
                    .error
                    .as_ref()
                    .ok_or_else(|| AuthError::internal("Missing captured join error"))?,
            )?;
        }
        Ok(result) => {
            assert!(expected.returned, "{case:?}");
            let (observed, json) = if let Some(row) = result {
                let user = row.user.field_values()?;
                let mut member = row.member.field_values()?;
                let _ = member.insert("user".into(), FieldValue::from(user.clone()));
                let observed = FieldValue::from(member);
                let mut json = serde_json::to_value(&row.member)?;
                let fields = json
                    .as_object_mut()
                    .ok_or_else(|| AuthError::internal("Expected serialized member object"))?;
                let _ = fields.insert("user".into(), serde_json::to_value(&row.user)?);
                let key_order = expected
                    .key_order
                    .as_ref()
                    .ok_or_else(|| AuthError::internal("Missing captured property order"))?;
                let expected_user_order = key_order
                    .iter()
                    .find(|entry| entry.get("path") == Some(&json!(["user"])))
                    .and_then(|entry| entry.get("keys"))
                    .ok_or_else(|| AuthError::internal("Missing captured summary keys"))?;
                assert_eq!(
                    json!(user.keys().collect::<Vec<_>>()),
                    *expected_user_order,
                    "{case:?}"
                );
                (observed, json)
            } else {
                assert_eq!(
                    expected.key_order.as_deref(),
                    Some([].as_slice()),
                    "{case:?}"
                );
                (FieldValue::Null, Value::Null)
            };
            assert_eq!(
                observed,
                values::revive(expected.result.as_ref().unwrap_or(&Value::Null))?,
                "{case:?}: {}",
                expected.path
            );
            assert_eq!(
                json,
                expected.json.clone().unwrap_or(Value::Null),
                "{case:?}: {}",
                expected.path
            );
        }
    }
    Ok(())
}
