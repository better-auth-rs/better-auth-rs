use super::*;
use fixture::Operation;

pub(super) type Observation = (FieldValue, Value);

fn user(row: &UserView) -> AuthResult<Observation> {
    Ok((
        FieldMap::from(row.clone()).into(),
        serde_json::to_value(row)?,
    ))
}

fn account(row: &AccountView) -> AuthResult<Observation> {
    let fields = FieldValue::from(row.internal_fields()?);
    let json = fields
        .json()?
        .ok_or_else(|| AuthError::internal("Expected complete internal Account JSON"))?;
    Ok((fields, json))
}

fn relation<T>(
    rows: &JoinValue<T>,
    observe: impl Fn(&T) -> AuthResult<Observation>,
) -> AuthResult<Observation> {
    match rows {
        JoinValue::One(Some(row)) => observe(row),
        JoinValue::One(None) => Ok((FieldValue::Null, Value::Null)),
        JoinValue::Many(rows) => {
            let (fields, json): (Vec<_>, Vec<_>) = rows
                .iter()
                .map(observe)
                .collect::<AuthResult<Vec<_>>>()?
                .into_iter()
                .unzip();
            Ok((fields.into(), json.into()))
        }
    }
}

pub(super) fn owner(row: Option<AccountOwner>) -> AuthResult<Observation> {
    let Some(row) = row else {
        return Ok((FieldValue::Null, Value::Null));
    };
    let (account, account_json) = account(&row.account)?;
    if matches!(&row.user, JoinValue::One(None)) {
        return Ok((
            FieldMap::from([
                ("kind".into(), "orphaned".into()),
                ("account".into(), account),
            ])
            .into(),
            json!({"kind": "orphaned", "account": account_json}),
        ));
    }
    let (user, user_json) = relation(&row.user, user)?;
    Ok((
        FieldMap::from([
            ("kind".into(), "owned".into()),
            ("user".into(), user),
            ("account".into(), account),
        ])
        .into(),
        json!({"kind": "owned", "user": user_json, "account": account_json}),
    ))
}

pub(super) fn accounts(row: Option<UserAccounts>) -> AuthResult<Observation> {
    let Some(row) = row else {
        return Ok((FieldValue::Null, Value::Null));
    };
    let (user, user_json) = user(&row.user)?;
    let (accounts, accounts_json) = relation(&row.accounts, account)?;
    Ok((
        FieldMap::from([("user".into(), user), ("accounts".into(), accounts)]).into(),
        json!({"user": user_json, "accounts": accounts_json}),
    ))
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "The helper propagates observation errors and compares every captured result field and event."
)]
pub(super) fn assert_result(
    result: AuthResult<Observation>,
    expected: &Operation,
    case: &Case,
) -> AuthResult<()> {
    match result {
        Err(error) => {
            assert!(!expected.returned, "{case:?}: {error:?}");
            let AuthError::Internal(message) = error else {
                return Err(AuthError::internal(format!(
                    "Expected duplicate Account identity error, got {error:?}"
                )));
            };
            let captured = expected
                .error
                .as_ref()
                .ok_or_else(|| AuthError::internal("Missing captured Account identity error"))?;
            assert_eq!(captured.get("message"), Some(&json!(message)), "{case:?}");
            assert_eq!(
                captured.get("name"),
                Some(&json!("BetterAuthError")),
                "{case:?}"
            );
            assert_eq!(
                captured.get("properties"),
                Some(&json!({"name": "BetterAuthError"})),
                "{case:?}"
            );
            assert_eq!(captured.get("keys"), Some(&json!(["name"])), "{case:?}");
        }
        Ok((observed, json)) => {
            assert!(expected.returned, "{case:?}");
            assert_eq!(
                observed,
                values::revive(expected.result.as_ref().unwrap_or(&Value::Null))?,
                "{case:?}: {}",
                expected.operation
            );
            assert_eq!(
                json,
                expected.json.clone().unwrap_or(Value::Null),
                "{case:?}: {}",
                expected.operation
            );
            let key_order = expected.key_order.as_ref().ok_or_else(|| {
                AuthError::internal("Missing captured Account/User property order")
            })?;
            match &observed {
                FieldValue::Null => assert!(key_order.is_empty(), "{case:?}"),
                FieldValue::Object(fields) => {
                    // Core record key order remains a documented gap; compare the internal result boundary without rearranging records.
                    assert_eq!(
                        key_order.first(),
                        Some(&json!({"path": [], "keys": fields.keys().collect::<Vec<_>>()})),
                        "{case:?}"
                    );
                }
                _ => {
                    return Err(AuthError::internal(
                        "Expected an Account/User result object or null",
                    ));
                }
            }
        }
    }
    Ok(())
}
