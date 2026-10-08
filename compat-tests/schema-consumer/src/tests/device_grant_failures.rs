use super::{TestResult, contract, contract_chrono as chrono};
use better_auth::__private_core::{AuthError, AuthSchema, AuthStore, AuthUser, HttpMethod};
use serde_json::{Map, Value, json};
use std::{future::Future, sync::Arc};

struct Stage {
    failure: Option<contract::Failure>,
    name: &'static str,
    row: &'static str,
    method: HttpMethod,
    path: &'static str,
    body: Option<Value>,
    query: Option<Value>,
    authenticated: bool,
}

fn stages(body: Value) -> [Stage; 4] {
    [
        Stage {
            failure: Some(contract::Failure::AuthorizeRequest),
            name: "issuance",
            row: "issued",
            method: HttpMethod::Post,
            path: "/device/code",
            body: Some(body),
            query: None,
            authenticated: false,
        },
        Stage {
            failure: Some(contract::Failure::GetVerificationContext),
            name: "verification",
            row: "claimed",
            method: HttpMethod::Get,
            path: "/device",
            body: None,
            query: Some(json!({"user_code": contract::USER_CODE})),
            authenticated: true,
        },
        Stage {
            failure: None,
            name: "approval",
            row: "approved",
            method: HttpMethod::Post,
            path: "/device/approve",
            body: Some(json!({"userCode": contract::USER_CODE})),
            query: None,
            authenticated: true,
        },
        Stage {
            failure: Some(contract::Failure::AssertSessionRedemption),
            name: "redemption",
            row: "consumed",
            method: HttpMethod::Post,
            path: "/device/token",
            body: Some(json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": contract::DEVICE_CODE,
                "client_id": "ordinary-grant-client",
            })),
            query: None,
            authenticated: false,
        },
    ]
}

fn visible_device(rows: &Value, owner: &Value) -> TestResult<Value> {
    let mut rows = rows
        .as_array()
        .ok_or("Expected persisted Device rows")?
        .clone();
    for row in &mut rows {
        let row = row
            .as_object_mut()
            .ok_or("Expected a persisted Device object")?;
        assert!(
            row.get("id")
                .and_then(Value::as_str)
                .is_some_and(|id| !id.is_empty())
        );
        assert_eq!(row.get("deviceCode"), Some(&json!(contract::DEVICE_CODE)));
        assert_eq!(row.get("userCode"), Some(&json!(contract::USER_CODE)));
        let expiry = row
            .get("expiresAt")
            .and_then(Value::as_str)
            .ok_or("Expected persisted Device expiration")?
            .parse::<chrono::DateTime<chrono::Utc>>()?;
        assert!(expiry > chrono::Utc::now());
        let user_id = row
            .get("userId")
            .ok_or("Expected the nullable Device owner column")?;
        assert!(user_id.is_null() || user_id == owner);
        if !user_id.is_null() {
            let _ = row.insert("userId".into(), json!("<owner-id>"));
        }
        let _ = row.insert("id".into(), json!("<device-id>"));
        let _ = row.insert("expiresAt".into(), json!("<device-expiry>"));
    }
    Ok(json!(rows))
}

pub(super) async fn check<S, F, Fut>(
    raw: Arc<dyn AuthStore<S>>,
    expected: &Value,
    snapshot: F,
) -> TestResult
where
    S: AuthSchema,
    F: Fn() -> Fut,
    Fut: Future<Output = TestResult<Value>>,
{
    let input: contract::Input = serde_json::from_value(
        expected
            .get("input")
            .ok_or("Expected a Device failure input")?
            .clone(),
    )?;
    let failure = input.failure.ok_or("Expected a Device failure phase")?;
    let contract::Fixture {
        auth,
        owner,
        cookie,
        events,
    } = contract::setup(&input, raw).await?;
    let mut prior = Map::new();
    for stage in stages(input.body.clone()) {
        let cookie = stage.authenticated.then_some(cookie.as_str());
        if stage.failure != Some(failure) {
            let response = contract::call(
                &auth,
                input.transport,
                stage.method,
                stage.path,
                stage.body,
                stage.query,
                cookie,
            )
            .await?;
            assert_eq!(response.status, 200);
            let _ = prior.insert(stage.name.into(), serde_json::to_value(response)?);
            let _ = prior.insert(stage.row.into(), contract::stored(&auth).await?);
            continue;
        }
        let before = snapshot().await?;
        let returned = contract::request(
            &auth,
            input.transport,
            stage.method,
            stage.path,
            stage.body,
            stage.query,
            cookie,
        )
        .await;
        let (response, error) = match returned {
            Ok(response) => {
                assert_eq!(
                    response.status, 500,
                    "The failed callback must reject the endpoint"
                );
                let mut headers: Vec<_> = response
                    .headers
                    .iter()
                    .map(|(key, value)| (key.to_ascii_lowercase(), value.clone()))
                    .collect();
                headers.sort();
                (
                    json!({"status": response.status, "headers": headers,
                    "body": String::from_utf8(response.body.bytes()?.into_owned())?}),
                    Value::Null,
                )
            }
            Err(AuthError::Internal(message)) => {
                assert_eq!(message, format!("ordinary {} failure", failure.phase()));
                (Value::Null, json!({"name": "Error", "message": message}))
            }
            Err(error) => return Err(error.into()),
        };
        let after = snapshot().await?;
        let events: Vec<_> = events.try_iter().collect();
        eprintln!(
            "{}",
            json!({"input": input, "before": before, "after": after,
            "response": response, "error": error, "events": events})
        );
        let mut unchanged = Map::new();
        for table in ["user", "session", "account", "verification"] {
            let original = before.get(table).ok_or("Missing original table snapshot")?;
            let current = after.get(table).ok_or("Missing current table snapshot")?;
            assert_eq!(
                current,
                original,
                "{} must preserve every {table} field",
                failure.phase()
            );
            let _ = unchanged.insert(table.into(), json!(current == original));
        }
        let sessions = before
            .get("session")
            .and_then(Value::as_array)
            .ok_or("Expected persisted sessions")?;
        assert_eq!(
            sessions.len(),
            1,
            "The setup creates exactly one owner session"
        );
        let original = before
            .get("deviceCode")
            .ok_or("Missing original Device rows")?;
        let current = after
            .get("deviceCode")
            .ok_or("Missing current Device rows")?;
        let mut permitted = original.clone();
        let owner_id = owner.id().json()?.ok_or("Missing Device owner ID")?;
        if failure == contract::Failure::GetVerificationContext {
            let rows = permitted
                .as_array_mut()
                .ok_or("Expected original Device rows")?;
            assert_eq!(rows.len(), 1);
            rows[0]["userId"] = owner_id.clone();
        }
        assert_eq!(
            current, &permitted,
            "Only verification ownership may change before the failed callback"
        );
        let phase = json!(failure.phase());
        assert_eq!(
            events
                .iter()
                .filter(|event| event.get("phase") == Some(&phase))
                .count(),
            1
        );
        assert_eq!(
            events.last().and_then(|event| event.get("phase")),
            Some(&phase)
        );
        let session_count = after
            .get("session")
            .and_then(Value::as_array)
            .ok_or("Expected final persisted sessions")?
            .len();
        let observed = json!({"input": input, "prior": prior, "response": response, "error": error,
            "events": events, "before": visible_device(original, &owner_id)?,
            "after": visible_device(current, &owner_id)?, "unchanged": unchanged, "sessionCount": session_count});
        // The upstream fixture uses JSON.stringify, which emits integral numbers without a fractional suffix.
        let observed: Value = serde_json::from_str(
            &better_auth::__private_core::utils::json::stringify(&observed)?,
        )?;
        assert_eq!(
            &observed, expected,
            "Complete Device callback failure observation"
        );
        return Ok(());
    }
    Err("Missing Device failure stage".into())
}
