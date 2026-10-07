use super::*;
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct Anchors {
    pub(super) token: Option<String>,
    pub(super) session_id: Option<String>,
    account_updated_at: Option<i64>,
    pub(super) session_dates: BTreeMap<&'static str, i64>,
}

pub(super) fn hook<'a>(events: &'a [Value], model: &str, phase: &str) -> Option<&'a Value> {
    events
        .iter()
        .find(|event| event["kind"] == "hook" && event["model"] == model && event["phase"] == phase)
        .map(|event| &event["data"])
}

fn text<'a>(record: &'a Value, field: &str) -> TestResult<&'a str> {
    record
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Missing string {field}: {record}").into())
}

fn rows<'a>(snapshot: &'a Value, model: &str) -> TestResult<&'a [Value]> {
    snapshot
        .get(model)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| format!("Missing {model} rows").into())
}

fn millis(value: &Value) -> TestResult<i64> {
    let value = if value.get("type").and_then(Value::as_str) == Some("date") {
        &value["value"]
    } else {
        value
    };
    Ok(value
        .as_str()
        .ok_or("Timestamp must be a Date observation or stored string")?
        .parse::<chrono::DateTime<chrono::Utc>>()?
        .timestamp_millis())
}

pub(super) fn issued_tokens(events: &[Value]) -> TestResult<Vec<String>> {
    events
        .iter()
        .filter(|event| {
            event["kind"] == "hook" && event["model"] == "session" && event["phase"] == "before"
        })
        .map(|event| text(&event["data"], "token").map(str::to_owned))
        .collect()
}

pub(super) fn verify_dynamic(
    events: &[Value],
    after: &Value,
    case: &Case,
    start: i64,
    end: i64,
) -> TestResult<Anchors> {
    let Some(issued) = hook(events, "session", "before") else {
        assert!(rows(after, "session")?.is_empty(), "{case:?}");
        assert_eq!(
            case.response.status, 500,
            "Session issuance must precede a successful response"
        );
        return Ok(Anchors::default());
    };
    let admissions: Vec<_> = events
        .iter()
        .filter(|event| event["kind"] == "admission")
        .collect();
    assert_eq!(admissions.len(), 1, "{case:?}");
    let admission = admissions.first().ok_or("Missing admission")?;
    let selected_id = admission["data"]["user"]
        .get("id")
        .ok_or("Admission must own the selected User ID")?;
    assert_eq!(
        issued.get("userId"),
        Some(selected_id),
        "{case:?}: admission and issuance must preserve own Undefined"
    );

    let mut anchors = account_update_anchors(events, after, case, start..=end)?;
    let updated = anchors
        .account_updated_at
        .ok_or("Missing Account update anchor")?;

    let token = text(issued, "token")?;
    assert_eq!(token.len(), 32);
    assert!(token.bytes().all(|byte| byte.is_ascii_alphanumeric()));
    anchors.token = Some(token.to_owned());
    for name in ["createdAt", "updatedAt", "expiresAt"] {
        let _ = anchors.session_dates.insert(name, millis(&issued[name])?);
    }
    let created = anchors.session_dates["createdAt"];
    let modified = anchors.session_dates["updatedAt"];
    assert!((start..=end).contains(&created));
    assert!((created..=end).contains(&modified));
    assert!(updated <= created);
    assert!((start..=created).contains(&(anchors.session_dates["expiresAt"] - 3_600_000)));

    if case.observations.is_some() {
        assert_eq!(
            after["session"],
            if case.backend == "sqlite" {
                Value::Null
            } else {
                json!([])
            }
        );
        assert_eq!(selected_id, &json!({"type": "undefined"}));
        let completed = hook(events, "session", "after").ok_or("Missing Session after hook")?;
        assert_eq!(completed, issued);
        let id = text(issued, "id")?;
        assert!(!id.is_empty());
        anchors.session_id = Some(id.into());
        return Ok(anchors);
    }

    let sessions = rows(after, "session")?;
    if case.response.status == 500 {
        assert_eq!(case.backend, "sqlite");
        assert!(matches!(
            case.scenario.as_str(),
            "social-owner-many"
                | "social-owner-many-direct-override"
                | "social-owner-many-callback-override"
        ));
        assert_eq!(selected_id, &json!({"type": "undefined"}));
        assert!(sessions.is_empty());
        assert!(hook(events, "session", "after").is_none());
    } else {
        assert_eq!(sessions.len(), 1);
        let stored = sessions.first().ok_or("Missing issued Session")?;
        let completed = hook(events, "session", "after").ok_or("Missing Session after hook")?;
        let id = text(stored, "id")?;
        assert!(!id.is_empty());
        assert_eq!(text(completed, "id")?, id);
        assert_eq!(text(stored, "token")?, token);
        assert_eq!(text(completed, "token")?, token);
        assert_eq!(stored.get("userId"), Some(selected_id));
        assert_eq!(completed.get("userId"), Some(selected_id));
        for name in ["createdAt", "updatedAt", "expiresAt"] {
            assert_eq!(millis(&stored[name])?, anchors.session_dates[name]);
            assert_eq!(millis(&completed[name])?, anchors.session_dates[name]);
        }
        anchors.session_id = Some(id.into());
    }
    Ok(anchors)
}

pub(super) fn account_update_anchors(
    events: &[Value],
    after: &Value,
    case: &Case,
    request_window: std::ops::RangeInclusive<i64>,
) -> TestResult<Anchors> {
    let account = rows(after, "account")?
        .iter()
        .find(|row| row["id"] == "account-a")
        .ok_or("Missing updated Account")?;
    assert_eq!(account["userId"], "user-a");
    let updated = millis(&account["updatedAt"])?;
    assert!(
        request_window.contains(&updated),
        "{case:?}: Account updatedAt {updated} outside {request_window:?}"
    );
    let completed_account =
        hook(events, "account", "after").ok_or("Missing Account update after hook")?;
    assert_eq!(millis(&completed_account["updatedAt"])?, updated);
    Ok(Anchors {
        account_updated_at: Some(updated),
        ..Default::default()
    })
}

fn normalize_record(model: &str, row: &mut Value, anchors: &Anchors) -> TestResult {
    let updated_account =
        model == "account" && row.get("id").and_then(Value::as_str) == Some("account-a");
    let fields = row
        .as_object_mut()
        .ok_or("Expected complete hook or storage record")?;
    for (name, value) in fields {
        let anchor = if model == "session" {
            anchors.session_dates.get(name.as_str()).copied()
        } else if updated_account && name == "updatedAt" {
            anchors.account_updated_at
        } else {
            None
        };
        if let Some(anchor) = anchor {
            assert_eq!(
                millis(value)?,
                anchor,
                "Every normalized timestamp must equal its independently verified anchor"
            );
            let label = format!("<{model}.{name}>");
            if value.get("type").and_then(Value::as_str) == Some("date") {
                value["value"] = json!(label);
            } else {
                *value = json!(label);
            }
        } else if model == "session" && name == "token" {
            assert_eq!(value.as_str(), anchors.token.as_deref());
            *value = json!("<session-token>");
        } else if model == "session" && name == "id" {
            assert_eq!(value.as_str(), anchors.session_id.as_deref());
            *value = json!("<session-id>");
        }
    }
    Ok(())
}

pub(super) fn normalize(events: &mut [Value], after: &mut Value, anchors: &Anchors) -> TestResult {
    for event in events {
        if event["kind"] == "hook" {
            let model = text(event, "model")?.to_owned();
            if matches!(model.as_str(), "account" | "session") {
                normalize_record(&model, &mut event["data"], anchors)?;
            }
        }
    }
    for model in ["account", "session"] {
        if model == "session" && after[model].is_null() {
            continue;
        }
        for row in after[model].as_array_mut().ok_or("Missing stored rows")? {
            normalize_record(model, row, anchors)?;
        }
    }
    Ok(())
}

pub(super) fn assert_events(actual: &[Value], expected: &[Value], case: &Case) -> TestResult {
    let errors: Vec<_> = actual
        .iter()
        .filter(|event| event["kind"] == "api-error")
        .collect();
    if matches!(case.response.status, 200 | 302) {
        assert!(errors.is_empty(), "{case:?}: {errors:?}");
    } else {
        assert_eq!(errors.len(), 1, "{case:?}");
        let native = &errors.first().ok_or("Missing native error")?["native"];
        assert_eq!(native["isApiError"], false, "{case:?}: {native}");
        let message = text(native, "message")?;
        if case.scenario.ends_with("accounts-one") {
            assert_eq!(native["variant"], "internal", "{native}");
            assert_eq!(
                message, "Internal server error: accounts.find is not a function",
                "{case:?}"
            );
        } else {
            assert_eq!(native["variant"], "database", "{native}");
            assert!(
                message.contains("NOT NULL constraint failed: session.userId"),
                "{native}"
            );
        }
        println!(
            "Account/User HTTP native diagnostic ({}/{}/joins={}): {native}",
            case.backend, case.scenario, case.joins
        );
    }
    let paired = |events: &[Value]| {
        events
            .iter()
            .filter(|event| event["kind"] != "console.error")
            .map(|event| {
                if event["kind"] == "api-error" {
                    json!({"kind": "api-error"})
                } else {
                    event.clone()
                }
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        paired(actual),
        paired(expected),
        "{case:?}: complete paired callback and query sequence"
    );
    Ok(())
}

pub(super) fn assert_checked(
    case: &Case,
    scenario: &Scenario,
    anchors: &Anchors,
    events: &[Value],
) {
    if scenario.callback {
        assert_eq!(case.request.method, "GET");
        assert_eq!(
            case.request.url,
            format!(
                "{ORIGIN}/api/auth/callback/google?code=account-user-auth-code&state=<oauth-state>"
            )
        );
        assert_eq!(
            case.checked["userProfileOverrideReached"],
            hook(events, "user", "before").is_some()
        );
        assert_eq!(hook(events, "user", "after"), Some(&Value::Null));
    } else {
        assert_eq!(case.request.method, "POST");
        assert_eq!(
            case.request.url,
            format!("{ORIGIN}/api/auth/sign-in/{}", scenario.route)
        );
        assert!(case.checked.get("userProfileOverrideReached").is_none());
        assert!(hook(events, "user", "before").is_none());
        assert!(hook(events, "user", "after").is_none());
    }
    assert_eq!(
        case.checked["admissionMatchesSessionInput"],
        anchors.token.is_some()
    );
    assert_eq!(
        case.checked["preservedCanonicalAccountOwner"],
        anchors.account_updated_at.is_some()
    );
    assert_eq!(
        case.checked["sessionDatesWithinRequest"],
        !anchors.session_dates.is_empty()
    );
    assert_eq!(
        case.checked["sessionCookieMatchesStoredToken"],
        anchors.session_id.is_some()
    );
}
