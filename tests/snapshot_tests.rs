//! Snapshot tests for endpoint response shapes using the `insta` crate.
//!
//! These tests capture the *structure* of each endpoint's JSON response as a
//! YAML snapshot.  Dynamic values (IDs, timestamps, tokens) are redacted so
//! that snapshots are deterministic across runs.
//!
//! When the response shape changes, `cargo insta review` presents a diff and
//! lets maintainers accept or reject it — replacing dozens of manual
//! `assert!(json["field"].is_string())` lines.
//!
//! ## Comparison with TypeScript better-auth (v1.4.19)
//!
//! Snapshots were validated against the TypeScript reference implementation.
//! The Rust responses are a **superset** of the TS responses: every field
//! returned by TS is present in Rust with the same camelCase name and
//! compatible type.  The following *additional* fields appear because
//! `create_test_auth()` registers plugins (admin, organization, two-factor):
//!
//! - **User object**: `banned`, `banReason`, `banExpires`, `role`,
//!   `twoFactorEnabled`, `username`, `displayUsername` (all nullable/default)
//! - **Session object**: `activeOrganizationId`, `impersonatedBy` (nullable)
//! - **Signin response**: extra `url: ~` field (redirect URL, always null)
//!
//! ### Known implementation gaps vs TypeScript better-auth
//!
//! | Area | TypeScript | Rust | Tracking |
//! |------|-----------|------|----------|
//! | Error responses | `{code, message}` | `{message}` only | Missing `code` field |
//! | `/list-accounts` | Returns account objects with `scopes` | Returns `[]` | Not yet implemented |
//! | `/forget-password` | Empty 200 body | `{status: true}` | Acceptable deviation |
//! | `/delete-user` | Disabled by default | `{message, success}` | TS requires opt-in |

mod compat;

use compat::helpers::*;
use insta::{assert_yaml_snapshot, with_settings};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Redact dynamic values from a JSON response so snapshots are stable.
///
/// Replaces UUIDs, session tokens, ISO-8601 timestamps, and hashed keys
/// with deterministic placeholder strings.
fn redact(value: &Value) -> Value {
    match value {
        Value::String(s) => {
            // UUID v4/v7 pattern
            if is_uuid(s) {
                return Value::String("[uuid]".to_string());
            }
            // Session tokens: session_<base64>
            if s.starts_with("session_") && s.len() > 20 && !s.contains('@') {
                return Value::String("[session_token]".to_string());
            }
            // ISO-8601 timestamps (e.g. 2024-01-01T00:00:00Z or with fractional seconds)
            if is_iso_timestamp(s) {
                return Value::String("[timestamp]".to_string());
            }
            // API key hashes (SHA-256 hex, 64 chars)
            if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
                return Value::String("[sha256_hash]".to_string());
            }
            // API key tokens: ba_<...>
            if s.starts_with("ba_") && s.len() > 10 {
                return Value::String("[api_key_token]".to_string());
            }
            Value::String(s.clone())
        }
        Value::Array(arr) => Value::Array(arr.iter().map(redact).collect()),
        Value::Object(map) => {
            Value::Object(map.iter().map(|(k, v)| (k.clone(), redact(v))).collect())
        }
        other => other.clone(),
    }
}

fn is_uuid(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && parts[0].len() == 8
        && parts[1].len() == 4
        && parts[2].len() == 4
        && parts[3].len() == 4
        && parts[4].len() == 12
        && parts
            .iter()
            .all(|p| p.chars().all(|c| c.is_ascii_hexdigit()))
}

fn is_iso_timestamp(s: &str) -> bool {
    if s.len() < 19 {
        return false;
    }
    s.as_bytes()[4] == b'-'
        && s.as_bytes()[7] == b'-'
        && s.as_bytes()[10] == b'T'
        && s[..4].chars().all(|c| c.is_ascii_digit())
}

// ---------------------------------------------------------------------------
// Snapshot tests
// ---------------------------------------------------------------------------

/// POST /sign-up/email response shape
#[tokio::test]
async fn snapshot_signup_response() {
    let auth = create_test_auth().await;
    let req = post_json(
        "/sign-up/email",
        serde_json::json!({
            "name": "Snapshot User",
            "email": "snap@example.com",
            "password": "password123"
        }),
    );
    let (status, body) = send_request(&auth, req).await;
    assert_eq!(status, 200);

    with_settings!({snapshot_suffix => "signup"}, {
        assert_yaml_snapshot!(redact(&body));
    });
}

/// POST /sign-in/email response shape
#[tokio::test]
async fn snapshot_signin_response() {
    let auth = create_test_auth().await;
    signup_user(
        &auth,
        "signin_snap@example.com",
        "password123",
        "Signin Snap",
    )
    .await;

    let req = post_json(
        "/sign-in/email",
        serde_json::json!({
            "email": "signin_snap@example.com",
            "password": "password123"
        }),
    );
    let (status, body) = send_request(&auth, req).await;
    assert_eq!(status, 200);

    with_settings!({snapshot_suffix => "signin"}, {
        assert_yaml_snapshot!(redact(&body));
    });
}

/// GET /get-session response shape
#[tokio::test]
async fn snapshot_get_session_response() {
    let auth = create_test_auth().await;
    let (token, _) = signup_user(
        &auth,
        "session_snap@example.com",
        "password123",
        "Session Snap",
    )
    .await;

    let (status, body) = send_request(&auth, get_with_auth("/get-session", &token)).await;
    assert_eq!(status, 200);

    with_settings!({snapshot_suffix => "get_session"}, {
        assert_yaml_snapshot!(redact(&body));
    });
}

/// GET /list-sessions response shape
#[tokio::test]
async fn snapshot_list_sessions_response() {
    let auth = create_test_auth().await;
    let (token, _) = signup_user(
        &auth,
        "listsess_snap@example.com",
        "password123",
        "ListSess Snap",
    )
    .await;

    let (status, body) = send_request(&auth, get_with_auth("/list-sessions", &token)).await;
    assert_eq!(status, 200);

    with_settings!({snapshot_suffix => "list_sessions"}, {
        assert_yaml_snapshot!(redact(&body));
    });
}

/// POST /sign-out response shape
#[tokio::test]
async fn snapshot_sign_out_response() {
    let auth = create_test_auth().await;
    let (token, _) = signup_user(
        &auth,
        "signout_snap@example.com",
        "password123",
        "Signout Snap",
    )
    .await;

    let (status, body) = send_request(
        &auth,
        post_json_with_auth("/sign-out", serde_json::json!({}), &token),
    )
    .await;
    assert_eq!(status, 200);

    with_settings!({snapshot_suffix => "sign_out"}, {
        assert_yaml_snapshot!(redact(&body));
    });
}

/// POST /change-password response shape
#[tokio::test]
async fn snapshot_change_password_response() {
    let auth = create_test_auth().await;
    let (token, _) = signup_user(
        &auth,
        "chgpwd_snap@example.com",
        "password123",
        "ChgPwd Snap",
    )
    .await;

    let (status, body) = send_request(
        &auth,
        post_json_with_auth(
            "/change-password",
            serde_json::json!({
                "currentPassword": "password123",
                "newPassword": "newpassword456",
                "revokeOtherSessions": "false"
            }),
            &token,
        ),
    )
    .await;
    assert_eq!(status, 200);

    with_settings!({snapshot_suffix => "change_password"}, {
        assert_yaml_snapshot!(redact(&body));
    });
}

/// POST /update-user response shape
#[tokio::test]
async fn snapshot_update_user_response() {
    let auth = create_test_auth().await;
    let (token, _) = signup_user(
        &auth,
        "updusr_snap@example.com",
        "password123",
        "UpdUsr Snap",
    )
    .await;

    let (status, body) = send_request(
        &auth,
        post_json_with_auth(
            "/update-user",
            serde_json::json!({ "name": "Updated Name" }),
            &token,
        ),
    )
    .await;
    assert_eq!(status, 200);

    with_settings!({snapshot_suffix => "update_user"}, {
        assert_yaml_snapshot!(redact(&body));
    });
}

/// POST /delete-user response shape
#[tokio::test]
async fn snapshot_delete_user_response() {
    let auth = create_test_auth().await;
    let (token, _) = signup_user(
        &auth,
        "delusr_snap@example.com",
        "password123",
        "DelUsr Snap",
    )
    .await;

    let (status, body) = send_request(
        &auth,
        post_json_with_auth("/delete-user", serde_json::json!({}), &token),
    )
    .await;
    assert_eq!(status, 200);

    with_settings!({snapshot_suffix => "delete_user"}, {
        assert_yaml_snapshot!(redact(&body));
    });
}

/// POST /change-email response shape
#[tokio::test]
async fn snapshot_change_email_response() {
    let auth = create_test_auth().await;
    let (token, _) = signup_user(
        &auth,
        "chgemail_snap@example.com",
        "password123",
        "ChgEmail Snap",
    )
    .await;

    let (status, body) = send_request(
        &auth,
        post_json_with_auth(
            "/change-email",
            serde_json::json!({ "newEmail": "newemail_snap@example.com" }),
            &token,
        ),
    )
    .await;
    assert_eq!(status, 200);

    with_settings!({snapshot_suffix => "change_email"}, {
        assert_yaml_snapshot!(redact(&body));
    });
}

/// POST /forget-password response shape
#[tokio::test]
async fn snapshot_forget_password_response() {
    let auth = create_test_auth().await;
    signup_user(
        &auth,
        "forgotpwd_snap@example.com",
        "password123",
        "ForgotPwd Snap",
    )
    .await;

    let (status, body) = send_request(
        &auth,
        post_json(
            "/forget-password",
            serde_json::json!({ "email": "forgotpwd_snap@example.com" }),
        ),
    )
    .await;
    assert_eq!(status, 200);

    with_settings!({snapshot_suffix => "forget_password"}, {
        assert_yaml_snapshot!(redact(&body));
    });
}

/// GET /list-accounts response shape
#[tokio::test]
async fn snapshot_list_accounts_response() {
    let auth = create_test_auth().await;
    let (token, _) = signup_user(
        &auth,
        "listacct_snap@example.com",
        "password123",
        "ListAcct Snap",
    )
    .await;

    let (status, body) = send_request(&auth, get_with_auth("/list-accounts", &token)).await;
    assert_eq!(status, 200);

    with_settings!({snapshot_suffix => "list_accounts"}, {
        assert_yaml_snapshot!(redact(&body));
    });
}

/// GET /ok response shape
#[tokio::test]
async fn snapshot_ok_response() {
    let auth = create_test_auth().await;
    let (status, body) = send_request(&auth, get_request("/ok")).await;
    assert_eq!(status, 200);

    with_settings!({snapshot_suffix => "ok"}, {
        assert_yaml_snapshot!(redact(&body));
    });
}

/// Error response shapes (400, 401, 409)
#[tokio::test]
async fn snapshot_error_responses() {
    let auth = create_test_auth().await;

    // 400: Missing required fields
    let (status_400, body_400) =
        send_request(&auth, post_json("/sign-up/email", serde_json::json!({}))).await;
    assert!(status_400 >= 400);

    with_settings!({snapshot_suffix => "error_400"}, {
        assert_yaml_snapshot!(redact(&body_400));
    });

    // 401: Invalid credentials
    let (status_401, body_401) = send_request(
        &auth,
        post_json(
            "/sign-in/email",
            serde_json::json!({
                "email": "nonexistent@example.com",
                "password": "password123"
            }),
        ),
    )
    .await;
    assert_eq!(status_401, 401);

    with_settings!({snapshot_suffix => "error_401"}, {
        assert_yaml_snapshot!(redact(&body_401));
    });

    // 409: Duplicate email
    signup_user(&auth, "dup_snap@example.com", "password123", "Dup User").await;

    let (status_409, body_409) = send_request(
        &auth,
        post_json(
            "/sign-up/email",
            serde_json::json!({
                "name": "Dup User 2",
                "email": "dup_snap@example.com",
                "password": "password456"
            }),
        ),
    )
    .await;
    assert_eq!(status_409, 409);

    with_settings!({snapshot_suffix => "error_409"}, {
        assert_yaml_snapshot!(redact(&body_409));
    });
}
