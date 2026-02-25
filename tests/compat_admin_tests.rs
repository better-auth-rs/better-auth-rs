//! Compatibility tests for Admin plugin endpoints (Phase 1).
//!
//! Endpoints tested:
//! - GET  /admin/list-users
//! - POST /admin/create-user
//! - POST /admin/remove-user
//! - POST /admin/set-user-password
//! - POST /admin/set-role
//! - POST /admin/has-permission

mod compat;

use better_auth::{AuthUser, UserOps};
use compat::helpers::*;
use serde_json::json;

// ---------------------------------------------------------------------------
// Helper: create an admin user and return the admin token
// ---------------------------------------------------------------------------

async fn setup_admin(auth: &better_auth::BetterAuth<better_auth::MemoryDatabaseAdapter>) -> String {
    // Sign up a regular user first
    let (token, _) = signup_user(auth, "admin@test.com", "password123", "Admin User").await;

    // Promote the user to admin using the database directly
    let user = auth
        .database()
        .get_user_by_email("admin@test.com")
        .await
        .unwrap()
        .unwrap();

    use better_auth::types::UpdateUser;
    let update = UpdateUser {
        role: Some("admin".to_string()),
        ..Default::default()
    };
    auth.database()
        .update_user(user.id(), update)
        .await
        .unwrap();

    token
}

// ---------------------------------------------------------------------------
// 1. GET /admin/list-users
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_admin_list_users_returns_users_array() {
    let auth = create_test_auth().await;
    let admin_token = setup_admin(&auth).await;

    // Create a second user so we have at least 2
    signup_user(&auth, "user2@test.com", "password123", "User Two").await;

    let req = get_with_auth("/admin/list-users", &admin_token);
    let (status, json) = send_request(&auth, req).await;

    assert_eq!(status, 200, "list-users should succeed: {}", json);
    assert!(
        json["users"].is_array(),
        "response must contain users array"
    );
    assert!(
        json["total"].is_number(),
        "response must contain total count"
    );
    let users = json["users"].as_array().unwrap();
    assert!(users.len() >= 2, "should have at least 2 users");

    // Verify user shape
    let first = &users[0];
    assert!(first["id"].is_string());
    assert!(first["email"].is_string());
}

#[tokio::test]
async fn test_admin_list_users_pagination() {
    let auth = create_test_auth().await;
    let admin_token = setup_admin(&auth).await;

    // Create extra users
    for i in 0..5 {
        signup_user(
            &auth,
            &format!("page{}@test.com", i),
            "password123",
            &format!("Page User {}", i),
        )
        .await;
    }

    let req = get_with_auth_and_query("/admin/list-users?limit=2&offset=0", &admin_token, vec![]);
    let (status, json) = send_request(&auth, req).await;

    assert_eq!(status, 200);
    let users = json["users"].as_array().unwrap();
    assert_eq!(users.len(), 2, "should return limit=2 users");
    assert!(json["total"].as_u64().unwrap() >= 6, "total should be >= 6");
}

#[tokio::test]
async fn test_admin_list_users_requires_admin() {
    let auth = create_test_auth().await;
    let (regular_token, _) = signup_user(&auth, "regular@test.com", "password123", "Regular").await;

    let req = get_with_auth("/admin/list-users", &regular_token);
    let (status, _json) = send_request(&auth, req).await;

    assert_eq!(status, 403, "non-admin should get 403");
}

// ---------------------------------------------------------------------------
// 2. POST /admin/create-user
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_admin_create_user_success() {
    let auth = create_test_auth().await;
    let admin_token = setup_admin(&auth).await;

    let req = post_json_with_auth(
        "/admin/create-user",
        json!({
            "email": "newuser@test.com",
            "password": "password123",
            "name": "New User",
            "role": "member"
        }),
        &admin_token,
    );
    let (status, json) = send_request(&auth, req).await;

    assert_eq!(status, 200, "create-user should succeed: {}", json);
    assert!(
        json["user"].is_object(),
        "response must contain user object"
    );
    assert_eq!(json["user"]["email"].as_str().unwrap(), "newuser@test.com");
    assert_eq!(json["user"]["name"].as_str().unwrap(), "New User");
}

#[tokio::test]
async fn test_admin_create_user_duplicate_email() {
    let auth = create_test_auth().await;
    let admin_token = setup_admin(&auth).await;

    // The admin already exists with admin@test.com
    let req = post_json_with_auth(
        "/admin/create-user",
        json!({
            "email": "admin@test.com",
            "password": "password123",
            "name": "Duplicate"
        }),
        &admin_token,
    );
    let (status, _json) = send_request(&auth, req).await;

    assert_eq!(status, 409, "duplicate email should get 409 conflict");
}

#[tokio::test]
async fn test_admin_create_user_requires_admin() {
    let auth = create_test_auth().await;
    let (regular_token, _) = signup_user(&auth, "regular@test.com", "password123", "Regular").await;

    let req = post_json_with_auth(
        "/admin/create-user",
        json!({
            "email": "blocked@test.com",
            "password": "password123",
            "name": "Blocked"
        }),
        &regular_token,
    );
    let (status, _json) = send_request(&auth, req).await;

    assert_eq!(status, 403, "non-admin should get 403");
}

// ---------------------------------------------------------------------------
// 3. POST /admin/remove-user
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_admin_remove_user_success() {
    let auth = create_test_auth().await;
    let admin_token = setup_admin(&auth).await;

    // Create a user to remove
    let (_, signup_json) =
        signup_user(&auth, "remove-me@test.com", "password123", "Remove Me").await;
    let user_id = signup_json["user"]["id"].as_str().unwrap();

    let req = post_json_with_auth(
        "/admin/remove-user",
        json!({ "userId": user_id }),
        &admin_token,
    );
    let (status, json) = send_request(&auth, req).await;

    assert_eq!(status, 200, "remove-user should succeed: {}", json);
    assert_eq!(json["success"].as_bool().unwrap(), true);

    // Verify user is actually gone
    let user = auth.database().get_user_by_id(user_id).await.unwrap();
    assert!(user.is_none(), "user should be deleted");
}

#[tokio::test]
async fn test_admin_remove_user_not_found() {
    let auth = create_test_auth().await;
    let admin_token = setup_admin(&auth).await;

    let req = post_json_with_auth(
        "/admin/remove-user",
        json!({ "userId": "nonexistent-id" }),
        &admin_token,
    );
    let (status, _json) = send_request(&auth, req).await;

    assert_eq!(status, 404, "missing user should get 404");
}

// ---------------------------------------------------------------------------
// 4. POST /admin/set-user-password
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_admin_set_user_password_success() {
    let auth = create_test_auth().await;
    let admin_token = setup_admin(&auth).await;

    // Create a target user
    let (_, signup_json) = signup_user(&auth, "target@test.com", "oldpassword1", "Target").await;
    let user_id = signup_json["user"]["id"].as_str().unwrap();

    let req = post_json_with_auth(
        "/admin/set-user-password",
        json!({
            "userId": user_id,
            "newPassword": "newpassword1"
        }),
        &admin_token,
    );
    let (status, json) = send_request(&auth, req).await;

    assert_eq!(status, 200, "set-user-password should succeed: {}", json);
    assert_eq!(json["status"].as_bool().unwrap(), true);

    // Verify the new password works by signing in
    let (_, _signin_json) = signin_user(&auth, "target@test.com", "newpassword1").await;
}

#[tokio::test]
async fn test_admin_set_user_password_user_not_found() {
    let auth = create_test_auth().await;
    let admin_token = setup_admin(&auth).await;

    let req = post_json_with_auth(
        "/admin/set-user-password",
        json!({
            "userId": "nonexistent-id",
            "newPassword": "newpassword1"
        }),
        &admin_token,
    );
    let (status, _json) = send_request(&auth, req).await;

    assert_eq!(status, 404, "missing user should get 404");
}

// ---------------------------------------------------------------------------
// 5. POST /admin/set-role
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_admin_set_role_success() {
    let auth = create_test_auth().await;
    let admin_token = setup_admin(&auth).await;

    // Create a target user
    let (_, signup_json) =
        signup_user(&auth, "role-user@test.com", "password123", "Role User").await;
    let user_id = signup_json["user"]["id"].as_str().unwrap();

    let req = post_json_with_auth(
        "/admin/set-role",
        json!({
            "userId": user_id,
            "role": "moderator"
        }),
        &admin_token,
    );
    let (status, json) = send_request(&auth, req).await;

    assert_eq!(status, 200, "set-role should succeed: {}", json);
    assert!(
        json["user"].is_object(),
        "response must contain user object"
    );
    // Verify the role was updated  (depends on whether User serializes role)
    // The response should have the updated user
}

#[tokio::test]
async fn test_admin_set_role_user_not_found() {
    let auth = create_test_auth().await;
    let admin_token = setup_admin(&auth).await;

    let req = post_json_with_auth(
        "/admin/set-role",
        json!({
            "userId": "nonexistent-id",
            "role": "admin"
        }),
        &admin_token,
    );
    let (status, _json) = send_request(&auth, req).await;

    assert_eq!(status, 404, "missing user should get 404");
}

// ---------------------------------------------------------------------------
// 6. POST /admin/has-permission
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_admin_has_permission_admin_succeeds() {
    let auth = create_test_auth().await;
    let admin_token = setup_admin(&auth).await;

    let req = post_json_with_auth(
        "/admin/has-permission",
        json!({
            "permissions": {
                "user": ["create", "delete"]
            }
        }),
        &admin_token,
    );
    let (status, json) = send_request(&auth, req).await;

    assert_eq!(status, 200, "has-permission should succeed: {}", json);
    assert_eq!(json["success"].as_bool().unwrap(), true);
}

#[tokio::test]
async fn test_admin_has_permission_requires_admin() {
    let auth = create_test_auth().await;
    let (regular_token, _) = signup_user(&auth, "regular@test.com", "password123", "Regular").await;

    let req = post_json_with_auth(
        "/admin/has-permission",
        json!({
            "permissions": {
                "user": ["create"]
            }
        }),
        &regular_token,
    );
    let (status, _json) = send_request(&auth, req).await;

    assert_eq!(status, 403, "non-admin should get 403");
}

// ---------------------------------------------------------------------------
// Auth requirement tests (unauthenticated)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_admin_endpoints_require_authentication() {
    let auth = create_test_auth().await;

    // list-users without auth
    let req = get_request("/admin/list-users");
    let (status, _) = send_request(&auth, req).await;
    assert_eq!(status, 401, "list-users without auth should get 401");

    // create-user without auth
    let req = post_json(
        "/admin/create-user",
        json!({
            "email": "no-auth@test.com",
            "password": "password123",
            "name": "No Auth"
        }),
    );
    let (status, _) = send_request(&auth, req).await;
    assert_eq!(status, 401, "create-user without auth should get 401");

    // remove-user without auth
    let req = post_json("/admin/remove-user", json!({ "userId": "some-id" }));
    let (status, _) = send_request(&auth, req).await;
    assert_eq!(status, 401, "remove-user without auth should get 401");

    // set-user-password without auth
    let req = post_json(
        "/admin/set-user-password",
        json!({ "userId": "some-id", "newPassword": "new" }),
    );
    let (status, _) = send_request(&auth, req).await;
    assert_eq!(status, 401, "set-user-password without auth should get 401");

    // set-role without auth
    let req = post_json(
        "/admin/set-role",
        json!({ "userId": "some-id", "role": "admin" }),
    );
    let (status, _) = send_request(&auth, req).await;
    assert_eq!(status, 401, "set-role without auth should get 401");

    // has-permission without auth
    let req = post_json(
        "/admin/has-permission",
        json!({ "permissions": { "user": ["read"] } }),
    );
    let (status, _) = send_request(&auth, req).await;
    assert_eq!(status, 401, "has-permission without auth should get 401");
}
