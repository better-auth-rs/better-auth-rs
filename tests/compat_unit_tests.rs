//! Unit tests for the compatibility framework's internal logic.
//!
//! These are pure (non-async) tests that verify shape comparison, camelCase
//! detection, type-signature extraction, and schema resolution without
//! spinning up an auth instance.

mod compat;

use compat::schema::{extract_success_schema, load_openapi_spec, resolve_object_schema};
use compat::shapes::{check_camel_case_fields, compare_shapes, extract_type_signature};

// ---------------------------------------------------------------------------
// Shape comparison
// ---------------------------------------------------------------------------

#[test]
fn test_compare_shapes_identical() {
    let a = serde_json::json!({"token": "abc", "user": {"id": "1", "email": "a@b.com"}});
    let b = serde_json::json!({"token": "xyz", "user": {"id": "2", "email": "c@d.com"}});
    let diffs = compare_shapes(&a, &b, "", false);
    assert!(
        diffs.is_empty(),
        "Identical shapes should produce no diffs: {:?}",
        diffs
    );
}

#[test]
fn test_compare_shapes_missing_field() {
    let reference = serde_json::json!({"token": "abc", "user": {"id": "1"}});
    let target = serde_json::json!({"user": {"id": "2"}});
    let diffs = compare_shapes(&reference, &target, "", false);
    assert_eq!(diffs.len(), 1, "Should detect one missing field");
    assert!(diffs[0].contains("MISSING"), "Should be a MISSING diff");
}

#[test]
fn test_compare_shapes_type_mismatch() {
    let reference = serde_json::json!({"status": true});
    let target = serde_json::json!({"status": "true"});
    let diffs = compare_shapes(&reference, &target, "", false);
    assert_eq!(diffs.len(), 1, "Should detect one type mismatch");
    assert!(diffs[0].contains("TYPE"), "Should be a TYPE diff");
}

#[test]
fn test_compare_shapes_extra_fields_lenient() {
    let reference = serde_json::json!({"token": "abc"});
    let target = serde_json::json!({"token": "xyz", "extra": "field"});
    let diffs = compare_shapes(&reference, &target, "", false);
    assert!(diffs.is_empty(), "Lenient mode should ignore extra fields");
}

#[test]
fn test_compare_shapes_extra_fields_strict() {
    let reference = serde_json::json!({"token": "abc"});
    let target = serde_json::json!({"token": "xyz", "extra": "field"});
    let diffs = compare_shapes(&reference, &target, "", true);
    assert_eq!(diffs.len(), 1, "Strict mode should detect extra fields");
    assert!(diffs[0].contains("EXTRA"), "Should be an EXTRA diff");
}

#[test]
fn test_compare_shapes_nullable_accepted() {
    let reference = serde_json::json!({"image": "http://example.com/img.png"});
    let target = serde_json::json!({"image": null});
    let diffs = compare_shapes(&reference, &target, "", false);
    assert!(diffs.is_empty(), "Null target should be accepted");
}

// ---------------------------------------------------------------------------
// camelCase
// ---------------------------------------------------------------------------

#[test]
fn test_camel_case_check() {
    let val = serde_json::json!({"userId": "1", "user_name": "Alice", "created_at": "2024-01-01"});
    let violations = check_camel_case_fields(&val, "");
    assert_eq!(violations.len(), 2, "Should detect 2 snake_case fields");
}

// ---------------------------------------------------------------------------
// Type signature extraction
// ---------------------------------------------------------------------------

#[test]
fn test_extract_type_signature() {
    let val = serde_json::json!({"token": "abc", "user": {"id": "1", "verified": true}});
    let sig = extract_type_signature(&val, 0);
    assert!(sig.contains("token: string"), "Should include token type");
    assert!(
        sig.contains("verified: boolean"),
        "Should include verified type"
    );
}

// ---------------------------------------------------------------------------
// Schema resolution
// ---------------------------------------------------------------------------

#[test]
fn test_schema_resolution() {
    let spec = load_openapi_spec();
    let components = spec.components.as_ref().expect("spec must have components");

    // Verify User schema can be resolved
    let user_ref = components.schemas.get("User");
    assert!(user_ref.is_some(), "Should have User schema in components");

    if let Some(obj_or_ref) = user_ref {
        let user = resolve_object_schema(&spec, obj_or_ref);
        assert!(user.is_some(), "Should resolve User schema");
        let user = user.unwrap();
        assert!(
            user.properties.contains_key("id"),
            "User should have 'id' property"
        );
        assert!(
            user.properties.contains_key("email"),
            "User should have 'email' property"
        );
    }

    // Verify Session schema can be resolved
    let session_ref = components.schemas.get("Session");
    assert!(
        session_ref.is_some(),
        "Should have Session schema in components"
    );
}

#[test]
fn test_success_schema_extraction() {
    let spec = load_openapi_spec();

    // Extract signup success schema
    let schema = extract_success_schema(&spec, "/sign-up/email", "post");
    assert!(
        schema.is_some(),
        "Should extract /sign-up/email success schema"
    );

    let signup_schema = schema.unwrap();
    assert!(
        signup_schema.fields.contains_key("token"),
        "Signup schema should have 'token' field"
    );
    assert!(
        signup_schema.fields.contains_key("user"),
        "Signup schema should have 'user' field"
    );

    // Extract signin success schema
    let schema = extract_success_schema(&spec, "/sign-in/email", "post");
    assert!(
        schema.is_some(),
        "Should extract /sign-in/email success schema"
    );

    let signin_schema = schema.unwrap();
    assert!(
        signin_schema.fields.contains_key("token"),
        "Signin schema should have 'token' field"
    );
    assert!(
        signin_schema.fields.contains_key("redirect"),
        "Signin schema should have 'redirect' field"
    );
    assert!(
        signin_schema.fields.contains_key("user"),
        "Signin schema should have 'user' field"
    );
}
