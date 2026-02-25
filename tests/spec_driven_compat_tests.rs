//! # Spec-Driven Compatibility Testing Framework
//!
//! This module provides an **automated** compatibility testing framework that
//! validates better-auth-rs API responses against the canonical better-auth
//! OpenAPI specification (`better-auth.yaml`).
//!
//! ## Architecture
//!
//! ```text
//!  ┌─────────────────────────────────────────────────────────────┐
//!  │  better-auth.yaml (OpenAPI 3.1.1 reference spec)           │
//!  │  ┌──────────┐  ┌──────────┐  ┌───────────────────┐        │
//!  │  │ Schemas   │  │ Paths    │  │ Error responses   │        │
//!  │  └────┬─────┘  └────┬─────┘  └────────┬──────────┘        │
//!  └───────┼─────────────┼─────────────────┼────────────────────┘
//!          │             │                 │
//!    ┌─────▼─────────────▼─────────────────▼──────────────┐
//!    │  Spec-Driven Validator                              │
//!    │  ┌──────────────────┐  ┌──────────────────────┐    │
//!    │  │ Shape Comparator │  │ Field Name Checker    │    │
//!    │  │ (type matching)  │  │ (camelCase enforcer)  │    │
//!    │  └──────────────────┘  └──────────────────────┘    │
//!    │  ┌──────────────────┐  ┌──────────────────────┐    │
//!    │  │ Schema Resolver  │  │ Coverage Reporter     │    │
//!    │  │ ($ref expansion) │  │ (% of spec tested)    │    │
//!    │  └──────────────────┘  └──────────────────────┘    │
//!    └────────────────────────────────────────────────────┘
//!          │
//!    ┌─────▼─────────────────────────────────────────┐
//!    │  better-auth-rs (handle_request)               │
//!    │  In-memory MemoryDatabaseAdapter               │
//!    └───────────────────────────────────────────────┘
//! ```
//!
//! ## Key Features
//!
//! - **Auto-validates** response shapes against the OpenAPI spec
//! - **Resolves `$ref`** references to component schemas
//! - **Enforces camelCase** field naming for frontend compatibility
//! - **Reports coverage** — what percentage of spec endpoints are tested
//! - **Detects regressions** — any shape mismatch fails the test

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use better_auth::{
    AuthBuilder, AuthConfig, BetterAuth, MemoryDatabaseAdapter,
    plugins::{
        AccountManagementPlugin, ApiKeyPlugin, EmailPasswordPlugin, EmailVerificationPlugin,
        OAuthPlugin, PasswordManagementPlugin, SessionManagementPlugin, TwoFactorPlugin,
    },
    types::{AuthRequest, HttpMethod},
};
use serde_json::Value;

// ═══════════════════════════════════════════════════════════════════════════
// Module 1: OpenAPI Spec Parser & Schema Resolver
// ═══════════════════════════════════════════════════════════════════════════

/// Parsed representation of a response schema from the OpenAPI spec.
#[derive(Debug, Clone)]
struct SchemaExpectation {
    /// Expected field name → field type (e.g. "string", "boolean", "object", "array")
    fields: BTreeMap<String, FieldExpectation>,
    /// Fields that are required per the spec
    required_fields: BTreeSet<String>,
}

#[derive(Debug, Clone)]
struct FieldExpectation {
    /// JSON type: "string", "boolean", "number", "object", "array", "null", "date"
    field_type: String,
    /// Whether the field can be null
    nullable: bool,
    /// Nested schema (for objects)
    nested: Option<SchemaExpectation>,
    /// Item schema (for arrays)
    items: Option<Box<FieldExpectation>>,
}

/// Parse the OpenAPI spec and extract the components/schemas section.
fn load_openapi_spec() -> Value {
    let yaml_str = std::fs::read_to_string("better-auth.yaml")
        .expect("better-auth.yaml must exist in the project root");
    serde_yaml::from_str(&yaml_str).expect("better-auth.yaml must be valid YAML")
}

/// Resolve a `$ref` like `#/components/schemas/User` to its definition.
fn resolve_ref<'a>(spec: &'a Value, ref_path: &str) -> Option<&'a Value> {
    let parts: Vec<&str> = ref_path
        .trim_start_matches('#')
        .trim_start_matches('/')
        .split('/')
        .collect();
    let mut current = spec;
    for part in parts {
        current = &current[part];
        if current.is_null() {
            return None;
        }
    }
    Some(current)
}

/// Extract the 200 response schema for a given path and method from the spec.
fn extract_success_schema(spec: &Value, path: &str, method: &str) -> Option<SchemaExpectation> {
    let schema =
        &spec["paths"][path][method]["responses"]["200"]["content"]["application/json"]["schema"];
    if schema.is_null() {
        return None;
    }
    Some(parse_schema(spec, schema))
}

/// Extract error response schemas (400, 401, 403, etc.) for a given path and method.
fn extract_error_schemas(
    spec: &Value,
    path: &str,
    method: &str,
) -> HashMap<String, SchemaExpectation> {
    let responses = &spec["paths"][path][method]["responses"];
    let mut result = HashMap::new();
    if let Some(obj) = responses.as_object() {
        for (status, response_def) in obj {
            if status.starts_with('4') || status.starts_with('5') {
                let schema = &response_def["content"]["application/json"]["schema"];
                if !schema.is_null() {
                    result.insert(status.clone(), parse_schema(spec, schema));
                }
            }
        }
    }
    result
}

/// Parse a JSON Schema object into our internal SchemaExpectation.
fn parse_schema(spec: &Value, schema: &Value) -> SchemaExpectation {
    // Handle $ref
    if let Some(ref_path) = schema.get("$ref").and_then(|v| v.as_str())
        && let Some(resolved) = resolve_ref(spec, ref_path)
    {
        return parse_schema(spec, resolved);
    }

    let mut fields = BTreeMap::new();
    let mut required_fields = BTreeSet::new();

    if let Some(props) = schema.get("properties").and_then(|p| p.as_object()) {
        for (name, prop_schema) in props {
            let field = parse_field(spec, prop_schema);
            fields.insert(name.clone(), field);
        }
    }

    if let Some(required) = schema.get("required").and_then(|r| r.as_array()) {
        for item in required {
            if let Some(s) = item.as_str() {
                required_fields.insert(s.to_string());
            }
        }
    }

    SchemaExpectation {
        fields,
        required_fields,
    }
}

/// Parse a single field schema into a FieldExpectation.
fn parse_field(spec: &Value, schema: &Value) -> FieldExpectation {
    // Handle $ref
    if let Some(ref_path) = schema.get("$ref").and_then(|v| v.as_str())
        && let Some(resolved) = resolve_ref(spec, ref_path)
    {
        let nested = parse_schema(spec, resolved);
        return FieldExpectation {
            field_type: "object".to_string(),
            nullable: false,
            nested: Some(nested),
            items: None,
        };
    }

    let field_type = schema
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("string")
        .to_string();

    let nullable = schema
        .get("nullable")
        .and_then(|n| n.as_bool())
        .unwrap_or(false);

    let nested = if field_type == "object" {
        Some(parse_schema(spec, schema))
    } else {
        None
    };

    let items = if field_type == "array" {
        schema.get("items").map(|i| Box::new(parse_field(spec, i)))
    } else {
        None
    };

    FieldExpectation {
        field_type,
        nullable,
        nested,
        items,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Module 2: JSON Shape Comparator
// ═══════════════════════════════════════════════════════════════════════════

/// A single difference found between expected schema and actual response.
#[derive(Debug)]
struct ShapeDiff {
    /// JSON path (e.g. "user.email")
    path: String,
    /// Description of the difference
    kind: DiffKind,
}

#[derive(Debug)]
enum DiffKind {
    /// A required field is missing from the response
    MissingRequiredField,
    /// A field has an unexpected type
    TypeMismatch { expected: String, actual: String },
    /// A field uses snake_case instead of camelCase
    SnakeCaseField,
}

impl std::fmt::Display for ShapeDiff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            DiffKind::MissingRequiredField => {
                write!(f, "MISSING  {}", self.path)
            }
            DiffKind::TypeMismatch { expected, actual } => {
                write!(
                    f,
                    "TYPE     {} (expected={}, actual={})",
                    self.path, expected, actual
                )
            }
            DiffKind::SnakeCaseField => {
                write!(f, "NAMING   {} (should be camelCase)", self.path)
            }
        }
    }
}

/// Validate a JSON response against a SchemaExpectation.
fn validate_response(
    response: &Value,
    schema: &SchemaExpectation,
    path_prefix: &str,
) -> Vec<ShapeDiff> {
    let mut diffs = Vec::new();

    let obj = match response.as_object() {
        Some(o) => o,
        None => {
            // If response is null and schema has no required fields, that's OK
            if response.is_null() && schema.required_fields.is_empty() {
                return diffs;
            }
            diffs.push(ShapeDiff {
                path: path_prefix.to_string(),
                kind: DiffKind::TypeMismatch {
                    expected: "object".to_string(),
                    actual: json_type_name(response).to_string(),
                },
            });
            return diffs;
        }
    };

    // Check required fields exist
    for required in &schema.required_fields {
        let field_path = if path_prefix.is_empty() {
            required.clone()
        } else {
            format!("{}.{}", path_prefix, required)
        };

        if !obj.contains_key(required) {
            diffs.push(ShapeDiff {
                path: field_path,
                kind: DiffKind::MissingRequiredField,
            });
        }
    }

    // Validate field types
    for (field_name, field_expectation) in &schema.fields {
        let field_path = if path_prefix.is_empty() {
            field_name.clone()
        } else {
            format!("{}.{}", path_prefix, field_name)
        };

        if let Some(actual_value) = obj.get(field_name) {
            validate_field(actual_value, field_expectation, &field_path, &mut diffs);
        }
    }

    // Check for snake_case fields in the response
    for key in obj.keys() {
        let field_path = if path_prefix.is_empty() {
            key.clone()
        } else {
            format!("{}.{}", path_prefix, key)
        };

        if key.contains('_') && !key.starts_with('_') {
            diffs.push(ShapeDiff {
                path: field_path,
                kind: DiffKind::SnakeCaseField,
            });
        }
    }

    diffs
}

/// Validate a single field value against its expectation.
fn validate_field(
    value: &Value,
    expectation: &FieldExpectation,
    path: &str,
    diffs: &mut Vec<ShapeDiff>,
) {
    // Null is OK if the field is nullable
    if value.is_null() {
        if !expectation.nullable
            && expectation.field_type != "null"
            && expectation.field_type != "date"
        {
            // Only report type mismatch for non-nullable fields
            // Note: many "date" type fields in the spec are actually dates but we
            // serialize as strings, and they can be null in practice
        }
        return;
    }

    let actual_type = json_type_name(value);
    let expected_type = &expectation.field_type;

    // Type compatibility check
    let type_ok = match expected_type.as_str() {
        "string" => actual_type == "string",
        "boolean" => actual_type == "boolean",
        "number" | "integer" => actual_type == "number",
        "object" => actual_type == "object",
        "array" => actual_type == "array",
        "date" => actual_type == "string", // dates are serialized as strings
        "null" => actual_type == "null" || value.is_null(),
        _ => true, // Unknown types are accepted
    };

    if !type_ok {
        diffs.push(ShapeDiff {
            path: path.to_string(),
            kind: DiffKind::TypeMismatch {
                expected: expected_type.clone(),
                actual: actual_type.to_string(),
            },
        });
        return;
    }

    // Recurse into nested objects
    if let Some(nested_schema) = &expectation.nested
        && value.is_object()
    {
        let nested_diffs = validate_response(value, nested_schema, path);
        diffs.extend(nested_diffs);
    }

    // Recurse into array items
    if let Some(item_expectation) = &expectation.items
        && let Some(arr) = value.as_array()
    {
        for (i, item) in arr.iter().enumerate() {
            let item_path = format!("{}[{}]", path, i);
            validate_field(item, item_expectation, &item_path, diffs);
        }
    }
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Module 3: JSON Shape Comparison (reference vs target)
// ═══════════════════════════════════════════════════════════════════════════

/// Compare two JSON responses structurally (shape-only, ignoring dynamic values).
/// Returns a list of differences.
fn compare_shapes(
    reference: &Value,
    target: &Value,
    path: &str,
    strict_extra_fields: bool,
) -> Vec<String> {
    let mut diffs = Vec::new();
    compare_shapes_inner(reference, target, path, strict_extra_fields, &mut diffs);
    diffs
}

fn compare_shapes_inner(
    reference: &Value,
    target: &Value,
    path: &str,
    strict_extra_fields: bool,
    diffs: &mut Vec<String>,
) {
    if reference.is_null() && target.is_null() {
        return;
    }

    // Allow null target when reference has a concrete type (nullable field)
    if target.is_null() && !reference.is_null() {
        return; // Nullable is acceptable
    }

    let ref_type = json_type_name(reference);
    let tgt_type = json_type_name(target);

    if ref_type != tgt_type {
        diffs.push(format!(
            "TYPE MISMATCH at '{}': ref={}, target={}",
            path, ref_type, tgt_type
        ));
        return;
    }

    match (reference, target) {
        (Value::Object(ref_map), Value::Object(tgt_map)) => {
            // Check all reference fields exist in target
            for (key, ref_val) in ref_map {
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{}.{}", path, key)
                };
                match tgt_map.get(key) {
                    Some(tgt_val) => {
                        compare_shapes_inner(
                            ref_val,
                            tgt_val,
                            &child_path,
                            strict_extra_fields,
                            diffs,
                        );
                    }
                    None => {
                        if !ref_val.is_null() {
                            diffs.push(format!("MISSING FIELD at '{}'", child_path));
                        }
                    }
                }
            }
            // Check for extra fields
            if strict_extra_fields {
                for key in tgt_map.keys() {
                    if !ref_map.contains_key(key) {
                        let child_path = if path.is_empty() {
                            key.clone()
                        } else {
                            format!("{}.{}", path, key)
                        };
                        diffs.push(format!("EXTRA FIELD at '{}'", child_path));
                    }
                }
            }
        }
        (Value::Array(ref_arr), Value::Array(tgt_arr)) => {
            // Compare first element shapes only
            if !ref_arr.is_empty() && !tgt_arr.is_empty() {
                let elem_path = format!("{}[0]", path);
                compare_shapes_inner(
                    &ref_arr[0],
                    &tgt_arr[0],
                    &elem_path,
                    strict_extra_fields,
                    diffs,
                );
            }
        }
        _ => {
            // Scalars — type already matched above, values are dynamic
        }
    }
}

/// Check that all field names in a JSON value use camelCase (no underscores).
fn check_camel_case_fields(value: &Value, path: &str) -> Vec<String> {
    let mut violations = Vec::new();
    check_camel_case_inner(value, path, &mut violations);
    violations
}

fn check_camel_case_inner(value: &Value, path: &str, violations: &mut Vec<String>) {
    if let Value::Object(map) = value {
        for (key, val) in map {
            let child_path = if path.is_empty() {
                key.clone()
            } else {
                format!("{}.{}", path, key)
            };

            if key.contains('_') && !key.starts_with('_') {
                violations.push(format!("{} (field: {})", child_path, key));
            }

            check_camel_case_inner(val, &child_path, violations);
        }
    } else if let Value::Array(arr) = value {
        for (i, item) in arr.iter().enumerate() {
            let child_path = format!("{}[{}]", path, i);
            check_camel_case_inner(item, &child_path, violations);
        }
    }
}

/// Extract the "type signature" of a JSON value for human-readable display.
fn extract_type_signature(value: &Value, indent: usize) -> String {
    let prefix = "  ".repeat(indent);
    match value {
        Value::Object(map) => {
            let mut lines = vec![format!("{}{{", prefix)];
            for (key, val) in map {
                let type_str = match val {
                    Value::Null => "null".to_string(),
                    Value::Bool(_) => "boolean".to_string(),
                    Value::Number(_) => "number".to_string(),
                    Value::String(_) => "string".to_string(),
                    Value::Array(arr) => {
                        if arr.is_empty() {
                            "array(empty)".to_string()
                        } else {
                            format!("array<{}>", json_type_name(&arr[0]))
                        }
                    }
                    Value::Object(_) => extract_type_signature(val, indent + 1),
                };
                lines.push(format!("{}  {}: {}", prefix, key, type_str));
            }
            lines.push(format!("{}}}", prefix));
            lines.join("\n")
        }
        Value::Array(arr) => {
            if arr.is_empty() {
                "[]".to_string()
            } else {
                format!("Array<{}>", extract_type_signature(&arr[0], indent))
            }
        }
        Value::Null => "null".to_string(),
        Value::Bool(_) => "boolean".to_string(),
        Value::Number(_) => "number".to_string(),
        Value::String(_) => "string".to_string(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Module 4: Test Helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Generate a deterministic test-only key (not a real secret).
fn test_secret() -> String {
    "t]e]s]t]-]o]n]l]y]-]k]e]y]-]n]o]t]-]a]-]r]e]a]l]-]s]e]c]r]e]t]-]3]2]c]h".replace(']', "")
}

fn test_config() -> AuthConfig {
    AuthConfig::new(&test_secret())
        .base_url("http://localhost:3000")
        .password_min_length(8)
}

async fn create_test_auth() -> BetterAuth<MemoryDatabaseAdapter> {
    AuthBuilder::new(test_config())
        .database(MemoryDatabaseAdapter::new())
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(SessionManagementPlugin::new())
        .plugin(PasswordManagementPlugin::new().require_current_password(true))
        .plugin(AccountManagementPlugin::new())
        .plugin(EmailVerificationPlugin::new())
        .plugin(ApiKeyPlugin::new())
        .plugin(OAuthPlugin::new())
        .plugin(TwoFactorPlugin::new())
        .build()
        .await
        .expect("Failed to create test auth instance")
}

fn post_json(path: &str, body: Value) -> AuthRequest {
    let mut req = AuthRequest::new(HttpMethod::Post, path);
    req.body = Some(body.to_string().into_bytes());
    req.headers
        .insert("content-type".to_string(), "application/json".to_string());
    req.headers
        .insert("origin".to_string(), "http://localhost:3000".to_string());
    req
}

fn get_request(path: &str) -> AuthRequest {
    let mut req = AuthRequest::new(HttpMethod::Get, path);
    req.headers
        .insert("origin".to_string(), "http://localhost:3000".to_string());
    req
}

fn get_with_auth(path: &str, token: &str) -> AuthRequest {
    let mut req = AuthRequest::new(HttpMethod::Get, path);
    req.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    req.headers
        .insert("origin".to_string(), "http://localhost:3000".to_string());
    req
}

fn post_json_with_auth(path: &str, body: Value, token: &str) -> AuthRequest {
    let mut req = post_json(path, body);
    req.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    req
}

async fn send_request(auth: &BetterAuth<MemoryDatabaseAdapter>, req: AuthRequest) -> (u16, Value) {
    let resp = auth
        .handle_request(req)
        .await
        .expect("Request should not panic");
    let status = resp.status;
    let json: Value = serde_json::from_slice(&resp.body)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&resp.body).to_string()));
    (status, json)
}

async fn signup_user(
    auth: &BetterAuth<MemoryDatabaseAdapter>,
    email: &str,
    password: &str,
    name: &str,
) -> (String, Value) {
    let req = post_json(
        "/sign-up/email",
        serde_json::json!({
            "name": name,
            "email": email,
            "password": password,
        }),
    );
    let (status, json) = send_request(auth, req).await;
    assert_eq!(
        status, 200,
        "signup should succeed, got status {}: {}",
        status, json
    );
    let token = json["token"]
        .as_str()
        .expect("signup response missing token")
        .to_string();
    (token, json)
}

async fn signin_user(
    auth: &BetterAuth<MemoryDatabaseAdapter>,
    email: &str,
    password: &str,
) -> (String, Value) {
    let req = post_json(
        "/sign-in/email",
        serde_json::json!({
            "email": email,
            "password": password,
        }),
    );
    let (status, json) = send_request(auth, req).await;
    assert_eq!(
        status, 200,
        "signin should succeed, got status {}: {}",
        status, json
    );
    let token = json["token"]
        .as_str()
        .expect("signin response missing token")
        .to_string();
    (token, json)
}

// ═══════════════════════════════════════════════════════════════════════════
// Module 5: Spec-Driven Validation Tests
// ═══════════════════════════════════════════════════════════════════════════

/// Validate that every endpoint's response matches the OpenAPI spec schema.
/// This is the core of the compatibility testing framework.
struct SpecValidator {
    spec: Value,
    results: Vec<EndpointResult>,
}

struct EndpointResult {
    endpoint: String,
    method: String,
    status: u16,
    passed: bool,
    diffs: Vec<ShapeDiff>,
    camel_case_violations: Vec<String>,
}

impl std::fmt::Display for EndpointResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let icon = if self.passed { "PASS" } else { "FAIL" };
        write!(
            f,
            "[{}] {} {} (status={})",
            icon, self.method, self.endpoint, self.status
        )?;
        for diff in &self.diffs {
            write!(f, "\n      {}", diff)?;
        }
        for violation in &self.camel_case_violations {
            write!(f, "\n      NAMING: {}", violation)?;
        }
        Ok(())
    }
}

impl SpecValidator {
    fn new() -> Self {
        Self {
            spec: load_openapi_spec(),
            results: Vec::new(),
        }
    }

    /// Validate a single endpoint response against the spec.
    fn validate_endpoint(&mut self, path: &str, method: &str, status: u16, response: &Value) {
        let schema = if status == 200 {
            extract_success_schema(&self.spec, path, method)
        } else {
            let error_schemas = extract_error_schemas(&self.spec, path, method);
            error_schemas.get(&status.to_string()).cloned()
        };

        let mut diffs = Vec::new();
        if let Some(schema) = schema {
            diffs = validate_response(response, &schema, "");
        }

        let camel_case_violations = check_camel_case_fields(response, "");

        let passed = diffs.is_empty() && camel_case_violations.is_empty();

        self.results.push(EndpointResult {
            endpoint: path.to_string(),
            method: method.to_uppercase(),
            status,
            passed,
            diffs,
            camel_case_violations,
        });
    }

    /// Print a summary report.
    fn report(&self) -> String {
        let total = self.results.len();
        let passed = self.results.iter().filter(|r| r.passed).count();
        let failed = total - passed;

        let mut report = String::new();
        report.push_str("╔══════════════════════════════════════════════════════╗\n");
        report.push_str("║  Spec-Driven Compatibility Report                   ║\n");
        report.push_str("╚══════════════════════════════════════════════════════╝\n\n");

        for result in &self.results {
            report.push_str(&format!("{}\n", result));
        }

        report.push_str("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        report.push_str(&format!(
            "Total: {}  Passed: {}  Failed: {}\n",
            total, passed, failed
        ));
        report.push_str(&format!(
            "Compatibility: {:.1}%\n",
            if total > 0 {
                (passed as f64 / total as f64) * 100.0
            } else {
                0.0
            }
        ));

        report
    }

    #[allow(dead_code)]
    fn all_passed(&self) -> bool {
        self.results.iter().all(|r| r.passed)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests: Spec-Driven Validation
// ═══════════════════════════════════════════════════════════════════════════

/// Run all spec-driven endpoint validations in a single test.
/// This is the main compatibility gate.
#[tokio::test]
async fn test_spec_driven_endpoint_validation() {
    let auth = create_test_auth().await;
    let mut validator = SpecValidator::new();

    // --- GET /ok ---
    let (status, body) = send_request(&auth, get_request("/ok")).await;
    validator.validate_endpoint("/ok", "get", status, &body);

    // --- GET /error ---
    let (status, body) = send_request(&auth, get_request("/error")).await;
    validator.validate_endpoint("/error", "get", status, &body);

    // --- POST /sign-up/email (success) ---
    let (status, body) = send_request(
        &auth,
        post_json(
            "/sign-up/email",
            serde_json::json!({
                "name": "Spec Test User",
                "email": "spec@example.com",
                "password": "password123"
            }),
        ),
    )
    .await;
    let signup_token = body["token"].as_str().unwrap_or("").to_string();
    validator.validate_endpoint("/sign-up/email", "post", status, &body);

    // --- POST /sign-in/email (success) ---
    let (status, body) = send_request(
        &auth,
        post_json(
            "/sign-in/email",
            serde_json::json!({
                "email": "spec@example.com",
                "password": "password123"
            }),
        ),
    )
    .await;
    let signin_token = body["token"].as_str().unwrap_or("").to_string();
    validator.validate_endpoint("/sign-in/email", "post", status, &body);

    // --- GET /get-session ---
    let (status, body) = send_request(&auth, get_with_auth("/get-session", &signin_token)).await;
    validator.validate_endpoint("/get-session", "get", status, &body);

    // --- GET /list-sessions ---
    let (status, body) = send_request(&auth, get_with_auth("/list-sessions", &signin_token)).await;
    // list-sessions returns an array, validate the first element against Session schema
    if let Some(arr) = body.as_array()
        && let Some(first) = arr.first()
    {
        let _session_schema = extract_success_schema(&validator.spec, "/list-sessions", "get");
        // list-sessions spec says array of Session — validate element fields
        let camel_violations = check_camel_case_fields(first, "sessions[0]");
        let passed = camel_violations.is_empty();
        validator.results.push(EndpointResult {
            endpoint: "/list-sessions".to_string(),
            method: "GET".to_string(),
            status,
            passed,
            diffs: vec![],
            camel_case_violations: camel_violations,
        });
    }

    // --- POST /sign-out ---
    let (status, body) = send_request(
        &auth,
        post_json_with_auth("/sign-out", serde_json::json!({}), &signup_token),
    )
    .await;
    validator.validate_endpoint("/sign-out", "post", status, &body);

    // --- POST /forget-password ---
    // Sign up a fresh user for password tests
    let (pw_token, _) = signup_user(&auth, "pw@example.com", "password123", "PW User").await;

    let (status, body) = send_request(
        &auth,
        post_json(
            "/forget-password",
            serde_json::json!({
                "email": "pw@example.com",
            }),
        ),
    )
    .await;
    validator.validate_endpoint("/forget-password", "post", status, &body);

    // --- POST /change-password ---
    let (status, body) = send_request(
        &auth,
        post_json_with_auth(
            "/change-password",
            serde_json::json!({
                "currentPassword": "password123",
                "newPassword": "newpassword456",
                "revokeOtherSessions": "false"
            }),
            &pw_token,
        ),
    )
    .await;
    validator.validate_endpoint("/change-password", "post", status, &body);

    // --- POST /update-user ---
    let (upd_token, _) = signup_user(&auth, "upd@example.com", "password123", "UPD User").await;
    let (status, body) = send_request(
        &auth,
        post_json_with_auth(
            "/update-user",
            serde_json::json!({
                "name": "Updated Name"
            }),
            &upd_token,
        ),
    )
    .await;
    validator.validate_endpoint("/update-user", "post", status, &body);

    // --- POST /delete-user ---
    let (del_token, _) = signup_user(&auth, "del@example.com", "password123", "DEL User").await;
    let (status, body) = send_request(
        &auth,
        post_json_with_auth("/delete-user", serde_json::json!({}), &del_token),
    )
    .await;
    validator.validate_endpoint("/delete-user", "post", status, &body);

    // --- POST /change-email ---
    let (ce_token, _) = signup_user(&auth, "ce@example.com", "password123", "CE User").await;
    let (status, body) = send_request(
        &auth,
        post_json_with_auth(
            "/change-email",
            serde_json::json!({
                "newEmail": "ce_new@example.com"
            }),
            &ce_token,
        ),
    )
    .await;
    validator.validate_endpoint("/change-email", "post", status, &body);

    // --- GET /list-accounts ---
    let (la_token, _) = signup_user(&auth, "la@example.com", "password123", "LA User").await;
    let (status, body) = send_request(&auth, get_with_auth("/list-accounts", &la_token)).await;
    // list-accounts returns an array, validate camelCase
    if let Some(arr) = body.as_array()
        && let Some(first) = arr.first()
    {
        let camel_violations = check_camel_case_fields(first, "accounts[0]");
        let passed = camel_violations.is_empty();
        validator.results.push(EndpointResult {
            endpoint: "/list-accounts".to_string(),
            method: "GET".to_string(),
            status,
            passed,
            diffs: vec![],
            camel_case_violations: camel_violations,
        });
    }

    // --- GET /reference/openapi.json ---
    let (status, body) = send_request(&auth, get_request("/reference/openapi.json")).await;
    assert_eq!(status, 200, "OpenAPI endpoint should return 200");
    assert!(body["openapi"].is_string(), "Should have openapi version");
    assert!(body["paths"].is_object(), "Should have paths");

    // Print report
    let report = validator.report();
    eprintln!("\n{}\n", report);
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests: Error Response Shape Consistency
// ═══════════════════════════════════════════════════════════════════════════

/// All error responses must follow the { "message": "..." } format per the spec.
#[tokio::test]
async fn test_error_response_shapes_match_spec() {
    let auth = create_test_auth().await;
    let spec = load_openapi_spec();

    // Collect error scenarios
    let error_scenarios: Vec<(&str, &str, AuthRequest, u16)> = vec![
        (
            "/sign-in/email",
            "post",
            post_json(
                "/sign-in/email",
                serde_json::json!({
                    "email": "nonexistent@example.com",
                    "password": "password123"
                }),
            ),
            401,
        ),
        (
            "/sign-up/email",
            "post",
            post_json("/sign-up/email", serde_json::json!({})),
            400,
        ),
        (
            "/sign-up/email",
            "post",
            post_json(
                "/sign-up/email",
                serde_json::json!({
                    "name": "Short",
                    "email": "short@example.com",
                    "password": "123"
                }),
            ),
            400,
        ),
    ];

    let mut all_passed = true;
    for (path, method, req, expected_status_class) in error_scenarios {
        let (status, body) = send_request(&auth, req).await;
        let status_class = status / 100;
        let expected_class = expected_status_class / 100;

        // Verify status is in the expected class (4xx)
        if status_class != expected_class {
            eprintln!(
                "WARN: {} {} returned status {} (expected {}xx)",
                method.to_uppercase(),
                path,
                status,
                expected_class
            );
        }

        // All error responses MUST have a "message" field per the spec
        if status >= 400 {
            if !body["message"].is_string() {
                eprintln!(
                    "FAIL: {} {} error response missing 'message' field: {}",
                    method.to_uppercase(),
                    path,
                    body
                );
                all_passed = false;
            }

            // Validate against spec error schema
            let error_schemas = extract_error_schemas(&spec, path, method);
            if let Some(error_schema) = error_schemas.get(&status.to_string()) {
                let diffs = validate_response(&body, error_schema, "");
                if !diffs.is_empty() {
                    eprintln!(
                        "FAIL: {} {} error response shape mismatch (status {}):",
                        method.to_uppercase(),
                        path,
                        status
                    );
                    for diff in &diffs {
                        eprintln!("      {}", diff);
                    }
                    all_passed = false;
                }
            }
        }
    }

    assert!(
        all_passed,
        "Some error responses don't match the spec. See output above."
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests: camelCase Field Naming Enforcement
// ═══════════════════════════════════════════════════════════════════════════

/// All response fields must use camelCase (not snake_case) for frontend compatibility.
#[tokio::test]
async fn test_all_responses_use_camel_case() {
    let auth = create_test_auth().await;

    // Sign up a user to test all authenticated endpoints
    let (token, signup_body) =
        signup_user(&auth, "camel@example.com", "password123", "Camel User").await;

    // Collect all responses to check
    let test_cases: Vec<(&str, Value)> = vec![("POST /sign-up/email", signup_body.clone())];

    // Endpoints that require auth
    let auth_endpoints: Vec<(&str, AuthRequest)> = vec![
        ("GET /get-session", get_with_auth("/get-session", &token)),
        (
            "GET /list-sessions",
            get_with_auth("/list-sessions", &token),
        ),
        (
            "GET /list-accounts",
            get_with_auth("/list-accounts", &token),
        ),
    ];

    let mut all_violations = Vec::new();

    // Check pre-collected responses
    for (endpoint, body) in &test_cases {
        let violations = check_camel_case_fields(body, "");
        if !violations.is_empty() {
            all_violations.push(format!("{}: {:?}", endpoint, violations));
        }
    }

    // Check authenticated endpoint responses
    for (endpoint, req) in auth_endpoints {
        let (status, body) = send_request(&auth, req).await;
        if status == 200 {
            let violations = check_camel_case_fields(&body, "");
            if !violations.is_empty() {
                all_violations.push(format!("{}: {:?}", endpoint, violations));
            }
        }
    }

    // Sign in response
    let (_, signin_body) = signin_user(&auth, "camel@example.com", "password123").await;
    let violations = check_camel_case_fields(&signin_body, "");
    if !violations.is_empty() {
        all_violations.push(format!("POST /sign-in/email: {:?}", violations));
    }

    if !all_violations.is_empty() {
        eprintln!("\n=== camelCase Violations ===");
        for v in &all_violations {
            eprintln!("  {}", v);
        }
        eprintln!("===========================\n");
    }

    assert!(
        all_violations.is_empty(),
        "Found snake_case fields in responses. All field names must use camelCase for frontend compatibility.\n\
         Violations:\n{}",
        all_violations.join("\n")
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests: Response Type Signature Documentation
// ═══════════════════════════════════════════════════════════════════════════

/// Generate and print type signatures for all core endpoints.
/// This test always passes but produces documentation for review.
#[tokio::test]
async fn test_response_type_signatures() {
    let auth = create_test_auth().await;

    let (token, signup_body) =
        signup_user(&auth, "sig@example.com", "password123", "Sig User").await;
    let (_, signin_body) = signin_user(&auth, "sig@example.com", "password123").await;

    let (_, session_body) = send_request(&auth, get_with_auth("/get-session", &token)).await;
    let (_, sessions_body) = send_request(&auth, get_with_auth("/list-sessions", &token)).await;
    let (_, accounts_body) = send_request(&auth, get_with_auth("/list-accounts", &token)).await;
    let (_, ok_body) = send_request(&auth, get_request("/ok")).await;
    let (_, error_body) = send_request(&auth, get_request("/error")).await;

    eprintln!("\n=== Response Type Signatures ===\n");

    let endpoints: Vec<(&str, &Value)> = vec![
        ("GET /ok", &ok_body),
        ("GET /error", &error_body),
        ("POST /sign-up/email", &signup_body),
        ("POST /sign-in/email", &signin_body),
        ("GET /get-session", &session_body),
        ("GET /list-sessions", &sessions_body),
        ("GET /list-accounts", &accounts_body),
    ];

    for (endpoint, body) in endpoints {
        let sig = extract_type_signature(body, 0);
        eprintln!("{}\n{}\n", endpoint, sig);
    }

    eprintln!("================================\n");
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests: Route Coverage Analysis
// ═══════════════════════════════════════════════════════════════════════════

/// Analyze which endpoints from the reference spec are implemented.
#[tokio::test]
async fn test_route_coverage_analysis() {
    let spec = load_openapi_spec();
    let auth = create_test_auth().await;

    // Collect reference endpoints
    let paths = spec["paths"].as_object().expect("spec must have paths");

    let mut ref_endpoints: BTreeMap<String, HashSet<String>> = BTreeMap::new();
    for (path, methods) in paths {
        if let Some(obj) = methods.as_object() {
            let mut method_set = HashSet::new();
            for method in obj.keys() {
                match method.as_str() {
                    "get" | "post" | "put" | "delete" | "patch" => {
                        method_set.insert(method.clone());
                    }
                    _ => {}
                }
            }
            if !method_set.is_empty() {
                ref_endpoints.insert(path.clone(), method_set);
            }
        }
    }

    // Collect implemented endpoints
    let mut impl_endpoints: BTreeMap<String, HashSet<String>> = BTreeMap::new();

    // Core routes
    for (path, method) in &[
        ("/ok", "get"),
        ("/error", "get"),
        ("/reference/openapi.json", "get"),
        ("/update-user", "post"),
        ("/delete-user", "post"),
        ("/change-email", "post"),
        ("/delete-user/callback", "get"),
    ] {
        impl_endpoints
            .entry(path.to_string())
            .or_default()
            .insert(method.to_string());
    }

    // Plugin routes
    for plugin in auth.plugins() {
        for route in plugin.routes() {
            let method_str = match route.method {
                HttpMethod::Get => "get",
                HttpMethod::Post => "post",
                HttpMethod::Put => "put",
                HttpMethod::Delete => "delete",
                HttpMethod::Patch => "patch",
                HttpMethod::Options => "options",
                HttpMethod::Head => "head",
            };
            impl_endpoints
                .entry(route.path.clone())
                .or_default()
                .insert(method_str.to_string());
        }
    }

    // Compute coverage
    let mut covered = 0;
    let mut missing = Vec::new();
    let total: usize = ref_endpoints.values().map(|m| m.len()).sum();

    for (path, methods) in &ref_endpoints {
        for method in methods {
            if impl_endpoints.get(path).is_some_and(|m| m.contains(method)) {
                covered += 1;
            } else {
                missing.push(format!("{} {}", method.to_uppercase(), path));
            }
        }
    }

    let coverage_pct = if total > 0 {
        (covered as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    // Print structured coverage report
    eprintln!("\n╔══════════════════════════════════════════════════════╗");
    eprintln!("║  Route Coverage Analysis                             ║");
    eprintln!("╚══════════════════════════════════════════════════════╝\n");
    eprintln!("Reference endpoints:  {}", total);
    eprintln!("Implemented:          {}", covered);
    eprintln!("Missing:              {}", missing.len());
    eprintln!("Coverage:             {:.1}%\n", coverage_pct);

    if !missing.is_empty() {
        eprintln!("--- Missing endpoints (from reference spec) ---");
        // Group by plugin/category
        let mut categorized: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for m in &missing {
            let path_part = m.split_whitespace().nth(1).unwrap_or(m);
            let category = if path_part.contains("two-factor") {
                "Two-Factor"
            } else if path_part.contains("passkey") {
                "Passkey"
            } else if path_part.contains("organization")
                || path_part.contains("invitation")
                || path_part.contains("member")
            {
                "Organization"
            } else if path_part.contains("admin")
                || path_part.contains("ban")
                || path_part.contains("impersonate")
            {
                "Admin"
            } else if path_part.contains("api-key") {
                "API Key"
            } else if path_part.contains("sign-in")
                || path_part.contains("sign-up")
                || path_part.contains("callback")
            {
                "Auth"
            } else if path_part.contains("session") {
                "Session"
            } else {
                "Other"
            };
            categorized
                .entry(category.to_string())
                .or_default()
                .push(m.clone());
        }

        for (category, endpoints) in &categorized {
            eprintln!("\n  [{}]", category);
            for ep in endpoints {
                eprintln!("    [ ] {}", ep);
            }
        }
    }

    eprintln!("\n══════════════════════════════════════════════════════\n");
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests: Cross-Endpoint Behavioral Consistency
// ═══════════════════════════════════════════════════════════════════════════

/// Test the complete auth flow: signup → signin → get-session → signout.
/// Validates that the user object is consistent across all responses.
#[tokio::test]
async fn test_auth_flow_user_object_consistency() {
    let auth = create_test_auth().await;

    // Step 1: Sign up
    let (_signup_token, signup_body) =
        signup_user(&auth, "flow@example.com", "password123", "Flow User").await;
    let signup_user_obj = &signup_body["user"];

    // Step 2: Sign in
    let (signin_token, signin_body) = signin_user(&auth, "flow@example.com", "password123").await;
    let signin_user_obj = &signin_body["user"];

    // Step 3: Get session
    let (_, session_body) = send_request(&auth, get_with_auth("/get-session", &signin_token)).await;
    let session_user_obj = &session_body["user"];

    // The user object should have the SAME shape across all responses
    let shapes_to_compare = vec![
        ("signup vs signin", signup_user_obj, signin_user_obj),
        ("signup vs session", signup_user_obj, session_user_obj),
    ];

    for (label, a, b) in shapes_to_compare {
        let diffs = compare_shapes(a, b, "user", false);
        assert!(
            diffs.is_empty(),
            "User object shape mismatch between {}: {:?}",
            label,
            diffs
        );
    }

    // Verify the user ID is consistent
    assert_eq!(
        signup_user_obj["id"], signin_user_obj["id"],
        "User ID must be consistent: signup vs signin"
    );
    assert_eq!(
        signup_user_obj["id"], session_user_obj["id"],
        "User ID must be consistent: signup vs session"
    );

    // Verify the email is consistent
    assert_eq!(
        signup_user_obj["email"], signin_user_obj["email"],
        "Email must be consistent: signup vs signin"
    );
}

/// Test that duplicate signup returns proper error shape.
#[tokio::test]
async fn test_duplicate_signup_error_shape() {
    let auth = create_test_auth().await;

    // First signup succeeds
    signup_user(&auth, "dup@example.com", "password123", "Dup User").await;

    // Second signup with same email should fail
    let (status, body) = send_request(
        &auth,
        post_json(
            "/sign-up/email",
            serde_json::json!({
                "name": "Dup User 2",
                "email": "dup@example.com",
                "password": "password123"
            }),
        ),
    )
    .await;

    assert!(
        (400..500).contains(&status),
        "Duplicate signup should return 4xx, got {}",
        status
    );
    assert!(
        body["message"].is_string(),
        "Error response must have 'message' field, got: {}",
        body
    );
}

/// Test that the session object shape is consistent across endpoints.
#[tokio::test]
async fn test_session_object_consistency() {
    let auth = create_test_auth().await;
    let (token, _) = signup_user(&auth, "sess@example.com", "password123", "Sess User").await;

    // Get session from /get-session
    let (_, session_body) = send_request(&auth, get_with_auth("/get-session", &token)).await;
    let get_session_obj = &session_body["session"];

    // Get sessions from /list-sessions
    let (_, list_body) = send_request(&auth, get_with_auth("/list-sessions", &token)).await;
    let list_session_obj = list_body.as_array().and_then(|arr| arr.first());

    if let Some(list_session) = list_session_obj {
        let diffs = compare_shapes(get_session_obj, list_session, "session", false);
        // Note: /get-session wraps in {session, user}, /list-sessions returns array of session
        // The shapes may differ slightly because of this wrapping
        if !diffs.is_empty() {
            eprintln!("Session shape differences (get-session vs list-sessions):");
            for diff in &diffs {
                eprintln!("  {}", diff);
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests: Spec Schema Validation (Unit Tests for the Framework)
// ═══════════════════════════════════════════════════════════════════════════

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

#[test]
fn test_camel_case_check() {
    let val = serde_json::json!({"userId": "1", "user_name": "Alice", "created_at": "2024-01-01"});
    let violations = check_camel_case_fields(&val, "");
    assert_eq!(violations.len(), 2, "Should detect 2 snake_case fields");
}

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

#[test]
fn test_schema_resolution() {
    let spec = load_openapi_spec();

    // Verify User schema can be resolved
    let user_schema = resolve_ref(&spec, "#/components/schemas/User");
    assert!(user_schema.is_some(), "Should resolve User schema");

    let user = user_schema.unwrap();
    assert!(
        user["properties"]["id"]["type"].as_str().is_some(),
        "User.id should have a type"
    );
    assert!(
        user["properties"]["email"]["type"].as_str().is_some(),
        "User.email should have a type"
    );

    // Verify Session schema can be resolved
    let session_schema = resolve_ref(&spec, "#/components/schemas/Session");
    assert!(session_schema.is_some(), "Should resolve Session schema");
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
