# Compatibility Testing Framework

This directory contains the **dual-server compatibility testing** infrastructure
for validating better-auth-rs against the canonical better-auth (TypeScript)
implementation.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  Compatibility Testing Framework                                     │
│                                                                      │
│  ┌──────────────────────┐   ┌──────────────────────────────────┐   │
│  │  Spec-Driven Tests   │   │  Dual-Server Tests               │   │
│  │  (tests/ directory)  │   │  (compat-tests/)                 │   │
│  │                      │   │                                   │   │
│  │  - OpenAPI schema    │   │  ┌─────────┐   ┌──────────────┐ │   │
│  │    auto-validation   │   │  │ Rust    │   │ Node.js ref  │ │   │
│  │  - camelCase check   │   │  │ (mem)   │   │ server       │ │   │
│  │  - Field type check  │   │  └────┬────┘   └──────┬───────┘ │   │
│  │  - Coverage report   │   │       │               │          │   │
│  └──────────────────────┘   │       └───────┬───────┘          │   │
│                              │               │                  │   │
│  better-auth.yaml            │     Response Shape Comparison    │   │
│  (OpenAPI 3.1.1 ref spec)   │                                   │   │
│                              └──────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

## Components

### 1. Spec-Driven Validation (`tests/spec_driven_compat_tests.rs`)

Automated tests that parse `better-auth.yaml` and validate Rust responses
against the OpenAPI spec. Runs with `cargo test`:

```bash
# Run all spec-driven compatibility tests
cargo test --test spec_driven_compat_tests -- --nocapture

# Run specific test
cargo test --test spec_driven_compat_tests test_spec_driven_endpoint_validation -- --nocapture
```

Features:
- **Schema auto-validation**: Parses OpenAPI spec schemas and validates response fields
- **`$ref` resolution**: Follows `$ref` references to component schemas
- **camelCase enforcement**: Ensures all field names use camelCase (not snake_case)
- **Route coverage analysis**: Reports what % of spec endpoints are implemented
- **Response type signatures**: Generates human-readable type docs for all endpoints
- **Cross-endpoint consistency**: Validates user/session objects are consistent across responses
- **Shape comparison engine**: Compares two JSON structures ignoring dynamic values

### 2. Existing Compatibility Tests (`tests/compatibility_tests.rs`)

Contract tests and route coverage reports against the reference spec.

### 3. Response Shape Tests (`src/tests/response_shape_tests.rs`)

Per-endpoint response shape validation tests.

### 4. Reference Server (`compat-tests/reference-server/`)

A Node.js server running the canonical better-auth (TypeScript) implementation
for dual-server comparison testing.

#### Setup

```bash
cd compat-tests/reference-server
npm install
npm start  # starts on port 3100
```

#### Usage

The reference server is used by the dual-server test runner to:
1. Send identical requests to both implementations
2. Compare response shapes (not exact values)
3. Report any structural differences

## Test Categories

| Category | Command | Description |
|----------|---------|-------------|
| Spec validation | `cargo test --test spec_driven_compat_tests` | Auto-validates responses against OpenAPI spec |
| Route coverage | `cargo test --test spec_driven_compat_tests test_route_coverage_analysis -- --nocapture` | Reports which spec endpoints are implemented |
| camelCase check | `cargo test --test spec_driven_compat_tests test_all_responses_use_camel_case` | Ensures frontend-compatible field names |
| Error shapes | `cargo test --test spec_driven_compat_tests test_error_response_shapes_match_spec` | Validates error response format |
| Flow consistency | `cargo test --test spec_driven_compat_tests test_auth_flow_user_object_consistency` | Validates user object consistency across flows |
| Type signatures | `cargo test --test spec_driven_compat_tests test_response_type_signatures -- --nocapture` | Generates response type documentation |
| Existing compat | `cargo test --test compatibility_tests` | Route coverage + contract tests |
| Response shapes | `cargo test response_shape_tests` | Per-endpoint response shape tests |

## Adding New Tests

### Adding a new spec-driven endpoint test

Add a new section to the `test_spec_driven_endpoint_validation` test:

```rust
// --- POST /your-endpoint ---
let (status, body) = send_request(
    &auth,
    post_json_with_auth("/your-endpoint", serde_json::json!({...}), &token),
).await;
validator.validate_endpoint("/your-endpoint", "post", status, &body);
```

The validator will automatically:
1. Look up the endpoint in `better-auth.yaml`
2. Extract the expected response schema
3. Validate all required fields are present
4. Check field types match
5. Verify camelCase naming

### Adding a new shape comparison test

```rust
let diffs = compare_shapes(&reference_json, &target_json, "", false);
assert!(diffs.is_empty(), "Shape mismatch: {:?}", diffs);
```
