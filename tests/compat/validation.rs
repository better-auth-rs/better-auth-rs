//! Response validation against OpenAPI schemas.
//!
//! Validates JSON responses field-by-field against `SchemaExpectation`,
//! producing a list of `ShapeDiff` items for any mismatches.

use serde_json::Value;

use super::schema::{FieldExpectation, SchemaExpectation};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A single difference found between expected schema and actual response.
#[derive(Debug)]
pub struct ShapeDiff {
    /// JSON path (e.g. "user.email")
    pub path: String,
    /// Description of the difference
    pub kind: DiffKind,
}

#[derive(Debug)]
pub enum DiffKind {
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

// ---------------------------------------------------------------------------
// Response validation
// ---------------------------------------------------------------------------

/// Validate a JSON response against a `SchemaExpectation`.
pub fn validate_response(
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
            // Non-required fields that are null are implicitly nullable -- the spec
            // may say `type: string` but the implementation legitimately returns
            // null for optional/unset fields.
            if actual_value.is_null() && !schema.required_fields.contains(field_name) {
                continue;
            }
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
pub fn validate_field(
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
            diffs.push(ShapeDiff {
                path: path.to_string(),
                kind: DiffKind::TypeMismatch {
                    expected: expectation.field_type.clone(),
                    actual: "null".to_string(),
                },
            });
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

/// Return the JSON type name for a value.
pub fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}
