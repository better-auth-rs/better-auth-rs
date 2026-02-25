//! JSON shape comparison, camelCase enforcement, and type-signature extraction.
//!
//! These utilities compare two JSON values structurally (ignoring dynamic
//! values like IDs and tokens) and verify field-naming conventions.

use serde_json::Value;

use super::validation::json_type_name;

// ---------------------------------------------------------------------------
// Shape comparison
// ---------------------------------------------------------------------------

/// Compare two JSON responses structurally (shape-only, ignoring dynamic values).
/// Returns a list of differences.
pub fn compare_shapes(
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
            // Scalars -- type already matched above, values are dynamic
        }
    }
}

// ---------------------------------------------------------------------------
// camelCase enforcement
// ---------------------------------------------------------------------------

/// Check that all field names in a JSON value use camelCase (no underscores).
pub fn check_camel_case_fields(value: &Value, path: &str) -> Vec<String> {
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

// ---------------------------------------------------------------------------
// Type-signature extraction
// ---------------------------------------------------------------------------

/// Extract the "type signature" of a JSON value for human-readable display.
pub fn extract_type_signature(value: &Value, indent: usize) -> String {
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
