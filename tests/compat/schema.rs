//! OpenAPI spec loading, `$ref` resolution, and `SchemaExpectation` types.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use oas3::spec::{ObjectOrReference, ObjectSchema, SchemaType, SchemaTypeSet};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Parsed representation of a response schema from the OpenAPI spec.
#[derive(Debug, Clone)]
pub struct SchemaExpectation {
    /// Expected field name -> field type (e.g. "string", "boolean", "object", "array")
    pub fields: BTreeMap<String, FieldExpectation>,
    /// Fields that are required per the spec
    pub required_fields: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub struct FieldExpectation {
    /// JSON type: "string", "boolean", "number", "object", "array", "null", "date"
    pub field_type: String,
    /// Whether the field can be null
    pub nullable: bool,
    /// Nested schema (for objects)
    pub nested: Option<SchemaExpectation>,
    /// Item schema (for arrays)
    pub items: Option<Box<FieldExpectation>>,
}

// ---------------------------------------------------------------------------
// Spec loading
// ---------------------------------------------------------------------------

/// Load and parse the OpenAPI spec using `oas3`.
///
/// The canonical `better-auth.yaml` uses the non-standard `type: date` for
/// date/time fields.  JSON Schema (and therefore OpenAPI 3.1) only recognises
/// `type: string` with `format: date-time`, so we normalise the YAML before
/// handing it to the parser.
pub fn load_openapi_spec() -> oas3::spec::Spec {
    let yaml_str = std::fs::read_to_string("better-auth.yaml")
        .expect("better-auth.yaml must exist in the project root");

    // Normalise non-standard "type: date" -> "type: string" (+ format kept in
    // our FieldExpectation as "date" via a post-processing step).
    //
    // We use a line-by-line approach instead of a blanket `replace()` to avoid
    // corrupting values like "type: date-time" or "type: daterange".
    let yaml_str: String = yaml_str
        .lines()
        .map(|line| {
            let trimmed = line.trim_start();
            if let Some(rest) = trimmed.strip_prefix("type: date") {
                // Only replace when "date" is the complete value (end-of-line,
                // followed by whitespace, or followed by a YAML comment).
                if rest.is_empty()
                    || rest.starts_with(' ')
                    || rest.starts_with('#')
                    || rest.starts_with('\t')
                {
                    line.replacen("type: date", "type: string", 1)
                } else {
                    line.to_string()
                }
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    oas3::from_yaml(yaml_str).expect("better-auth.yaml must be valid OpenAPI 3.1")
}

// ---------------------------------------------------------------------------
// Path / operation helpers
// ---------------------------------------------------------------------------

/// Look up the `PathItem` for a given API path.
pub fn get_path_item<'a>(
    spec: &'a oas3::spec::Spec,
    path: &str,
) -> Option<&'a oas3::spec::PathItem> {
    spec.paths.as_ref()?.get(path)
}

/// Get the `Operation` for a given method on a `PathItem`.
pub fn get_operation<'a>(
    path_item: &'a oas3::spec::PathItem,
    method: &str,
) -> Option<&'a oas3::spec::Operation> {
    match method {
        "get" => path_item.get.as_ref(),
        "post" => path_item.post.as_ref(),
        "put" => path_item.put.as_ref(),
        "delete" => path_item.delete.as_ref(),
        "patch" => path_item.patch.as_ref(),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Schema resolution
// ---------------------------------------------------------------------------

/// Resolve an `ObjectOrReference<ObjectSchema>` to a concrete `ObjectSchema`.
pub fn resolve_object_schema(
    spec: &oas3::spec::Spec,
    obj_or_ref: &ObjectOrReference<ObjectSchema>,
) -> Option<ObjectSchema> {
    match obj_or_ref {
        ObjectOrReference::Object(obj) => Some(obj.clone()),
        ObjectOrReference::Ref { .. } => obj_or_ref.resolve(spec).ok(),
    }
}

/// Extract the JSON schema from a response's `application/json` content.
pub fn schema_from_response(
    spec: &oas3::spec::Spec,
    response: &ObjectOrReference<oas3::spec::Response>,
) -> Option<ObjectSchema> {
    let resp = match response {
        ObjectOrReference::Object(r) => r.clone(),
        ObjectOrReference::Ref { .. } => response.resolve(spec).ok()?,
    };
    let media = resp.content.get("application/json")?;
    let schema_ref = media.schema.as_ref()?;
    resolve_object_schema(spec, schema_ref)
}

// ---------------------------------------------------------------------------
// Schema extraction
// ---------------------------------------------------------------------------

/// Extract the 200 response schema for a given path and method from the spec.
pub fn extract_success_schema(
    spec: &oas3::spec::Spec,
    path: &str,
    method: &str,
) -> Option<SchemaExpectation> {
    let path_item = get_path_item(spec, path)?;
    let operation = get_operation(path_item, method)?;
    let response = operation.responses.as_ref()?.get("200")?;
    let obj_schema = schema_from_response(spec, response)?;
    Some(object_schema_to_expectation(spec, &obj_schema))
}

/// Extract error response schemas (4xx, 5xx) for a given path and method.
pub fn extract_error_schemas(
    spec: &oas3::spec::Spec,
    path: &str,
    method: &str,
) -> HashMap<String, SchemaExpectation> {
    let mut result = HashMap::new();
    let Some(path_item) = get_path_item(spec, path) else {
        return result;
    };
    let Some(operation) = get_operation(path_item, method) else {
        return result;
    };
    let Some(responses) = &operation.responses else {
        return result;
    };
    for (status, response) in responses {
        if status.starts_with('4') || status.starts_with('5') {
            if let Some(obj_schema) = schema_from_response(spec, response) {
                result.insert(
                    status.clone(),
                    object_schema_to_expectation(spec, &obj_schema),
                );
            }
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

/// Convert an `oas3` `ObjectSchema` into our internal `SchemaExpectation`.
pub fn object_schema_to_expectation(
    spec: &oas3::spec::Spec,
    obj: &ObjectSchema,
) -> SchemaExpectation {
    let mut fields = BTreeMap::new();
    let required_fields: BTreeSet<String> = obj.required.iter().cloned().collect();

    for (name, prop_ref) in &obj.properties {
        if let Some(prop_schema) = resolve_object_schema(spec, prop_ref) {
            fields.insert(name.clone(), object_schema_to_field(spec, &prop_schema));
        } else {
            // Unresolvable ref -- treat as unknown string
            fields.insert(
                name.clone(),
                FieldExpectation {
                    field_type: "string".to_string(),
                    nullable: false,
                    nested: None,
                    items: None,
                },
            );
        }
    }

    SchemaExpectation {
        fields,
        required_fields,
    }
}

/// Convert an `oas3` `ObjectSchema` for a single field into `FieldExpectation`.
pub fn object_schema_to_field(spec: &oas3::spec::Spec, obj: &ObjectSchema) -> FieldExpectation {
    let (field_type, nullable) = schema_type_info(obj);

    let nested = if field_type == "object" && !obj.properties.is_empty() {
        Some(object_schema_to_expectation(spec, obj))
    } else {
        None
    };

    let items = if field_type == "array" {
        obj.items
            .as_ref()
            .and_then(|item_schema| match item_schema.as_ref() {
                oas3::spec::Schema::Object(boxed) => resolve_object_schema(spec, boxed)
                    .map(|s| Box::new(object_schema_to_field(spec, &s))),
                oas3::spec::Schema::Boolean(_) => None,
            })
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

/// Extract the type name and nullability from an `ObjectSchema`'s `schema_type`.
pub fn schema_type_info(obj: &ObjectSchema) -> (String, bool) {
    match &obj.schema_type {
        Some(SchemaTypeSet::Single(t)) => (schema_type_to_string(*t), *t == SchemaType::Null),
        Some(SchemaTypeSet::Multiple(types)) => {
            let nullable = types.contains(&SchemaType::Null);
            let primary = types
                .iter()
                .find(|t| **t != SchemaType::Null)
                .copied()
                .unwrap_or(SchemaType::String);
            (schema_type_to_string(primary), nullable)
        }
        None => {
            // No explicit type -- if it has properties, it's an object; otherwise "string"
            if !obj.properties.is_empty() {
                ("object".to_string(), false)
            } else {
                ("string".to_string(), false)
            }
        }
    }
}

pub fn schema_type_to_string(t: SchemaType) -> String {
    match t {
        SchemaType::Boolean => "boolean",
        SchemaType::Integer => "integer",
        SchemaType::Number => "number",
        SchemaType::String => "string",
        SchemaType::Array => "array",
        SchemaType::Object => "object",
        SchemaType::Null => "null",
    }
    .to_string()
}
