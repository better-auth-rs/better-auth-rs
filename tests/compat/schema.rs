//! Generated upstream OpenAPI loading, `$ref` resolution, and schema types.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

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

/// Upstream OpenAPI profile to generate from the pinned published TS package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenApiProfile {
    /// Default blocking structural contract.
    Core,
    /// Blocking structural contract for the Better Auth surface we intend to match.
    AlignedRs,
    /// Informational full-surface report over the broader upstream plugin set.
    AllIn,
}

impl OpenApiProfile {
    fn as_str(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::AlignedRs => "aligned-rs",
            Self::AllIn => "all-in",
        }
    }
}

static CORE_OPENAPI: OnceLock<Result<String, String>> = OnceLock::new();
static ALIGNED_RS_OPENAPI: OnceLock<Result<String, String>> = OnceLock::new();
static ALL_IN_OPENAPI: OnceLock<Result<String, String>> = OnceLock::new();

/// Load and parse the default upstream OpenAPI contract.
///
/// The default blocking contract is the generated `core` profile from the
/// pinned published `better-auth` package in `compat-tests/reference-server`.
pub fn load_openapi_spec() -> oas3::spec::Spec {
    load_openapi_spec_with_profile(OpenApiProfile::Core)
}

/// Load and parse a generated upstream OpenAPI contract for the given profile.
pub fn load_openapi_spec_with_profile(profile: OpenApiProfile) -> oas3::spec::Spec {
    let raw = cached_openapi_spec(profile)
        .as_ref()
        .unwrap_or_else(|message| panic!("{message}"));

    oas3::from_yaml(raw.clone()).unwrap_or_else(|e| {
        panic!(
            "generated upstream OpenAPI profile `{}` must be valid OpenAPI 3.1: {e}",
            profile.as_str()
        )
    })
}

fn cached_openapi_spec(profile: OpenApiProfile) -> &'static Result<String, String> {
    let cache = match profile {
        OpenApiProfile::Core => &CORE_OPENAPI,
        OpenApiProfile::AlignedRs => &ALIGNED_RS_OPENAPI,
        OpenApiProfile::AllIn => &ALL_IN_OPENAPI,
    };

    cache.get_or_init(|| generate_openapi_spec(profile))
}

fn generate_openapi_spec(profile: OpenApiProfile) -> Result<String, String> {
    let workspace_dir = Path::new("compat-tests/reference-server");
    if !workspace_dir.join("package.json").exists() {
        return Err(format!(
            "compat reference workspace missing at {}",
            workspace_dir.display()
        ));
    }
    if !workspace_dir.join("generate-openapi.mjs").exists() {
        return Err(format!(
            "OpenAPI generator missing at {}",
            workspace_dir.join("generate-openapi.mjs").display()
        ));
    }

    let output_path = temp_output_path(profile);
    let bun = Command::new("bun")
        .arg("./generate-openapi.mjs")
        .arg("--profile")
        .arg(profile.as_str())
        .arg("--output")
        .arg(&output_path)
        .current_dir(workspace_dir)
        .output()
        .map_err(|e| {
            format!(
                "failed to run bun for upstream OpenAPI generation: {e}. Install Bun and run `cd compat-tests/reference-server && bun install`."
            )
        })?;

    if !bun.status.success() {
        return Err(format!(
            "failed to generate upstream OpenAPI profile `{}` via `compat-tests/reference-server/generate-openapi.mjs`.\nstdout:\n{}\nstderr:\n{}\nRun `cd compat-tests/reference-server && bun install` to refresh the pinned dependencies.",
            profile.as_str(),
            String::from_utf8_lossy(&bun.stdout).trim(),
            String::from_utf8_lossy(&bun.stderr).trim()
        ));
    }

    let raw = std::fs::read_to_string(&output_path).map_err(|e| {
        format!(
            "generated upstream OpenAPI profile `{}` did not produce readable output at {}: {e}",
            profile.as_str(),
            output_path.display()
        )
    })?;
    let _ = std::fs::remove_file(&output_path);
    Ok(raw)
}

fn temp_output_path(profile: OpenApiProfile) -> PathBuf {
    std::env::temp_dir().join(format!(
        "better-auth-rs-openapi-{}-{}.json",
        profile.as_str(),
        std::process::id()
    ))
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
    let responses = operation.responses.as_ref()?;
    let mut success_statuses: Vec<&String> = responses
        .keys()
        .filter(|status| status.starts_with('2'))
        .collect();
    success_statuses.sort();

    for status in success_statuses {
        let response = responses.get(status)?;
        if let Some(obj_schema) = schema_from_response(spec, response) {
            return Some(object_schema_to_expectation(spec, &obj_schema));
        }
    }

    None
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
        if (status.starts_with('4') || status.starts_with('5'))
            && let Some(obj_schema) = schema_from_response(spec, response)
        {
            let _ = result.insert(
                status.clone(),
                object_schema_to_expectation(spec, &obj_schema),
            );
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
            let _ = fields.insert(name.clone(), object_schema_to_field(spec, &prop_schema));
        } else {
            // Unresolvable ref -- treat as unknown string
            let _ = fields.insert(
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
