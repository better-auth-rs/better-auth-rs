use better_auth::{
    AuthConfig, AuthError, AuthResult, BetterAuth,
    middleware::RateLimitConfig,
    plugins::{
        OpenApiPlugin,
        device_authorization::{
            DeviceAuthorizationPlugin, DeviceGrant, DeviceRequestField, DeviceRequestFields,
        },
    },
    store::StatelessSchema,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fmt::Debug,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

const OPERATIONS: [(&str, &str); 5] = [
    ("/device/code", "post"),
    ("/device/token", "post"),
    ("/device", "get"),
    ("/device/approve", "post"),
    ("/device/deny", "post"),
];

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct FieldInput {
    name: String,
    kind: String,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct ResponseProperties {
    status: String,
    keys: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Operation {
    path: String,
    method: String,
    operation: Value,
    response_keys: Vec<String>,
    request_property_keys: Option<Vec<String>>,
    request_required: Option<Vec<String>>,
    response_property_keys: Vec<ResponseProperties>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SchemaCase {
    name: String,
    fields: Vec<FieldInput>,
    operations: Vec<Operation>,
    callback_calls: usize,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Fixture {
    version: String,
    cases: Vec<SchemaCase>,
}

fn same<T: Debug + PartialEq>(actual: &T, expected: &T, label: &str) -> AuthResult<()> {
    if actual != expected {
        return Err(AuthError::internal(format!(
            "{label}: actual {actual:?}; expected {expected:?}"
        )));
    }
    Ok(())
}

fn field_schema(kind: &str) -> AuthResult<(Value, bool)> {
    // These declarations describe the sampler's inputs independently of its observed document.
    match kind {
        "label" => Ok((
            json!({
                "type": "string", "minLength": 2, "maxLength": 12, "description": "Device label",
            }),
            true,
        )),
        "optional-count" => Ok((json!({ "type": "number" }), false)),
        "location" => Ok((json!({ "type": "string", "enum": ["desk", "rack"] }), true)),
        "optional-nullable-label" => Ok((json!({ "type": ["string", "null"] }), false)),
        "default-label" | "optional-async-label" => Ok((json!({ "type": "string" }), false)),
        "settings" => Ok((
            json!({
                "type": "object",
                "properties": {
                    "enabled": { "type": "boolean" },
                    "labels": { "type": "array", "items": { "type": "string" } },
                },
                "required": ["enabled"],
            }),
            true,
        )),
        "transformed-label" => Ok((json!({ "type": "string" }), true)),
        "optional-flag" => Ok((json!({ "type": "boolean" }), false)),
        _ => Err(AuthError::internal(format!(
            "Unknown request schema kind: {kind}"
        ))),
    }
}

fn unexpected_field(calls: Arc<AtomicUsize>, asynchronous: bool) -> DeviceRequestField {
    if asynchronous {
        DeviceRequestField::new_async(move |_| {
            let calls = calls.clone();
            async move {
                let _ = calls.fetch_add(1, Ordering::SeqCst);
                Err(AuthError::internal(
                    "Schema generation called async field validation",
                ))
            }
        })
    } else {
        DeviceRequestField::new(move |_| {
            let _ = calls.fetch_add(1, Ordering::SeqCst);
            Err(AuthError::internal(
                "Schema generation called field validation",
            ))
        })
    }
}

fn request_fields(
    input: &[FieldInput],
    calls: Arc<AtomicUsize>,
) -> AuthResult<DeviceRequestFields> {
    let mut fields = DeviceRequestFields::new();
    for input in input {
        let (schema, required) = field_schema(&input.kind)?;
        let field = unexpected_field(calls.clone(), input.kind == "optional-async-label")
            .openapi_schema(schema, required);
        fields = fields.field(&input.name, field)?;
    }
    Ok(fields)
}

fn configured_grant(calls: Arc<AtomicUsize>) -> DeviceGrant<StatelessSchema> {
    let authorize_calls = calls.clone();
    let redemption_calls = calls.clone();
    DeviceGrant::new(
        move |_, _| {
            let _ = authorize_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                Err(AuthError::internal(
                    "Schema generation called authorizeRequest",
                ))
            })
        },
        move |_, _| {
            let _ = redemption_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                Err(AuthError::internal(
                    "Schema generation called assertSessionRedemption",
                ))
            })
        },
    )
    .verification_context(move |_| {
        let _ = calls.fetch_add(1, Ordering::SeqCst);
        Err(AuthError::internal(
            "Schema generation called getVerificationContext",
        ))
    })
}

async fn document(
    fields: DeviceRequestFields,
    grant: bool,
    calls: Arc<AtomicUsize>,
) -> AuthResult<Value> {
    let mut config =
        AuthConfig::new("ordinary-device-request-schema-secret-at-least-32-characters")
            .base_url("http://device-request-schema.test");
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    let builder = BetterAuth::stateless(config).rate_limit(RateLimitConfig::new().enabled(false));
    let plugin = DeviceAuthorizationPlugin::new().request_fields(fields);
    let builder = if grant {
        builder.plugin(plugin.grant(configured_grant(calls)))
    } else {
        builder.plugin(plugin)
    };
    let auth = builder.plugin(OpenApiPlugin::new()).build().await?;
    Ok(auth.openapi_spec()?.to_value()?)
}

fn property_keys(schema: Option<&Value>) -> Option<Vec<String>> {
    schema
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object)
        .map(|properties| properties.keys().cloned().collect())
}

fn observe_operations(document: &Value) -> AuthResult<Vec<Operation>> {
    OPERATIONS
        .into_iter()
        .map(|(path, method)| {
            let operation = document
                .get("paths")
                .and_then(|paths| paths.get(path))
                .and_then(|path| path.get(method))
                .ok_or_else(|| {
                    AuthError::internal(format!("Expected the complete {method} {path} operation"))
                })?;
            let responses = operation
                .get("responses")
                .and_then(Value::as_object)
                .ok_or_else(|| AuthError::internal(format!("Expected responses for {path}")))?;
            let request = operation.pointer("/requestBody/content/application~1json/schema");
            let request_required = request
                .and_then(|schema| schema.get("required"))
                .map(|required| serde_json::from_value(required.clone()))
                .transpose()?;
            Ok(Operation {
                path: path.into(),
                method: method.into(),
                operation: operation.clone(),
                response_keys: responses.keys().cloned().collect(),
                request_property_keys: property_keys(request),
                request_required,
                response_property_keys: responses
                    .iter()
                    .map(|(status, response)| ResponseProperties {
                        status: status.clone(),
                        keys: property_keys(response.pointer("/content/application~1json/schema")),
                    })
                    .collect(),
            })
        })
        .collect()
}

#[tokio::test]
async fn device_request_schemas_match_upstream_operations_and_input_requiredness()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let expected: Fixture = serde_json::from_str(&std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/device-request-schema-1.7.6.json"
    ))?)?;
    same(
        &expected.version.as_str(),
        &"1.7.6",
        "Pinned upstream version",
    )?;
    same(
        &expected
            .cases
            .iter()
            .map(|case| case.name.as_str())
            .collect::<Vec<_>>(),
        &vec!["mixed-inputs", "optional-inputs", "replacement-position"],
        "Complete request schema matrix",
    )?;
    let mut cases = Vec::new();
    for case in &expected.cases {
        let calls = Arc::new(AtomicUsize::new(0));
        let fields = request_fields(&case.fields, calls.clone())?;
        let document = document(fields, true, calls.clone()).await?;
        let callback_calls = calls.load(Ordering::SeqCst);
        same(
            &callback_calls,
            &0,
            "Schema generation must not execute callbacks",
        )?;
        cases.push(SchemaCase {
            name: case.name.clone(),
            fields: case.fields.clone(),
            operations: observe_operations(&document)?,
            callback_calls,
        });
    }
    same(
        &Fixture {
            version: "1.7.6".into(),
            cases,
        },
        &expected,
        "Device request schema operations",
    )?;
    Ok(())
}

#[tokio::test]
async fn standalone_annotations_keep_native_requiredness_and_omit_unannotated_fields()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let baseline = document(DeviceRequestFields::new(), false, calls.clone()).await?;
    let unannotated =
        DeviceRequestFields::new().field("hidden", unexpected_field(calls.clone(), false))?;
    same(
        &document(unannotated.clone(), false, calls.clone()).await?,
        &baseline,
        "Unannotated fields leave standalone documentation unchanged",
    )?;
    let fields = unannotated.field(
        "2",
        unexpected_field(calls.clone(), false).openapi_schema(json!({ "type": "string" }), true),
    )?;
    let actual = document(fields, false, calls.clone()).await?;
    let schema = actual
        .pointer("/paths/~1device~1code/post/requestBody/content/application~1json/schema")
        .ok_or_else(|| AuthError::internal("Expected the standalone Device request schema"))?;
    same(
        &schema.get("required"),
        &Some(&json!(["2", "client_id"])),
        "Standalone required fields follow property order",
    )?;
    same(
        &schema.pointer("/properties/hidden"),
        &None,
        "Unannotated validator remains undocumented",
    )?;
    same(&schema.pointer("/properties/client_id"),
        &baseline.pointer("/paths/~1device~1code/post/requestBody/content/application~1json/schema/properties/client_id"),
        "Standalone native client schema remains unchanged")?;
    same(
        &calls.load(Ordering::SeqCst),
        &0,
        "Standalone schema generation must not execute validators",
    )?;
    Ok(())
}
