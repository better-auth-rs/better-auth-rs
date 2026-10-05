use better_auth::{
    AuthConfig, AuthError, AuthResult, BetterAuth,
    middleware::RateLimitConfig,
    plugins::{
        OpenApiPlugin,
        device_authorization::{DeviceAuthorizationPlugin, DeviceGrant},
    },
    store::StatelessSchema,
};
use serde::Deserialize;
use serde_json::{Map, Value};
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GrantInput {
    #[serde(default)]
    request_error_codes: Vec<String>,
    #[serde(default, rename = "requestOpenAPIResponses")]
    request_openapi_responses: Map<String, Value>,
    #[serde(default, rename = "verificationOpenAPIProperties")]
    verification_openapi_properties: Map<String, Value>,
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
    response_property_keys: Vec<ResponseProperties>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MetadataCase {
    name: String,
    grant: Option<Value>,
    operations: Vec<Operation>,
    callback_calls: usize,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfigurationErrorCase {
    name: String,
    grant: Value,
    error: String,
    callback_calls: usize,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Fixture {
    version: String,
    cases: Vec<MetadataCase>,
    configuration_errors: Vec<ConfigurationErrorCase>,
}

fn same<T: Debug + PartialEq>(actual: &T, expected: &T, label: &str) -> AuthResult<()> {
    if actual != expected {
        return Err(AuthError::internal(format!(
            "{label}: actual {actual:?}; expected {expected:?}"
        )));
    }
    Ok(())
}

fn configured_grant(
    input: &Value,
    calls: Arc<AtomicUsize>,
) -> AuthResult<DeviceGrant<StatelessSchema>> {
    let input: GrantInput = serde_json::from_value(input.clone())?;
    let authorize_calls = calls.clone();
    let redemption_calls = calls.clone();
    Ok(DeviceGrant::new(
        move |_, _| {
            let _ = authorize_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                Err(AuthError::internal(
                    "Metadata generation called authorizeRequest",
                ))
            })
        },
        move |_, _| {
            let _ = redemption_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                Err(AuthError::internal(
                    "Metadata generation called assertSessionRedemption",
                ))
            })
        },
    )
    .verification_context(move |_| {
        let _ = calls.fetch_add(1, Ordering::SeqCst);
        Err(AuthError::internal(
            "Metadata generation called getVerificationContext",
        ))
    })
    .request_error_codes(input.request_error_codes)
    .request_openapi_responses(input.request_openapi_responses)
    .verification_openapi_properties(input.verification_openapi_properties))
}

async fn document(grant: Option<&Value>, calls: Arc<AtomicUsize>) -> AuthResult<Value> {
    let mut config =
        AuthConfig::new("ordinary-device-grant-metadata-secret-at-least-32-characters")
            .base_url("http://device-grant-metadata.test");
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    let builder = BetterAuth::stateless(config).rate_limit(RateLimitConfig::new().enabled(false));
    let builder = if let Some(input) = grant {
        builder.plugin(DeviceAuthorizationPlugin::new().grant(configured_grant(input, calls)?))
    } else {
        builder.plugin(DeviceAuthorizationPlugin::new())
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
            Ok(Operation {
                path: path.into(),
                method: method.into(),
                operation: operation.clone(),
                response_keys: responses.keys().cloned().collect(),
                request_property_keys: property_keys(
                    operation.pointer("/requestBody/content/application~1json/schema"),
                ),
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
async fn device_grant_metadata_matches_complete_upstream_operations_and_key_order()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let expected: Fixture = serde_json::from_str(&std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/device-grant-metadata-1.7.6.json"
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
        &vec!["no-grant", "empty-grant", "custom-metadata"],
        "Complete ordinary metadata matrix",
    )?;
    same(
        &expected
            .configuration_errors
            .iter()
            .map(|case| case.name.as_str())
            .collect::<Vec<_>>(),
        &vec![
            "reserved-user-code",
            "reserved-status",
            "reserved-client-id",
            "reserved-scope",
            "reserved-declaration-order",
        ],
        "Complete configuration error matrix",
    )?;

    let mut cases = Vec::new();
    for case in &expected.cases {
        let calls = Arc::new(AtomicUsize::new(0));
        let document = document(case.grant.as_ref(), calls.clone()).await?;
        let callback_calls = calls.load(Ordering::SeqCst);
        same(
            &callback_calls,
            &0,
            "Metadata must not execute grant callbacks",
        )?;
        cases.push(MetadataCase {
            name: case.name.clone(),
            grant: case.grant.clone(),
            operations: observe_operations(&document)?,
            callback_calls,
        });
    }
    let mut configuration_errors = Vec::new();
    for case in &expected.configuration_errors {
        let calls = Arc::new(AtomicUsize::new(0));
        let error = match document(Some(&case.grant), calls.clone()).await {
            Err(AuthError::Config(message)) => message,
            Err(error) => return Err(error.into()),
            Ok(_) => {
                return Err(AuthError::internal(
                    "Reserved verification properties must reject plugin configuration",
                )
                .into());
            }
        };
        let callback_calls = calls.load(Ordering::SeqCst);
        same(
            &callback_calls,
            &0,
            "Configuration validation must not execute grant callbacks",
        )?;
        configuration_errors.push(ConfigurationErrorCase {
            name: case.name.clone(),
            grant: case.grant.clone(),
            error,
            callback_calls,
        });
    }
    same(
        &Fixture {
            version: "1.7.6".into(),
            cases,
            configuration_errors,
        },
        &expected,
        "Device grant metadata and configuration errors",
    )?;
    Ok(())
}
