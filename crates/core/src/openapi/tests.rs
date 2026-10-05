use super::{OpenApiBuilder, OpenApiRegistry, OpenApiRouteMetadata, OpenApiSpec};
use crate::{AuthConfig, HttpMethod, user_fields::UserConfig};
use serde_json::json;

fn core_spec() -> OpenApiSpec {
    OpenApiRegistry::new(
        &AuthConfig::default(),
        &UserConfig::default(),
        [],
        false,
        false,
        &Default::default(),
    )
    .unwrap()
    .generate("http://localhost:3000/api/auth")
}

#[test]
fn test_builder_core_routes() {
    let spec = core_spec();
    assert_eq!(spec.openapi, "3.1.1");
    assert_eq!(spec.info.title, "Better Auth");
    assert!(spec.paths.contains_key("/ok"));
    assert!(spec.paths.contains_key("/error"));
    assert!(spec.paths.contains_key("/update-user"));
    let ok = &spec.paths["/ok"]["get"];
    assert_eq!(ok["responses"]["200"]["description"], "API is working");
    assert!(ok.get("operationId").is_none());
}

#[test]
fn test_builder_custom_route() {
    let spec = OpenApiBuilder::new("Test", "1.0.0")
        .documented_route(
            &HttpMethod::Post,
            "/sign-in/email",
            Some("email-password"),
            &OpenApiRouteMetadata {
                operation_id: Some("sign_in_email".into()),
                ..Default::default()
            },
        )
        .build();
    let path = &spec.paths["/sign-in/email"];
    assert!(path.contains_key("post"));
    assert_eq!(path["post"]["tags"], json!(["Email-password"]));
}

#[test]
fn test_native_response_status_order() -> Result<(), Box<dyn std::error::Error>> {
    let spec = OpenApiBuilder::new("Test", "1.0.0")
        .documented_route(
            &HttpMethod::Get,
            "/custom",
            Some("custom"),
            &OpenApiRouteMetadata {
                responses: [
                    ("default", json!({"description":"Default response"})),
                    ("201", json!({"description":"Created"})),
                    ("2XX", json!({"description":"Successful response"})),
                    ("400", json!({"description":"Custom validation error"})),
                    ("200", json!({"description":"OK"})),
                ]
                .into_iter()
                .map(|(status, response)| (status.into(), response))
                .collect(),
                ..Default::default()
            },
        )
        .build()
        .to_value()?;
    let responses = spec
        .pointer("/paths/~1custom/get/responses")
        .and_then(serde_json::Value::as_object)
        .ok_or("custom route response metadata is missing or is not an object")?;
    assert_eq!(
        responses.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "200", "201", "400", "401", "403", "404", "429", "500", "default", "2XX"
        ]
    );
    assert_eq!(
        responses.get("400").ok_or("400 response is missing")?,
        &json!({"description":"Custom validation error"})
    );
    Ok(())
}

#[test]
fn test_spec_to_json() {
    let output = core_spec().to_json().unwrap();
    assert!(output.contains("\"openapi\": \"3.1.1\""));
    assert!(output.contains("\"/ok\""));
}

#[test]
fn test_spec_to_value() {
    let value = core_spec().to_value().unwrap();
    assert_eq!(value["openapi"], "3.1.1");
    assert!(value["paths"]["/ok"]["get"]["responses"]["200"].is_object());
    assert!(value["paths"]["/sign-up/email"]["post"]["operationId"].is_string());
}
