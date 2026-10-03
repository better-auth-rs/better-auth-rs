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
