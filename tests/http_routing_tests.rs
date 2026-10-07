#![cfg(feature = "axum")]

#[path = "../compat-tests/rust-server/src/trailing_slashes.rs"]
mod fixture;

use axum::{
    body::{Body, to_bytes},
    http::Request,
};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::server_api::EndpointInput;
use better_auth_core::{AuthError, AuthRequest, HttpMethod};
use serde_json::{Value, json};
use tower::ServiceExt;

#[tokio::test]
async fn nested_axum_routes_keep_relative_matching_and_original_transport_urls() {
    for tolerant in [false, true] {
        let (auth, events) = fixture::auth(
            if tolerant {
                "trailing-slashes-true"
            } else {
                "trailing-slashes-false"
            },
            "http://localhost:3000",
        )
        .await
        .unwrap();
        let app = axum::Router::new()
            .nest("/mounted/auth", auth.clone().axum_router())
            .with_state(auth);
        for (path, status) in [
            ("/probe", 200),
            ("/probe/", if tolerant { 200 } else { 404 }),
            ("/disabled//", 404),
        ] {
            events.lock().unwrap().clear();
            let url = format!("/mounted/auth{path}?proof=original");
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("http://localhost:3000{url}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), status, "{url}");
            if status == 200 {
                let body = to_bytes(response.into_body(), 8192).await.unwrap();
                let body: Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(body["url"], url);
                assert_eq!(body["path"], "/probe");
                assert_eq!(body["query"], json!({"proof":"original"}));
            }
            if path == "/disabled//" {
                assert!(events.lock().unwrap().is_empty());
            }
        }
    }
}

#[tokio::test]
async fn http_route_selection_preserves_transport_url_and_named_endpoint_context() {
    for tolerant in [false, true] {
        let profile = if tolerant {
            "trailing-slashes-true"
        } else {
            "trailing-slashes-false"
        };
        let app = fixture::router(profile, "http://localhost:3000")
            .await
            .unwrap();
        for method in ["GET", "POST"] {
            for (path, endpoint, matched) in [
                ("/api/auth/dynamic/value", "/dynamic/:id", true),
                ("/api/auth/dynamic/value/", "/dynamic/:id", tolerant),
                ("/api/auth/declared/", "/declared/", true),
                ("/api/auth/declared", "/declared/", tolerant),
                ("/api/auth/dynamic/value//", "", false),
                ("/api/authentication/dynamic/value", "", false),
                ("/dynamic/value", "", false),
            ] {
                let url = format!("{path}?proof=unchanged");
                let response = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .method(method)
                            .uri(format!("http://localhost:3000{url}"))
                            .header("content-type", "application/json")
                            .body(if method == "POST" {
                                Body::from(r#"{"proof":"body"}"#)
                            } else {
                                Body::empty()
                            })
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    response.status().as_u16(),
                    if matched { 200 } else { 404 },
                    "{profile}: {method} {url}"
                );
                assert!(response.headers().get("location").is_none());
                let body = to_bytes(response.into_body(), 8192).await.unwrap();
                if matched {
                    let body: Value = serde_json::from_slice(&body).unwrap();
                    assert_eq!(body["path"], endpoint);
                    assert_eq!(body["url"], url);
                    assert_eq!(body["query"], json!({"proof":"unchanged"}));
                    assert_eq!(
                        body["params"],
                        if endpoint == "/dynamic/:id" {
                            json!({"id":"value"})
                        } else {
                            json!({})
                        }
                    );
                    assert_eq!(
                        body["body"],
                        if method == "POST" {
                            json!({"proof":"body"})
                        } else {
                            Value::Null
                        }
                    );
                } else {
                    assert!(body.is_empty());
                }
            }
        }
    }
}

#[tokio::test]
async fn native_matching_stays_exact_and_url_less_http_keeps_base_relative_support() {
    for tolerant in [false, true] {
        let profile = if tolerant {
            "trailing-slashes-true"
        } else {
            "trailing-slashes-false"
        };
        let (auth, events) = fixture::auth(profile, "http://localhost:3000")
            .await
            .unwrap();
        for (path, status) in [("/probe", 200), ("/probe/", 404)] {
            events.lock().unwrap().clear();
            let result = auth
                .call_endpoint(HttpMethod::Get, path, EndpointInput::default())
                .await;
            if status == 404 {
                let error = result.expect_err("an unmatched native endpoint returns an API error");
                assert!(matches!(error, AuthError::Response(_)));
                assert_eq!(error.status_code(), status);
            } else {
                assert_eq!(result.unwrap().status, status);
            }
            let events = events.lock().unwrap();
            assert!(events.iter().all(|event| !matches!(
                event["phase"].as_str(),
                Some("http" | "response" | "later-response")
            )));
        }
        for path in ["/probe", "/api/auth/probe"] {
            assert_eq!(
                auth.handle_request(AuthRequest::new(HttpMethod::Get, path))
                    .await
                    .unwrap()
                    .status,
                200
            );
        }
        assert_eq!(
            auth.handle_request(AuthRequest::new(HttpMethod::Get, "/probe/"))
                .await
                .unwrap()
                .status,
            if tolerant { 200 } else { 404 }
        );
    }
}

#[tokio::test]
async fn response_hooks_cover_router_errors_but_skip_disabled_and_early_responses() {
    let (auth, events) = fixture::auth("trailing-slashes-true", "http://localhost:3000")
        .await
        .unwrap();
    for (path, content_type, body, status, phases) in [
        (
            "/probe",
            "application/json",
            "{",
            400,
            vec!["http", "response"],
        ),
        (
            "/probe",
            "text/plain",
            "body",
            415,
            vec!["http", "response"],
        ),
        (
            "/missing",
            "application/json",
            "{}",
            404,
            vec!["http", "response"],
        ),
        ("/disabled//", "application/json", "{}", 404, vec![]),
        ("/early", "application/json", "{}", 202, vec!["http"]),
        (
            "/replace-response",
            "application/json",
            "{}",
            202,
            vec!["http", "before", "endpoint", "after", "response"],
        ),
        (
            "/response-chain",
            "application/json",
            "{}",
            200,
            vec![
                "http",
                "before",
                "endpoint",
                "after",
                "response",
                "later-response",
            ],
        ),
    ] {
        events.lock().unwrap().clear();
        let mut request = AuthRequest::new(HttpMethod::Post, format!("/api/auth{path}"))
            .with_url(url::Url::parse(&format!("http://localhost:3000/api/auth{path}")).unwrap());
        let _ = request
            .headers
            .insert("content-type".to_owned(), content_type.to_owned());
        request.body = Some(body.as_bytes().to_vec());
        let response = auth.handle_request(request).await.unwrap();
        assert_eq!(response.status, status, "{path}");
        let events = events.lock().unwrap();
        assert_eq!(
            events
                .iter()
                .map(|event| event["phase"].as_str().unwrap())
                .collect::<Vec<_>>(),
            phases,
            "{path}"
        );
        if path == "/disabled//" {
            assert_eq!(response.body.bytes().unwrap().as_ref(), b"Not Found");
        }
        if path == "/replace-response" {
            assert_eq!(
                serde_json::from_slice::<Value>(&response.body.bytes().unwrap()).unwrap(),
                json!({"replaced":true})
            );
        }
        if path == "/response-chain" {
            assert_eq!(
                response.headers.get("x-response-chain"),
                Some(&"second".to_owned())
            );
        }
    }
}
