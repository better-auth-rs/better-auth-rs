use super::*;
use better_auth_core::request_runtime::ResolvedCookie;
use better_auth_core::utils::cookie_utils::{create_chunked_cookies, create_clear_chunked_cookies};

fn sorted(mut headers: Vec<Value>) -> Value {
    headers.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
    json!(headers)
}

#[test]
fn explicit_expiration_contributes_to_chunk_capacity_and_survives_cleanup() {
    let fixture = fixture();
    let source_anchor = fixture["metadata"]["serializerNow"].as_i64().unwrap();
    for name in ["omitted", "futureMillis"] {
        let now = anchor();
        let expected = &fixture["chunks"][name];
        let cookie = ResolvedCookie {
            name: "ordinary".into(),
            attributes: CookieAttributes {
                path: Some("/".into()),
                http_only: Some(true),
                same_site: Some(better_auth_core::SameSite::Lax),
                expires: date(&expected["input"]["expires"], source_anchor, now),
                ..Default::default()
            },
        };
        let mut request = AuthRequest::new(HttpMethod::Get, "/");
        let _ = request.headers.insert(
            "cookie".into(),
            "ordinary=display; ordinary.5=display".into(),
        );
        let headers = create_chunked_cookies(&request, &cookie, &"x".repeat(8000)).unwrap();
        let cleaned = create_clear_chunked_cookies(&request, &cookie).unwrap();
        for (label, actual) in [("chunk", headers), ("clean", cleaned)] {
            let expected_headers = expected[label]["value"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value["header"].clone())
                .collect();
            assert_eq!(
                normalize(
                    &sorted(actual.iter().map(|value| shape(value)).collect()),
                    now
                ),
                normalize(&sorted(expected_headers), source_anchor),
                "{name}/{label}"
            );
        }
        let mut probe = cookie;
        probe.name = "ordinary.99".into();
        let empty = render_cookie("", &probe).unwrap();
        assert_eq!(
            normalize(&shape(&empty), now),
            normalize(&expected["emptyChunkHeader"]["value"], source_anchor),
            "{name}/overhead"
        );
    }
}
