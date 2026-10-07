use super::*;
use axum::{Router, body::Body, http::Request as HttpRequest};
use better_auth::integrations::axum::AxumIntegration;
use better_auth::seaorm::__private_chrono::{DateTime, Utc};
use tower::ServiceExt;

pub(super) fn now() -> i64 {
    Utc::now().timestamp_millis()
}

fn timestamp(value: &Value) -> TestResult<i64> {
    let text = value
        .as_str()
        .or_else(|| {
            (value["type"] == "date")
                .then(|| value["value"].as_str())
                .flatten()
        })
        .ok_or("Expected a timestamp string or Date observation")?;
    Ok(text.parse::<DateTime<Utc>>()?.timestamp_millis())
}

#[derive(Default)]
pub(super) struct Dates(BTreeMap<String, BTreeMap<&'static str, i64>>);

impl Dates {
    pub(super) fn insert(
        &mut self,
        stored: &Value,
        window: std::ops::RangeInclusive<i64>,
    ) -> TestResult {
        for row in stored.as_array().ok_or("Expected API Key rows")? {
            let id = row["id"].as_str().ok_or("Missing API Key ID")?;
            let times = ["createdAt", "updatedAt"]
                .into_iter()
                .map(|field| Ok((field, timestamp(&row[field])?)))
                .collect::<TestResult<BTreeMap<_, _>>>()?;
            if let Some(previous) = self.0.get(id) {
                assert_eq!(
                    &times, previous,
                    "The existing API Key dates must remain unchanged"
                );
            } else {
                for time in times.values() {
                    assert!(
                        window.contains(time),
                        "The API Key date must use the operation clock"
                    );
                }
                assert_eq!(times["createdAt"], times["updatedAt"]);
                let _ = self.0.insert(id.into(), times);
            }
        }
        Ok(())
    }

    pub(super) fn normalize(&self, value: &Value) -> TestResult<Value> {
        Ok(match value {
            Value::Array(values) => Value::Array(
                values
                    .iter()
                    .map(|value| self.normalize(value))
                    .collect::<TestResult<_>>()?,
            ),
            Value::Object(fields) => {
                let id = fields.get("id").and_then(Value::as_str);
                let mut result = serde_json::Map::new();
                for (key, value) in fields {
                    let normalized = if let Some(id) = id
                        && matches!(key.as_str(), "createdAt" | "updatedAt")
                    {
                        let times = self
                            .0
                            .get(id)
                            .ok_or("Response or storage contains an unknown API Key ID")?;
                        assert_eq!(
                            timestamp(value)?,
                            times[key.as_str()],
                            "Response dates must equal stored dates"
                        );
                        let marker = format!("<{id}.{key}>");
                        if value.is_string() {
                            json!(marker)
                        } else {
                            json!({"type":"date", "value":marker})
                        }
                    } else {
                        self.normalize(value)?
                    };
                    let _ = result.insert(key.clone(), normalized);
                }
                Value::Object(result)
            }
            value => value.clone(),
        })
    }
}

pub(super) async fn request<S: AuthSchema>(
    auth: Arc<BetterAuth<S>>,
    input: &Request,
    cookie: &str,
) -> TestResult<Response> {
    let router = Router::new()
        .nest("/api/auth", auth.clone().axum_router())
        .with_state(auth);
    let mut request = HttpRequest::builder()
        .method(input.method.as_str())
        .uri(&input.url);
    for [name, value] in &input.headers {
        let value = if name == "cookie" {
            assert_eq!(value, "better-auth.session_token=<owner-session-cookie>");
            cookie
        } else {
            value
        };
        request = request.header(name, value);
    }
    let body = input.body.clone().map_or_else(Body::empty, Body::from);
    let response = router.oneshot(request.body(body)?).await?;
    let status = response.status().as_u16();
    let mut headers = response
        .headers()
        .iter()
        .map(|(name, value)| Ok([name.to_string(), value.to_str()?.to_owned()]))
        .collect::<TestResult<Vec<_>>>()?;
    headers.sort();
    let cookies = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|value| value.to_str().map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    let body = String::from_utf8(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await?
            .to_vec(),
    )?;
    for [name, value] in &headers {
        if name == "content-length" {
            assert_eq!(value.parse::<usize>()?, body.len());
        }
    }
    headers.retain(|[name, _]| name != "content-length");
    Ok(Response {
        status,
        status_text: String::new(),
        headers,
        cookies,
        body,
    })
}

pub(super) fn assert_response(actual: Response, expected: &Response, dates: &Dates) -> TestResult {
    assert_eq!(actual.status, expected.status);
    assert_eq!(actual.headers, expected.headers);
    assert_eq!(actual.cookies, expected.cookies);
    assert_eq!(
        expected.status_text,
        if expected.status == 400 { "400" } else { "" }
    );
    let body: Value = serde_json::from_str(&actual.body)?;
    assert_eq!(
        dates.normalize(&body)?,
        serde_json::from_str::<Value>(&expected.body)?
    );
    Ok(())
}
