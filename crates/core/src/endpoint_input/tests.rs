#![expect(
    clippy::panic_in_result_fn,
    reason = "Regressions assert request identity, getter scheduling, and cache invalidation."
)]

use super::{EndpointInputPatch, ValidatedBody, ValidatedInput};
use crate::{
    AuthError, AuthRequest, AuthResult, FieldMap, FieldObject, FieldValue, HttpMethod,
    field_value::{FieldObjectSource, FieldPropertyDescriptor},
    hooks::RequestHookContext,
};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn object(value: &FieldValue) -> AuthResult<&FieldObject> {
    value
        .as_object()
        .ok_or_else(|| AuthError::internal("Expected input object"))
}

fn request(mode: &str) -> AuthResult<AuthRequest> {
    let mut request = AuthRequest::new(HttpMethod::Post, "/input");
    request.body = Some(br#"{ "name": "before", "metadata": { "value": 1 } }"#.to_vec());
    match mode {
        "http-json" => {
            let _ = request
                .headers
                .insert("content-type".into(), "application/json".into());
            request.parse_http_body(&["application/json".into()])?;
        }
        "http-form" => {
            request.body = Some(b"name=before&metadata=raw".to_vec());
            let _ = request.headers.insert(
                "content-type".into(),
                "application/x-www-form-urlencoded".into(),
            );
            request.parse_http_body(&["application/x-www-form-urlencoded".into()])?;
        }
        "json-projection" => request.set_endpoint_body(ValidatedBody::new(
            Some(json!({"name": "before", "metadata": {"value": 1}})),
            "typed".to_owned(),
        )),
        _ => (),
    }
    Ok(request)
}

#[test]
fn input_reads_and_request_clones_share_one_live_projection() -> AuthResult<()> {
    for mode in ["raw", "http-json", "http-form", "json-projection"] {
        let request = request(mode)?;
        let before_read = request.clone();
        let bytes = request.body.clone();
        let first = request.input_field_value()?;
        assert!(first.strict_equals(&request.input_field_value()?), "{mode}");
        assert!(
            first.strict_equals(&before_read.input_field_value()?),
            "{mode}"
        );
        assert!(
            first.strict_equals(&request.clone().input_field_value()?),
            "{mode}"
        );
        let input = request.unvalidated_input()?;
        assert!(first.strict_equals(&input.field_value()), "{mode}");
        assert!(input.get::<String>().is_none());
        if mode == "json-projection" {
            assert_eq!(
                request.validated_body::<String>().map(String::as_str),
                Some("typed")
            );
        }
        object(&first)?.set("name", "after".into())?;
        let expected = if mode == "http-form" {
            json!({"name": "after", "metadata": "raw"})
        } else {
            json!({"name": "after", "metadata": {"value": 1}})
        };
        assert_eq!(request.input_body()?, Some(expected.clone()), "{mode}");
        assert_eq!(before_read.input_body()?, Some(expected.clone()), "{mode}");
        assert_eq!(request.body_as_json::<Value>()?, expected, "{mode}");
        assert_eq!(request.body, bytes, "{mode}");
        if let Some(snapshot) = request.parsed_http_body() {
            assert_eq!(snapshot.get("name"), Some(&json!("before")));
        }
    }
    Ok(())
}

#[test]
fn raw_replacement_detaches_cached_input_without_invalidating_other_clones() -> AuthResult<()> {
    for mode in ["raw", "http-json", "http-form", "json-projection"] {
        let mut request = request(mode)?;
        let unchanged = request.clone();
        let initial = request.input_field_value()?;
        object(&initial)?.set("name", "mutated".into())?;
        request.body = Some(br#"{"name":"replacement"}"#.to_vec());
        let replacement = request.input_field_value()?;
        assert!(!initial.strict_equals(&replacement), "{mode}");
        assert!(
            replacement.strict_equals(&request.input_field_value()?),
            "{mode}"
        );
        assert!(
            replacement.strict_equals(&request.clone().input_field_value()?),
            "{mode}"
        );
        assert!(
            initial.strict_equals(&unchanged.input_field_value()?),
            "{mode}"
        );
        assert_eq!(
            object(&unchanged.input_field_value()?)?.get("name")?,
            Some("mutated".into())
        );
        assert_eq!(
            request.input_body()?,
            Some(json!({"name": "replacement"})),
            "{mode}"
        );
        assert!(request.validated_body::<String>().is_none());
        assert!(request.parsed_http_body().is_none());
        request.body = Some(b"{".to_vec());
        assert!(request.input_field_value().is_err(), "{mode}");
        assert!(request.input_body().is_err(), "{mode}");
        assert!(
            initial.strict_equals(&unchanged.input_field_value()?),
            "{mode}"
        );
    }
    Ok(())
}

struct ReadProbe(AtomicUsize);

impl ReadProbe {
    fn reject<T>(&self) -> AuthResult<T> {
        let _ = self.0.fetch_add(1, Ordering::SeqCst);
        Err(AuthError::internal("Input property was read"))
    }
}

impl FieldObjectSource for ReadProbe {
    fn own_keys(&self) -> AuthResult<Vec<String>> {
        self.reject()
    }
    fn own_property_descriptor(&self, _: &str) -> AuthResult<Option<FieldPropertyDescriptor>> {
        self.reject()
    }
    fn get_with_receiver(&self, _: &str, _receiver: &FieldValue) -> AuthResult<Option<FieldValue>> {
        self.reject()
    }
    fn set_with_receiver(
        &self,
        _: String,
        _: FieldValue,
        _receiver: &FieldValue,
    ) -> AuthResult<bool> {
        self.reject()
    }
    fn delete(&self, _: &str) -> AuthResult<bool> {
        self.reject()
    }
    fn snapshot_fields(&self) -> AuthResult<FieldMap> {
        self.reject()
    }
    fn identity(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }

    fn define_own_property(
        &self,
        _name: String,
        _definition: crate::FieldPropertyDefinition,
    ) -> AuthResult<bool> {
        Err(AuthError::internal(
            "This contract source does not define properties",
        ))
    }
}

#[test]
fn native_input_reads_and_hook_snapshots_do_not_traverse_getters() -> AuthResult<()> {
    let source = Arc::new(ReadProbe(AtomicUsize::new(0)));
    let value = FieldValue::Object(FieldObject::from_source(source.clone()));
    let validated = ValidatedBody::native(value.clone(), "typed".to_owned());
    assert!(value.strict_equals(&validated.field_value()));
    assert!(value.strict_equals(&validated.clone().field_value()));
    let mut request = AuthRequest::new(HttpMethod::Post, "/input");
    request.set_endpoint_body(validated);
    let clone = request.clone();
    assert!(value.strict_equals(&request.input_field_value()?));
    assert!(value.strict_equals(&request.input_field_value()?));
    assert!(value.strict_equals(&clone.input_field_value()?));
    assert!(value.strict_equals(&request.unvalidated_input()?.field_value()));
    let hook = RequestHookContext::from_request(&request)?;
    assert!(value.strict_equals(&hook.body));
    assert!(value.strict_equals(&hook.request.input_field_value()?));
    assert_eq!(
        request.validated_body::<String>().map(String::as_str),
        Some("typed")
    );
    assert_eq!(source.0.load(Ordering::SeqCst), 0);
    assert!(request.input_body().is_err());
    assert_eq!(source.0.load(Ordering::SeqCst), 1);
    assert!(value.strict_equals(&clone.input_field_value()?));
    assert_eq!(source.0.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn raw_cache_preserves_http_policy_and_empty_body_json_errors() -> AuthResult<()> {
    let mut request = AuthRequest::new(HttpMethod::Post, "/input");
    request.body = Some(b"invalid=json".to_vec());
    let hook = RequestHookContext::from_request(&request)?;
    assert_eq!(hook.body, FieldValue::Undefined);
    assert!(request.parsed_http_body().is_none());
    request.body = Some(Vec::new());
    assert_eq!(request.input_field_value()?, FieldValue::Undefined);
    assert!(request.body_as_json::<Value>().is_err());
    Ok(())
}

#[test]
fn query_clones_share_identity_until_the_raw_source_changes() -> AuthResult<()> {
    let mut request = AuthRequest::new(HttpMethod::Get, "/input");
    request.query = Some(json!({"name":"before", "metadata":{"value":1}}));
    let before_read = request.clone();
    let input = request.input_query_field_value()?;
    assert!(input.strict_equals(&before_read.input_query_field_value()?));
    object(&input)?.set("name", "live".into())?;
    assert_eq!(request.query_string("name")?, Some("live".to_owned()));
    assert_eq!(
        before_read.input_query()?,
        Some(json!({"name":"live", "metadata":{"value":1}}))
    );
    request.set_endpoint_query(ValidatedInput::native(input.clone(), 7_u32));
    let unchanged = request.clone();
    assert_eq!(request.validated_query::<u32>(), Some(&7));
    request.query = Some(json!({"name":"replacement"}));
    let replacement = request.input_query_field_value()?;
    assert!(!input.strict_equals(&replacement));
    assert!(replacement.strict_equals(&request.clone().input_query_field_value()?));
    assert!(input.strict_equals(&unchanged.input_query_field_value()?));
    assert!(request.validated_query::<u32>().is_none());
    assert_eq!(unchanged.validated_query::<u32>(), Some(&7));
    assert_eq!(
        request.query_string("name")?,
        Some("replacement".to_owned())
    );
    assert_eq!(unchanged.query_string("name")?, Some("live".to_owned()));
    Ok(())
}

#[test]
fn query_source_reordering_invalidates_raw_and_typed_caches() -> AuthResult<()> {
    for (before, after) in [
        (r#"{"first":1,"second":2}"#, r#"{"second":2,"first":1}"#),
        (
            r#"{"nested":{"first":1,"second":2}}"#,
            r#"{"nested":{"second":2,"first":1}}"#,
        ),
        (
            r#"{"nested":[{"first":1,"second":2}]}"#,
            r#"{"nested":[{"second":2,"first":1}]}"#,
        ),
    ] {
        for typed in [false, true] {
            let mut request = AuthRequest::new(HttpMethod::Get, "/input");
            request.query = Some(serde_json::from_str(before)?);
            let initial = request.input_query_field_value()?;
            if typed {
                request.set_endpoint_query(ValidatedInput::native(initial.clone(), 1_u32));
            }
            let unchanged = request.clone();
            request.query = Some(serde_json::from_str(after)?);
            let replacement = request.input_query_field_value()?;
            assert!(!initial.strict_equals(&replacement));
            assert!(initial.strict_equals(&unchanged.input_query_field_value()?));
            assert_eq!(initial.stringify()?.as_deref(), Some(before));
            assert_eq!(replacement.stringify()?.as_deref(), Some(after));
            assert!(request.validated_query::<u32>().is_none());
            assert_eq!(unchanged.validated_query::<u32>().is_some(), typed);
        }
    }
    let mut request = AuthRequest::new(HttpMethod::Get, "/input");
    request.query = Some(serde_json::from_str("-0.0")?);
    let negative = request.input_query_field_value()?;
    request.set_endpoint_query(ValidatedInput::native(negative.clone(), 1_u32));
    request.query = Some(serde_json::from_str("0.0")?);
    assert_eq!(
        negative.as_f64().map(f64::to_bits),
        Some((-0.0_f64).to_bits())
    );
    assert_eq!(
        request
            .input_query_field_value()?
            .as_f64()
            .map(f64::to_bits),
        Some(0.0_f64.to_bits())
    );
    assert!(request.validated_query::<u32>().is_none());
    Ok(())
}

#[tokio::test]
async fn native_query_validation_does_not_cross_the_legacy_json_bridge() -> AuthResult<()> {
    let source = Arc::new(ReadProbe(AtomicUsize::new(0)));
    let value = FieldValue::Object(FieldObject::from_source(source.clone()));
    let mut request = AuthRequest::new(HttpMethod::Get, "/input");
    request.set_endpoint_query(ValidatedInput::native(value.clone(), "raw".to_owned()));
    let scope = RequestHookContext::from_request(&request)?;
    assert!(value.strict_equals(&scope.query));
    assert!(value.strict_equals(&scope.request.input_query_field_value()?));
    let route = crate::AuthRoute::get("/input", "input").query_validator_native(|request| {
        Ok(ValidatedInput::native(
            request.input_query_field_value()?,
            "validated".to_owned(),
        ))
    });
    let output = route
        .query_validator
        .ok_or_else(|| AuthError::internal("Expected a native query validator"))?
        .validate(&request)
        .await?;
    assert!(value.strict_equals(&output.field_value()));
    request.set_endpoint_query(output);
    assert_eq!(
        request.validated_query::<String>().map(String::as_str),
        Some("validated")
    );
    assert_eq!(source.0.load(Ordering::SeqCst), 0);

    // The legacy callback cannot run until its explicit JSON bridge reads the input.
    let legacy = crate::AuthRoute::get("/input", "input").query_validator(Ok);
    assert!(
        legacy
            .query_validator
            .ok_or_else(|| AuthError::internal("Expected a JSON query validator"))?
            .validate(&request)
            .await
            .is_err()
    );
    assert_eq!(source.0.load(Ordering::SeqCst), 1);
    assert!(request.query_string("name").is_err());
    assert_eq!(source.0.load(Ordering::SeqCst), 2);
    assert!(value.strict_equals(&request.clone().input_query_field_value()?));
    Ok(())
}

#[test]
fn query_patch_retains_native_values_and_the_existing_recursive_merge() -> AuthResult<()> {
    let retained: FieldValue = FieldMap::from([("same".into(), true.into())]).into();
    let replacement: FieldValue = vec!["patch".into()].into();
    let date = FieldValue::Date(crate::FieldDate::from_milliseconds(1_000.0));
    let raw = json!({"list":["old"],"nested":{"keep":true,"replace":"before"},"name":"raw"});
    let mut request = AuthRequest::new(HttpMethod::Get, "/input");
    request.query = Some(raw.clone());
    let original = request.input_query_field_value()?;
    let mut patch = EndpointInputPatch {
        query: Some(
            FieldMap::from([
                ("retained".into(), retained.clone()),
                ("date".into(), date.clone()),
                ("nan".into(), f64::NAN.into()),
                ("list".into(), replacement.clone()),
                (
                    "nested".into(),
                    json!({"replace":"after","null":null,"constructor":"ignored"}).into(),
                ),
            ])
            .into(),
        ),
        ..Default::default()
    };
    patch.merge(EndpointInputPatch {
        query: Some(
            FieldMap::from([
                ("name".into(), FieldValue::Null),
                ("retained".into(), FieldValue::Undefined),
                ("__proto__".into(), "ignored".into()),
            ])
            .into(),
        ),
        ..Default::default()
    })?;
    patch.apply(&mut request)?;
    let merged = request.input_query_field_value()?;
    assert!(!original.strict_equals(&merged));
    assert!(merged.model_property("retained")?.strict_equals(&retained));
    assert!(merged.model_property("date")?.strict_equals(&date));
    assert!(
        merged
            .model_property("nan")?
            .as_f64()
            .is_some_and(f64::is_nan)
    );
    assert!(merged.model_property("list")?.strict_equals(&replacement));
    assert_eq!(
        merged.model_property("nested")?.json()?,
        Some(json!({"keep":true,"replace":"after"}))
    );
    assert_eq!(merged.model_property("name")?, "raw".into());
    assert!(merged.model_property("__proto__")?.is_undefined());
    assert_eq!(request.query, Some(raw.clone()));
    assert_eq!(original.json()?, Some(raw));
    Ok(())
}
