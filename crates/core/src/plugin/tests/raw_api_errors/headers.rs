#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
use super::*;

#[tokio::test]
async fn headers_identity_controls_rereads_and_prevents_duplicate_context_cookies() -> AuthResult<()>
{
    for mode in ["falsey", "same", "distinct", "shifting"] {
        let events = Events::default();
        let captured = Arc::new(Mutex::new(FieldValue::Undefined));
        let first: FieldValue = {
            let mut headers = Headers::new();
            let _ = headers.insert("x-ignored", "first");
            headers.into()
        };
        let last: FieldValue = {
            let mut headers = Headers::new();
            let _ = headers.insert("x-final", "third");
            headers.append("set-cookie", "explicit=1");
            headers.into()
        };
        let getter: Getter = Arc::new({
            let events = events.clone();
            let captured = captured.clone();
            let reads = Mutex::new(0);
            move || {
                let mut reads = reads.lock().unwrap();
                *reads += 1;
                events.lock().unwrap().push(format!("headers:{reads}"));
                Ok(match mode {
                    "falsey" => FieldValue::Null,
                    "same" => captured.lock().unwrap().clone(),
                    "shifting" if *reads < 3 => first.clone(),
                    _ => last.clone(),
                })
            }
        });
        let value = raw_error(&events, &["APIError"], None, vec![("headers", getter)]);
        let mut config = (*crate::test_store::test_config()).clone();
        config.experimental.instrumentation.enabled = false;
        config.logger = crate::LoggerConfig {
            disabled: Some(true),
            level: Some(LogLevel::Warn),
            ..Default::default()
        }
        .into();
        let config = Arc::new(config);
        let context = AuthContext::new(config.clone(), Arc::new(EphemeralStore::new(config)))
            .expect("fixture context initializes");
        let route = AuthRoute::get("/raw-headers", "rawHeaders");
        let dispatcher = EndpointDispatcher::new(
            Arc::new(Vec::new()),
            EndpointHooks::default(),
            [route.clone()],
        );
        let error = dispatcher
            .native(
                AuthRequest::new(HttpMethod::Get, "/raw-headers"),
                route,
                &context,
                {
                    let captured = captured.clone();
                    let value = value.clone();
                    move |request, _context| async move {
                        let handle = request.response_headers_value()?;
                        assert!(handle.strict_equals(&request.clone().response_headers_value()?));
                        *captured.lock().unwrap() = handle;
                        request.set_response_header("x-handler", "1")?;
                        request.append_response_header("set-cookie", "context=1".into())?;
                        Err(AuthError::from_thrown(value))
                    }
                },
            )
            .await
            .unwrap_err();
        assert_raw(&error, &value);
        let count = match mode {
            "falsey" => 1,
            "same" => 2,
            _ => 3,
        };
        let mut expected: Vec<String> = ["name:1", "name:2", "name:3"].map(Into::into).into();
        expected.extend((1..=count).map(|read| format!("headers:{read}")));
        expected.extend(["name:4", "name:5"].map(Into::into));
        assert_eq!(*events.lock().unwrap(), expected, "{mode}");
        let original = captured.lock().unwrap().clone();
        assert_headers(
            &Headers::from_field_value(&original)?,
            &[("x-handler", "1")],
            &["context=1"],
        );
        let final_value = error.captured_headers_value().unwrap();
        assert!(!final_value.strict_equals(&original));
        let mut ordinary = vec![("x-handler", "1")];
        let mut cookies = vec!["context=1"];
        if count == 3 {
            ordinary.push(("x-final", "third"));
            cookies.push("explicit=1");
        }
        assert_headers(
            &Headers::from_field_value(&final_value)?,
            &ordinary,
            &cookies,
        );
    }
    Ok(())
}

#[tokio::test]
async fn router_error_callback_preserves_raw_identity_and_classification_count() -> AuthResult<()> {
    let events = Events::default();
    let value = raw_error(&events, &["APIError"], None, vec![]);
    let mut hooks = Hooks::new("before-throw", value, &events);
    hooks.router = true;
    let response = hooks.run(true, SchemaValue::Undefined).await?;
    assert_eq!(
        *events.lock().unwrap(),
        [
            "before", "name:1", "name:2", "name:3", "on-error", "name:4", "name:5"
        ]
    );
    assert_eq!(response.status, 418);
    assert_eq!(response.status_text, "BAD_REQUEST".into());
    assert_headers(
        &response.headers,
        &[("content-type", "application/json"), ("x-owned", "1")],
        &["owned=1"],
    );
    assert_eq!(
        response.body.bytes()?.as_ref(),
        br#"{"code":"RAW_API_ERROR","message":"raw failure"}"#
    );
    Ok(())
}
