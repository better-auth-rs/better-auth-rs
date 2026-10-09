use super::*;

#[test]
fn model_properties_preserve_native_identity_and_nullish_access_errors() -> AuthResult<()> {
    let id = FieldValue::from(FieldMap::from([("native".into(), true.into())]));
    let record = FieldValue::from(FieldMap::from([("id".into(), id.clone())]));
    assert!(record.model_property("id")?.strict_equals(&id));
    assert!(record.model_property("missing")?.is_undefined());
    for receiver in [false.into(), 0.0.into(), "".into(), vec![id].into()] {
        assert!(receiver.model_property("id")?.is_undefined());
    }
    for (receiver, kind) in [
        (FieldValue::Null, "null"),
        (FieldValue::Undefined, "undefined"),
    ] {
        assert!(
            matches!(receiver.model_property("id"), Err(AuthError::TypeError(message))
            if message == format!("Cannot read properties of {kind} (reading 'id')"))
        );
    }
    Ok(())
}

#[test]
fn ordinary_object_primitive_conversion_checks_only_the_selected_method() -> AuthResult<()> {
    let display = crate::Utf16String::from("[object Object]");
    for value in [
        serde_json::json!({}),
        serde_json::json!({"valueOf": null}),
        serde_json::json!({"nested": {"toString": null}}),
        serde_json::json!({"__proto__": {"toString": null}}),
    ] {
        let value = FieldValue::from_json(value)?;
        assert_eq!(value.display_utf16()?, display);
        assert!(crate::query::field_number(&value)?.is_nan());
        assert_eq!(
            crate::query::field_compare(&value, &FieldValue::from("[object Object]"))?,
            Some(std::cmp::Ordering::Equal)
        );
    }
    for method in [
        FieldValue::Undefined,
        FieldValue::Null,
        FieldValue::Bool(false),
        FieldValue::Number(0.0),
        FieldValue::from(""),
        FieldValue::from(Vec::<FieldValue>::new()),
        FieldValue::from(FieldMap::new()),
    ] {
        let object = FieldValue::from(FieldMap::from_iter([("toString".into(), method)]));
        for value in [object.clone(), FieldValue::from(vec![object])] {
            for result in [
                value.display_utf16().map(drop),
                crate::query::field_number(&value).map(drop),
                crate::query::field_compare(&value, &FieldValue::Null).map(drop),
                crate::query::field_compare(&FieldValue::Null, &value).map(drop),
            ] {
                assert!(matches!(result, Err(AuthError::Internal(message))
                    if message == "No default value"));
            }
        }
    }
    assert_eq!(
        FieldValue::from_json(serde_json::json!({"toString": null}))?.stringify()?,
        Some("{\"toString\":null}".into())
    );
    Ok(())
}

#[test]
fn object_identity_and_numeric_membership_use_distinct_comparisons() {
    let date = FieldValue::from(FieldDate::from_milliseconds(42.9));
    let same_time = FieldValue::from(FieldDate::from_milliseconds(42.0));
    assert_eq!(date, same_time);
    assert!(date.strict_equals(&date.clone()));
    assert!(!date.strict_equals(&same_time));

    let array = FieldValue::from(vec![date.clone()]);
    let same_contents = FieldValue::from(vec![date]);
    assert_eq!(array, same_contents);
    assert!(array.strict_equals(&array.clone()));
    assert!(!array.strict_equals(&same_contents));

    let nan = FieldValue::Number(f64::NAN);
    assert!(!nan.strict_equals(&nan));
    assert!(nan.same_value_zero(&nan));
    assert!(!nan.is_truthy());
    assert!(FieldValue::Number(-0.0).strict_equals(&FieldValue::Number(0.0)));
    assert!(!FieldValue::Number(2.0).same_value_zero(&FieldValue::String("2".into())));
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "The fixed graph must retain every field and array element after cloning"
)]
fn structured_clone_preserves_aliases_across_records_without_reusing_source_identity() {
    let date = FieldValue::from(FieldDate::invalid());
    let array = FieldValue::from(vec![date.clone()]);
    let object = FieldValue::from(FieldMap::from_iter([("date".into(), date.clone())]));
    let fields = FieldMap::from_iter([
        ("date".into(), date.clone()),
        ("array".into(), array.clone()),
        ("object".into(), object.clone()),
    ]);
    let mut context = StructuredCloneContext::new();
    let first = context.clone_map(&fields).expect("cloneable graph");
    let second = context.clone_map(&fields).expect("cloneable graph");
    for (name, original) in &fields {
        let copied = first.get(name).expect("first record field");
        assert!(!copied.strict_equals(original));
        assert!(copied.strict_equals(second.get(name).expect("second record field")));
        assert!(copied.strict_equals(&context.clone_value(original).expect("cloneable value")));
    }
    let copied_date = first.get("date").expect("cloned date");
    let nested_date = first
        .get("array")
        .and_then(FieldValue::as_array)
        .and_then(|array| array.first())
        .expect("date inside cloned array");
    assert!(copied_date.strict_equals(nested_date));
    let object_date = first
        .get("object")
        .and_then(FieldValue::as_object)
        .and_then(|object| object.get("date"))
        .expect("date inside cloned object");
    assert!(copied_date.strict_equals(object_date));
    let independent = StructuredCloneContext::new()
        .clone_value(&date)
        .expect("cloneable date");
    assert!(!copied_date.strict_equals(&independent));
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "The fixed JSON boundary must serialize valid field values and omit top-level undefined"
)]
fn json_boundary_preserves_omission_and_applies_javascript_value_conversion() {
    let fields = FieldMap::from_iter([
        ("omit".into(), FieldValue::Undefined),
        ("tail".into(), FieldValue::Number(f64::NAN)),
        ("2".into(), FieldValue::Number(f64::INFINITY)),
        ("1".into(), FieldDate::invalid().into()),
        (
            "array".into(),
            vec![
                FieldValue::Undefined,
                FieldValue::Number(f64::NEG_INFINITY),
                FieldValue::Number(-0.0),
                FieldDate::from_milliseconds(0.0).into(),
            ]
            .into(),
        ),
    ]);
    assert_eq!(
        FieldValue::from(fields)
            .stringify()
            .expect("serializable field values")
            .as_deref(),
        Some(r#"{"1":null,"2":null,"tail":null,"array":[null,null,0,"1970-01-01T00:00:00.000Z"]}"#)
    );
    assert!(
        FieldValue::Undefined
            .json()
            .expect("undefined projection")
            .is_none()
    );
    assert!(
        FieldValue::Undefined
            .stringify()
            .expect("undefined serialization")
            .is_none()
    );
    let imported = FieldValue::from_json(serde_json::json!("1970-01-01T00:00:00.000Z"))
        .expect("JSON string import");
    assert!(matches!(imported, FieldValue::String(_)));
    for (year, expected) in [
        (0, r#""0000-01-01T00:00:00.000Z""#),
        (9999, r#""9999-01-01T00:00:00.000Z""#),
        (10_000, r#""+010000-01-01T00:00:00.000Z""#),
        (-1, r#""-000001-01-01T00:00:00.000Z""#),
    ] {
        let date = chrono::NaiveDate::from_ymd_opt(year, 1, 1)
            .expect("supported calendar year")
            .and_hms_opt(0, 0, 0)
            .expect("midnight")
            .and_utc();
        assert_eq!(
            FieldValue::from(date)
                .stringify()
                .expect("expanded-year Date JSON")
                .as_deref(),
            Some(expected)
        );
    }
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "The fixed JavaScript number encodings must parse and project at both JSON boundaries"
)]
fn numeric_json_projection_matches_javascript_number_encodings() {
    for (number, expected) in [
        (0.0, "0"),
        (-0.0, "0"),
        (1.0, "1"),
        (-1.0, "-1"),
        (1.5, "1.5"),
        (-1.5, "-1.5"),
        (9_007_199_254_740_992.0, "9007199254740992"),
        (1e20, "100000000000000000000"),
        (1e21, "1e+21"),
        (1e-6, "0.000001"),
        (1e-7, "1e-7"),
        (f64::NAN, "null"),
        (f64::INFINITY, "null"),
        (f64::NEG_INFINITY, "null"),
    ] {
        let value = FieldValue::Number(number);
        let expected_json: JsonValue =
            serde_json::from_str(expected).expect("fixed JavaScript number JSON");
        assert_eq!(
            value.json().expect("number JSON projection"),
            Some(expected_json),
            "JSON value for {number}"
        );
        assert_eq!(
            value
                .stringify()
                .expect("number JSON serialization")
                .as_deref(),
            Some(expected),
            "JSON text for {number}"
        );
    }
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "The fixed finite records must have JSON representations for change detection"
)]
fn structural_equality_does_not_replace_stringify_change_detection() {
    let left = FieldValue::from(FieldMap::from_iter([
        ("first".into(), FieldValue::Null),
        ("second".into(), FieldValue::Null),
    ]));
    let right = FieldValue::from(FieldMap::from_iter([
        ("second".into(), FieldValue::Null),
        ("first".into(), FieldValue::Null),
    ]));
    assert_eq!(left, right);
    assert_ne!(
        left.stringify().expect("left record JSON"),
        right.stringify().expect("right record JSON")
    );
    for value in [FieldValue::Number(f64::NAN), FieldDate::invalid().into()] {
        assert_ne!(value, FieldValue::Null);
        assert_eq!(
            value.stringify().expect("null JSON projection"),
            FieldValue::Null.stringify().expect("null JSON")
        );
    }
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "Date JSON conversion must serialize valid TimeClip endpoints and invalid dates"
)]
fn valid_timeclip_values_outside_chrono_are_not_invalid_dates() {
    let date = FieldDate::from_milliseconds(8_640_000_000_000_000.0);
    assert_eq!(date.milliseconds(), 8_640_000_000_000_000.0);
    assert!(date.to_datetime().is_err());
    assert_eq!(
        FieldValue::from(date)
            .json()
            .expect("TimeClip endpoint JSON"),
        Some(serde_json::json!("+275760-09-13T00:00:00.000Z"))
    );
    for milliseconds in [
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        8_640_000_000_000_001.0,
        -8_640_000_000_000_001.0,
    ] {
        let date = FieldDate::from_milliseconds(milliseconds);
        assert!(date.milliseconds().is_nan());
        let value = FieldValue::from(date);
        assert_eq!(
            value.json().expect("invalid Date JSON"),
            Some(JsonValue::Null)
        );
        assert_eq!(
            value
                .stringify()
                .expect("invalid Date serialization")
                .as_deref(),
            Some("null")
        );
    }
}

#[test]
#[expect(
    clippy::expect_used,
    reason = "The fixed calendar boundaries and clipped millisecond values must have JSON representations"
)]
fn timeclip_json_preserves_calendar_boundaries_and_millisecond_precision() {
    for (milliseconds, expected) in [
        (8_639_999_999_999_999.0, "+275760-09-12T23:59:59.999Z"),
        (8_640_000_000_000_000.0, "+275760-09-13T00:00:00.000Z"),
        (-8_640_000_000_000_000.0, "-271821-04-20T00:00:00.000Z"),
        (-8_639_999_999_999_999.0, "-271821-04-20T00:00:00.001Z"),
        (8_458_214_918_399_999.0, "+270000-02-28T23:59:59.999Z"),
        (8_458_214_918_400_000.0, "+270000-02-29T00:00:00.000Z"),
        (8_458_215_004_799_999.0, "+270000-02-29T23:59:59.999Z"),
        (8_458_215_004_800_000.0, "+270000-03-01T00:00:00.000Z"),
        (-8_582_539_161_600_001.0, "-270000-02-28T23:59:59.999Z"),
        (-8_582_539_161_600_000.0, "-270000-02-29T00:00:00.000Z"),
    ] {
        let date = FieldDate::from_milliseconds(milliseconds);
        assert!(date.to_datetime().is_err());
        let value = FieldValue::from(date);
        assert_eq!(
            value.json().expect("calendar boundary JSON"),
            Some(serde_json::json!(expected))
        );
        assert_eq!(
            value.stringify().expect("calendar boundary serialization"),
            Some(format!("\"{expected}\""))
        );
    }
    for (milliseconds, expected) in [
        (-1.9, "1969-12-31T23:59:59.999Z"),
        (-0.9, "1970-01-01T00:00:00.000Z"),
        (0.9, "1970-01-01T00:00:00.000Z"),
        (1.9, "1970-01-01T00:00:00.001Z"),
    ] {
        assert_eq!(
            FieldValue::from(FieldDate::from_milliseconds(milliseconds))
                .json()
                .expect("clipped millisecond JSON"),
            Some(serde_json::json!(expected))
        );
    }
}
