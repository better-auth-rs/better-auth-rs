use super::*;

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
    let first = context.clone_map(&fields);
    let second = context.clone_map(&fields);
    for (name, original) in &fields {
        let copied = first.get(name).expect("first record field");
        assert!(!copied.strict_equals(original));
        assert!(copied.strict_equals(second.get(name).expect("second record field")));
        assert!(copied.strict_equals(&context.clone_value(original)));
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
    let independent = StructuredCloneContext::new().clone_value(&date);
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
fn valid_timeclip_values_outside_chrono_are_not_invalid_dates() {
    let date = FieldDate::from_milliseconds(8_640_000_000_000_000.0);
    assert_eq!(date.milliseconds(), 8_640_000_000_000_000.0);
    assert!(date.to_datetime().is_err());
    assert!(FieldValue::from(date).json().is_err());
    for milliseconds in [f64::NAN, f64::INFINITY, 8_640_000_000_000_001.0] {
        assert!(
            FieldDate::from_milliseconds(milliseconds)
                .milliseconds()
                .is_nan()
        );
    }
}
