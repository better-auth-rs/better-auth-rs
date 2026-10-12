use super::*;
use properties::Properties;

pub(super) struct Input {
    pub value: Arc<FieldValue>,
    pub custom_result: Option<FieldValue>,
    pub date: FieldValue,
    pub function: FieldValue,
    pub original: FieldValue,
    pub logger_failure: FieldValue,
}

fn unread() -> FieldFunction {
    FieldFunction::contextual(|_, _| {
        Err(AuthError::internal(
            "The native contract forbids this getter",
        ))
    })
}

impl Input {
    pub(super) fn new(name: &str, observer: &Observer) -> AuthResult<Self> {
        let original: FieldValue = FieldMap::from([
            ("failure".into(), name.into()),
            ("ownUndefined".into(), FieldValue::Undefined),
        ])
        .into();
        let logger_failure = FieldMap::from([
            ("loggerFailure".into(), name.into()),
            ("original".into(), original.clone()),
        ])
        .into();
        let fields = Properties::new(observer);
        let properties = FieldObject::from_source(fields.clone());
        let date: FieldValue = FieldDate::from_milliseconds_with_properties(
            1_893_553_445_000.0,
            if name == "date-root-skips-properties" {
                properties.clone()
            } else {
                FieldMap::new().into()
            },
        )
        .into();
        let function: FieldValue = FieldFunction::contextual_with_properties(
            |_, _| Ok(FieldValue::Undefined),
            if name == "function-root-skips-properties" {
                properties.clone()
            } else {
                FieldMap::new().into()
            },
        )
        .into();
        let mut custom_result = None;
        let value = if name.starts_with("array-") && name != "array-holes-and-undefined" {
            let array = FieldArray::with_length_and_properties(3, properties);
            array.set(0, ISO.into())?;
            array.set(2, "ordinary".into())?;
            let value = fields.bind(array.into());
            let custom_fields = FieldMap::from([
                ("untouched".into(), ISO.into()),
                ("preservedDate".into(), date.clone()),
                ("preservedFunction".into(), function.clone()),
            ]);
            let custom: FieldValue = if name == "array-own-map-function-result" {
                FieldFunction::contextual_with_properties(
                    |_, _| Ok(FieldValue::Undefined),
                    custom_fields.into(),
                )
                .into()
            } else {
                custom_fields.into()
            };
            custom_result = Some(custom.clone());
            let expected = Arc::downgrade(&value);
            let observed = observer.clone();
            let preserved_date = date.clone();
            let preserved_function = function.clone();
            let method_failure = (name == "array-map-method-error").then(|| original.clone());
            let method: FieldValue = FieldFunction::contextual(move |receiver, arguments| {
                let expected = expected
                    .upgrade()
                    .ok_or_else(|| AuthError::internal("Map receiver is absent"))?;
                observed
                    .lock()
                    .call("call:map", receiver, &expected, arguments)?;
                let [FieldValue::Function(revive)] = arguments else {
                    return Err(AuthError::internal(
                        "Map must receive one native reviver callback",
                    ));
                };
                if let Some(error) = &method_failure {
                    return Err(AuthError::from_thrown(error.clone()));
                }
                let parsed = revive.call_with(
                    &"ignored receiver".into(),
                    &[ISO.into(), 9.into(), receiver.clone()],
                )?;
                let date = revive.call_with(
                    &FieldValue::Undefined,
                    std::slice::from_ref(&preserved_date),
                )?;
                let function = revive
                    .call_with(&FieldValue::Null, std::slice::from_ref(&preserved_function))?;
                let missing = revive.call()?;
                let mut observer = observed.lock();
                let parsed_value = observer.observe(&parsed)?;
                let date_value = observer.observe(&date)?;
                let function_value = observer.observe(&function)?;
                let missing_value = observer.observe(&missing)?;
                observer.record(
                    "map:reviver-results",
                    [
                        ("parsed".into(), parsed_value),
                        ("date".into(), date_value),
                        ("fn".into(), function_value),
                        ("missing".into(), missing_value),
                        (
                            "sameDate".into(),
                            date.strict_equals(&preserved_date).into(),
                        ),
                        (
                            "sameFunction".into(),
                            function.strict_equals(&preserved_function).into(),
                        ),
                    ],
                );
                Ok(custom.clone())
            })
            .into();
            let getter_failure = (name == "array-map-getter-error").then(|| original.clone());
            let noncallable = name == "array-map-noncallable";
            fields.getter(
                "map",
                FieldFunction::contextual(move |_, _| {
                    if let Some(error) = &getter_failure {
                        return Err(AuthError::from_thrown(error.clone()));
                    }
                    Ok(if noncallable {
                        FieldValue::Undefined
                    } else {
                        method.clone()
                    })
                }),
                false,
            );
            value
        } else if name == "array-holes-and-undefined" {
            let array = FieldArray::with_length(5);
            array.set(0, ISO.into())?;
            array.set(2, FieldValue::Undefined)?;
            array.set(3, date.clone())?;
            array.set(4, function.clone())?;
            array.properties().set("ignoredNamedField", ISO.into())?;
            Arc::new(array.into())
        } else if name == "object-key-snapshot-and-late-getters" {
            let value = fields.bind(properties.into());
            let child_fields = Properties::new(observer);
            let child = child_fields.bind(FieldObject::from_source(child_fields.clone()).into());
            child_fields.getter(
                "date",
                FieldFunction::contextual(|_, _| Ok(ISO.into())),
                true,
            );
            let late = Arc::new(Mutex::new(FieldValue::from("before")));
            let changed_late = late.clone();
            fields.getter(
                "first",
                FieldFunction::contextual(move |receiver, _| {
                    let object = receiver
                        .as_object()
                        .ok_or_else(|| AuthError::internal("Expected object getter receiver"))?;
                    let _ = object.delete("removed")?;
                    *changed_late.lock() = ISO.into();
                    object
                        .source::<Properties>()
                        .ok_or_else(|| AuthError::internal("Expected native getter source"))?
                        .getter("added", unread(), true);
                    Ok(child.as_ref().clone())
                }),
                true,
            );
            fields.getter("removed", unread(), true);
            fields.getter(
                "later",
                FieldFunction::contextual(move |_, _| Ok(late.lock().clone())),
                true,
            );
            fields.getter("hidden", unread(), false);
            value
        } else if matches!(name, "object-getter-error" | "logger-original-error") {
            let value = fields.bind(properties.into());
            let error = original.clone();
            fields.getter(
                "first",
                FieldFunction::contextual(move |receiver, _| {
                    receiver.set_model_property("mutation", "retained-before-error".into())?;
                    Err(AuthError::from_thrown(error.clone()))
                }),
                true,
            );
            fields.getter("later", unread(), true);
            value
        } else if name == "date-root-skips-properties" || name == "function-root-skips-properties" {
            let value = fields.bind(if name.starts_with("date-") {
                date.clone()
            } else {
                function.clone()
            });
            value.set_model_property("iso", ISO.into())?;
            fields.getter("unread", unread(), true);
            if name.starts_with("date-") {
                fields.getter("getTime", unread(), false);
            }
            value
        } else if name == "object-native-children" {
            Arc::new(
                FieldMap::from([
                    ("date".into(), date.clone()),
                    ("fn".into(), function.clone()),
                    ("iso".into(), ISO.into()),
                    (
                        "nested".into(),
                        FieldMap::from([
                            ("date".into(), date.clone()),
                            ("fn".into(), function.clone()),
                        ])
                        .into(),
                    ),
                ])
                .into(),
            )
        } else {
            return Err(AuthError::internal(format!(
                "Unknown safeJSONParse source case {name}"
            )));
        };
        Ok(Self {
            value,
            custom_result,
            date,
            function,
            original,
            logger_failure,
        })
    }
}
