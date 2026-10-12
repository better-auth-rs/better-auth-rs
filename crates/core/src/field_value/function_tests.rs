use super::*;
use crate::{AuthError, FieldDate, FieldMap, user_fields::UserFieldFactory};
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn contextual_calls_preserve_handles_and_expose_callback_mutations() -> AuthResult<()> {
    let receiver = FieldValue::from(FieldMap::from([("remove".into(), true.into())]));
    let object = FieldValue::from(FieldMap::new());
    let arguments = [
        object.clone(),
        vec![object.clone()].into(),
        FieldDate::from_milliseconds(0.0).into(),
        FieldFunction::contextual(|_, _| {
            Err(AuthError::internal("Argument function must not run"))
        })
        .into(),
        FieldValue::Undefined,
        FieldValue::Null,
        "last".into(),
    ];
    let expected_receiver = receiver.clone();
    let expected_arguments = arguments.clone();
    let function = FieldFunction::contextual(move |receiver, arguments| {
        assert!(receiver.strict_equals(&expected_receiver));
        assert_eq!(arguments.len(), expected_arguments.len());
        for (actual, expected) in arguments.iter().zip(&expected_arguments) {
            assert!(actual.strict_equals(expected));
        }
        let FieldValue::Object(receiver) = receiver else {
            return Err(AuthError::internal("Expected an object receiver"));
        };
        assert_eq!(receiver.get("remove")?, Some(true.into()));
        assert!(receiver.delete("remove")?);
        let [FieldValue::Object(object), result, _, next, ..] = arguments else {
            return Err(AuthError::internal("Expected the original arguments"));
        };
        assert_eq!(receiver.get("next")?, None);
        receiver.set("next", next.clone())?;
        assert_eq!(object.get("visited")?, None);
        object.set("visited", true.into())?;
        Ok(result.clone())
    });
    let cloned = function.clone();
    assert_eq!(function, cloned);
    assert_eq!(function.identity(), cloned.identity());
    let returned = function.call_with(&receiver, &arguments)?;
    assert!(returned.strict_equals(&arguments[1]));
    assert!(receiver.model_property("remove")?.is_undefined());
    assert!(
        receiver
            .model_property("next")?
            .strict_equals(&arguments[3])
    );
    assert_eq!(object.model_property("visited")?, true.into());
    let FieldValue::Array(returned) = returned else {
        return Err(AuthError::internal("Expected the original array result"));
    };
    let child = returned
        .first()?
        .ok_or_else(|| AuthError::internal("Expected the original array child"))?;
    assert_eq!(child.model_property("visited")?, true.into());
    Ok(())
}

#[test]
fn calls_without_context_supply_undefined_and_no_arguments() -> AuthResult<()> {
    let function = FieldFunction::contextual(|receiver, arguments| {
        assert!(arguments.is_empty());
        Ok(receiver.clone())
    });
    assert!(function.call()?.is_undefined());
    assert!(function.call_with(&FieldValue::Null, &[])?.is_null());
    assert_ne!(
        function,
        FieldFunction::contextual(|receiver, _| Ok(receiver.clone()))
    );
    Ok(())
}

#[test]
fn repeated_factory_adaptation_keeps_identity_and_result_handles() -> AuthResult<()> {
    let result = FieldValue::from(FieldMap::new());
    let returned = result.clone();
    let factory: UserFieldFactory = UserFieldFactory::new(move || Ok(returned.clone()));
    let first = FieldFunction::from(factory.clone());
    let second = FieldFunction::from(factory.clone());
    assert_eq!(first, second);
    assert_eq!(first.identity(), factory.function().identity());
    assert_eq!(first.identity(), second.identity());
    assert!(first.call()?.strict_equals(&result));
    assert!(
        second
            .call_with(&FieldValue::Null, &["ignored".into()])?
            .strict_equals(&result)
    );
    let distinct: UserFieldFactory = UserFieldFactory::new(move || Ok(result.clone()));
    assert_ne!(first, FieldFunction::from(distinct));
    Ok(())
}

#[test]
fn calls_preserve_the_original_error_allocation() -> AuthResult<()> {
    for legacy in [false, true] {
        let allocation = Arc::new(AtomicUsize::new(0));
        let original = allocation.clone();
        let fail = move || -> AuthResult<FieldValue> {
            let message = "original-field-function-error".to_owned();
            original.store(message.as_ptr() as usize, Ordering::SeqCst);
            Err(AuthError::FieldInput {
                code: "CALL_REJECTED",
                message,
            })
        };
        let function = if legacy {
            FieldFunction::from(UserFieldFactory::new(fail))
        } else {
            FieldFunction::contextual(move |_, _| fail())
        };
        let result = function.call_with(&FieldValue::Null, &[false.into()]);
        let Err(AuthError::FieldInput { code, message }) = result else {
            return Err(AuthError::internal(
                "Expected the original field input error",
            ));
        };
        assert_eq!(code, "CALL_REJECTED");
        assert_eq!(message, "original-field-function-error");
        assert_eq!(message.as_ptr() as usize, allocation.load(Ordering::SeqCst));
    }
    Ok(())
}

#[tokio::test]
async fn awaited_calls_observe_mutations_through_original_handles() -> AuthResult<()> {
    let receiver = FieldValue::from(FieldMap::new());
    let argument = FieldValue::from(FieldMap::new());
    let expected_receiver = receiver.clone();
    let expected_argument = argument.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed_calls = calls.clone();
    let function = FieldFunction::asynchronous_contextual(move |receiver, arguments| {
        let expected_receiver = expected_receiver.clone();
        let expected_argument = expected_argument.clone();
        let observed_calls = observed_calls.clone();
        async move {
            let _ = observed_calls.fetch_add(1, Ordering::SeqCst);
            assert!(receiver.strict_equals(&expected_receiver));
            assert!(arguments[0].strict_equals(&expected_argument));
            tokio::task::yield_now().await;
            assert_eq!(receiver.model_property("visited")?, true.into());
            assert_eq!(arguments[0].model_property("visited")?, true.into());
            Ok(arguments[0].clone())
        }
    });
    assert!(function.call_with(&receiver, &[]).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(function, function.clone());
    let arguments = [argument.clone()];
    let (result, mutation) =
        tokio::join!(function.call_awaited_with(&receiver, &arguments), async {
            for value in [&receiver, &argument] {
                let FieldValue::Object(object) = value else {
                    return Err(AuthError::internal("Expected an object handle"));
                };
                object.set("visited", true.into())?;
            }
            AuthResult::Ok(())
        },);
    mutation?;
    assert!(result?.strict_equals(&argument));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn awaited_calls_preserve_sync_results_and_async_rejections() -> AuthResult<()> {
    let result = FieldValue::from(FieldMap::new());
    let returned = result.clone();
    let sync = FieldFunction::contextual(move |_, _| Ok(returned.clone()));
    assert!(
        sync.call_awaited_with(&FieldValue::Null, &[])
            .await?
            .strict_equals(&result)
    );

    let thrown = FieldValue::from(FieldMap::from([("cause".into(), result)]));
    let original = thrown.clone();
    let asynchronous = FieldFunction::asynchronous_contextual(move |_, _| {
        let thrown = original.clone();
        async move { Err(AuthError::from_thrown(thrown)) }
    });
    let Err(error) = asynchronous.call_awaited_with(&FieldValue::Null, &[]).await else {
        return Err(AuthError::internal("Expected the original rejection"));
    };
    assert!(
        error
            .raw_value()
            .is_some_and(|value| value.strict_equals(&thrown))
    );
    Ok(())
}

#[tokio::test]
async fn host_callbacks_borrow_the_active_context_from_the_retained_binding() -> AuthResult<()> {
    struct Callback;
    impl Callback {
        async fn call(&self, context: &mut FieldMap) -> AuthResult<FieldValue> {
            tokio::task::yield_now().await;
            context
                .remove("token")
                .ok_or_else(|| AuthError::internal("Missing token"))
        }
    }
    let function = FieldFunction::bound(Callback);
    let token = FieldValue::from(FieldMap::new());
    let mut context = FieldMap::from([("token".into(), token.clone())]);
    let cloned = function.clone();
    assert_eq!(cloned, function);
    assert!(function.binding::<String>().is_none());
    assert!(function.call().is_err());
    assert!(
        function
            .call_awaited_with(&FieldValue::Null, &[])
            .await
            .is_err()
    );
    let binding = cloned
        .binding::<Callback>()
        .ok_or_else(|| AuthError::internal("Missing callback"))?;
    assert!(binding.call(&mut context).await?.strict_equals(&token));
    assert!(context.is_empty());
    Ok(())
}
