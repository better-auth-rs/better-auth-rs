use super::*;
use better_auth_core::{
    NativeRequest,
    observability::{LogArgument, LogLevel, LogSink},
};

struct FailureTrace {
    events: Mutex<Vec<&'static str>>,
    admission_error: FieldValue,
    logger_error: Option<FieldValue>,
}

#[async_trait]
impl<S: AuthSchema> ValidateUserInfo<S> for FailureTrace {
    async fn validate(
        &self,
        data: &UserValidationData,
        _: &EndpointContext<'_, S>,
    ) -> AuthResult<Option<UserValidationRejection>> {
        assert_eq!(data.source.method, "contract");
        assert_eq!(
            data.user.get("email"),
            Some(&FieldValue::from("logger@admission.test")),
        );
        self.events
            .lock()
            .expect("Admission trace remains available")
            .push("admission");
        Err(AuthError::from_thrown(self.admission_error.clone()))
    }
}

impl LogSink for FailureTrace {
    fn log(
        &self,
        level: LogLevel,
        message: LogArgument<'_>,
        arguments: &[LogArgument<'_>],
    ) -> AuthResult<()> {
        assert_eq!(level, LogLevel::Error);
        assert_eq!(message.to_string(), "validateUserInfo callback threw");
        let [LogArgument::Error(error)] = arguments else {
            return Err(AuthError::internal("Admission must log its original error"));
        };
        let error = error
            .downcast_ref::<AuthError>()
            .ok_or_else(|| AuthError::internal("Admission must retain the original error type"))?;
        assert!(
            error
                .raw_value()
                .is_some_and(|value| value.strict_equals(&self.admission_error))
        );
        self.events
            .lock()
            .expect("Admission trace remains available")
            .push("logger");
        match &self.logger_error {
            Some(error) => Err(AuthError::from_thrown(error.clone())),
            None => Ok(()),
        }
    }
}

async fn check_failure<S: AuthSchema>(
    store: Arc<dyn AuthStore<S>>,
    logger_fails: bool,
) -> AuthResult<()> {
    let trace = Arc::new(FailureTrace {
        events: Mutex::default(),
        admission_error: FieldMap::from([("source".into(), "admission".into())]).into(),
        logger_error: logger_fails
            .then(|| FieldMap::from([("source".into(), "logger".into())]).into()),
    });
    let mut config = test_helpers::create_test_config();
    config.logger = better_auth_core::LoggerConfig {
        log: Some(trace.clone()),
        ..Default::default()
    }
    .into();
    let config = Arc::new(config);
    let store = store.with_runtime(config.clone(), vec![], Default::default())?;
    let mut context = AuthContext::new(config, store)?;
    context
        .extensions
        .insert(trace.clone() as Arc<dyn ValidateUserInfo<S>>);
    let result = context
        .with_native_context(
            NativeRequest {
                request: None,
                headers: None,
            },
            |active| async move {
                create_user_optional(
                    CreateUser {
                        name: Some("Rejected user".into()).into(),
                        email: Some("logger@admission.test".into()),
                        ..Default::default()
                    },
                    "contract",
                    &EndpointContext::new(None, FieldValue::Null, &active),
                )
                .await
            },
        )
        .await;
    let error = result.expect_err("Admission failures must stop user creation");
    if let Some(original) = &trace.logger_error {
        assert!(
            error
                .raw_value()
                .is_some_and(|value| value.strict_equals(original))
        );
    } else {
        assert_eq!(error.status_value()?, "FORBIDDEN".into());
        assert_eq!(error.status_code()?, 403);
        assert!(error.is_api_error_instance(better_auth_core::ApiErrorClass::BetterAuth));
        assert_eq!(
            error
                .body_value()?
                .enumerable_fields()?
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["code", "message"],
        );
        let response = error.to_auth_response()?.into_http_response()?;
        assert_eq!(response.status, 403);
        assert_eq!(
            response.body.json()?,
            Some(serde_json::json!({
                "code": "validation_failed",
                "message": "User validation failed",
            })),
        );
    }
    assert_eq!(
        *trace
            .events
            .lock()
            .expect("Admission trace remains available"),
        ["admission", "logger"],
    );
    assert!(
        context
            .database
            .get_user_by_email("logger@admission.test")
            .await?
            .is_none()
    );
    assert_eq!(context.database.list_users(Default::default()).await?.1, 0);
    Ok(())
}

#[tokio::test]
async fn admission_logger_failures_retain_identity_and_prevent_user_creation() -> AuthResult<()> {
    for logger_fails in [false, true] {
        let memory: Arc<dyn AuthStore<StatelessSchema>> = Arc::new(EphemeralStore::new(config()));
        check_failure(memory, logger_fails).await?;
        check_failure(test_helpers::create_test_database().await, logger_fails).await?;
    }
    Ok(())
}
