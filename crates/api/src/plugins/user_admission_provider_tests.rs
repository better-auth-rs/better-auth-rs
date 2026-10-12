#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report exact contract mismatches while Result propagates fixture errors."
)]
#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
//! Admission validates provider presence before invoking callbacks with the original value.

use super::*;
use better_auth_core::{
    AuthContext,
    store::{EphemeralStore, StatelessSchema},
};
use std::sync::Mutex;

#[derive(Default)]
struct ProviderTrace(Mutex<Vec<FieldValue>>);

#[async_trait]
impl ValidateUserInfo<StatelessSchema> for ProviderTrace {
    async fn validate(
        &self,
        data: &UserValidationData,
        _: &EndpointContext<'_, StatelessSchema>,
    ) -> AuthResult<Option<UserValidationRejection>> {
        let provider = data
            .source
            .oauth
            .as_ref()
            .or(data.source.sso.as_ref())
            .ok_or_else(|| AuthError::internal("Provider source missing"))?;
        self.0
            .lock()
            .map_err(|_| AuthError::internal("Provider trace lock poisoned"))?
            .push(provider.provider_id.field_value());
        Ok(None)
    }
}

#[tokio::test]
async fn provider_admission_uses_native_truthiness_and_preserves_callback_identity()
-> AuthResult<()> {
    let config = Arc::new(crate::plugins::test_helpers::create_test_config());
    let store = Arc::new(EphemeralStore::new(config.clone()));
    let mut context = AuthContext::new(config, store).expect("fixture context initializes");
    let trace = Arc::new(ProviderTrace::default());
    context
        .extensions
        .insert(trace.clone() as Arc<dyn ValidateUserInfo<StatelessSchema>>);
    let endpoint = EndpointContext::new(None, FieldValue::Null, &context);
    for method in ["oauth", "sso-oidc", "sso-saml"] {
        for (provider, admitted) in [
            (FieldValue::Undefined, false),
            (FieldValue::Null, false),
            (FieldValue::Bool(false), false),
            (FieldValue::Number(0.0), false),
            (FieldValue::Number(f64::NAN), false),
            (FieldValue::from(""), false),
            (FieldValue::from("provider"), true),
            (FieldValue::Number(7.0), true),
            (FieldMap::new().into(), true),
            (Vec::<FieldValue>::new().into(), true),
        ] {
            let mut source =
                UserValidationSource::oauth(&provider, None, UserValidationAction::SignIn);
            source.method = method.into();
            if method != "oauth" {
                source.sso = source.oauth.take();
            }
            let result = validate(
                UserValidationData {
                    user: FieldMap::new(),
                    source,
                },
                &endpoint,
            )
            .await?;
            let mut observed = trace
                .0
                .lock()
                .map_err(|_| AuthError::internal("Provider trace lock poisoned"))?;
            if admitted {
                assert!(result.is_none());
                assert_eq!(observed.len(), 1);
                assert!(
                    observed
                        .first()
                        .is_some_and(|value| value.strict_equals(&provider))
                );
            } else {
                let rejection =
                    result.ok_or_else(|| AuthError::internal("Missing provider was admitted"))?;
                assert_eq!(rejection.error, "validation_source_missing");
                assert_eq!(
                    rejection.error_description.as_deref(),
                    Some(if method == "oauth" {
                        "OAuth user validation source requires oauth.providerId"
                    } else {
                        "SSO user validation source requires sso.providerId"
                    })
                );
                assert!(observed.is_empty());
            }
            observed.clear();
        }
    }
    Ok(())
}
