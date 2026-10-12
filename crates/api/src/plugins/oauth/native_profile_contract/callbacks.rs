use super::super::{
    GenericOAuthConfig, OAuthAccountSubject, OAuthCodeExchange, OAuthIdTokenVerifier,
    OAuthProfileMapper, OAuthProvider, OAuthTokenHandler, OAuthTokenSet, OAuthUserInfoHandler,
    OAuthUserInfoRequest,
    generic::{GenericOAuthProfileContext, GenericOAuthUserInfoHandler},
};
use super::*;
use crate::plugins::{
    endpoint_context::EndpointContext,
    user_admission::{UserValidationData, UserValidationRejection, ValidateUserInfo},
};
use async_trait::async_trait;
use better_auth_core::{AuthSchema, NativeRequest};

pub(super) struct Callbacks(pub Arc<State>);

impl Callbacks {
    fn get(&self, tokens: &OAuthUserInfoRequest) -> AuthResult<()> {
        let fields = tokens.fields();
        if self.0.scenario.provider == "social" && self.0.scenario.operation == "callback" {
            self.0
                .generated_date(fields.get("accessTokenExpiresAt").unwrap(), 3_600_000)?;
        }
        self.0
            .log
            .event(json!({"kind": "get-user-info", "tokens": observe::native(&fields.into())?}));
        Ok(())
    }
}

#[async_trait]
impl GenericOAuthUserInfoHandler for Callbacks {
    async fn get_user_info_native(
        &self,
        tokens: &OAuthUserInfoRequest,
        _: GenericOAuthProfileContext<'_>,
    ) -> AuthResult<FieldValue> {
        self.get(tokens)?;
        Ok(self.0.raw.clone())
    }
}

#[async_trait]
impl OAuthUserInfoHandler for Callbacks {
    async fn get_user_info_native(&self, tokens: OAuthUserInfoRequest) -> AuthResult<FieldValue> {
        self.get(&tokens)?;
        self.0.tracking.lock().unwrap().info = Some(self.0.social_response.clone());
        Ok(self.0.social_response.clone())
    }
}

#[async_trait]
impl OAuthProfileMapper for Callbacks {
    async fn map_profile_native(&self, raw: &FieldValue) -> AuthResult<FieldValue> {
        if self.0.scenario.provider == "social" {
            self.0
                .log
                .event(json!({"kind": "unexpected-social-mapper"}));
            return Err(AuthError::from_thrown(self.0.failure.clone()));
        }
        self.0.tracking.lock().unwrap().mapper_input = Some(raw.clone());
        self.0
            .log
            .event(json!({"kind": "mapper", "sameProfile": raw.strict_equals(&self.0.raw)}));
        if self.0.scenario.shape == "mapper-error" {
            return Err(AuthError::from_thrown(self.0.failure.clone()));
        }
        if self.0.scenario.shape == "identity" {
            raw.as_object()
                .unwrap()
                .set("mapperMarker", self.0.marker.clone())?;
        }
        Ok(self.0.mapped.clone())
    }
}

#[async_trait]
impl OAuthAccountSubject for Callbacks {
    async fn resolve_subject_native(
        &self,
        tokens: &FieldValue,
        profile: &FieldValue,
    ) -> AuthResult<FieldValue> {
        self.0.tracking.lock().unwrap().subject_input = Some(profile.clone());
        let same = profile.strict_equals(&self.0.raw);
        let tokens = observe::native(tokens)?;
        self.0
            .log
            .event(json!({"kind": "subject", "sameProfile": same, "tokens": tokens}));
        if self.0.scenario.provider == "social" {
            return Ok(OAuthProvider::google("client", "secret")
                .builtin_account_subject(profile)?
                .unwrap());
        }
        self.0
            .log
            .event(json!({"kind": "generic-subject", "sameProfile": same, "tokens": tokens}));
        if self.0.scenario.operation == "account-info" {
            return Err(AuthError::from_thrown(self.0.failure.clone()));
        }
        if self.0.scenario.shape == "identity" {
            assert!(
                profile
                    .model_property("mapperMarker")?
                    .strict_equals(&self.0.marker)
            );
            profile
                .as_object()
                .unwrap()
                .set("subjectMarker", self.0.marker.clone())?;
            return Ok(23.0.into());
        }
        profile.model_property("id")
    }
}

#[async_trait]
impl OAuthTokenHandler for Callbacks {
    async fn get_token(&self, request: OAuthCodeExchange<'_>) -> AuthResult<OAuthTokenSet> {
        self.0
            .remember(request.code_verifier.unwrap(), "code-verifier");
        let input = object([
            ("code", request.code.into()),
            (
                "codeVerifier",
                request
                    .code_verifier
                    .map_or(FieldValue::Undefined, Into::into),
            ),
            (
                "deviceId",
                request.device_id.map_or(FieldValue::Undefined, Into::into),
            ),
            ("redirectURI", request.redirect_uri.into()),
        ]);
        self.0
            .log
            .event(json!({"kind": "token", "input": observe::native(&input)?}));
        Ok(OAuthTokenSet::from_fields(fields([
            ("accessToken", ACCESS_TOKEN.into()),
            ("scopes", vec!["profile".into()].into()),
        ])))
    }
}

#[async_trait]
impl OAuthIdTokenVerifier for Callbacks {
    async fn verify_id_token(
        &self,
        token: &str,
        nonce: Option<&str>,
        _: Option<NativeRequest<'_>>,
    ) -> Result<bool, String> {
        let path = better_auth_core::hooks::current_request_hook_context()
            .unwrap()
            .path;
        self.0
            .log
            .event(json!({"kind": "verify", "token": token, "nonce": nonce, "path": path}));
        Ok(true)
    }
}

#[async_trait]
impl<S: AuthSchema> ValidateUserInfo<S> for Callbacks {
    async fn validate(
        &self,
        data: &UserValidationData,
        context: &EndpointContext<'_, S>,
    ) -> AuthResult<Option<UserValidationRejection>> {
        let oauth = data.source.oauth.as_ref().unwrap();
        let profile = oauth.profile.as_ref().unwrap();
        self.0.generated_record_dates(&data.user, false)?;
        let (mapper, subject) = {
            let tracking = self.0.tracking.lock().unwrap();
            (
                tracking.mapper_input.clone(),
                tracking.subject_input.clone(),
            )
        };
        let source = object([
            ("method", data.source.method.clone().into()),
            (
                "oauth",
                object([
                    ("providerId", oauth.provider_id.field_value()),
                    ("profile", profile.clone()),
                ]),
            ),
            (
                "action",
                FieldValue::from(serde_json::to_value(data.source.action)?),
            ),
        ]);
        self.0.tracking.lock().unwrap().admissions.push(object([
            ("user", data.user.clone().into()),
            ("source", source),
        ]));
        self.0.log.event(json!({
            "kind": "admission", "path": context.path, "action": data.source.action,
            "method": data.source.method, "providerId": oauth.provider_id,
            "sameProfile": profile.strict_equals(&self.0.raw),
            "sameMapperProfile": mapper.as_ref().is_some_and(|value| profile.strict_equals(value)),
            "sameSubjectProfile": subject.as_ref().is_some_and(|value| profile.strict_equals(value)),
            "user": observe::native(&data.user.clone().into())?
        }));
        if self.0.scenario.shape == "identity" {
            assert!(profile.strict_equals(mapper.as_ref().unwrap()));
            assert!(profile.strict_equals(subject.as_ref().unwrap()));
            assert!(
                profile
                    .model_property("subjectMarker")?
                    .strict_equals(&self.0.marker)
            );
            profile
                .as_object()
                .unwrap()
                .set("admissionMarker", self.0.marker.clone())?;
        }
        Ok(None)
    }
}

pub(super) fn generic(callbacks: &Arc<Callbacks>) -> GenericOAuthConfig {
    GenericOAuthConfig {
        client_id: "client".into(),
        authorization_url: Some("https://provider.example.test/authorize".into()),
        get_token: Some(callbacks.clone()),
        get_user_info: Some(callbacks.clone()),
        map_profile_to_user: Some(callbacks.clone()),
        account_subject: Some(callbacks.clone()),
        ..Default::default()
    }
}
