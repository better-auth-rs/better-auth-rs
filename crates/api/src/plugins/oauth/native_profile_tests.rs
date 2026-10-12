//! Native provider callbacks retain identity until endpoint projection.
#![expect(
    clippy::unwrap_used,
    reason = "Regression tests must fail immediately when callback identity or field access changes."
)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use better_auth_core::{AuthError, AuthResult, FieldMap, FieldValue};
use serde_json::json;

use super::{
    GenericOAuthConfig, OAuthAccountSubject, OAuthProfileMapper, OAuthProvider,
    OAuthUserInfoHandler, OAuthUserInfoRequest,
    generic::{GenericOAuthProfileContext, GenericOAuthUserInfoHandler},
    generic_profile::{fetch_profile, resolve_account_subject},
    resolved::{ResolvedGenericOAuth, ResolvedProvider},
    social_profile::fetch_user_info_from_provider,
};

struct MutableProfile {
    raw: FieldValue,
    image: FieldValue,
    extension: FieldValue,
    events: Mutex<Vec<&'static str>>,
}

#[async_trait]
impl GenericOAuthUserInfoHandler for MutableProfile {
    async fn get_user_info_native(
        &self,
        _: &OAuthUserInfoRequest,
        _: GenericOAuthProfileContext<'_>,
    ) -> AuthResult<FieldValue> {
        self.events.lock().unwrap().push("get");
        Ok(self.raw.clone())
    }
}

#[async_trait]
impl OAuthProfileMapper for MutableProfile {
    async fn map_profile_native(&self, profile: &FieldValue) -> AuthResult<FieldValue> {
        self.events.lock().unwrap().push("map");
        assert!(profile.strict_equals(&self.raw));
        let raw = profile.as_object().unwrap();
        raw.set("email", FieldValue::Number(17.0))?;
        raw.set("emailVerified", "truthy".into())?;
        raw.set("image", self.image.clone())?;
        Ok(FieldMap::from([
            ("id".into(), "mapped-id".into()),
            ("name".into(), false.into()),
            ("extension".into(), self.extension.clone()),
            ("optional".into(), FieldValue::Undefined),
        ])
        .into())
    }
}

#[tokio::test]
async fn generic_mapper_mutation_precedes_default_reads_and_retains_native_aliases() {
    let callbacks = Arc::new(MutableProfile {
        raw: json!({
            "id": 23,
            "email": "before@example.test",
            "emailVerified": false,
            "image": "before.png",
            "name": "Before"
        })
        .into(),
        image: json!({"kind": "native-image"}).into(),
        extension: json!({"kind": "native-extension"}).into(),
        events: Mutex::new(Vec::new()),
    });
    let provider = ResolvedGenericOAuth {
        config: GenericOAuthConfig {
            get_user_info: Some(callbacks.clone()),
            map_profile_to_user: Some(callbacks.clone()),
            ..Default::default()
        },
        issuer: None,
        is_oidc: false,
        verifier: None,
    };
    let response = fetch_profile(&provider, &OAuthUserInfoRequest::default(), None)
        .await
        .unwrap();
    let data = response.model_property("data").unwrap();
    let user = response.model_property("user").unwrap();
    assert!(data.strict_equals(&callbacks.raw));
    assert!(
        user.model_property("image")
            .unwrap()
            .strict_equals(&callbacks.image)
    );
    assert!(
        user.model_property("extension")
            .unwrap()
            .strict_equals(&callbacks.extension)
    );
    assert!(user.as_object().unwrap().has_property("optional").unwrap());
    assert!(user.model_property("optional").unwrap().is_undefined());
    assert_eq!(
        user.json().unwrap(),
        Some(json!({
            "email": 17,
            "emailVerified": "truthy",
            "image": {"kind": "native-image"},
            "name": false,
            "id": "mapped-id",
            "extension": {"kind": "native-extension"}
        }))
    );
    assert_eq!(*callbacks.events.lock().unwrap(), ["get", "map"]);
    assert_eq!(
        resolve_account_subject(&provider, &better_auth_core::FieldMap::new().into(), &data)
            .await
            .unwrap(),
        FieldValue::from("23")
    );
}

struct CustomResponse {
    value: FieldValue,
    events: Mutex<Vec<&'static str>>,
}

#[async_trait]
impl OAuthUserInfoHandler for CustomResponse {
    async fn get_user_info_native(&self, _: OAuthUserInfoRequest) -> AuthResult<FieldValue> {
        self.events.lock().unwrap().push("get");
        Ok(self.value.clone())
    }
}

#[async_trait]
impl OAuthProfileMapper for CustomResponse {
    async fn map_profile_native(&self, _: &FieldValue) -> AuthResult<FieldValue> {
        self.events.lock().unwrap().push("map");
        Err(AuthError::internal(
            "Custom provider response must bypass the mapper",
        ))
    }
}

#[async_trait]
impl OAuthAccountSubject for CustomResponse {
    async fn resolve_subject_native(
        &self,
        _: &FieldValue,
        _: &FieldValue,
    ) -> AuthResult<FieldValue> {
        self.events.lock().unwrap().push("subject");
        Err(AuthError::internal(
            "Profile fetch must defer account subject resolution",
        ))
    }
}

#[tokio::test]
async fn custom_social_profile_preserves_the_complete_response_identity() {
    let value: FieldValue = FieldMap::from([
        (
            "user".into(),
            json!({"name": 19, "emailVerified": "yes"}).into(),
        ),
        ("data".into(), json!({"sub": 23}).into()),
        ("extra".into(), json!({"kind": "extension"}).into()),
        ("optional".into(), FieldValue::Undefined),
    ])
    .into();
    let callbacks = Arc::new(CustomResponse {
        value: value.clone(),
        events: Mutex::new(Vec::new()),
    });
    let mut config = OAuthProvider::google("client", "secret");
    config.get_user_info = Some(callbacks.clone());
    config.map_profile_to_user = Some(callbacks.clone());
    config.account_subject = Some(callbacks.clone());
    let provider = ResolvedProvider {
        config,
        generic: None,
    };
    let response = fetch_user_info_from_provider(&provider, OAuthUserInfoRequest::default(), None)
        .await
        .unwrap();
    assert!(response.value.strict_equals(&value));
    assert!(
        response
            .value
            .as_object()
            .unwrap()
            .has_property("optional")
            .unwrap()
    );
    assert!(
        response
            .value
            .model_property("optional")
            .unwrap()
            .is_undefined()
    );
    assert_eq!(
        response.value.json().unwrap(),
        Some(json!({
            "user": {"name": 19, "emailVerified": "yes"},
            "data": {"sub": 23},
            "extra": {"kind": "extension"}
        }))
    );
    assert_eq!(*callbacks.events.lock().unwrap(), ["get"]);
}
