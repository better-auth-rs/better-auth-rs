use std::{error::Error as _, fmt::Write as _, sync::Arc};

use async_trait::async_trait;
use better_auth_core::{AuthError, AuthResult};
use serde_json::{Map, Value};

use super::{
    GenericOAuthConfig, GenericOAuthProfileContext, GenericOAuthUserInfoHandler,
    OAuthAccountSubject, OAuthUserInfoRequest,
};
use crate::plugins::json_body;

impl GenericOAuthConfig {
    /// Configure Microsoft Entra ID for one concrete tenant GUID with verified ID tokens.
    pub fn microsoft_entra_id(
        client_id: &str,
        client_secret: &str,
        tenant_id: &str,
    ) -> AuthResult<Self> {
        let tenant = tenant_id.to_ascii_lowercase();
        if !uuid::Uuid::parse_str(&tenant)
            .is_ok_and(|value| value.hyphenated().to_string() == tenant)
        {
            return Err(AuthError::config(
                "The generic Microsoft Entra ID provider requires a concrete tenant GUID",
            ));
        }
        let issuer = format!("https://login.microsoftonline.com/{tenant}");
        Ok(Self {
            client_id: client_id.into(),
            client_secret: Some(client_secret.into()),
            discovery_url: Some(format!("{issuer}/v2.0/.well-known/openid-configuration")),
            require_id_token_verification: true,
            authorization_url: Some(format!("{issuer}/oauth2/v2.0/authorize")),
            token_url: Some(format!("{issuer}/oauth2/v2.0/token")),
            user_info_url: Some("https://graph.microsoft.com/oidc/userinfo".into()),
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
            get_user_info: Some(Arc::new(EntraProfile)),
            account_subject: Some(Arc::new(EntraSubject)),
            ..Default::default()
        })
    }
}

struct EntraProfile;

#[async_trait]
impl GenericOAuthUserInfoHandler for EntraProfile {
    async fn get_user_info(&self, _: &OAuthUserInfoRequest) -> AuthResult<Value> {
        Err(AuthError::internal(
            "Microsoft Entra ID requires verified ID-token claims",
        ))
    }

    async fn get_user_info_with_context(
        &self,
        tokens: &OAuthUserInfoRequest,
        context: GenericOAuthProfileContext<'_>,
    ) -> AuthResult<Value> {
        let claims = context
            .verified_claims()
            .ok_or_else(|| {
                AuthError::internal("Microsoft Entra ID requires verified ID-token claims")
            })?
            .as_value();
        let token_profile = profile(claims, None)?;
        let Some(access_token) = tokens
            .access_token
            .as_deref()
            .filter(|value| !value.is_empty())
        else {
            return Ok(token_profile);
        };
        let endpoint = context
            .user_info_url()
            .ok_or_else(|| AuthError::internal("Missing Microsoft Graph userinfo endpoint"))?;
        let response = reqwest::Client::new()
            .get(endpoint)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|error| request_error("request failed", error))?;
        // The upstream Entra helper retains the verified token profile after a Graph HTTP error.
        if !response.status().is_success() {
            return Ok(token_profile);
        }
        let graph: Value = response
            .json()
            .await
            .map_err(|error| request_error("response failed", error))?;
        if !claims.get("sub").is_some_and(Value::is_string) || graph.get("sub") != claims.get("sub")
        {
            return Ok(token_profile);
        }
        profile(claims, Some(&graph))
    }
}

fn profile(claims: &Value, graph: Option<&Value>) -> AuthResult<Value> {
    let oid = claims
        .get("oid")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AuthError::internal("Microsoft Entra ID claims have no object ID"))?;
    let mut output = graph
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    output.extend(
        claims
            .as_object()
            .ok_or_else(|| AuthError::internal("Microsoft Entra ID claims must be an object"))?
            .clone(),
    );
    replace(
        &mut output,
        "name",
        name(claims).or_else(|| graph.and_then(name)),
    );
    replace(
        &mut output,
        "image",
        match graph {
            Some(graph) => non_null(claims, "picture").or_else(|| graph.get("picture")),
            None => claims.get("picture"),
        }
        .cloned(),
    );
    let email =
        non_null(claims, "email").or_else(|| graph.and_then(|graph| non_null(graph, "email")));
    let verified = if email.is_some_and(|value| graph.is_some() || json_body::is_truthy(value)) {
        non_null(claims, "email_verified")
            .or_else(|| graph.and_then(|graph| non_null(graph, "email_verified")))
            .cloned()
            .unwrap_or(Value::Bool(false))
    } else {
        Value::Bool(false)
    };
    let email = match email {
        Some(email) => email.clone(),
        None => {
            let email = format!("{oid}@microsoft-entra-id.placeholder.invalid");
            if !json_body::valid_email(&email)? {
                return Err(AuthError::internal("Invalid placeholder email"));
            }
            Value::String(email)
        }
    };
    let _ = output.insert("email".into(), email);
    let _ = output.insert("emailVerified".into(), verified);
    Ok(Value::Object(output))
}

fn non_null<'a>(profile: &'a Value, field: &str) -> Option<&'a Value> {
    profile.get(field).filter(|value| !value.is_null())
}

fn name(profile: &Value) -> Option<Value> {
    non_null(profile, "name").cloned().or_else(|| {
        let given = non_null(profile, "given_name")
            .or_else(|| non_null(profile, "givenname"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let family = non_null(profile, "family_name")
            .or_else(|| non_null(profile, "familyname"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let name = format!("{given} {family}")
            .trim_matches(crate::plugins::helpers::oauth_scope_whitespace)
            .to_owned();
        (!name.is_empty()).then_some(Value::String(name))
    })
}

fn replace(output: &mut Map<String, Value>, field: &str, value: Option<Value>) {
    if let Some(value) = value {
        let _ = output.insert(field.into(), value);
    } else {
        let _ = output.remove(field);
    }
}

struct EntraSubject;

fn request_error(context: &str, error: reqwest::Error) -> AuthError {
    let error = error.without_url();
    let mut message = format!("Microsoft Graph {context}: {error}");
    let mut cause = error.source();
    while let Some(error) = cause {
        let _ = write!(message, ": {error}");
        cause = error.source();
    }
    AuthError::internal(message)
}

#[async_trait]
impl OAuthAccountSubject for EntraSubject {
    async fn resolve_subject(
        &self,
        _: &OAuthUserInfoRequest,
        profile: &Value,
    ) -> AuthResult<String> {
        Ok(profile
            .get("oid")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .into())
    }
}

#[cfg(test)]
#[path = "microsoft_entra_tests.rs"]
mod tests;
