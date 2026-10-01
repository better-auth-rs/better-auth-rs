use std::{future::Future, pin::Pin, sync::Arc};

use better_auth_core::types::WalletAddress;
use better_auth_core::utils::cookie_utils::create_session_cookie;
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema, AuthSession,
    AuthUser, CreateAccount, CreateUser, CreateVerification, RequestMeta,
};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde_json::{Value, json};
use sha3::{Digest, Keccak256};
use validator::ValidateEmail;

use super::helpers::{SessionIssueError, issue_user_session};

type CallbackFuture<T> = Pin<Box<dyn Future<Output = AuthResult<T>> + Send>>;
type NonceCallback = dyn Fn() -> CallbackFuture<String> + Send + Sync;
type VerifyCallback = dyn Fn(SiweVerification) -> CallbackFuture<bool> + Send + Sync;
type EnsCallback = dyn Fn(String) -> CallbackFuture<EnsProfile> + Send + Sync;

/// Validated signed-message context passed to the application's SIWE verifier.
#[derive(Debug, Clone)]
pub struct SiweVerification {
    /// Original ERC-4361 message, without normalization.
    pub message: String,
    /// Signature supplied by the wallet.
    pub signature: String,
    /// EIP-55 checksum address parsed from the message.
    pub address: String,
    /// Positive chain identifier parsed from the message.
    pub chain_id: i64,
    /// Upstream CACAO context for application verifiers.
    pub cacao: Value,
}
/// Optional ENS attributes used when creating a wallet identity.
#[derive(Debug, Clone, Default)]
pub struct EnsProfile {
    /// Display name; omission uses the checksum address.
    pub name: Option<String>,
    /// Avatar URL; omission uses an empty image value.
    pub avatar: Option<String>,
}

/// Sign-In with Ethereum. The required verifier must authenticate the signature.
#[derive(Clone)]
pub struct SiwePlugin {
    domain: String,
    get_nonce: Arc<NonceCallback>,
    verify_message: Arc<VerifyCallback>,
    ens_lookup: Option<Arc<EnsCallback>>,
    anonymous: bool,
    email_domain_name: Option<String>,
}
impl SiwePlugin {
    /// Configure the expected domain, nonce generator, and signature verifier.
    pub fn new<N, NF, V, VF>(domain: impl Into<String>, nonce: N, verify: V) -> Self
    where
        N: Fn() -> NF + Send + Sync + 'static,
        NF: Future<Output = AuthResult<String>> + Send + 'static,
        V: Fn(SiweVerification) -> VF + Send + Sync + 'static,
        VF: Future<Output = AuthResult<bool>> + Send + 'static,
    {
        Self {
            domain: domain.into(),
            get_nonce: Arc::new(move || Box::pin(nonce())),
            verify_message: Arc::new(move |message| Box::pin(verify(message))),
            ens_lookup: None,
            anonymous: true,
            email_domain_name: None,
        }
    }
    /// Permit verification without email; enabled by default.
    pub fn anonymous(mut self, anonymous: bool) -> Self {
        self.anonymous = anonymous;
        self
    }
    /// Use this domain for generated wallet placeholder emails.
    pub fn email_domain_name(mut self, domain: impl Into<String>) -> Self {
        self.email_domain_name = Some(domain.into());
        self
    }
    /// Resolve display attributes for a newly registered checksum address.
    pub fn ens_lookup<F, Fut>(mut self, callback: F) -> Self
    where
        F: Fn(String) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = AuthResult<EnsProfile>> + Send + 'static,
    {
        self.ens_lookup = Some(Arc::new(move |address| Box::pin(callback(address))));
        self
    }

    async fn nonce(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body = match super::json_body::parse(req) {
            Ok(body) => body,
            Err(response) => return Ok(response),
        };
        if let Some(body) = body {
            if !body.is_object() {
                return Ok(super::json_body::validation_error(
                    &super::json_body::invalid_type("body", "object", Some(&body)),
                ));
            }
            if let Some(message) = unknown_keys(&body, &[]) {
                return Ok(super::json_body::validation_error(&message));
            }
        }
        let nonce = (self.get_nonce)().await?;
        if !valid_nonce(&nonce) {
            return Ok(AuthResponse::json(
                500,
                &json!({"message":"SIWE getNonce must return an ERC-4361 nonce: 8-250 alphanumeric characters.","status":500,"code":"SIWE_INVALID_NONCE"}),
            )?);
        }
        let _ = ctx
            .database
            .create_verification(CreateVerification {
                identifier: format!("siwe:{nonce}"),
                value: nonce.clone(),
                expires_at: Utc::now() + Duration::minutes(15),
            })
            .await?;
        Ok(AuthResponse::json(200, &json!({"nonce":nonce}))?)
    }
    async fn verify(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let value = match super::json_body::parse(req) {
            Ok(body) => body,
            Err(response) => return Ok(response),
        };
        if !value.as_ref().is_some_and(Value::is_object) {
            return Ok(super::json_body::validation_error(
                &super::json_body::invalid_type("body", "object", value.as_ref()),
            ));
        }
        let body = value.unwrap_or_default();
        let mut errors = Vec::new();
        for key in ["message", "signature"] {
            match body.get(key).and_then(Value::as_str) {
                None => errors.push(super::json_body::invalid_type(
                    &format!("body.{key}"),
                    "string",
                    body.get(key),
                )),
                Some("") => errors.push(format!(
                    "[body.{key}] Too small: expected string to have >=1 characters"
                )),
                Some(_) => {}
            }
        }
        let email = body.get("email").and_then(Value::as_str);
        if body.get("email").is_some() {
            match email {
                None => errors.push(super::json_body::invalid_type(
                    "body.email",
                    "string",
                    body.get("email"),
                )),
                Some(email) if !email.validate_email() => {
                    errors.push("[body.email] Invalid email address".into())
                }
                _ => {}
            }
        }
        if let Some(message) = unknown_keys(&body, &["message", "signature", "email"]) {
            errors.push(message);
        }
        if !self.anonymous && email.is_none() {
            errors.push(
                "[body.email] Email is required when the anonymous plugin option is disabled."
                    .into(),
            );
        }
        if !errors.is_empty() {
            return Ok(super::json_body::validation_error(&errors.join("; ")));
        }
        match self
            .verify_inner(
                req,
                ctx,
                body.get("message")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                body.get("signature")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                email,
            )
            .await
        {
            Ok(response) => Ok(response),
            Err(cause @ (AuthError::Upstream { .. } | AuthError::BannedUser(_))) => Err(cause),
            Err(cause) => Ok(AuthResponse::json(
                401,
                &json!({"message":"Something went wrong. Please try again later.","error":cause.to_string(),"status":401}),
            )?),
        }
    }
    async fn verify_inner(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
        message: &str,
        signature: &str,
        email: Option<&str>,
    ) -> AuthResult<AuthResponse> {
        let parsed = ParsedMessage::parse(message);
        let Some(nonce) = parsed.nonce.filter(|nonce| valid_nonce(nonce)) else {
            return mismatch();
        };
        if ctx
            .database
            .consume_verification_by_identifier(&format!("siwe:{nonce}"))
            .await?
            .is_none()
        {
            return unauthorized(
                "Unauthorized: Invalid or expired nonce",
                Some("UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE"),
            );
        }
        let Some(address) = parsed.address.and_then(checksum_address) else {
            return mismatch();
        };
        let Some(chain_id) = parsed.chain_id.filter(|chain| *chain > 0) else {
            return mismatch();
        };
        if parsed
            .domain
            .is_none_or(|domain| normalize_domain(domain) != normalize_domain(&self.domain))
        {
            return mismatch();
        }
        if parsed
            .expiration_time
            .and_then(parse_date)
            .is_some_and(|time| Utc::now() >= time)
        {
            return unauthorized(
                "Unauthorized: SIWE message has expired",
                Some("UNAUTHORIZED_SIWE_MESSAGE_EXPIRED"),
            );
        }
        if parsed
            .not_before
            .and_then(parse_date)
            .is_some_and(|time| Utc::now() < time)
        {
            return unauthorized(
                "Unauthorized: SIWE message is not yet valid",
                Some("UNAUTHORIZED_SIWE_MESSAGE_NOT_YET_VALID"),
            );
        }
        let arguments = SiweVerification {
            message: message.to_owned(),
            signature: signature.to_owned(),
            address: address.clone(),
            chain_id,
            cacao: json!({"h":{"t":"caip122"},"p":{"domain":self.domain,"aud":self.domain,"nonce":nonce,"iss":self.domain,"version":"1"},"s":{"t":"eip191","s":signature}}),
        };
        if !(self.verify_message)(arguments).await? {
            return unauthorized("Unauthorized: Invalid SIWE signature", None);
        }
        let exact_wallet = ctx
            .database
            .get_wallet_address(&address, Some(chain_id))
            .await?;
        let wallet = match exact_wallet.as_ref() {
            Some(wallet) => Some(wallet.clone()),
            None => ctx.database.get_wallet_address(&address, None).await?,
        };
        let user = match wallet {
            Some(wallet) => ctx.database.get_user_by_id(&wallet.user_id).await?,
            None => None,
        };
        let new_user = user.is_none();
        let user = if let Some(user) = user {
            user
        } else {
            let wallet_email = match &self.email_domain_name {
                Some(domain) => format!("{address}@{domain}"),
                None => format!("{address}@siwe.placeholder.invalid"),
            };
            let supplied_email = email.map(str::to_lowercase).filter(|_| !self.anonymous);
            let mut email_claim = None;
            let mut user_email = wallet_email.clone();
            if let Some(email) = &supplied_email {
                let identifier = format!("siwe-email-claim-{email}");
                let reserved = ctx
                    .database
                    .reserve_verification_value(CreateVerification {
                        identifier: identifier.clone(),
                        value: address.clone(),
                        expires_at: Utc::now() + Duration::minutes(1),
                    })
                    .await;
                let reserved = match reserved {
                    Ok(reserved) => reserved,
                    Err(cause) => {
                        tracing::warn!(error=?cause,"SIWE email reservation failed; using wallet placeholder email");
                        false
                    }
                };
                if reserved {
                    email_claim = Some(identifier);
                    if ctx.database.get_user_by_email(email).await?.is_none() {
                        user_email = email.clone();
                    }
                }
            }
            let profile = match &self.ens_lookup {
                Some(lookup) => lookup(address.clone()).await?,
                None => EnsProfile::default(),
            };
            let mut create = CreateUser::new()
                .with_email(&user_email)
                .with_name(profile.name.unwrap_or_else(|| address.clone()));
            create.image = Some(profile.avatar.unwrap_or_default());

            let endpoint =
                super::endpoint_context::EndpointContext::new(Some(req), req.body_as_json()?, ctx);
            let created =
                super::user_admission::create_user(create.clone(), "siwe", &endpoint).await;
            let created = match created {
                Err(error) if supplied_email.as_deref() == Some(user_email.as_str()) => {
                    if ctx.database.get_user_by_email(&user_email).await?.is_some() {
                        create.email = Some(wallet_email);
                        super::user_admission::create_user(create, "siwe", &endpoint).await
                    } else {
                        Err(error)
                    }
                }
                result => result,
            };
            if let Some(identifier) = email_claim
                && let Err(cause) = ctx
                    .database
                    .consume_verification_by_identifier(&identifier)
                    .await
            {
                tracing::warn!(error=?cause,"SIWE email reservation cleanup failed");
            }
            created?
        };
        if new_user || exact_wallet.is_none() {
            let _ = ctx
                .database
                .create_wallet_address(WalletAddress {
                    id: uuid::Uuid::new_v4().to_string(),
                    user_id: user.id().into_owned(),
                    address: address.clone(),
                    chain_id,
                    is_primary: new_user,
                    created_at: Utc::now(),
                })
                .await?;
            let _ = ctx
                .database
                .create_account(CreateAccount {
                    user_id: user.id().into_owned(),
                    provider_id: "siwe".into(),
                    account_id: format!("{address}:{chain_id}"),
                    access_token: None,
                    refresh_token: None,
                    id_token: None,
                    access_token_expires_at: None,
                    refresh_token_expires_at: None,
                    scope: None,
                    password: None,
                })
                .await?;
        }
        let meta = RequestMeta::from_request_with_config(req, &ctx.config.advanced.ip_address);
        let issued = issue_user_session(ctx, &user.id(), meta.ip_address, meta.user_agent)
            .await
            .map_err(SessionIssueError::into_auth_error)?;
        Ok(AuthResponse::json(200,&json!({"token":issued.session.token(),"success":true,"user":{"id":user.id(),"walletAddress":address,"chainId":chain_id}}))?.with_header("Set-Cookie",create_session_cookie(issued.session.token(),&ctx.config)))
    }
}

fn valid_nonce(nonce: &str) -> bool {
    (8..=250).contains(&nonce.len()) && nonce.bytes().all(|byte| byte.is_ascii_alphanumeric())
}
fn normalize_domain(domain: &str) -> String {
    let value = domain.trim().to_lowercase();
    let value = value
        .split_once("://")
        .map_or(value.as_str(), |(_, rest)| rest);
    value.split('/').next().unwrap_or_default().to_owned()
}
fn parse_date(date: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(date)
        .or_else(|_| DateTime::parse_from_rfc2822(date))
        .ok()
        .map(|date| date.with_timezone(&Utc))
        .or_else(|| {
            NaiveDate::parse_from_str(date, "%Y-%m-%d")
                .ok()?
                .and_hms_opt(0, 0, 0)
                .map(|date| date.and_utc())
        })
}
fn mismatch() -> AuthResult<AuthResponse> {
    unauthorized(
        "Unauthorized: SIWE message does not match the expected nonce, domain, address, or chain ID",
        Some("UNAUTHORIZED_SIWE_MESSAGE_MISMATCH"),
    )
}
fn unauthorized(message: &str, code: Option<&str>) -> AuthResult<AuthResponse> {
    let mut body = serde_json::Map::from_iter([
        (String::from("message"), json!(message)),
        (String::from("status"), json!(401)),
    ]);
    if let Some(code) = code {
        let _ = body.insert("code".into(), json!(code));
    }
    Ok(AuthResponse::json(401, &body)?)
}

/// Convert a valid Ethereum address to its EIP-55 checksum representation.
fn checksum_address(address: &str) -> Option<String> {
    let address = address.strip_prefix("0x")?;
    if address.len() != 40 || !address.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let lowercase = address.to_ascii_lowercase();
    let digest = Keccak256::digest(lowercase.as_bytes());
    let nibbles = digest.iter().flat_map(|byte| [byte >> 4, byte & 15]);
    let mut result = String::from("0x");
    for (byte, nibble) in lowercase.bytes().zip(nibbles) {
        result.push(char::from(if nibble >= 8 {
            byte.to_ascii_uppercase()
        } else {
            byte
        }));
    }
    Some(result)
}

#[derive(Default)]
struct ParsedMessage<'a> {
    domain: Option<&'a str>,
    address: Option<&'a str>,
    chain_id: Option<i64>,
    nonce: Option<&'a str>,
    expiration_time: Option<&'a str>,
    not_before: Option<&'a str>,
}
impl<'a> ParsedMessage<'a> {
    fn parse(message: &'a str) -> Self {
        let mut parsed = Self::default();
        let mut lines = message.lines();
        parsed.domain = lines
            .next()
            .and_then(|line| line.strip_suffix(" wants you to sign in with your Ethereum account:"))
            .and_then(|header| {
                let domain = header
                    .split_once("://")
                    .map_or(header, |(_, domain)| domain);
                (!domain.is_empty() && !domain.chars().any(char::is_whitespace)).then_some(domain)
            });
        parsed.address = lines.next().map(str::trim);
        for line in message.lines() {
            if let Some((key, value)) = line.split_once(": ") {
                match key {
                    "Chain ID" => {
                        parsed.chain_id = value
                            .trim()
                            .parse::<f64>()
                            .ok()
                            .filter(|value| {
                                value.fract() == 0.0
                                    && *value < i64::MAX as f64
                                    && *value >= i64::MIN as f64
                            })
                            .map(|value| value as i64)
                    }
                    "Nonce" => parsed.nonce = Some(value),
                    "Expiration Time" => parsed.expiration_time = Some(value),
                    "Not Before" => parsed.not_before = Some(value),
                    _ => {}
                }
            }
        }
        parsed
    }
}

better_auth_core::impl_auth_plugin!(SiwePlugin, "siwe";
    routes {
        post "/siwe/nonce" => nonce, "getSiweNonce";
        post "/siwe/get-nonce" => nonce, "getNonce";
        post "/siwe/verify" => verify, "verifySiweMessage";
    }
);

fn unknown_keys(body: &Value, allowed: &[&str]) -> Option<String> {
    let keys: Vec<_> = body
        .as_object()?
        .keys()
        .filter(|key| !allowed.contains(&key.as_str()))
        .map(|key| format!("\"{key}\""))
        .collect();
    if keys.is_empty() {
        None
    } else {
        Some(format!(
            "[body] Unrecognized {}: {}",
            if keys.len() == 1 { "key" } else { "keys" },
            keys.join(", ")
        ))
    }
}
