#[cfg(test)]
mod native_tests;
mod request;
use std::{future::Future, pin::Pin, sync::Arc};

use better_auth_core::{
    AuthContext, AuthError, AuthRecordFields, AuthRequest, AuthResponse, AuthResult, AuthSchema,
    AuthUser, CreateAccount, CreateUser, CreateVerification, FieldMap, FieldValue, RequestMeta,
};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde_json::{Value, json};
use sha3::{Digest, Keccak256};

use super::helpers::{SessionIssueError, issue_selected_user_session_optional};

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
    pub chain_id: f64,
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
        if req.validated_body::<()>().is_none() {
            let _ = request::nonce(req)?;
        }
        let nonce = (self.get_nonce)().await?;
        if !valid_nonce(&nonce) {
            return Err(AuthResponse::json(
                500,
                &json!({"message":"SIWE getNonce must return an ERC-4361 nonce: 8-250 alphanumeric characters.","status":500,"code":"SIWE_INVALID_NONCE"}),
            )?.into());
        }
        let _ = ctx
            .database
            .create_verification_optional(CreateVerification {
                identifier: (format!("siwe:{nonce}")).into(),
                value: (nonce.clone()).into(),
                expires_at: (Utc::now() + Duration::minutes(15)).into(),
                ..Default::default()
            })
            .await?;
        Ok(AuthResponse::json(None, &json!({"nonce":nonce}))?)
    }
    async fn verify(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body = request::read(req, self.anonymous)?;
        match self
            .verify_inner(
                req,
                ctx,
                &body.message,
                &body.signature,
                body.email.as_deref(),
            )
            .await
        {
            Ok(response) => Ok(response),
            Err(cause) if cause.is_api_error() => Err(cause),
            Err(cause) => Err(AuthResponse::json(
                401,
                &json!({"message":"Something went wrong. Please try again later.","error":cause.to_string(),"status":401}),
            )?.into()),
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
        let Some(chain_id) = parsed.chain_id.filter(|chain| *chain > 0.0) else {
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
            .get_wallet_address_value(&address.clone().into(), Some(&chain_id.into()))
            .await?;
        let wallet = match exact_wallet.as_ref() {
            Some(wallet) => Some(wallet.clone()),
            None => {
                ctx.database
                    .get_wallet_address_value(&address.clone().into(), None)
                    .await?
            }
        };
        let user = match wallet {
            Some(wallet) => {
                ctx.database
                    .get_user_by_id_value(&wallet.user_id.field_value())
                    .await?
            }
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
                        identifier: (identifier.clone()).into(),
                        value: (address.clone()).into(),
                        expires_at: (Utc::now() + Duration::minutes(1)).into(),
                        ..Default::default()
                    })
                    .await;
                let reserved = match reserved {
                    Ok(reserved) => reserved,
                    Err(cause) => {
                        better_auth_core::observability::logger::current().warn(
                            "SIWE email reservation failed; using wallet placeholder email",
                            &[better_auth_core::observability::LogArgument::Error(&cause)],
                        );
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
            create.image = Some(profile.avatar.unwrap_or_default()).into();

            let endpoint = super::endpoint_context::EndpointContext::new(
                Some(req),
                req.input_field_value()?,
                ctx,
            );
            let created =
                super::user_admission::create_user_optional(create.clone(), "siwe", &endpoint)
                    .await;
            let created = match created {
                Err(error) if supplied_email.as_deref() == Some(user_email.as_str()) => {
                    if ctx.database.get_user_by_email(&user_email).await?.is_some() {
                        create.email = Some(wallet_email);
                        super::user_admission::create_user_optional(create, "siwe", &endpoint).await
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
                better_auth_core::observability::logger::current().warn(
                    "SIWE email reservation cleanup failed",
                    &[better_auth_core::observability::LogArgument::Error(&cause)],
                );
            }
            created?.ok_or_else(|| {
                AuthError::internal("Cannot read properties of null (reading 'id')")
            })?
        };
        if new_user || exact_wallet.is_none() {
            let _ = ctx
                .database
                .create_wallet_address_record(FieldMap::from([
                    ("userId".into(), user.id().field_value()),
                    ("address".into(), address.clone().into()),
                    ("chainId".into(), chain_id.into()),
                    ("isPrimary".into(), new_user.into()),
                    (
                        "createdAt".into(),
                        better_auth_core::FieldDate::from(Utc::now()).into(),
                    ),
                ]))
                .await?;
            let _ = ctx
                .database
                .create_account_optional(CreateAccount {
                    user_id: user.id().into_owned(),
                    provider_id: "siwe".into(),
                    account_id: (format!(
                        "{address}:{}",
                        better_auth_core::schema_value::number_string(chain_id)
                    ))
                    .into(),
                    access_token: Default::default(),
                    refresh_token: Default::default(),
                    id_token: Default::default(),
                    access_token_expires_at: Default::default(),
                    refresh_token_expires_at: Default::default(),
                    scope: Default::default(),
                    password: Default::default(),
                    ..Default::default()
                })
                .await?;
        }
        let meta = RequestMeta::from_request_with_config(req, &ctx.config.advanced.ip_address);
        let data = issue_selected_user_session_optional(
            ctx,
            FieldMap::from(user.clone()).into(),
            &meta,
            ctx.config.session.expires_in(),
        )
        .await
        .map_err(SessionIssueError::into_auth_error)?;
        let Some(data) = data else {
            return Err(AuthResponse::json(
                500,
                &json!({"message":"Internal Server Error","status":500}),
            )?
            .into());
        };
        let token = data
            .session
            .field_values()?
            .get("token")
            .cloned()
            .unwrap_or_default();
        ctx.session_manager()
            .set_native_session_cookie(req, data, None)
            .await?;
        Ok(AuthResponse::native(
            None,
            FieldMap::from([
                ("token".into(), token),
                ("success".into(), true.into()),
                (
                    "user".into(),
                    FieldMap::from([
                        ("id".into(), user.id().field_value()),
                        ("walletAddress".into(), address.into()),
                        ("chainId".into(), chain_id.into()),
                    ])
                    .into(),
                ),
            ])
            .into(),
        ))
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
    Err(AuthResponse::json(401, &body)?.into())
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
    chain_id: Option<f64>,
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
                        parsed.chain_id =
                            better_auth_core::query::field_number(&FieldValue::from(value))
                                .ok()
                                .filter(|value| value.is_finite() && value.fract() == 0.0)
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

#[async_trait::async_trait]
impl<S: AuthSchema> better_auth_core::AuthPlugin<S> for SiwePlugin {
    fn name(&self) -> &'static str {
        "siwe"
    }
    fn routes(&self) -> Vec<better_auth_core::AuthRoute> {
        let anonymous = self.anonymous;
        vec![
            better_auth_core::AuthRoute::post("/siwe/nonce", "getSiweNonce")
                .body_validator(request::nonce),
            better_auth_core::AuthRoute::post("/siwe/get-nonce", "getNonce")
                .body_validator(request::nonce),
            better_auth_core::AuthRoute::post("/siwe/verify", "verifySiweMessage")
                .body_validator(move |req| request::verify(req, anonymous)),
        ]
    }
    async fn on_init(&self, ctx: &mut better_auth_core::AuthInitContext<S>) -> AuthResult<()> {
        let role = better_auth_core::store::schema::EntityRole::WalletAddress;
        ctx.register_model_fields(
            role,
            better_auth_core::plugin_runtime::ModelFields::plugin_native_fields(role),
        )
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        if req.method != better_auth_core::HttpMethod::Post {
            return Ok(None);
        }
        match req.path() {
            "/siwe/nonce" | "/siwe/get-nonce" => self.nonce(req, ctx).await.map(Some),
            "/siwe/verify" => self.verify(req, ctx).await.map(Some),
            _ => Ok(None),
        }
    }
}

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
