use better_auth_core::entity::AuthPasskey;
use serde::{Deserialize, Serialize};
use validator::Validate;

// -- Request types --

#[cfg(feature = "axum")]
#[derive(Debug, Deserialize)]
pub(crate) struct RegisterOptionsQuery {
    #[serde(rename = "authenticatorAttachment")]
    pub(crate) authenticator_attachment: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VerifyRegistrationRequest {
    pub(super) response: serde_json::Value,
    pub(super) name: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VerifyAuthenticationRequest {
    pub(super) response: serde_json::Value,
}

#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeletePasskeyRequest {
    #[validate(length(min = 1))]
    pub(super) id: String,
}

#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UpdatePasskeyRequest {
    #[validate(length(min = 1))]
    pub(super) id: String,
    #[validate(length(min = 1))]
    pub(super) name: String,
}

// -- Response helpers --

#[derive(Debug, Serialize)]
pub(crate) struct PasskeyView {
    id: String,
    name: String,
    #[serde(rename = "credentialID")]
    credential_id: String,
    #[serde(rename = "userId")]
    user_id: String,
    #[serde(rename = "publicKey")]
    public_key: String,
    counter: u64,
    #[serde(rename = "deviceType")]
    device_type: String,
    #[serde(rename = "backedUp")]
    backed_up: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    transports: Option<String>,
    #[serde(rename = "createdAt")]
    created_at: String,
}

impl PasskeyView {
    pub(super) fn from_entity(pk: &impl AuthPasskey) -> Self {
        Self {
            id: pk.id().to_string(),
            name: pk.name().to_string(),
            credential_id: pk.credential_id().to_string(),
            user_id: pk.user_id().to_string(),
            public_key: pk.public_key().to_string(),
            counter: pk.counter(),
            device_type: pk.device_type().to_string(),
            backed_up: pk.backed_up(),
            transports: pk.transports().map(|s| s.to_string()),
            created_at: pk.created_at().to_rfc3339(),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct SessionUserResponse<U: Serialize, S: Serialize> {
    pub(crate) session: S,
    pub(crate) user: U,
}

#[derive(Debug, Serialize)]
pub(crate) struct PasskeyResponse {
    pub(super) passkey: PasskeyView,
}
