use axum::{routing::post, Json, Router};
use better_auth::__private_core::{
    store::{UserStore, VerificationStore},
    AuthUser, UpdateUser,
};
use better_auth::{
    plugins::{
        anonymous::AnonymousPlugin,
        phone_number::{PhoneNumberPlugin, PhoneOtp},
        siwe::{SiwePlugin, SiweVerification},
    },
    AuthBuilder, AuthResult,
};
use better_auth_seaorm::{
    sea_orm::{EntityTrait, QueryOrder},
    SeaOrmStore,
};
use chrono::{Duration, Utc};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

#[derive(Default)]
struct State {
    outbox: HashMap<String, Vec<Value>>,
    links: Vec<Value>,
    counter: u64,
}
#[derive(Clone, Default)]
pub(super) struct IdentityFixture {
    state: Arc<Mutex<State>>,
}
impl IdentityFixture {
    pub(super) async fn reset(&self) {
        *self.state.lock().await = State::default();
    }
    async fn send(&self, otp: PhoneOtp, purpose: &str) -> AuthResult<()> {
        self.state
            .lock()
            .await
            .outbox
            .entry(otp.phone_number.clone())
            .or_default()
            .push(json!({"phoneNumber":otp.phone_number,"code":otp.code,"purpose":purpose}));
        Ok(())
    }
    pub(super) fn add_plugins(
        &self,
        builder: AuthBuilder<super::TestSchema>,
        profile: &str,
    ) -> AuthBuilder<super::TestSchema> {
        if profile.starts_with("anonymous") || profile == "oauth-proxy-anonymous" {
            let generator = self.clone();
            let callback = self.clone();
            builder.plugin(AnonymousPlugin::new().generate_random_email(move||{let fixture=generator.clone();async move {let mut state=fixture.state.lock().await;state.counter+=1;Ok(format!("anonymous-{}@example.com",state.counter))}}).disable_delete_anonymous_user(profile=="anonymous-disabled").on_link_account(move|link|{let fixture=callback.clone();async move {fixture.state.lock().await.links.push(json!({"anonymousId":link.anonymous_user.id,"newId":link.new_user.id}));Ok(())}}))
        } else if profile.starts_with("phone-number") || profile == "email-otp-reuse" {
            let sender = self.clone();
            let reset = self.clone();
            let plugin = PhoneNumberPlugin::new()
                .send_otp(move |otp, _| {
                    let fixture = sender.clone();
                    async move { fixture.send(otp, "verify").await }
                })
                .send_password_reset_otp(move |otp, _| {
                    let fixture = reset.clone();
                    async move { fixture.send(otp, "reset").await }
                })
                .phone_number_validator(|phone| async move {
                    Ok(phone.starts_with('+')
                        && (11..=16).contains(&phone.len())
                        && phone[1..].bytes().all(|byte| byte.is_ascii_digit()))
                })
                .require_verification(profile == "phone-number-options");
            let plugin = if profile == "phone-number-options" {
                plugin
            } else {
                plugin.sign_up_on_verification(|phone| format!("{}@phone.example.com", &phone[1..]))
            };
            builder.plugin(plugin)
        } else if profile.starts_with("siwe") {
            let generator = self.clone();
            builder.plugin(
                SiwePlugin::new(
                    "wallet.example.com",
                    move || {
                        let fixture = generator.clone();
                        async move {
                            let mut state = fixture.state.lock().await;
                            state.counter += 1;
                            Ok(format!("identitynonce{:08}", state.counter))
                        }
                    },
                    |message| async move { Ok(verify_signature(&message)) },
                )
                .anonymous(profile != "siwe-email"),
            )
        } else {
            builder
        }
    }
    pub(super) fn router(&self, store: Arc<SeaOrmStore<super::TestSchema>>) -> Router {
        let fixture = self.clone();
        Router::new().route("/__test/identity",post(move|Json(body):Json<Value>|{let fixture=fixture.clone();let store=store.clone();async move {
            match body["action"].as_str() {
                Some("links")=>Json(json!(fixture.state.lock().await.links)),
                Some("expire")=>{store.update_verification_by_identifier(body["identifier"].as_str().unwrap(),None,Some(Utc::now()-Duration::seconds(1))).await.unwrap();Json(json!({"success":true}))},
                Some("phone")=>{let user=store.get_user_by_email(body["email"].as_str().unwrap()).await.unwrap().unwrap();store.update_user(&user.id(),UpdateUser{phone_number:Some(Some(body["phoneNumber"].as_str().unwrap().to_owned())),phone_number_verified:Some(body["verified"].as_bool().unwrap_or(false)),..Default::default()}).await.unwrap();Json(json!({"success":true}))},
                Some("wallets")=>{use better_auth_seaorm::store::entities::wallet_address::{Entity,Column};let wallets=Entity::find().order_by_asc(Column::ChainId).all(store.connection()).await.unwrap();Json(json!(wallets.into_iter().map(|wallet|json!({"address":wallet.address,"chainId":wallet.chain_id,"isPrimary":wallet.is_primary,"userId":wallet.user_id})).collect::<Vec<_>>()))},
                _=>Json(json!(fixture.state.lock().await.outbox.get(body["phoneNumber"].as_str().unwrap()).cloned().unwrap_or_default())),
            }
        }}))
    }
}

fn verify_signature(message: &SiweVerification) -> bool {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    let Some(signature) = message.signature.strip_prefix("0x").and_then(decode_hex) else {
        return false;
    };
    if signature.len() != 65 {
        return false;
    }
    let Ok(sig) = Signature::from_slice(&signature[..64]) else {
        return false;
    };
    let Some(recovery) = signature[64]
        .checked_sub(27)
        .and_then(RecoveryId::from_byte)
    else {
        return false;
    };
    let hash = Keccak256::digest(format!(
        "\x19Ethereum Signed Message:\n{}{}",
        message.message.len(),
        message.message
    ));
    let Ok(key) = VerifyingKey::recover_from_prehash(&hash, &sig, recovery) else {
        return false;
    };
    let public = key.to_sec1_point(false);
    let address = Keccak256::digest(&public.as_bytes()[1..]);
    let address = format!(
        "0x{}",
        address[12..]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    address == message.address.to_ascii_lowercase()
}
fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|bytes| {
            std::str::from_utf8(bytes)
                .ok()
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
        })
        .collect()
}
