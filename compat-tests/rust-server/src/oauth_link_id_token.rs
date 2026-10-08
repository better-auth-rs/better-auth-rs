use super::TestSchema;
use async_trait::async_trait;
use axum::{Json, Router, routing::post};
use better_auth::plugins::{
    endpoint_context::EndpointContext,
    oauth::{
        OAuthIdTokenVerifier, OAuthPlugin, OAuthProvider, OAuthUserInfo, OAuthUserInfoHandler,
        OAuthUserInfoRequest, OAuthUserInfoResponse,
        encryption::{maybe_decrypt, maybe_encrypt},
    },
    user_admission::{UserValidationData, UserValidationRejection, ValidateUserInfo},
};
use better_auth::{AuthBuilder, AuthConfig, AuthError, AuthResult, BetterAuth};
use better_auth_core::store::AccountStore;
use better_auth_core::{AuthUser, CreateAccount, UpdateAccount};
use better_auth_seaorm::hooks::{HookControl, SeaOrmHookContext, SeaOrmHooks};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct State {
    provider: Value,
    failure: String,
    events: Vec<String>,
    image_updates: Vec<Value>,
    admissions: usize,
}
#[derive(Clone, Default)]
pub(super) struct OAuthLinkIdTokenFixture {
    state: Arc<Mutex<State>>,
}
#[async_trait]
impl OAuthIdTokenVerifier for OAuthLinkIdTokenFixture {
    async fn verify_id_token(
        &self,
        _: &str,
        _: Option<&str>,
        _: Option<better_auth_core::NativeRequest<'_>>,
    ) -> Result<bool, String> {
        Ok(true)
    }
}
#[async_trait]
impl OAuthUserInfoHandler for OAuthLinkIdTokenFixture {
    async fn get_user_info(
        &self,
        _: OAuthUserInfoRequest,
    ) -> AuthResult<Option<OAuthUserInfoResponse>> {
        let data = self.state.lock().unwrap().provider.clone();
        let mut additional_fields = data.as_object().cloned().unwrap_or_default();
        for name in ["id", "email", "name", "image", "emailVerified"] {
            additional_fields.remove(name);
        }
        Ok(Some(OAuthUserInfoResponse {
            user: OAuthUserInfo {
                id: data["id"].as_str().unwrap_or_default().into(),
                email: Some(data["email"].as_str().unwrap_or_default().into()).into(),
                name: data["name"]
                    .as_str()
                    .map(|value| Some(value.to_owned()).into())
                    .unwrap_or_default(),
                image: data
                    .get("image")
                    .cloned()
                    .map(serde_json::from_value)
                    .transpose()
                    .map_err(|error| better_auth_core::AuthError::internal(error.to_string()))?,
                email_verified: Some(data["emailVerified"] == true).into(),
                additional_fields: better_auth_core::FieldMap::from_json(additional_fields)?,
            },
            data: {
                let mut data = data;
                data["sub"] = data["id"].clone();
                data
            },
        }))
    }
}
#[async_trait]
impl ValidateUserInfo<TestSchema> for OAuthLinkIdTokenFixture {
    async fn validate(
        &self,
        _: &UserValidationData,
        _: &EndpointContext<'_, TestSchema>,
    ) -> AuthResult<Option<UserValidationRejection>> {
        self.state.lock().unwrap().admissions += 1;
        Ok(None)
    }
}
impl OAuthLinkIdTokenFixture {
    pub(super) fn enabled(profile: &str) -> bool {
        profile.starts_with("oauth-link-id-token")
    }
    pub(super) fn configure(profile: &str, config: &mut AuthConfig) {
        if !Self::enabled(profile) {
            return;
        }
        config.account.encrypt_oauth_tokens = Some(true);
        config.account.account_linking.enabled = Some(profile != "oauth-link-id-token-disabled");
        config.account.account_linking.update_user_info_on_link = Some(true);
        config.account.account_linking.trusted_providers = Some(Default::default());
        config.account.account_linking.allow_different_emails = false;
        config.user.fields_mut().insert(
            "department".into(),
            better_auth::config::UserFieldConfig {
                required: Some(false),
                ..Default::default()
            },
        );
        config.user.fields_mut().insert(
            "internalCode".into(),
            better_auth::config::UserFieldConfig {
                required: Some(false),
                input: Some(false),
                default_value: Some("protected".into()),
                ..Default::default()
            },
        );
    }
    pub(super) fn oauth(&self, profile: &str, plugin: OAuthPlugin) -> OAuthPlugin {
        if !Self::enabled(profile) {
            return plugin;
        }
        let mut provider = OAuthProvider::google("fixture-google", "fixture-secret");
        provider.verify_id_token = Some(Arc::new(self.clone()));
        provider.get_user_info = Some(Arc::new(self.clone()));
        plugin.add_provider("google", provider)
    }
    pub(super) fn builder(
        &self,
        profile: &str,
        builder: AuthBuilder<TestSchema>,
    ) -> AuthBuilder<TestSchema> {
        if Self::enabled(profile) {
            builder.validate_user_info(Arc::new(self.clone()))
        } else {
            builder
        }
    }
    pub(super) fn hooks(&self) -> Arc<dyn SeaOrmHooks<TestSchema>> {
        Arc::new(self.clone())
    }
    pub(super) fn reset(&self) {
        *self.state.lock().unwrap() = State::default();
    }
    fn hook(&self, name: &str, ctx: &SeaOrmHookContext<'_, TestSchema>) -> AuthResult<()> {
        if !ctx.request.as_ref().is_some_and(|request| {
            request
                .path
                .as_deref()
                .is_some_and(|path| path.ends_with("/link-social"))
        }) {
            return Ok(());
        }
        let mut state = self.state.lock().unwrap();
        state.events.push(name.into());
        if state.failure == name {
            return Err(AuthError::internal(format!("fixture {name}")));
        }
        Ok(())
    }
    fn cancel(&self, name: &str) -> HookControl {
        if self.state.lock().unwrap().failure == format!("{name}.cancel") {
            HookControl::Cancel
        } else {
            HookControl::Continue
        }
    }
    pub(super) fn router(&self, auth: Arc<BetterAuth<TestSchema>>) -> Router {
        let fixture = self.clone();
        Router::new().route("/__test/oauth-link-id-token", post(move |Json(body): Json<Value>| { let fixture=fixture.clone(); let auth=auth.clone(); async move {
            {
                let mut state=fixture.state.lock().unwrap();
                if let Some(provider)=body.get("provider") { state.provider=provider.clone(); }
                if let Some(failure)=body["failure"].as_str() { state.failure=failure.into(); }
                if body["clear"]==true { state.events.clear(); state.image_updates.clear(); state.admissions=0; }
            }
            let user=match body["email"].as_str() { Some(email)=>auth.store().get_user_by_email(email).await?, None=>None };
            let secret=auth.config().encryption_secret();
            if body["seed"]==true { if let Some(user)=&user {
                let account_id=fixture.state.lock().unwrap().provider["id"].as_str().unwrap().to_owned();
                let _=auth.store().create_account(CreateAccount {
user_id: (user.id().into_owned()).into(),
provider_id: "google".into(),
account_id: (account_id).into(),
access_token: (maybe_encrypt(Some("seed-access".into()),true,secret)?).map(|value| better_auth_core::SchemaValue::Typed(Some(value))).unwrap_or_default(),
refresh_token: (maybe_encrypt(Some("seed-refresh".into()),true,secret)?).map(|value| better_auth_core::SchemaValue::Typed(Some(value))).unwrap_or_default(),
id_token: (Some("seed-id".into())).into(),
scope: (Some("seed-scope".into())).into(),
access_token_expires_at: Default::default(),
refresh_token_expires_at: Default::default(),
password: Default::default(),
..Default::default()
}).await?;
            }}
            let accounts=match &user { Some(user)=>auth.store().get_user_accounts(user.id().typed().unwrap()).await?, None=>vec![] };
            let account=accounts.iter().find(|account|account.provider_id=="google");
            let account=account.map(|account| {
                let raw_access = account.access_token.typed()?.as_deref();
                let access=maybe_decrypt(raw_access,true,secret)?;
                let refresh=maybe_decrypt(account.refresh_token.typed()?.as_deref(),true,secret)?;
                Ok::<_,AuthError>(json!({"encrypted":access.as_ref().is_some_and(|token|!token.is_empty() && Some(token.as_str())!=raw_access),"accessToken":access,"refreshToken":refresh,"idToken":account.id_token.typed()?.as_deref(),"scope":account.scope.typed()?.as_deref(),"accessTokenExpiresAt":account.access_token_expires_at.json()?}))
            }).transpose()?;
            let user=user.map(|user| {
                Ok::<_,AuthError>(json!({"name":user.name,"email":user.email(),"emailVerified":user.email_verified(),"image":user.image,
                    "department":user.additional_fields.get("department").map(better_auth_core::FieldValue::json).transpose()?.flatten(),
                    "internalCode":user.additional_fields.get("internalCode").map(better_auth_core::FieldValue::json).transpose()?.flatten()}))
            }).transpose()?;
            let state=fixture.state.lock().unwrap();
            Ok::<_,AuthError>(Json(json!({"events":state.events,"imageUpdates":state.image_updates,"admissions":state.admissions,"nestedAccounts":accounts.iter().filter(|account|account.provider_id=="nested-cancel").count(),"user":user,"account":account})))
        }}))
    }
}
#[better_auth::database_hooks()]
impl SeaOrmHooks<TestSchema> for OAuthLinkIdTokenFixture {
    async fn before_create_account(
        &self,
        account: &mut CreateAccount,
        ctx: &SeaOrmHookContext<'_, TestSchema>,
    ) -> AuthResult<HookControl> {
        if account.provider_id == "nested-cancel" {
            self.state
                .lock()
                .unwrap()
                .events
                .push("account.create.nested".into());
            return Ok(HookControl::Cancel);
        }
        self.hook("account.create.before", ctx)?;
        let nested = self.state.lock().unwrap().failure == "account.create.nested";
        if nested
            && ctx.request.as_ref().is_some_and(|request| {
                request
                    .path
                    .as_deref()
                    .is_some_and(|path| path.ends_with("/link-social"))
            })
        {
            let mut input = account.clone();
            input.provider_id = "nested-cancel".into();
            input.account_id = format!("{}.nested", input.account_id.typed()?).into();
            let store = better_auth_seaorm::SeaOrmStore::<TestSchema>::new(
                ctx.config.clone(),
                ctx.db.clone(),
            )
            .with_hooks(vec![self.hooks()]);
            let _ = store.create_account(input).await?;
        }
        Ok(self.cancel("account.create.before"))
    }
    async fn after_create_account(
        &self,
        _: Option<&better_auth_core::wire::AccountView>,
        ctx: &SeaOrmHookContext<'_, TestSchema>,
    ) -> AuthResult<()> {
        self.hook("account.create.after", ctx)
    }
    async fn before_update_account(
        &self,
        _: &str,
        _: &UpdateAccount,
        ctx: &SeaOrmHookContext<'_, TestSchema>,
    ) -> AuthResult<better_auth::seaorm::DatabaseHookUpdate<UpdateAccount>> {
        self.hook("account.update.before", ctx)?;
        Ok(if self.cancel("account.update.before").is_cancelled() {
            better_auth::seaorm::DatabaseHookUpdate::Cancel
        } else {
            better_auth::seaorm::DatabaseHookUpdate::Continue
        })
    }
    async fn after_update_account(
        &self,
        _: Option<&better_auth_core::wire::AccountView>,
        ctx: &SeaOrmHookContext<'_, TestSchema>,
    ) -> AuthResult<()> {
        self.hook("account.update.after", ctx)
    }
    async fn before_update_user(
        &self,
        _: &better_auth_core::FieldValue,
        update: &mut better_auth_core::FieldMap,
        ctx: &SeaOrmHookContext<'_, TestSchema>,
    ) -> AuthResult<better_auth::seaorm::DatabaseHookUpdate<better_auth_core::FieldMap>> {
        if ctx.request.as_ref().is_some_and(|request| {
            request
                .path
                .as_deref()
                .is_some_and(|path| path.ends_with("/link-social"))
        }) {
            self.state.lock().unwrap().image_updates.push(
                match update
                    .get("image")
                    .unwrap_or(&better_auth_core::FieldValue::Undefined)
                    .json()?
                {
                    Some(image) => json!({ "image": image }),
                    None => json!({}),
                },
            );
        }
        self.hook("user.update.before", ctx)?;
        Ok(better_auth::seaorm::DatabaseHookUpdate::Continue)
    }
    async fn after_update_user(
        &self,
        _: Option<&better_auth_core::wire::UserView>,
        ctx: &SeaOrmHookContext<'_, TestSchema>,
    ) -> AuthResult<()> {
        self.hook("user.update.after", ctx)
    }
}
