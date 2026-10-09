use better_auth_core::{
    AuthConfig, AuthError, AuthResult, CreateUser, FieldMap, FieldValue, UpdateUser, UserView,
    store::{EphemeralStore, UserStore},
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform, UserFieldType},
};
use serde_json::Value;
use std::sync::{Arc, Mutex};

#[path = "device_where_values.rs"]
mod values;

pub(crate) fn observe(value: &FieldValue) -> AuthResult<Value> {
    values::observe(value)
}

pub(crate) fn revive(value: &Value) -> AuthResult<FieldValue> {
    values::revive(value)
}

pub(crate) const OWNER: &str = "runtime-owner";
pub(crate) const EMAIL: &str = "owner@runtime.test";
pub(crate) const DATE: &str = "2030-01-02T03:04:05.000Z";
pub(crate) type Calls = Arc<Mutex<Vec<FieldValue>>>;

pub(crate) fn cases() -> AuthResult<Value> {
    Ok(serde_json::from_str(include_str!(
        "../fixtures/user-runtime-output-cases.json"
    ))?)
}

pub(crate) fn config() -> AuthResult<AuthConfig> {
    let mut config = AuthConfig::new("user-runtime-output-secret-at-least-thirty-two-characters")
        .base_url("http://localhost:3000");
    config.logger.disabled = Some(true);
    config.telemetry.enabled = false;
    let cases = cases()?;
    for field in cases["fields"].as_array().unwrap() {
        let _ = config.user.fields_mut().insert(
            field["name"].as_str().unwrap().into(),
            UserFieldConfig {
                field_type: match field["type"].as_str().unwrap() {
                    "boolean" => UserFieldType::Boolean,
                    "date" => UserFieldType::Date,
                    "json" => UserFieldType::Json,
                    _ => UserFieldType::String,
                },
                required: Some(false),
                ..Default::default()
            },
        );
    }
    Ok(config)
}

pub(crate) fn replace(config: &mut AuthConfig, name: &str, value: FieldValue, fail: bool) -> Calls {
    let calls = Calls::default();
    let trace = calls.clone();
    config.user.fields_mut().get_mut(name).unwrap().transform = Some(FieldTransforms {
        output: Some(UserFieldTransform::new(move |original| {
            trace
                .lock()
                .map_err(|_| AuthError::internal("User output trace lock poisoned"))?
                .push(original);
            if fail {
                Err(AuthError::internal("user-output-stop"))
            } else {
                Ok(value.clone())
            }
        })),
        ..Default::default()
    });
    calls
}

pub(crate) async fn seed(config: &AuthConfig) -> AuthResult<(Arc<EphemeralStore>, UserView)> {
    let raw = Arc::new(EphemeralStore::new(Arc::new(config.clone())));
    let date = DATE.parse::<chrono::DateTime<chrono::Utc>>().unwrap();
    let user = raw
        .create_user(CreateUser {
            id: Some(OWNER.into()),
            name: Some("Owner".into()).into(),
            email: Some(EMAIL.into()),
            email_verified: Some(false),
            image: Some("image".into()).into(),
            created_at: Some(date.into()),
            updated_at: Some(date.into()),
            is_anonymous: Some(false),
            phone_number: Some("+12025550123".into()),
            phone_number_verified: Some(false),
            username: Some(Some("owner".into())),
            display_username: Some(Some("Owner".into())),
            role: Some("user".into()),
            banned: Some(false),
            ban_reason: Some("reason".into()),
            ban_expires: Some(date.into()),
            metadata: Some(FieldMap::from([("seed".into(), true.into())]).into()),
            additional_fields: FieldMap::from([("twoFactorEnabled".into(), false.into())]),
        })
        .await?;
    Ok((raw, user))
}

pub(crate) fn native_user() -> FieldMap {
    let date: chrono::DateTime<chrono::Utc> = DATE.parse().unwrap();
    FieldMap::from([
        ("id".into(), OWNER.into()),
        ("name".into(), "Owner".into()),
        ("email".into(), EMAIL.into()),
        ("emailVerified".into(), false.into()),
        ("image".into(), "image".into()),
        ("createdAt".into(), date.into()),
        ("updatedAt".into(), date.into()),
        ("isAnonymous".into(), false.into()),
        ("phoneNumber".into(), "+12025550123".into()),
        ("phoneNumberVerified".into(), false.into()),
        ("username".into(), "owner".into()),
        ("displayUsername".into(), "Owner".into()),
        ("twoFactorEnabled".into(), false.into()),
        ("role".into(), "user".into()),
        ("banned".into(), false.into()),
        ("banReason".into(), "reason".into()),
        ("banExpires".into(), date.into()),
        (
            "metadata".into(),
            FieldMap::from([("seed".into(), true.into())]).into(),
        ),
    ])
}

pub(crate) async fn write(
    store: &dyn UserStore<better_auth_core::store::StatelessSchema>,
    create: bool,
    fields: FieldMap,
) -> AuthResult<UserView> {
    if create {
        store
            .create_user(CreateUser {
                additional_fields: fields,
                ..Default::default()
            })
            .await
    } else {
        store
            .update_user(
                OWNER,
                UpdateUser {
                    additional_fields: fields,
                    ..Default::default()
                },
            )
            .await
    }
}
