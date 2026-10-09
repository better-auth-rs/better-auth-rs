use super::*;
use crate::plugins::{
    test_helpers,
    user_admission::{UserValidationData, UserValidationRejection, ValidateUserInfo},
};
use async_trait::async_trait;
use better_auth_core::{
    AuthInitContext, AuthPlugin, FieldMap, FieldValue, HttpMethod,
    plugin_runtime::AdapterUserFields,
    store::database_hooks::{DatabaseHookContext, DatabaseHookUpdate, DatabaseHooks},
    store::schema::SchemaConfiguration,
    store::{AuthStore, EphemeralStore, StatelessSchema},
    user_fields::{FieldValidators, UserConfig, UserFieldConfig, UserFieldType},
};
use std::sync::Mutex;

const PHONE: &str = "+15551230001";
const EMAIL: &str = "phone@admission.test";

#[derive(Default)]
struct Trace(Mutex<Vec<(&'static str, FieldMap)>>);

impl Trace {
    fn push(&self, phase: &'static str, fields: FieldMap) {
        self.0.lock().unwrap().push((phase, fields));
    }
}

#[async_trait]
impl<S: AuthSchema> ValidateUserInfo<S> for Trace {
    async fn validate(
        &self,
        data: &UserValidationData,
        _: &EndpointContext<'_, S>,
    ) -> AuthResult<Option<UserValidationRejection>> {
        assert_eq!(
            serde_json::to_value(&data.source)?,
            json!({"method":"phone-number", "action":"create-user"}),
        );
        self.push("admission", data.user.clone());
        Ok(None)
    }
}

#[better_auth_core::database_hooks()]
impl<S: AuthSchema> DatabaseHooks<S> for Trace {
    async fn before_create_user(
        &self,
        input: &mut FieldMap,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        self.push("before", input.clone());
        Ok(DatabaseHookUpdate::Continue)
    }

    async fn after_create_user(
        &self,
        user: Option<&UserView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        self.push("after", user.unwrap().clone().into());
        Ok(())
    }
}

async fn check_signup<S: AuthSchema>(
    store: Arc<dyn AuthStore<S>>,
    sqlite: bool,
    custom_name: bool,
) -> AuthResult<()> {
    let trace = Arc::new(Trace::default());
    let mut config = test_helpers::create_test_config();
    for name in ["email", "name"] {
        let observer = trace.clone();
        let _ = config.user.fields_mut().insert(
            name.into(),
            UserFieldConfig {
                required: Some(false),
                validator: Some(FieldValidators {
                    input: Some(Arc::new(move |value| {
                        observer.push(name, FieldMap::from([("input".into(), value)]));
                        Ok(FieldMap::from([("source".into(), "parsed".into())]).into())
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
    }
    let _ = config.user.fields_mut().insert(
        "phoneNumberVerified".into(),
        UserFieldConfig {
            field_type: UserFieldType::Boolean,
            required: Some(false),
            input: Some(false),
            default_value: Some(false.into()),
            ..Default::default()
        },
    );
    let observer = trace.clone();
    let _ = config.user.fields_mut().insert(
        "metadata".into(),
        UserFieldConfig {
            field_type: UserFieldType::Json,
            required: Some(false),
            validator: Some(FieldValidators {
                input: Some(Arc::new(move |value| {
                    observer.push(
                        "metadata",
                        FieldMap::from([("input".into(), value.clone())]),
                    );
                    Ok(FieldMap::from([
                        ("source".into(), "parsed".into()),
                        ("input".into(), value),
                    ])
                    .into())
                })),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    for (name, field_name, field_type) in [
        ("phoneNumber", None, UserFieldType::String),
        ("code", Some("username"), UserFieldType::String),
        (
            "disableSession",
            Some("displayUsername"),
            UserFieldType::Boolean,
        ),
        (
            "updatePhoneNumber",
            Some("banReason"),
            UserFieldType::Boolean,
        ),
    ] {
        let _ = config.user.fields_mut().insert(
            name.into(),
            UserFieldConfig {
                field_type,
                required: Some(false),
                field_name: field_name.map(str::to_owned),
                validator: Some(FieldValidators {
                    input: Some(Arc::new(move |_| {
                        panic!("Reserved route field {name} reached the user validator")
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
    }
    let config = Arc::new(config);
    let verifier = trace.clone();
    let email = trace.clone();
    let verified = trace.clone();
    let mut plugin = PhoneNumberPlugin::new()
        .send_otp(|_, _| async { Err(AuthError::internal("Verification must not send a new OTP")) })
        .verify_otp(move |otp, _| {
            assert_eq!(otp.phone_number, PHONE);
            assert_eq!(otp.code, "123456");
            verifier.push("verify", FieldMap::new());
            async { Ok(true) }
        })
        .sign_up_on_verification(move |phone| {
            assert_eq!(phone, PHONE);
            email.push("temp-email", FieldMap::new());
            EMAIL.to_uppercase()
        })
        .callback_on_verification(move |data, _| {
            assert_eq!(data.phone_number, PHONE);
            verified.push("verified", data.user.into());
            async { Ok(()) }
        });
    if custom_name {
        let name = trace.clone();
        plugin = plugin.temporary_name(move |phone| {
            assert_eq!(phone, PHONE);
            name.push("temp-name", FieldMap::new());
            "Phone Owner".into()
        });
    }
    let mut init = AuthInitContext::new(config.clone(), store.clone());
    plugin.on_init(&mut init).await?;
    let mut replacement_fields = UserConfig::default();
    for name in ["phoneNumber", "phoneNumberVerified"] {
        let _ = replacement_fields
            .fields_mut()
            .insert(name.into(), config.user.fields()[name].clone());
    }
    init.register_user_fields(replacement_fields);
    let parts = init.into_parts();
    let (adapter, endpoint, mut fields) = parts.plugin_fields.clone().resolve(&config);
    let adapter_fields = adapter.user.clone();
    let adapter = Arc::new(adapter);
    fields.set_schema_configuration(&SchemaConfiguration {
        config: adapter.clone(),
        plugins: vec!["phone-number", "phone-signup-field-contract"],
        metadata: parts.metadata.clone(),
        secondary_storage: false,
        database_rate_limit: false,
    });
    let store = store.with_runtime(adapter, vec![trace.clone()], fields)?;
    let mut context = AuthContext::new(Arc::new(endpoint), store);
    context.metadata = parts.metadata;
    context.extensions = parts.extensions;
    context.extensions.insert(AdapterUserFields(adapter_fields));
    context
        .extensions
        .insert(trace.clone() as Arc<dyn ValidateUserInfo<S>>);
    let request = test_helpers::create_auth_request_no_query(
        HttpMethod::Post,
        "/phone-number/verify",
        None,
        Some(
            json!({
                "phoneNumber":PHONE, "code":"123456", "disableSession":true,
                "updatePhoneNumber":false, "email":"client@admission.test", "name":"Client",
                "metadata":{"source":"client"},
            })
            .to_string()
            .into_bytes(),
        ),
    );
    let response = plugin.on_request(&request, &context).await?.unwrap();
    assert_eq!(response.status, 200);
    let events = trace.0.lock().unwrap().clone();
    let mut phases = vec!["verify", "email", "name", "metadata", "temp-email"];
    if custom_name {
        phases.push("temp-name");
    }
    phases.extend(["admission", "before", "after", "verified"]);
    assert_eq!(
        events.iter().map(|event| event.0).collect::<Vec<_>>(),
        phases
    );
    assert_eq!(
        events[1].1,
        FieldMap::from([("input".into(), "client@admission.test".into())])
    );
    assert_eq!(
        events[2].1,
        FieldMap::from([("input".into(), "Client".into())])
    );
    let input_metadata = FieldMap::from([("source".into(), "client".into())]);
    assert_eq!(
        events[3].1,
        FieldMap::from([("input".into(), input_metadata.clone().into())])
    );
    let metadata: FieldValue = FieldMap::from([
        ("source".into(), "parsed".into()),
        ("input".into(), input_metadata.into()),
    ])
    .into();
    let admitted = &events[events.len() - 4].1;
    assert!(matches!(admitted["createdAt"], FieldValue::Date(_)));
    assert!(matches!(admitted["updatedAt"], FieldValue::Date(_)));
    let name = if custom_name { "Phone Owner" } else { PHONE };
    let expected_input = FieldMap::from([
        ("createdAt".into(), admitted["createdAt"].clone()),
        ("updatedAt".into(), admitted["updatedAt"].clone()),
        ("email".into(), EMAIL.into()),
        ("name".into(), name.into()),
        ("phoneNumberVerified".into(), true.into()),
        ("metadata".into(), metadata.clone()),
        ("phoneNumber".into(), PHONE.into()),
    ]);
    assert_eq!(admitted, &expected_input);
    assert_eq!(
        admitted.keys().collect::<Vec<_>>(),
        expected_input.keys().collect::<Vec<_>>()
    );
    assert_eq!(events[events.len() - 3].1, expected_input);
    let stored = context.database.get_user_by_email(EMAIL).await?.unwrap();
    assert!(!stored.id.typed()?.is_empty());
    let absent = if sqlite {
        FieldValue::Null
    } else {
        FieldValue::Undefined
    };
    let expected_stored = FieldMap::from([
        ("id".into(), stored.id.field_value()),
        ("name".into(), name.into()),
        ("email".into(), EMAIL.into()),
        ("emailVerified".into(), false.into()),
        ("image".into(), absent.clone()),
        ("createdAt".into(), admitted["createdAt"].clone()),
        ("updatedAt".into(), admitted["updatedAt"].clone()),
        ("phoneNumberVerified".into(), true.into()),
        ("metadata".into(), metadata),
        ("phoneNumber".into(), PHONE.into()),
        ("code".into(), absent.clone()),
        ("disableSession".into(), absent.clone()),
        ("updatePhoneNumber".into(), absent),
    ]);
    assert_eq!(FieldMap::from(stored.clone()), expected_stored);
    assert_eq!(events[events.len() - 2].1, expected_stored);
    assert_eq!(events[events.len() - 1].1, expected_stored);
    assert_eq!(
        response.body.json()?,
        Some(json!({"status":true, "token":null, "user":expected_stored.json()?}))
    );
    assert_eq!(context.database.list_users(Default::default()).await?.1, 1);
    assert!(
        context
            .database
            .get_user_accounts(stored.id.typed()?)
            .await?
            .is_empty()
    );
    assert!(
        context
            .database
            .get_user_sessions(stored.id.typed()?)
            .await?
            .is_empty()
    );
    assert!(
        context
            .database
            .get_verification_by_identifier(PHONE)
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn phone_signup_parses_fields_before_temporary_identity_and_verified_proof() -> AuthResult<()>
{
    for custom_name in [false, true] {
        let memory: Arc<dyn AuthStore<StatelessSchema>> = Arc::new(EphemeralStore::new(Arc::new(
            test_helpers::create_test_config(),
        )));
        check_signup(memory, false, custom_name).await?;
        check_signup(
            test_helpers::create_test_database().await,
            true,
            custom_name,
        )
        .await?;
    }
    Ok(())
}
