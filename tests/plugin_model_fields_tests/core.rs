use super::*;

struct LegacyFields(&'static str, UserConfig, Arc<Mutex<Vec<&'static str>>>);

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for LegacyFields {
    fn name(&self) -> &'static str {
        self.0
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        self.2.lock().unwrap().push(self.0);
        context.register_user_fields(self.1.clone());
        Ok(())
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

async fn legacy_contract<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>) -> AuthResult<()> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let initializations = Arc::new(Mutex::new(Vec::new()));
    let policy =
        |label: &'static str| {
            let events = events.clone();
            fields(
                "name",
                UserFieldConfig {
                    transform: Some(FieldTransforms {
                        input: Some(UserFieldTransform::new(move |value| {
                            events.lock().unwrap().push(label);
                            Ok(value
                                .map(|value| json!(format!("{label}:{}", value.as_str().unwrap()))))
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
        };
    let auth = BetterAuth::new(config())
        .store_arc(raw)
        .plugin(LegacyFields(
            "first",
            policy("first"),
            initializations.clone(),
        ))
        .plugin(LegacyFields(
            "second",
            policy("second"),
            initializations.clone(),
        ))
        .build()
        .await?;
    let user = auth
        .store()
        .create_user(
            CreateUser::new()
                .with_name("Name")
                .with_email("legacy@fields.test"),
        )
        .await?;
    assert_eq!(user.name.json()?, Some(json!("second:Name")));
    assert_eq!(*events.lock().unwrap(), ["second"]);
    assert_eq!(*initializations.lock().unwrap(), ["first", "second"]);
    Ok(())
}

#[tokio::test]
async fn memory_legacy_registration_replaces_once_in_plugin_order() -> AuthResult<()> {
    legacy_contract(memory()).await
}
#[tokio::test]
async fn sqlite_legacy_registration_replaces_once_in_plugin_order() -> AuthResult<()> {
    legacy_contract(sqlite().await?).await
}

fn prefix(prefix: &'static str) -> UserFieldConfig {
    UserFieldConfig {
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                Ok(value.map(|value| json!(format!("{prefix}:{}", value.as_str().unwrap()))))
            })),
            ..Default::default()
        }),
        ..Default::default()
    }
}

async fn core_contract<S: AuthSchema>(raw: Arc<dyn AuthStore<S>>) -> AuthResult<()> {
    for application in [false, true] {
        let expected = if application { "application" } else { "plugin" };
        let mut config = config();
        if application {
            let _ = config
                .user
                .fields_mut()
                .insert("name".into(), prefix("application"));
            let _ = config
                .session
                .fields_mut()
                .insert("userAgent".into(), prefix("application"));
            let _ = config
                .account
                .additional_fields
                .insert("scope".into(), prefix("application"));
            let _ = config
                .verification
                .additional_fields
                .insert("value".into(), prefix("application"));
        }
        let registrations = [
            (EntityRole::User, "name"),
            (EntityRole::Session, "userAgent"),
            (EntityRole::Account, "scope"),
            (EntityRole::Verification, "value"),
        ]
        .into_iter()
        .map(|(role, name)| (role, fields(name, prefix("plugin"))))
        .collect();
        let auth = BetterAuth::new(config)
            .store_arc(raw.clone())
            .plugin(Fields(registrations))
            .build()
            .await?;
        let user = auth
            .store()
            .create_user(
                CreateUser::new()
                    .with_name("User")
                    .with_email(format!("core-{expected}@fields.test")),
            )
            .await?;
        assert_eq!(user.name.json()?, Some(json!(format!("{expected}:User"))));
        let account = auth
            .store()
            .create_account(CreateAccount {
                user_id: user.id.clone(),
                provider_id: "ordinary".into(),
                account_id: format!("ordinary-account-{expected}").into(),
                scope: Some("Scope".into()).into(),
                ..Default::default()
            })
            .await?;
        assert_eq!(
            account.scope.json()?,
            Some(json!(format!("{expected}:Scope")))
        );
        let session = auth
            .store()
            .create_session(CreateSession {
                user_id: user.id,
                expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
                ip_address: None,
                user_agent: Some("Agent".into()),
                impersonated_by: None,
                active_organization_id: None,
                additional_fields: serde_json::from_value(json!({"userAgent":"Agent"}))?,
            })
            .await?;
        assert_eq!(
            serde_json::to_value(session)?["userAgent"],
            format!("{expected}:Agent")
        );
        let verification = auth
            .store()
            .create_verification(CreateVerification {
                identifier: "ordinary".into(),
                value: "Value".into(),
                expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).into(),
                ..Default::default()
            })
            .await?;
        assert_eq!(
            verification.value.json()?,
            Some(json!(format!("{expected}:Value")))
        );
    }
    Ok(())
}

#[tokio::test]
async fn memory_core_registration_keeps_application_adapter_precedence() -> AuthResult<()> {
    core_contract(memory()).await
}
#[tokio::test]
async fn sqlite_core_registration_keeps_application_adapter_precedence() -> AuthResult<()> {
    core_contract(sqlite().await?).await
}

#[tokio::test]
async fn unsupported_model_fields_fail_during_initialization() {
    let cases = [
        (
            EntityRole::Passkey,
            fields("label", UserFieldConfig::default()),
        ),
        (
            EntityRole::Passkey,
            fields(
                "name",
                UserFieldConfig {
                    field_type: UserFieldType::Json,
                    ..Default::default()
                },
            ),
        ),
        (
            EntityRole::ApiKey,
            fields("label", UserFieldConfig::default()),
        ),
        (
            EntityRole::ApiKey,
            fields(
                "name",
                UserFieldConfig {
                    field_type: UserFieldType::Json,
                    ..Default::default()
                },
            ),
        ),
    ];
    for registration in cases {
        let result = BetterAuth::new(config())
            .store_arc(memory())
            .plugin(Fields(vec![registration]))
            .build()
            .await;
        assert!(matches!(result, Err(AuthError::Config(_))));
    }
}

#[test]
fn display_field_registration_preserves_omitted_empty_and_logical_aliases() {
    for (role, name) in [
        (EntityRole::Passkey, "name"),
        (EntityRole::Passkey, "aaguid"),
        (EntityRole::ApiKey, "name"),
        (EntityRole::DeviceCode, "scope"),
    ] {
        for alias in [None, Some(""), Some(name)] {
            let mut context = AuthInitContext::new(Arc::new(config()), memory());
            let result = context.register_model_fields(
                role,
                fields(
                    name,
                    UserFieldConfig {
                        field_name: alias.map(str::to_owned),
                        ..Default::default()
                    },
                ),
            );
            assert!(
                result.is_ok(),
                "registration: {role:?}.{name}, alias={alias:?}: {result:?}"
            );
            let registered = context.into_parts().plugin_fields;
            let declared = registered.fields(role).fields();
            assert_eq!(declared.len(), 1);
            assert_eq!(
                declared.get(name).map(|field| field.field_name.as_deref()),
                Some(alias),
                "raw declaration: {role:?}.{name}, alias={alias:?}"
            );
        }
    }
}
