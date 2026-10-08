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
        trace_lock(&self.2)?.push(self.0);
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
    let policy = |label: &'static str| {
        let events = events.clone();
        fields(
            "name",
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    input: Some(UserFieldTransform::new(move |value| {
                        trace_lock(&events)?.push(label);
                        Ok(match value {
                            FieldValue::Undefined => FieldValue::Undefined,
                            value => format!(
                                "{label}:{}",
                                required(value.as_str(), "Expected a string field callback value")?
                            )
                            .into(),
                        })
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
    assert_eq!(*trace_lock(&events)?, ["second"]);
    assert_eq!(*trace_lock(&initializations)?, ["first", "second"]);
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
                Ok(match value {
                    FieldValue::Undefined => FieldValue::Undefined,
                    value => format!(
                        "{prefix}:{}",
                        required(value.as_str(), "Expected a string field callback value")?
                    )
                    .into(),
                })
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
                inherited_fields: Default::default(),
                user_id: user.id,
                expires_at: (chrono::Utc::now() + chrono::Duration::hours(1)).into(),
                ip_address: None,
                user_agent: Some("Agent".into()),
                impersonated_by: None,
                active_organization_id: None,
                additional_fields: [("userAgent".into(), "Agent".into())].into(),
            })
            .await?;
        assert_eq!(
            required(
                serde_json::to_value(session)?.get("userAgent"),
                "Expected the session userAgent field"
            )?,
            &json!(format!("{expected}:Agent"))
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
async fn builder_retains_application_user_fields_before_plugin_merge() -> AuthResult<()> {
    for application_enabled in [false, true] {
        let mut config = config();
        let default = |value: &'static str| UserFieldConfig {
            default_value: Some(value.into()),
            ..Default::default()
        };
        if application_enabled {
            config.user.fields_mut().extend([
                ("last".into(), default("application-last")),
                ("shared".into(), default("application-shared")),
                ("2".into(), default("two")),
                ("1".into(), default("one")),
                ("absent".into(), UserFieldConfig::default()),
            ]);
        }
        let defaults = Arc::new(Mutex::new(0));
        let observed_defaults = defaults.clone();
        let mut plugin = fields("pluginOnly", default("plugin-only"));
        let _ = plugin.fields_mut().insert(
            "shared".into(),
            UserFieldConfig {
                default_value_fn: Some(Arc::new(move || {
                    *trace_lock(&observed_defaults)? += 1;
                    Ok("plugin-shared".into())
                })),
                ..Default::default()
            },
        );
        let auth = BetterAuth::new(config)
            .store_arc(memory())
            .plugin(Fields(vec![(EntityRole::User, plugin)]))
            .build()
            .await?;
        let context = auth.context();
        let declarations = &required(
            context
                .extensions
                .get::<better_auth_core::plugin_runtime::ApplicationUserFields>(),
            "Builder did not retain application user declarations",
        )?
        .0;
        let expected_names: &[&str] = if application_enabled {
            &["last", "shared", "2", "1", "absent"]
        } else {
            &[]
        };
        assert_eq!(
            declarations
                .fields()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            expected_names
        );
        assert_eq!(
            declarations
                .fields()
                .get("shared")
                .and_then(|field| field.default_value.as_ref()),
            application_enabled.then_some(&FieldValue::from("application-shared"))
        );
        let parsed = context.parse_user_input(&Default::default(), true)?;
        assert_eq!(
            parsed.get("shared"),
            Some(&FieldValue::from("plugin-shared"))
        );
        assert_eq!(
            parsed.get("pluginOnly"),
            Some(&FieldValue::from("plugin-only"))
        );
        let selected = context.select_application_user_fields(&parsed);
        let expected: FieldMap = if application_enabled {
            [
                ("1".into(), "one".into()),
                ("2".into(), "two".into()),
                ("last".into(), "application-last".into()),
                ("shared".into(), "plugin-shared".into()),
            ]
            .into()
        } else {
            FieldMap::new()
        };
        assert_eq!(selected, expected);
        assert_eq!(
            selected.keys().collect::<Vec<_>>(),
            expected.keys().collect::<Vec<_>>()
        );
        assert_eq!(*trace_lock(&defaults)?, 1);
    }
    Ok(())
}

#[tokio::test]
async fn native_replacements_initialize_while_unsupported_model_roles_fail() {
    let cases = [
        (
            EntityRole::Passkey,
            "credential",
            UserFieldType::String,
            None,
        ),
        (EntityRole::Passkey, "name", UserFieldType::Json, None),
        (EntityRole::ApiKey, "key", UserFieldType::String, None),
        (EntityRole::ApiKey, "name", UserFieldType::Json, None),
        (
            EntityRole::RateLimit,
            "count",
            UserFieldType::Number,
            Some("Plugin field registration does not support RateLimit"),
        ),
    ];
    for (role, name, field_type, expected_error) in cases {
        let result = BetterAuth::new(config())
            .store_arc(memory())
            .plugin(Fields(vec![(
                role,
                fields(
                    name,
                    UserFieldConfig {
                        field_type,
                        ..Default::default()
                    },
                ),
            )]))
            .build()
            .await;
        let error = result.err();
        match expected_error {
            Some(expected) => assert!(
                matches!(&error, Some(AuthError::Config(actual)) if actual == expected),
                "registration: {role:?}.{name}, expected configuration error {expected:?}, got {error:?}"
            ),
            None => assert!(
                error.is_none(),
                "registration: {role:?}.{name}, expected successful initialization, got {error:?}"
            ),
        }
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
