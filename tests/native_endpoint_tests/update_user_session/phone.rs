use super::*;
use better_auth::plugins::PhoneNumberPlugin;
use better_auth_core::{UpdateUser, user_fields::UserConfig};

struct PhoneInputPolicy;

#[async_trait]
impl AuthPlugin<S> for PhoneInputPolicy {
    fn name(&self) -> &'static str {
        "phone-input-policy"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }
    fn schema(&self, fields: &mut better_auth_core::plugin_runtime::ModelFields) -> AuthResult<()> {
        fields.register_user_fields(UserConfig {
            additional_fields: Some(
                [(
                    "phoneNumber".into(),
                    UserFieldConfig {
                        input: Some(false),
                        ..Default::default()
                    },
                )]
                .into(),
            ),
        });
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

#[derive(Clone)]
struct PhoneObserver {
    case: &'static str,
    state: Arc<Mutex<Observed>>,
}

#[better_auth::database_hooks]
impl DatabaseHooks<S> for PhoneObserver {
    async fn before_update_user(
        &self,
        input: &mut FieldMap,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        let mut state = lock(&self.state)?;
        state.events.push("db.before".into());
        state.inputs.push(input.clone());
        Ok(match self.case {
            "cancel" => DatabaseHookUpdate::Cancel,
            "patch" => DatabaseHookUpdate::Patch(FieldMap::from([(
                "phoneNumber".into(),
                "+15550000002".into(),
            )])),
            _ => DatabaseHookUpdate::Continue,
        })
    }

    async fn after_update_user(
        &self,
        user: Option<&UserView>,
        _: &DatabaseHookContext<'_, S>,
    ) -> AuthResult<()> {
        let mut state = lock(&self.state)?;
        state.events.push("db.after".into());
        state.updates.push(user.cloned().map(FieldMap::from));
        Ok(())
    }
}

fn phone_user() -> FieldMap {
    let mut fields = user("7");
    for name in ["marker", "private", "id"] {
        let _ = fields.shift_remove(name);
    }
    fields.extend([
        ("phoneNumber".into(), "+15550000001".into()),
        ("phoneNumberVerified".into(), true.into()),
        ("id".into(), "7".into()),
    ]);
    fields
}

#[tokio::test]
async fn phone_clear_policy_belongs_to_the_user_update_hook_and_preserves_fallback()
-> AuthResult<()> {
    for case in [
        "clear",
        "cancel",
        "missing",
        "patch",
        "application-shadowed",
        "blocked",
        "set",
    ] {
        for endpoint in [false, true] {
            if (matches!(case, "application-shadowed" | "blocked") && !endpoint)
                || (case == "set" && endpoint)
            {
                continue;
            }
            let state = Arc::new(Mutex::new(Observed::default()));
            let mut snapshot = phone_user();
            let _ = snapshot.insert("name".into(), "Snapshot".into());
            let _ = snapshot.insert("phoneNumber".into(), "+15550000003".into());
            let id: FieldValue = if case == "missing" {
                "missing".into()
            } else {
                "7".into()
            };
            let _ = snapshot.insert("id".into(), id.clone());
            let injected = NativeSessionData::new(
                SessionView::from_field_values(session("injected-token", "snapshot-user"))?,
                snapshot.clone().into(),
            );
            let hooks = SessionHooks {
                case,
                data: injected.clone(),
                thrown: FieldValue::Undefined,
                state: state.clone(),
            };
            let mut config = AuthConfig::new(SECRET);
            config.base_url = ORIGIN.into();
            config.logger = better_auth_core::LoggerConfig {
                disabled: Some(true),
                ..Default::default()
            }
            .into();
            let _ = config.user.fields_mut().insert(
                "updatedAt".into(),
                UserFieldConfig {
                    field_type: UserFieldType::Date,
                    on_update: Some(better_auth_core::user_fields::UserFieldFactory::new(|| {
                        Ok(date())
                    })),
                    ..Default::default()
                },
            );
            if case == "application-shadowed" {
                let _ = config.user.fields_mut().insert(
                    "phoneNumber".into(),
                    UserFieldConfig {
                        input: Some(false),
                        ..Default::default()
                    },
                );
            }
            let raw = EphemeralStore::from_storage(
                Arc::new(config.clone()),
                [
                    ("user".into(), vec![phone_user()]),
                    ("session".into(), Vec::new()),
                    ("account".into(), Vec::new()),
                    ("verification".into(), Vec::new()),
                ],
            )?
            .with_hooks(vec![Arc::new(PhoneObserver {
                case,
                state: state.clone(),
            })]);
            let mut auth = BetterAuth::stateless(config)
                .store(raw.clone())
                .plugin(PhoneNumberPlugin::new());
            if case == "blocked" {
                auth = auth.plugin(PhoneInputPolicy);
            }
            let auth = auth
                .hooks(EndpointHooks {
                    before: Some(Arc::new(hooks.clone())),
                    after: Some(Arc::new(hooks)),
                })
                .build()
                .await?;
            let phone = if case == "set" {
                "+15550000004".into()
            } else {
                FieldValue::Null
            };
            let input = FieldMap::from([("phoneNumber".into(), phone.clone())]);
            let mut returned = None;
            if endpoint {
                let result = auth
                    .call_endpoint(
                        HttpMethod::Post,
                        "/update-user",
                        EndpointInput {
                            body: Some(Value::Object(input.json()?)),
                            ..Default::default()
                        },
                    )
                    .await;
                if case == "blocked" {
                    let error = result
                        .err()
                        .ok_or_else(|| AuthError::internal("Expected no accepted fields"))?;
                    assert_eq!(error.status_value()?, "BAD_REQUEST".into());
                    assert_eq!(
                        error.body_value()?.json()?,
                        Some(json!({"message":"No fields to update"}))
                    );
                } else {
                    assert_eq!(result?.body.json()?, Some(json!({"status":true})));
                }
            } else {
                returned = auth
                    .store()
                    .update_user_by_id_value(
                        &id,
                        UpdateUser {
                            additional_fields: input.clone(),
                            ..Default::default()
                        },
                    )
                    .await?
                    .map(FieldMap::from);
            }
            let wrote = !matches!(case, "cancel" | "missing" | "blocked");
            let mut stored = phone_user();
            if wrote {
                let value = if case == "patch" {
                    "+15550000002".into()
                } else {
                    phone.clone()
                };
                let _ = stored.insert("phoneNumber".into(), value);
                if case != "set" {
                    let _ = stored.insert("phoneNumberVerified".into(), false.into());
                }
            }
            assert_eq!(
                raw.storage_rows(EntityRole::User)?,
                [stored.clone()],
                "{case}/{endpoint}"
            );
            for role in [
                EntityRole::Session,
                EntityRole::Account,
                EntityRole::Verification,
            ] {
                assert!(raw.storage_rows(role)?.is_empty());
            }
            let observed = lock(&state)?.clone();
            let mut events = Vec::new();
            if endpoint {
                events.push("endpoint.before");
            }
            if case != "blocked" {
                events.push("db.before");
                let mut expected_input = if endpoint {
                    FieldMap::from([
                        ("name".into(), FieldValue::Undefined),
                        ("image".into(), FieldValue::Undefined),
                    ])
                } else {
                    FieldMap::new()
                };
                expected_input.extend(input);
                assert_eq!(observed.inputs.len(), 1);
                ordered(
                    observed
                        .inputs
                        .first()
                        .ok_or_else(|| AuthError::internal("Expected original hook input"))?,
                    &expected_input,
                );
                if case != "cancel" {
                    events.push("db.after");
                }
                assert_eq!(
                    observed.updates,
                    if case == "cancel" {
                        Vec::new()
                    } else {
                        vec![wrote.then_some(stored.clone())]
                    }
                );
            } else {
                assert!(observed.inputs.is_empty());
                assert!(observed.updates.is_empty());
            }
            if endpoint {
                events.push("endpoint.after");
            }
            assert_eq!(observed.events, events, "{case}/{endpoint}");
            if endpoint {
                assert_eq!(observed.issued.len(), 1);
                let issued = observed
                    .issued
                    .first()
                    .ok_or_else(|| AuthError::internal("Expected endpoint hook"))?;
                if case == "blocked" {
                    assert!(issued.is_none());
                } else {
                    let data = issued
                        .as_ref()
                        .ok_or_else(|| AuthError::internal("Expected refreshed cookie snapshot"))?;
                    let expected = if wrote {
                        stored
                    } else {
                        let _ = snapshot.insert("phoneNumber".into(), phone);
                        snapshot
                    };
                    ordered(&data.user_value()?.enumerable_fields()?, &expected);
                    assert_eq!(data.session_value()?, injected.session_value()?);
                }
            } else {
                assert_eq!(returned, wrote.then_some(stored));
            }
        }
    }
    Ok(())
}
