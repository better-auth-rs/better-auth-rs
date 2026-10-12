use super::*;
use better_auth::plugins::UsernamePlugin;
use better_auth_core::UpdateUser;

const USERNAME_CASES: &[&str] = &[
    "same-id",
    "other-id",
    "zero-id",
    "false-id",
    "null-id",
    "undefined-id",
    "missing-id",
    "false-user",
    "number-user",
    "string-user",
    "array-user",
    "null-user",
    "undefined-user",
    "getter-id",
    "getter-error",
    "getter-unused",
];

struct UsernameUpdate {
    patch: FieldMap,
}

#[async_trait]
impl AuthPlugin<S> for UsernameUpdate {
    fn name(&self) -> &'static str {
        "username-session-consumer"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![AuthRoute::post("/username-session", "usernameSession")]
    }
    async fn on_request(
        &self,
        request: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        if request.path() != "/username-session" {
            return Ok(None);
        }
        let _ = context.require_native_session(request).await?;
        let user = context
            .database
            .update_user_by_id_value(
                &"7".into(),
                UpdateUser {
                    additional_fields: self.patch.clone(),
                    ..Default::default()
                },
            )
            .await?;
        Ok(Some(AuthResponse::json(200, &user)?))
    }
}

fn native_user(
    case: &'static str,
    shared: &FieldValue,
    state: &Arc<Mutex<Observed>>,
    thrown: &FieldValue,
) -> AuthResult<FieldValue> {
    Ok(match case {
        "same-id" => FieldMap::from([("id".into(), "7".into())]).into(),
        "other-id" => FieldMap::from([("id".into(), "other".into())]).into(),
        "zero-id" => FieldMap::from([("id".into(), 0.into())]).into(),
        "false-id" => FieldMap::from([("id".into(), false.into())]).into(),
        "getter-unused" => getter::injected_user("getter-error", shared, state, thrown)?,
        _ => getter::injected_user(case, shared, state, thrown)?,
    })
}

#[tokio::test]
async fn username_hook_reads_current_identity_only_when_validation_consumes_it() -> AuthResult<()> {
    for &case in USERNAME_CASES {
        for fallback in [false, true] {
            let state = Arc::new(Mutex::new(Observed::default()));
            let shared: FieldValue = FieldMap::new().into();
            let thrown: FieldValue = FieldMap::from([("failure".into(), case.into())]).into();
            let hooks = SessionHooks {
                case,
                thrown: thrown.clone(),
                state: state.clone(),
                data: NativeSessionData::new(
                    SessionView::from_field_values(session("injected-token", "snapshot-user"))?,
                    native_user(case, &shared, &state, &thrown)?,
                ),
            };
            let mut original = user("7");
            let _ = original.insert("username".into(), "same_user".into());
            let _ = original.insert("displayUsername".into(), "Same_User".into());
            let mut config = AuthConfig::new(SECRET);
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
            let raw = EphemeralStore::from_storage(
                Arc::new(config.clone()),
                [
                    ("user".into(), vec![original.clone()]),
                    ("session".into(), Vec::new()),
                    ("account".into(), Vec::new()),
                    ("verification".into(), Vec::new()),
                ],
            )?;
            let mut patch = FieldMap::from([("name".into(), "Changed".into())]);
            if case != "getter-unused" {
                let _ = patch.insert("username".into(), "SAME_USER".into());
            }
            if fallback {
                let _ = patch.insert("id".into(), "7".into());
            }
            let auth = BetterAuth::stateless(config)
                .store(raw.clone())
                .plugin(UsernamePlugin::default())
                .plugin(UsernameUpdate { patch })
                .hooks(EndpointHooks {
                    before: Some(Arc::new(hooks)),
                    after: None,
                })
                .build()
                .await?;
            let result = auth
                .call_endpoint(
                    HttpMethod::Post,
                    "/username-session",
                    EndpointInput::default(),
                )
                .await;
            let expected_success = case == "getter-unused"
                || case == "same-id"
                || case == "getter-id"
                || (fallback && !matches!(case, "other-id" | "getter-error"));
            let events = lock(&state)?.events.clone();
            assert_eq!(
                events,
                if matches!(case, "getter-id" | "getter-error") {
                    vec!["endpoint.before", "user.id"]
                } else {
                    vec!["endpoint.before"]
                },
                "{case}/{fallback}"
            );
            let mut stored = original;
            if expected_success {
                let response = result?;
                let _ = stored.insert("name".into(), "Changed".into());
                let mut projected = stored.clone();
                let _ = projected.shift_remove("marker");
                let _ = projected.shift_remove("private");
                assert_eq!(
                    response.body.json()?,
                    FieldValue::from(projected).json()?,
                    "{case}/{fallback}"
                );
            } else {
                let error = result.err().ok_or_else(|| {
                    AuthError::internal("Expected username collision or getter failure")
                })?;
                if case == "getter-error" {
                    assert!(
                        error
                            .raw_value()
                            .is_some_and(|value| value.strict_equals(&thrown))
                    );
                } else {
                    assert_eq!(error.status_value()?, "BAD_REQUEST".into());
                    assert_eq!(
                        error.body_value()?.json()?,
                        Some(json!({
                            "message":"Username is already taken. Please try another.", "code":"USERNAME_IS_ALREADY_TAKEN"
                        }))
                    );
                }
            }
            assert_eq!(
                raw.storage_rows(EntityRole::User)?,
                [stored],
                "{case}/{fallback}"
            );
            for role in [
                EntityRole::Session,
                EntityRole::Account,
                EntityRole::Verification,
            ] {
                assert!(raw.storage_rows(role)?.is_empty());
            }
        }
    }
    Ok(())
}
