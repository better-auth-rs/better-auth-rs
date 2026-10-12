#![expect(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract. Fixture indexing must fail when an expected record or property is missing."
)]
#![allow(
    clippy::expect_used,
    reason = "Fixture setup and response assertions require successful fallible construction."
)]
//! The access-token endpoint preserves native refresh values through the callback and Account write.

use super::*;
use better_auth_core::{
    AuthResult, FieldDate, FieldMap, FieldValue, NativeRequest,
    store::{
        EphemeralStore, StatelessSchema,
        database_hooks::{
            DatabaseHookContext, DatabaseHookUpdate, DatabaseHooks, DatabaseUpdateResult,
        },
        schema::EntityRole,
    },
    user_fields::{FieldTransforms, UserFieldConfig, UserFieldTransform, UserFieldType},
    wire::AccountView,
};

#[derive(Clone, Default)]
struct Events(Arc<std::sync::Mutex<Vec<(&'static str, FieldMap)>>>);

impl Events {
    fn push(&self, kind: &'static str, fields: FieldMap) {
        self.0.lock().unwrap().push((kind, fields));
    }
}

struct NativeRefresh {
    expected: FieldValue,
    returned: OAuthTokenSet,
    events: Events,
}

#[async_trait]
impl OAuthRefreshTokenHandler for NativeRefresh {
    async fn refresh_access_token(
        &self,
        token: &FieldValue,
        context: Option<NativeRequest<'_>>,
    ) -> Result<OAuthTokenSet, String> {
        assert!(token.strict_equals(&self.expected));
        let object = token.as_object().unwrap();
        assert_eq!(
            object.snapshot_fields().unwrap(),
            FieldMap::from([
                ("credential".into(), "native-refresh".into()),
                ("omitted".into(), FieldValue::Undefined),
            ])
        );
        assert_eq!(object.own_keys().unwrap(), ["credential", "omitted"]);
        assert_eq!(
            context
                .unwrap()
                .headers
                .and_then(|headers| headers.get("x-refresh-contract"))
                .map(String::as_str),
            Some("native-object")
        );
        let _ = object.set("consumed", true.into()).unwrap();
        self.events.push(
            "refresh",
            FieldMap::from([("refreshToken".into(), token.clone())]),
        );
        Ok(self.returned.clone())
    }
}

#[better_auth_core::database_hooks]
impl DatabaseHooks<StatelessSchema> for Events {
    async fn before_update_account(
        &self,
        fields: &mut FieldMap,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        self.push("before", fields.clone());
        Ok(DatabaseHookUpdate::Continue)
    }

    async fn after_update_account(
        &self,
        result: DatabaseUpdateResult<&AccountView>,
        _: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        let DatabaseUpdateResult::One(Some(account)) = result else {
            return Err(better_auth_core::AuthError::internal(
                "Token refresh must return its committed Account",
            ));
        };
        self.push("after", account.internal_fields()?);
        Ok(())
    }
}

// Better Auth 1.7.6 account.mjs uses nullish fallback for the response and truthy fallback for writes.
#[tokio::test]
async fn test_access_token_refresh_preserves_native_callback_values_and_fallbacks() {
    for falsey_id_token in [false, true] {
        let mut config = test_config();
        config.account.encrypt_oauth_tokens = Some(false);
        let raw = Arc::new(EphemeralStore::new(Arc::new(config.clone())));
        let db: Arc<dyn AuthStore<StatelessSchema>> = raw.clone();
        let user = db
            .create_user(
                CreateUser::new()
                    .with_email("native-refresh@example.com")
                    .with_name("Refresh Owner")
                    .with_email_verified(true),
            )
            .await
            .unwrap();
        let refresh_expiry = FieldDate::from_milliseconds(4_102_444_900_000.0);
        let original = db
            .create_account(CreateAccount {
                user_id: better_auth_core::SchemaValue::from_field(user.id().field_value()),
                provider_id: "google".into(),
                account_id: "google-native-refresh".into(),
                access_token: Some("stored-access".into()).into(),
                refresh_token: Some("stored-refresh".into()).into(),
                id_token: Some("stored-id".into()).into(),
                access_token_expires_at: Some(FieldDate::from_milliseconds(1.0)).into(),
                refresh_token_expires_at: Some(refresh_expiry.clone()).into(),
                scope: Some(" email, profile ,email ".into()).into(),
                ..Default::default()
            })
            .await
            .unwrap();
        let session = SessionManager::new(Arc::new(config.clone()), db.clone())
            .create_session(&user, None, None)
            .await
            .unwrap();
        let mut expected_storage = raw.storage_rows(EntityRole::Account).unwrap().remove(0);
        let unchanged =
            [EntityRole::User, EntityRole::Session].map(|role| raw.storage_rows(role).unwrap());
        let refresh_token: FieldValue = FieldMap::from([
            ("credential".into(), "native-refresh".into()),
            ("omitted".into(), FieldValue::Undefined),
        ])
        .into();
        let output_token = refresh_token.clone();
        config.account.additional_fields.insert(
            "refreshToken".into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    output: Some(UserFieldTransform::new(move |_| Ok(output_token.clone()))),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let updated_at = FieldDate::from_milliseconds(1_893_456_000_000.0);
        let updated_value = updated_at.clone();
        config.account.additional_fields.insert(
            "updatedAt".into(),
            UserFieldConfig {
                field_type: UserFieldType::Date,
                on_update: Some(better_auth_core::user_fields::UserFieldFactory::new(
                    move || Ok(updated_value.clone().into()),
                )),
                ..Default::default()
            },
        );
        let access_token: FieldValue = FieldMap::from([
            ("credential".into(), "native-access".into()),
            ("omitted".into(), FieldValue::Undefined),
        ])
        .into();
        let id_token = if falsey_id_token {
            FieldValue::Number(0.0)
        } else {
            FieldMap::from([("claim".into(), "native-id".into())]).into()
        };
        let expiry = FieldValue::Number(4_102_444_800_000.0);
        let events = Events::default();
        let mut provider = make_test_provider("http://localhost:65535");
        provider.refresh_access_token = Some(Arc::new(NativeRefresh {
            expected: refresh_token.clone(),
            returned: OAuthTokenSet::from_fields(FieldMap::from([
                ("accessToken".into(), access_token.clone()),
                ("refreshToken".into(), FieldValue::Null),
                ("accessTokenExpiresAt".into(), expiry.clone()),
                ("refreshTokenExpiresAt".into(), FieldValue::Null),
                ("idToken".into(), id_token.clone()),
                ("scopes".into(), vec![FieldValue::from("narrower")].into()),
            ])),
            events: events.clone(),
        }));
        let mut oauth_config = OAuthConfig::default();
        oauth_config.providers.insert("google".into(), provider);
        let plugin = OAuthPlugin::with_config(oauth_config);
        let config = Arc::new(config);
        let runtime = db
            .with_runtime(
                config.clone(),
                vec![Arc::new(events.clone())],
                Default::default(),
            )
            .unwrap();
        let context = AuthContext::new(config, runtime)
            .expect("fixture context initializes")
            .initialize_request_context()
            .await
            .unwrap();
        let mut request = AuthRequest::new(HttpMethod::Post, "/get-access-token");
        request.body = Some(json!({"accountId": original.id}).to_string().into_bytes());
        request
            .headers
            .insert("content-type".into(), "application/json".into());
        request
            .headers
            .insert("x-refresh-contract".into(), "native-object".into());
        request.headers.insert(
            "cookie".into(),
            session_cookie(session.token().typed().unwrap()),
        );
        let response = refresh_cookie::dispatch(&plugin, &request, &context)
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        let expected_response = json!({
            "accessToken": {"credential": "native-access"},
            "accessTokenExpiresAt": 4_102_444_800_000_u64,
            "scopes": ["email", "profile", "email"],
            "idToken": if falsey_id_token { json!(0) } else { json!({"claim": "native-id"}) }
        });
        assert_eq!(
            response.body.bytes().unwrap(),
            serde_json::to_vec(&expected_response).unwrap()
        );
        assert_eq!(
            response
                .headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect::<Vec<_>>(),
            [("content-type", "application/json")]
        );
        let persisted_id = if falsey_id_token {
            FieldValue::from("stored-id")
        } else {
            id_token.clone()
        };
        let expected_patch = FieldMap::from([
            ("accessToken".into(), access_token.clone()),
            ("accessTokenExpiresAt".into(), expiry),
            ("refreshToken".into(), refresh_token.clone()),
            ("refreshTokenExpiresAt".into(), refresh_expiry.into()),
            ("idToken".into(), persisted_id),
        ]);
        let mut expected_output = original.internal_fields().unwrap();
        expected_output.extend(expected_patch.clone());
        let _ = expected_output.insert("updatedAt".into(), updated_at.clone().into());
        {
            let recorded = events.0.lock().unwrap();
            assert_eq!(
                recorded.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(),
                ["refresh", "before", "after"]
            );
            assert!(recorded[0].1["refreshToken"].strict_equals(&refresh_token));
            assert_eq!(recorded[1].1, expected_patch);
            assert_eq!(
                recorded[1].1.keys().collect::<Vec<_>>(),
                expected_patch.keys().collect::<Vec<_>>()
            );
            assert_eq!(recorded[2].1, expected_output);
            assert_eq!(
                recorded[2].1.keys().collect::<Vec<_>>(),
                expected_output.keys().collect::<Vec<_>>()
            );
            for (_, fields) in &recorded[1..] {
                assert!(fields["refreshToken"].strict_equals(&refresh_token));
                assert!(fields["accessToken"].strict_equals(&access_token));
                if !falsey_id_token {
                    assert!(fields["idToken"].strict_equals(&id_token));
                }
            }
        }
        assert_eq!(
            refresh_token.model_property("consumed").unwrap(),
            true.into()
        );
        expected_storage.extend(expected_patch);
        let _ = expected_storage.insert("updatedAt".into(), updated_at.into());
        let stored = raw.storage_rows(EntityRole::Account).unwrap();
        assert_eq!(stored, [expected_storage.clone()]);
        assert_eq!(
            stored[0].keys().collect::<Vec<_>>(),
            expected_storage.keys().collect::<Vec<_>>()
        );
        assert!(stored[0]["refreshToken"].strict_equals(&refresh_token));
        assert!(stored[0]["accessToken"].strict_equals(&access_token));
        assert_eq!(
            [EntityRole::User, EntityRole::Session].map(|role| raw.storage_rows(role).unwrap()),
            unchanged
        );
    }
}
