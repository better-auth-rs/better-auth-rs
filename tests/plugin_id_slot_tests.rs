#![cfg(feature = "seaorm2")]

#[path = "support/jwk_fields.rs"]
mod jwk_fixture;
#[path = "support/wallet_fields.rs"]
mod wallet_fixture;

use async_trait::async_trait;
use better_auth::seaorm::sea_orm::EntityTrait;
use better_auth::{
    __private_core::{
        AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult,
        AuthRoute, AuthSchema, AuthStore, CreateJwk, CreateWalletAddress, FieldMap, FieldValue,
        id::{IdGeneration, IdGenerator},
        store::schema::EntityRole,
        user_fields::{FieldTransforms, UserConfig, UserFieldConfig, UserFieldTransform},
    },
    AuthConfig, BetterAuth,
};
use better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
use std::sync::{Arc, Mutex, MutexGuard};

type Events = Arc<Mutex<Vec<&'static str>>>;

struct Fields(EntityRole, UserConfig);

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for Fields {
    fn name(&self) -> &'static str {
        "plugin-id-slot"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        Vec::new()
    }

    async fn on_init(&self, context: &mut AuthInitContext<S>) -> AuthResult<()> {
        context.register_model_fields(self.0, self.1.clone())
    }

    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}

fn events_lock(events: &Events) -> AuthResult<MutexGuard<'_, Vec<&'static str>>> {
    events
        .lock()
        .map_err(|_| AuthError::internal("SQL ID slot event lock poisoned"))
}

fn policies(events: &Events, before_label: bool, reject: bool) -> UserConfig {
    let input_events = events.clone();
    let output_events = events.clone();
    let label = UserFieldConfig {
        field_name: Some("stored_label".into()),
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(move |value| {
                events_lock(&input_events)?.push("input");
                if reject {
                    return Err(AuthError::internal("label-input-rejected"));
                }
                Ok(value)
            })),
            output: Some(UserFieldTransform::new(move |value| {
                events_lock(&output_events)?.push("output");
                Ok(value)
            })),
        }),
        ..Default::default()
    };
    let id = UserFieldConfig {
        // The adapter replaces the complete ID policy, including an alias with no matching SQL column.
        field_name: Some("ignored_id_column".into()),
        transform: Some(FieldTransforms {
            input: Some(UserFieldTransform::new(|_| {
                Err(AuthError::internal("configured-id-input-called"))
            })),
            output: Some(UserFieldTransform::new(|_| {
                Err(AuthError::internal("configured-id-output-called"))
            })),
        }),
        ..Default::default()
    };
    UserConfig {
        additional_fields: Some(
            if before_label {
                [("id".into(), id), ("label".into(), label)]
            } else {
                [("label".into(), label), ("id".into(), id)]
            }
            .into(),
        ),
    }
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "The SQL contract asserts callback rejection and unchanged storage while propagating setup and database errors"
)]
async fn check(role: EntityRole, before_label: bool, reject: bool) -> AuthResult<()> {
    let model = match role {
        EntityRole::Jwk => "jwks",
        EntityRole::WalletAddress => "walletAddress",
        _ => return Err(AuthError::internal("Unexpected SQL ID slot model")),
    };
    let events = Events::default();
    let generate_events = events.clone();
    let mut config = AuthConfig::new("plugin-id-slot-secret-with-at-least-thirty-two-characters")
        .base_url("http://plugin-id-slot.test");
    config.advanced.database.generate_id =
        Some(IdGeneration::Custom(IdGenerator::new(move |request| {
            assert_eq!(request.model, model);
            assert_eq!(request.size, None);
            events_lock(&generate_events)?.push("generate");
            Ok(Some("generated-plugin-id".into()))
        })));
    let (raw, database): (Arc<dyn AuthStore<BundledSchema>>, _) = match role {
        EntityRole::Jwk => {
            let (store, database) = jwk_fixture::sqlite(config.clone()).await;
            (Arc::new(store), database)
        }
        EntityRole::WalletAddress => {
            let (store, database) = wallet_fixture::sqlite(config.clone()).await;
            (Arc::new(store), database)
        }
        _ => return Err(AuthError::internal("Unexpected SQL ID slot model")),
    };
    let auth = BetterAuth::new(config)
        .store_arc(raw)
        .plugin(Fields(role, policies(&events, before_label, reject)))
        .build()
        .await?;
    let store = auth.store();
    let created_at = chrono::DateTime::parse_from_rfc3339("2030-01-02T03:04:05.000Z")
        .map_err(|error| AuthError::internal(format!("Invalid SQL ID slot fixture date: {error}")))?
        .with_timezone(&chrono::Utc)
        .into();
    let additional_fields: FieldMap = [("label".into(), "selected".into())].into();
    let result = match role {
        EntityRole::Jwk => store
            .create_jwk(CreateJwk {
                created_at,
                public_key: "public-selected".into(),
                private_key: "private-selected".into(),
                expires_at: None,
                alg: "EdDSA".into(),
                crv: None,
                additional_fields,
            })
            .await
            .map(|row| (row.id, row.additional_fields)),
        EntityRole::WalletAddress => store
            .create_wallet_address(CreateWalletAddress {
                user_id: "owner".into(),
                address: "slot-selected".into(),
                chain_id: 1,
                is_primary: false,
                created_at,
                additional_fields,
            })
            .await
            .map(|row| (row.id, row.additional_fields)),
        _ => return Err(AuthError::internal("Unexpected SQL ID slot model")),
    };
    let expected_events = match (before_label, reject) {
        (true, true) => vec!["generate", "input"],
        (false, true) => vec!["input"],
        (true, false) => vec!["generate", "input", "output"],
        (false, false) => vec!["input", "generate", "output"],
    };
    assert_eq!(*events_lock(&events)?, expected_events);
    if reject {
        assert!(
            matches!(result, Err(AuthError::Internal(message)) if message == "label-input-rejected")
        );
    } else {
        let (id, fields) = result?;
        assert_eq!(id, "generated-plugin-id");
        assert_eq!(
            fields,
            FieldMap::from([("label".into(), FieldValue::from("selected"))])
        );
    }
    let stored = match role {
        EntityRole::Jwk => jwk_fixture::model::Entity::find()
            .all(&database)
            .await
            .map(|rows| {
                rows.into_iter()
                    .map(|row| (row.id, row.label))
                    .collect::<Vec<_>>()
            }),
        EntityRole::WalletAddress => wallet_fixture::model::Entity::find()
            .all(&database)
            .await
            .map(|rows| {
                rows.into_iter()
                    .map(|row| (row.id, row.label))
                    .collect::<Vec<_>>()
            }),
        _ => return Err(AuthError::internal("Unexpected SQL ID slot model")),
    }
    .map_err(|error| AuthError::internal(format!("Read SQL ID slot raw rows: {error}")))?;
    if reject {
        assert!(stored.is_empty());
    } else {
        assert_eq!(
            stored,
            vec![("generated-plugin-id".into(), Some("selected".into()))]
        );
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_plugin_id_slot_replaces_alias_and_preserves_generator_order() -> AuthResult<()> {
    for role in [EntityRole::Jwk, EntityRole::WalletAddress] {
        for before_label in [true, false] {
            for reject in [false, true] {
                check(role, before_label, reject).await?;
            }
        }
    }
    Ok(())
}
