#![expect(
    clippy::unwrap_used,
    reason = "Required fixture operations must succeed before comparing the contract."
)]

use super::invitation::accept_invitation_core;
use crate::plugins::{
    organization::{
        OrganizationConfig, OrganizationPlugin, OrganizationTeamsConfig,
        hooks::{OrganizationHooks, OrganizationInvitationEvent},
        types::AcceptInvitationRequest,
    },
    test_helpers,
};
use better_auth_core::{
    AuthError, AuthRequest, AuthResult, CreateInvitation, CreateOrganization, CreateSession,
    CreateTeam, CreateUser, FieldFunction, FieldMap, FieldValue, HttpMethod, Member,
    config::{
        CookieCacheConfig, CookieCacheVersion, FieldTransforms, UserFieldConfig, UserFieldTransform,
    },
    plugin::AuthContext,
    session::{NativeSessionData, SessionCookieContext, SessionCookieSigner},
    store::{
        AuthStore, EphemeralStore, MemoryCacheAdapter, SecondaryStorage, SessionStore,
        StatelessSchema, UserStore,
        database_hooks::{DatabaseHookContext, DatabaseHookUpdate, DatabaseHooks},
        secondary::SecondaryStore,
    },
    user_fields::UserFieldFactory,
    wire::SessionView,
};
use chrono::{Duration, Utc};
use std::sync::{Arc, Mutex};

type Events = Arc<Mutex<Vec<&'static str>>>;

fn required<T>(value: Option<T>) -> AuthResult<T> {
    value.ok_or_else(|| AuthError::internal("Expected invitation cookie fixture value"))
}

fn record(events: &Events, event: &'static str) -> AuthResult<()> {
    events
        .lock()
        .map_err(|_| AuthError::internal("Cookie event lock poisoned"))?
        .push(event);
    Ok(())
}

struct Hooks(Events);

#[better_auth_core::database_hooks()]
impl DatabaseHooks<StatelessSchema> for Hooks {
    async fn before_update_session(
        &self,
        fields: &mut FieldMap,
        context: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<DatabaseHookUpdate<FieldMap>> {
        assert!(context.transaction.is_some());
        record(
            &self.0,
            if fields.contains_key("activeTeamId") {
                "before.team"
            } else {
                "before.organization"
            },
        )?;
        Ok(DatabaseHookUpdate::Continue)
    }

    async fn after_update_session(
        &self,
        session: Option<&SessionView>,
        context: &DatabaseHookContext<'_, StatelessSchema>,
    ) -> AuthResult<()> {
        assert!(context.transaction.is_none());
        record(
            &self.0,
            if required(session)?
                .active_organization_id
                .field_value()
                .is_truthy()
            {
                "after.organization"
            } else {
                "after.team"
            },
        )
    }
}

#[async_trait::async_trait]
impl OrganizationHooks for Hooks {
    async fn after_accept_invitation(
        &self,
        _: &Member,
        _: OrganizationInvitationEvent<'_>,
    ) -> AuthResult<()> {
        record(&self.0, "after.accept")
    }
}

struct Signer {
    mode: &'static str,
    events: Events,
    organization: FieldValue,
}

#[async_trait::async_trait]
impl SessionCookieSigner<StatelessSchema> for Signer {
    async fn sign(
        &self,
        _: FieldMap,
        _: f64,
        context: SessionCookieContext<'_, StatelessSchema>,
    ) -> AuthResult<String> {
        record(&self.events, "signer")?;
        let transaction = required(context.transaction)?;
        assert_eq!(
            transaction
                .count_organization_members_value(&self.organization)
                .await?,
            0
        );
        let _ = required(
            transaction
                .create_user_optional(CreateUser::new().with_email("cookie-signer@example.test"))
                .await?,
        )?;
        if self.mode == "signer" {
            return Err(AuthError::type_error("cookie-signer"));
        }
        Ok("transaction-signed-cookie".into())
    }

    async fn verify(
        &self,
        _: &str,
        _: SessionCookieContext<'_, StatelessSchema>,
    ) -> AuthResult<Option<serde_json::Map<String, serde_json::Value>>> {
        Err(AuthError::internal(
            "Invitation cookie fixture does not read signed caches",
        ))
    }
}

async fn exercise(mode: &'static str, storage: &'static str) -> AuthResult<()> {
    let events = Events::default();
    let hooks = Arc::new(Hooks(events.clone()));
    let mut auth = test_helpers::create_test_config();
    auth.session.store_session_in_database = Some(storage != "cache-only");
    let callback_events = events.clone();
    auth.session.cookie_cache = Some(CookieCacheConfig {
        enabled: Some(true),
        version: CookieCacheVersion::dynamic(move |_| {
            let events = callback_events.clone();
            async move {
                record(&events, "version")?;
                if mode == "version" {
                    return Err(AuthError::type_error("cookie-version"));
                }
                Ok("acceptance".into())
            }
        }),
        ..Default::default()
    });
    if mode == "clone" {
        let callback: UserFieldFactory = UserFieldFactory::new(|| Ok(FieldValue::Undefined));
        let function = FieldValue::Function(FieldFunction::from(callback));
        let _ = auth.session.fields_mut().insert(
            "activeTeamId".into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    input: None,
                    output: Some(UserFieldTransform::new(move |value| {
                        Ok(if value.is_truthy() {
                            function.clone()
                        } else {
                            value
                        })
                    })),
                }),
                ..Default::default()
            },
        );
    }
    let mut organization = OrganizationConfig {
        hooks: Some(hooks.clone()),
        teams: OrganizationTeamsConfig {
            enabled: true,
            maximum_members_per_team: Some(1),
            ..Default::default()
        },
        ..Default::default()
    };
    if mode == "member" {
        let _ = organization.schema.member.fields_mut().insert(
            "role".into(),
            UserFieldConfig {
                transform: Some(FieldTransforms {
                    input: None,
                    output: Some(UserFieldTransform::new(|_| {
                        Err(AuthError::type_error("member-output"))
                    })),
                }),
                ..Default::default()
            },
        );
    }
    let auth = Arc::new(auth);
    let database = Arc::new(EphemeralStore::new(auth.clone()).with_hooks(vec![hooks]));
    let cache = Arc::new(MemoryCacheAdapter::new());
    let runtime: Arc<dyn AuthStore<StatelessSchema>> = if storage == "database" {
        database.clone()
    } else {
        Arc::new(SecondaryStore::new(
            database.clone(),
            cache.clone(),
            auth.clone(),
            Default::default(),
        )?)
    };
    let mut context: AuthContext<StatelessSchema> = test_helpers::initialize_test_context(
        auth,
        runtime,
        &[&OrganizationPlugin::with_config(organization.clone())],
    )
    .await?;
    let user = context
        .database
        .create_user(CreateUser::new().with_email("recipient@example.test"))
        .await?;
    let org = context
        .database
        .create_organization(CreateOrganization::new(
            "Cookie transaction",
            "cookie-transaction",
        ))
        .await?;
    let team = context
        .database
        .create_team(CreateTeam {
            name: "Team".into(),
            organization_id: org.id.clone(),
            ..Default::default()
        })
        .await?;
    let mut invitation = CreateInvitation::new(
        org.id.typed()?.clone(),
        "recipient@example.test",
        "member",
        user.id.typed()?.clone(),
        (Utc::now() + Duration::days(1)).into(),
    );
    invitation.team_id = Some(team.id.typed()?.clone());
    let invitation = context.database.create_invitation(invitation).await?;
    let session = context
        .database
        .create_session(CreateSession {
            inherited_fields: Default::default(),
            additional_fields: Default::default(),
            user_id: user.id.clone(),
            expires_at: (Utc::now() + Duration::hours(1)).into(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await?;
    let token = session.token.field_value();
    let original = database.get_session_by_token_value(&token).await?;
    let original_cache = cache.get_native(&token).await?;
    let signer: Arc<dyn SessionCookieSigner<StatelessSchema>> = Arc::new(Signer {
        mode,
        events: events.clone(),
        organization: org.id.field_value(),
    });
    context.extensions.insert(signer);
    let native = NativeSessionData::new(session, FieldMap::from(user.clone()).into());
    let request: AuthRequest = test_helpers::create_auth_json_request_no_query(
        HttpMethod::Post,
        "/organization/accept-invitation",
        None,
        None,
    );
    let result = accept_invitation_core(
        &AcceptInvitationRequest {
            invitation_id: invitation.id.typed()?.clone(),
        },
        &native,
        &organization,
        &context,
        &request,
    )
    .await;
    match mode {
        "commit" => {
            assert!(result.is_ok());
        }
        "clone" => assert!(matches!(result, Err(AuthError::DataClone))),
        _ => {
            let expected = match mode {
                "version" => "cookie-version",
                "signer" => "cookie-signer",
                _ => "member-output",
            };
            assert!(
                matches!(result, Err(AuthError::TypeError(ref message)) if message == expected)
            );
        }
    }
    let mut expected = vec!["before.team"];
    if mode != "clone" {
        expected.push("version");
    }
    if matches!(mode, "commit" | "signer" | "member") {
        expected.push("signer");
    }
    if mode == "commit" {
        expected.extend([
            "before.organization",
            "after.team",
            "after.organization",
            "after.accept",
        ]);
    }
    assert_eq!(
        *events
            .lock()
            .map_err(|_| AuthError::internal("Cookie event lock poisoned"))?,
        expected,
        "{storage}/{mode}"
    );
    assert_eq!(
        context
            .database
            .count_organization_members_value(&org.id.field_value())
            .await?,
        i64::from(mode == "commit")
    );
    assert_eq!(
        context
            .database
            .list_team_members_value(&team.id.field_value())
            .await?
            .len(),
        usize::from(mode == "commit")
    );
    assert_eq!(
        required(
            context
                .database
                .get_invitation_by_id_value(&invitation.id.field_value())
                .await?
        )?
        .status
        .field_value(),
        FieldValue::from(if mode == "commit" {
            "accepted"
        } else {
            "pending"
        })
    );
    assert_eq!(
        database
            .get_user_by_email("cookie-signer@example.test")
            .await?
            .is_some(),
        mode == "commit"
    );
    let stored = database.get_session_by_token_value(&token).await?;
    if mode != "commit" {
        assert_eq!(
            stored.map(FieldMap::from),
            original.map(FieldMap::from),
            "{storage}/{mode}"
        );
    } else if storage != "cache-only" {
        let stored = required(stored)?;
        assert_eq!(stored.active_team_id.field_value(), team.id.field_value());
        assert_eq!(
            stored.active_organization_id.field_value(),
            org.id.field_value()
        );
    } else {
        assert!(stored.is_none());
    }
    if storage != "database" {
        let initial = required(original_cache)?
            .as_str()
            .ok_or_else(|| AuthError::internal("Expected serialized cache fixture"))?
            .to_owned();
        let mut expected: serde_json::Value = serde_json::from_str(&initial)?;
        let fields = required(expected.get_mut("session"))?
            .as_object_mut()
            .ok_or_else(|| AuthError::internal("Expected cached Session fields"))?;
        let _ = fields.insert(
            "activeTeamId".into(),
            serde_json::to_value(team.id.typed()?)?,
        );
        if mode == "commit" {
            let _ = fields.insert(
                "activeOrganizationId".into(),
                serde_json::to_value(org.id.typed()?)?,
            );
        }
        let cached = required(cache.get_native(&token).await?)?;
        let cached: serde_json::Value = serde_json::from_str(
            cached
                .as_str()
                .ok_or_else(|| AuthError::internal("Expected serialized cache fixture"))?,
        )?;
        assert_eq!(cached, expected, "{storage}/{mode}");
    }
    let published = request.new_session()?;
    assert_eq!(published.is_some(), matches!(mode, "commit" | "member"));
    if let Some(published) = published {
        assert_eq!(
            published.session_property("activeTeamId").unwrap(),
            team.id.field_value()
        );
        assert!(
            !published
                .session_property("activeOrganizationId")
                .unwrap()
                .is_truthy()
        );
    }
    Ok(())
}

#[tokio::test]
async fn invitation_cookie_failures_share_the_database_transaction() -> AuthResult<()> {
    for mode in ["commit", "version", "clone", "signer", "member"] {
        exercise(mode, "database").await?;
    }
    Ok(())
}

#[tokio::test]
async fn invitation_secondary_writes_survive_cookie_transaction_rollback() -> AuthResult<()> {
    for storage in ["cache-only", "mirror"] {
        for mode in ["commit", "version", "signer", "member"] {
            exercise(mode, storage).await?;
        }
    }
    Ok(())
}
