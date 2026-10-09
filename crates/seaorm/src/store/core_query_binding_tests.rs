use crate::store::{
    SeaOrmStore, bundled_schema::BundledSchema, map_db_err, migrator::run_migrations,
};
use better_auth_core::{
    AuthConfig, AuthError, AuthResult, CreateAccount, CreateSession, CreateUser,
    CreateVerification,
    store::{AccountStore, JoinValue, SessionStore, UserStore, VerificationStore, transaction},
};
use chrono::Utc;
use sea_orm::{ConnectOptions, ConnectionTrait, Database, DatabaseConnection};

async fn database(encoding: &str) -> AuthResult<DatabaseConnection> {
    let mut options = ConnectOptions::new("sqlite::memory:");
    let _ = options.max_connections(1);
    let database = Database::connect(options).await.map_err(map_db_err)?;
    let _ = database
        .execute_unprepared(&format!("PRAGMA encoding = '{encoding}'"))
        .await
        .map_err(map_db_err)?;
    run_migrations(&database).await.map_err(map_db_err)?;
    Ok(database)
}

fn required<T>(value: Option<T>) -> AuthResult<T> {
    value.ok_or_else(|| AuthError::internal("Expected a query result"))
}

fn session(user_id: &str, token: &str) -> CreateSession {
    CreateSession {
        inherited_fields: Default::default(),
        additional_fields: [("token".into(), token.into())].into(),
        user_id: user_id.to_owned().into(),
        expires_at: (Utc::now() + chrono::Duration::hours(1)).into(),
        ip_address: None,
        user_agent: None,
        impersonated_by: None,
        active_organization_id: None,
    }
}

fn verification(identifier: &str, value: &str) -> CreateVerification {
    CreateVerification {
        identifier: identifier.to_owned().into(),
        value: value.to_owned().into(),
        expires_at: better_auth_core::FieldDate::from(Utc::now() + chrono::Duration::hours(1))
            .into(),
        ..Default::default()
    }
}

#[tokio::test]
async fn user_account_and_session_queries_share_sqlite_write_bindings() -> AuthResult<()> {
    for encoding in ["UTF-8", "UTF-16le", "UTF-16be"] {
        for joins in [false, true] {
            let database = database(encoding).await?;
            let mut config = AuthConfig::new("a-secret-that-is-at-least-32-characters");
            config.advanced.database.joins = Some(joins);
            let store = SeaOrmStore::<BundledSchema>::new(config, database.clone());
            let user = store
                .create_user(CreateUser {
                    id: Some("\u{feff}owner".into()),
                    email: Some("query-owner@example.test".into()),
                    name: Some("Query owner".into()).into(),
                    ..Default::default()
                })
                .await?;
            assert_eq!(user.id, "owner");
            assert_eq!(
                required(store.get_user_by_id("\u{feff}owner").await?)?.id,
                user.id
            );
            let selected = transaction(&store, |tx| {
                Box::pin(async move { tx.get_user_by_id("\u{feff}owner").await })
            })
            .await?;
            assert_eq!(required(selected)?.id, user.id);

            let account = store
                .create_account(CreateAccount {
                    user_id: user.id.clone(),
                    provider_id: "\u{feff}provider".into(),
                    account_id: "\u{feff}external-account".into(),
                    ..Default::default()
                })
                .await?;
            let owner = required(
                store
                    .get_account_owner("\u{feff}provider", "\u{feff}external-account")
                    .await?,
            )?;
            assert_eq!(owner.account.id, account.id);
            let JoinValue::One(owner) = owner.user else {
                return Err(AuthError::internal("Expected a single account owner"));
            };
            assert_eq!(required(owner)?.id, user.id);

            let selected = store
                .create_session(session("owner", "\u{feff}selected"))
                .await?;
            let retained = store.create_session(session("owner", "retained")).await?;
            let tokens = vec!["\u{feff}selected".into()];
            let snapshots = store.get_session_snapshots(&tokens, true).await?;
            assert_eq!(snapshots.len(), 1);
            assert_eq!(required(snapshots.first())?.0.id, selected.id);
            assert!(store.get_session_snapshots(&[], false).await?.is_empty());
            store.delete_sessions(&[]).await?;
            store.end_sessions(&tokens).await?;
            assert!(store.get_session_snapshots(&tokens, true).await?.is_empty());
            let snapshots = store.get_session_snapshots(&tokens, false).await?;
            assert_eq!(snapshots.len(), 1);
            assert!(
                required(snapshots.first())?
                    .0
                    .expires_at
                    .is_before(Utc::now())?
            );
            store.delete_sessions(&tokens).await?;
            assert!(
                store
                    .get_session_snapshots(&tokens, false)
                    .await?
                    .is_empty()
            );
            assert_eq!(
                required(store.get_session("retained").await?)?.id,
                retained.id
            );
            database.close().await.map_err(map_db_err)?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn verification_queries_share_sqlite_write_bindings_without_changing_transactions()
-> AuthResult<()> {
    for encoding in ["UTF-8", "UTF-16le", "UTF-16be"] {
        let database = database(encoding).await?;
        let store = SeaOrmStore::<BundledSchema>::new(
            AuthConfig::new("a-secret-that-is-at-least-32-characters"),
            database.clone(),
        );
        let claim = verification("\u{feff}claim", "\u{feff}proof");
        assert!(
            store
                .reserve_verification("\u{feff}reservation", claim.clone())
                .await?
        );
        assert!(
            !store
                .reserve_verification("\u{feff}reservation", claim)
                .await?
        );
        let selected = required(
            store
                .get_verification("\u{feff}claim", "\u{feff}proof")
                .await?,
        )?;
        assert_eq!(selected.id, "reservation");
        assert_eq!(selected.identifier, "claim");
        assert_eq!(selected.value, "proof");
        assert_eq!(
            required(store.get_verification_by_value("\u{feff}proof").await?)?.id,
            selected.id
        );
        assert_eq!(
            required(
                store
                    .get_verification_by_identifier("\u{feff}claim")
                    .await?
            )?
            .id,
            selected.id
        );
        store
            .update_verification_by_identifier(
                "\u{feff}claim",
                Some("\u{feff}updated".into()),
                None,
            )
            .await?;
        assert_eq!(
            required(
                store
                    .get_verification_including_expired("\u{feff}claim")
                    .await?
            )?
            .value,
            "updated"
        );
        store.delete_verification("\u{feff}reservation").await?;
        assert!(
            store
                .get_verification_including_expired("claim")
                .await?
                .is_none()
        );

        let retained = store
            .create_verification(verification("retained", "proof"))
            .await?;
        let _ = store
            .create_verification(verification("\u{feff}claim", "proof"))
            .await?;
        store
            .delete_verification_by_identifier("\u{feff}claim")
            .await?;
        assert!(
            store
                .get_verification_including_expired("claim")
                .await?
                .is_none()
        );
        let _ = store
            .create_verification(verification("\u{feff}claim", "proof"))
            .await?;
        transaction(&store, |tx| {
            Box::pin(async move { tx.delete_verification_by_identifier("\u{feff}claim").await })
        })
        .await?;
        assert!(
            store
                .get_verification_including_expired("claim")
                .await?
                .is_none()
        );

        let mut older = verification("\u{feff}claim", "older");
        older.created_at =
            better_auth_core::FieldDate::from(Utc::now() - chrono::Duration::minutes(1)).into();
        let _ = store.create_verification(older).await?;
        let latest = store
            .create_verification(verification("\u{feff}claim", "latest"))
            .await?;
        let consumed = required(
            store
                .consume_verification_including_expired("\u{feff}claim")
                .await?,
        )?;
        assert_eq!(consumed.id, latest.id);
        assert_eq!(consumed.value, "latest");
        assert!(
            store
                .get_verification_including_expired("claim")
                .await?
                .is_none()
        );
        assert_eq!(
            required(store.get_verification_including_expired("retained").await?)?.id,
            retained.id
        );
        database.close().await.map_err(map_db_err)?;
    }
    Ok(())
}

#[tokio::test]
async fn session_membership_applies_the_declared_policy_to_the_complete_query_value()
-> AuthResult<()> {
    use better_auth_core::{
        FieldValue,
        user_fields::{UserFieldConfig, UserFieldType},
    };

    for joins in [false, true] {
        let database = database("UTF-8").await?;
        let mut config = AuthConfig::new("a-secret-that-is-at-least-32-characters");
        config.advanced.database.joins = Some(joins);
        let _ = config.session.fields_mut().insert(
            "token".into(),
            UserFieldConfig {
                field_type: UserFieldType::Json,
                ..Default::default()
            },
        );
        let store = SeaOrmStore::<BundledSchema>::new(config, database.clone());
        let owner = store
            .create_user(
                CreateUser::new()
                    .with_email("json-token@example.test")
                    .with_name("Owner"),
            )
            .await?;
        let mut input = session(owner.id.typed()?, "unused");
        let _ = input
            .additional_fields
            .insert("token".into(), vec![FieldValue::from("selected")].into());
        let created = store.create_session(input).await?;
        let tokens = vec!["selected".into()];
        let snapshots = store.get_session_snapshots(&tokens, true).await?;
        assert_eq!(snapshots.len(), 1);
        assert_eq!(required(snapshots.first())?.0.id, created.id);
        assert_eq!(
            required(snapshots.first())?.0.token.field_value().json()?,
            Some(serde_json::json!(["selected"]))
        );
        store.delete_sessions(&tokens).await?;
        assert!(
            store
                .get_session_snapshots(&tokens, false)
                .await?
                .is_empty()
        );
        database.close().await.map_err(map_db_err)?;
    }
    Ok(())
}

#[tokio::test]
async fn organization_relations_rebind_stored_keys_through_the_write_policy() -> AuthResult<()> {
    use better_auth_core::{
        CreateInvitation, CreateMember, CreateOrganization, CreateTeam, InvitationStatus,
        store::{
            InvitationStore, MemberStore, OrganizationDetailsQuery, OrganizationKey,
            OrganizationStore, TeamStore,
        },
    };

    for encoding in ["UTF-8", "UTF-16le", "UTF-16be"] {
        for joins in [false, true] {
            let database = database(encoding).await?;
            let mut config = AuthConfig::new("a-secret-that-is-at-least-32-characters");
            config.advanced.database.joins = Some(joins);
            let store = SeaOrmStore::<BundledSchema>::new(config, database.clone());
            let owner_id = "owner\u{ffff}";
            let organization_id = "organization\u{ffff}";
            let team_id = "team\u{ffff}";
            let owner = store
                .create_user(CreateUser {
                    id: Some(owner_id.into()),
                    email: Some("relationship-owner@example.test".into()),
                    name: Some("Relationship owner".into()).into(),
                    ..Default::default()
                })
                .await?;
            let mut input = CreateOrganization::new("Organization", "\u{feff}selected");
            input.id = Some(organization_id.into());
            let organization = store.create_organization(input).await?;
            assert_eq!(organization.id, organization_id);
            assert_eq!(organization.slug, "selected");
            let member = store
                .create_member(CreateMember::new(organization_id, owner_id, "owner"))
                .await?;
            let mut team = store
                .create_team(CreateTeam {
                    id: Some(team_id.into()),
                    organization_id: organization_id.into(),
                    name: "Team".into(),
                    ..Default::default()
                })
                .await?;
            let _ = required(store.add_team_member(&team.id, owner_id, Some(1)).await?)?;
            assert_eq!(
                team.additional_fields
                    .insert("memberCount".into(), 1.into()),
                Some(0.into())
            );
            let mut input = CreateInvitation::new(
                organization_id,
                "\u{feff}invited@example.test",
                "member",
                owner_id,
                (Utc::now() + chrono::Duration::hours(1)).into(),
            );
            input.id = Some("invitation\u{ffff}".into());
            input.team_id = Some(team_id.into());
            let mut invitation = store.create_invitation(input).await?;
            assert_eq!(invitation.email, "invited@example.test");
            assert_eq!(
                required(
                    store
                        .get_pending_invitation(organization_id, "\u{feff}INVITED@example.test")
                        .await?
                )?,
                invitation
            );
            let invitations = store
                .list_user_invitations("\u{feff}INVITED@example.test")
                .await?;
            assert_eq!(invitations.len(), 1);
            assert_eq!(required(invitations.first())?.invitation, invitation);
            assert_eq!(
                required(invitations.first())?.organization.as_ref(),
                Some(&organization)
            );
            assert_eq!(
                store.list_user_organizations(owner_id).await?,
                [organization.clone()]
            );
            let mut public_team = team.clone();
            assert_eq!(
                public_team.additional_fields.shift_remove("memberCount"),
                Some(1.into())
            );
            assert_eq!(store.list_user_teams(owner_id).await?, [public_team]);
            let details = required(
                store
                    .get_organization_details(OrganizationDetailsQuery {
                        organization: OrganizationKey::Slug("\u{feff}selected"),
                        members_limit: None,
                        users_limit: 100.0,
                        include_teams: true,
                    })
                    .await?,
            )?;
            assert_eq!(details.organization, organization);
            assert_eq!(details.invitations, [invitation.clone()]);
            assert_eq!(details.members.len(), 1);
            assert_eq!(required(details.members.first())?.member, member);
            assert_eq!(required(details.members.first())?.user.id, owner.id);
            assert_eq!(required(details.teams)?, [team]);
            store
                .delete_team_value(&format!("\u{feff}{team_id}").into())
                .await?;
            assert!(store.get_team(team_id).await?.is_none());
            assert!(store.list_team_members(team_id).await?.is_empty());
            invitation.team_id = None.into();
            assert_eq!(
                required(store.get_invitation_by_id(invitation.id.typed()?).await?)?,
                invitation
            );
            let updated = store
                .update_invitation_status(invitation.id.typed()?, InvitationStatus::Accepted)
                .await?;
            assert_eq!(updated.status, InvitationStatus::Accepted);
            assert_eq!(
                required(store.get_invitation_by_id(invitation.id.typed()?).await?)?,
                updated
            );
            assert!(
                store
                    .get_pending_invitation(organization_id, "\u{feff}INVITED@example.test")
                    .await?
                    .is_none()
            );
            database.close().await.map_err(map_db_err)?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn rate_limit_key_bindings_preserve_atomic_increments_and_window_resets() -> AuthResult<()> {
    use crate::store::entities::rate_limit;
    use better_auth_core::{middleware::EndpointRateLimit, store::RateLimitStore};
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, sea_query::Expr};
    use std::sync::Arc;

    for encoding in ["UTF-8", "UTF-16le", "UTF-16be"] {
        let database = database(encoding).await?;
        let store = Arc::new(SeaOrmStore::<BundledSchema>::new(
            AuthConfig::new("a-secret-that-is-at-least-32-characters"),
            database.clone(),
        ));
        let rule = EndpointRateLimit {
            window: 60.0,
            max_requests: 4.0,
        };
        let key = "\u{feff}quota\u{ffff}";
        assert!(store.consume_rate_limit(key, rule, 3600.0).await?.allowed);
        let mut tasks = tokio::task::JoinSet::new();
        for index in 0..7 {
            let store = store.clone();
            let _ = tasks.spawn(async move {
                store
                    .consume_rate_limit(
                        if index % 2 == 0 { key } else { "quota\u{ffff}" },
                        rule,
                        3600.0,
                    )
                    .await
            });
        }
        let mut allowed = 1;
        while let Some(result) = tasks.join_next().await {
            let decision = result.map_err(|error| AuthError::internal(error.to_string()))??;
            allowed += usize::from(decision.allowed);
            if !decision.allowed {
                assert!(
                    decision
                        .retry_after
                        .is_some_and(|remaining| remaining > 0.0 && remaining <= 60.0)
                );
            }
        }
        assert_eq!(allowed, 4);
        let rows = rate_limit::Entity::find()
            .all(&database)
            .await
            .map_err(map_db_err)?;
        assert_eq!(rows.len(), 1);
        let row = required(rows.first())?;
        assert_eq!(row.key, "quota\u{ffff}");
        assert_eq!(row.count.0, 4.0);
        let _ = rate_limit::Entity::update_many()
            .col_expr(
                rate_limit::Column::LastRequest,
                Expr::value(Utc::now().timestamp_millis() - 120_000),
            )
            .filter(rate_limit::Column::Id.eq(row.id.clone()))
            .exec(&database)
            .await
            .map_err(map_db_err)?;
        assert!(store.consume_rate_limit(key, rule, 3600.0).await?.allowed);
        let rows = rate_limit::Entity::find()
            .all(&database)
            .await
            .map_err(map_db_err)?;
        assert_eq!(rows.len(), 1);
        assert_eq!(required(rows.first())?.id, row.id);
        assert_eq!(required(rows.first())?.count.0, 1.0);
        database.close().await.map_err(map_db_err)?;
    }
    Ok(())
}
