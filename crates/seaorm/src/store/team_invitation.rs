use super::{
    SeaOrmStore, SeaOrmTransaction, map_db_err,
    organization_models::{self as models, Entity, values},
};
use crate::SeaOrmOrganizationModel;
use crate::schema::{AuthSchema, SeaOrmSessionModel};
use crate::store::query_compile::Execute;
use better_auth_core::store::{
    AuthTransaction, SessionWriteEffects, database_hooks::SessionUpdate,
};
use better_auth_core::user_fields::UserConfig;
use better_auth_core::{AuthError, AuthResult, Invitation, Member, store::schema::EntityRole};
use better_auth_core::{FieldValue, SchemaField};
use chrono::Utc;
use sea_orm::{EntityTrait, QueryFilter, sea_query::Expr};
use std::sync::{Arc, Mutex};

impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> SeaOrmStore<S, O, P>
where
    S: AuthSchema,
    S::User: crate::SeaOrmUserModel,
    S::Session: SeaOrmSessionModel,
    S::Account: crate::SeaOrmAccountModel,
    S::Verification: crate::SeaOrmVerificationModel,
{
    pub(super) async fn accept_team_invitation(
        &self,
        invitation_id: &FieldValue,
        user_id: &FieldValue,
        session_token: Option<&FieldValue>,
        teams_enabled: bool,
        maximum: better_auth_core::store::TeamMemberLimits<'_>,
        effects: SessionWriteEffects<S>,
    ) -> AuthResult<(
        Member,
        better_auth_core::Invitation,
        Option<better_auth_core::wire::SessionView>,
    )> {
        let invitation = self
            .transition_invitation(invitation_id, Some("pending"), "accepted")
            .await?
            .ok_or_else(|| {
                AuthError::from_code(
                    "BAD_REQUEST",
                    "INVITATION_NOT_FOUND",
                    "Invitation not found",
                )
            })?;
        match self
            .accept_claimed_invitation(
                &invitation,
                user_id,
                session_token,
                teams_enabled,
                maximum,
                effects,
            )
            .await
        {
            Ok((member, session)) => Ok((member, invitation, session)),
            Err(error) => {
                let _ = self
                    .transition_invitation(invitation_id, Some("accepted"), "pending")
                    .await?;
                Err(error)
            }
        }
    }

    pub(super) async fn transition_invitation(
        &self,
        id: &FieldValue,
        from: Option<&str>,
        status: &str,
    ) -> AuthResult<Option<Invitation>> {
        let config = self.organization_fields()?.invitation;
        let id = self.bind_organization_query_field(EntityRole::Invitation, "id", id)?;
        let from = from
            .map(|from| {
                self.bind_organization_query_field(EntityRole::Invitation, "status", &from.into())
            })
            .transpose()?;
        let active = models::active::<O::Invitation>(
            values([("status", status.to_owned().into_field())]),
            Default::default(),
            &config,
            None,
            self.connection().get_database_backend(),
            self.config().advanced.database.generate_id(),
            (
                &self.model_fields,
                better_auth_core::store::schema::EntityRole::Invitation,
            ),
        )
        .await?;
        better_auth_core::store::validate_increment_one_update(false, !active.is_empty())?;
        let row = super::instrumentation::database_operation::<Entity<O::Invitation>, _>(
            self.config(),
            "incrementOne",
            async {
                let (id_column, id) = self.resolve_organization_query_field::<O::Invitation>(
                    EntityRole::Invitation,
                    id,
                )?;
                let from = from
                    .map(|from| {
                        self.resolve_organization_query_field::<O::Invitation>(
                            EntityRole::Invitation,
                            from,
                        )
                    })
                    .transpose()?;
                let predicates =
                    std::iter::once(super::value_filter::QueryPredicate::equals(id_column, id))
                        .chain(from.map(|(column, value)| {
                            super::value_filter::QueryPredicate::equals(column, value)
                        }))
                        .collect();
                super::updates::increment_returning_raw::<Entity<O::Invitation>>(
                    self.connection(),
                    active,
                    predicates,
                )
                .await
            },
        )
        .await?;
        // Output failures leave the committed status available to the next operation.
        match row {
            Some(row) => models::record::<O::Invitation>(
                &row.into(),
                &config,
                self.connection().get_database_backend(),
                (
                    &self.model_fields,
                    better_auth_core::store::schema::EntityRole::Invitation,
                ),
            )
            .await
            .map(Some),
            None => Ok(None),
        }
    }

    async fn accept_claimed_invitation(
        &self,
        invitation: &Invitation,
        user_id: &FieldValue,
        session_token: Option<&FieldValue>,
        teams_enabled: bool,
        maximum: better_auth_core::store::TeamMemberLimits<'_>,
        mut effects: SessionWriteEffects<S>,
    ) -> AuthResult<(Member, Option<better_auth_core::wire::SessionView>)> {
        let pending = Arc::new(Mutex::new(Vec::new()));
        let transaction = SeaOrmTransaction::begin(self, &pending).await?;
        let store = &transaction.store;
        let tx = &transaction.tx;
        let config = store.organization_fields()?;
        let result = async {
            let team_id = invitation.team_id.field_value();
            let team_ids: Vec<_> = if teams_enabled && team_id.is_truthy() {
                team_id
                    .as_str()
                    .ok_or_else(|| {
                        AuthError::type_error("acceptedI.teamId.split is not a function")
                    })?
                    .split(',')
                    .collect()
            } else {
                Vec::new()
            };
            for team_id in &team_ids {
                let team_value = FieldValue::from(*team_id);
                let condition = store.team_details_condition(
                    &team_value,
                    Some(&invitation.organization_id.field_value()),
                )?;
                let locked = Entity::<O::Team>::update_many()
                    .col_expr(
                        O::Team::column("member_count")?,
                        Expr::col(O::Team::column("member_count")?),
                    )
                    .filter(condition.clone())
                    .exec_native(tx)
                    .await?;
                if locked.rows_affected == 0 {
                    return Err(AuthError::from_code(
                        "BAD_REQUEST",
                        "TEAM_NOT_FOUND",
                        "Team not found",
                    ));
                }
                let details = store
                    .read_team_details_with_condition(tx, condition, false)
                    .await?
                    .ok_or_else(|| {
                        AuthError::from_code("BAD_REQUEST", "TEAM_NOT_FOUND", "Team not found")
                    })?;
                let _ = details.into_public_parts(
                    maximum
                        .team_output_fields()
                        .unwrap_or(&UserConfig::default()),
                )?;
                let maximum = maximum
                    .maximum(team_id, &invitation.organization_id.field_value())
                    .await?;
                let membership_key =
                    better_auth_core::organization_fields::team_membership_key_values(
                        &team_value,
                        user_id,
                    )?
                    .into();
                let existing = store
                    .find_team_member_by_key_or_pair(tx, &team_value, user_id, &membership_key)
                    .await?;
                if existing.is_none() {
                    let query = Entity::<O::TeamMember>::find().filter(
                        store.organization_field_equals::<O::TeamMember>(
                            better_auth_core::store::schema::EntityRole::TeamMember,
                            "teamId",
                            &team_value,
                        )?,
                    );
                    let count = super::plugin_rows::count(tx, query).await?;
                    super::team_capacity::sync::<O::Team, _>(
                        tx,
                        &team_value,
                        count,
                        &config.team,
                        store.config(),
                        (&store.model_fields, EntityRole::Team),
                    )
                    .await?;
                    if let Some(maximum) = maximum {
                        if !super::team_capacity::reserve::<O::Team, _>(
                            tx,
                            &team_value,
                            maximum,
                            &config.team,
                            store.config(),
                            (&store.model_fields, EntityRole::Team),
                        )
                        .await?
                        {
                            return Err(AuthError::from_code(
                                "FORBIDDEN",
                                "TEAM_MEMBER_LIMIT_REACHED",
                                "Team member limit reached",
                            ));
                        }
                        let _ = store
                            .create_reserved_team_member(tx, &team_value, user_id, &membership_key)
                            .await?;
                    } else {
                        let _ = store
                            .create_unlimited_team_member(tx, &team_value, user_id, &membership_key)
                            .await?;
                    }
                }
            }
            let cookie_session = match (session_token, team_ids.as_slice()) {
                (Some(session_token), [team_id]) => {
                    let session = transaction
                        .update_session_with_writer_by_token_value(
                            session_token,
                            SessionUpdate {
                                additional_fields: [("activeTeamId".into(), (*team_id).into())]
                                    .into(),
                                ..Default::default()
                            },
                            effects
                                .secondary
                                .as_ref()
                                .map(|factory| factory.bind(session_token.clone())),
                        )
                        .await?
                        .ok_or_else(|| {
                            AuthError::type_error(
                                "Cannot read properties of null (reading 'token')",
                            )
                        })?;
                    if let Some(effect) = effects.after_output.take() {
                        effect(session.clone(), transaction.clone_handle()).await?;
                    }
                    Some(session)
                }
                _ => None,
            };
            let member = models::insert::<O::Member, _>(
                tx,
                super::create_readback::ReadbackScope::Transaction,
                values([
                    ("organization_id", invitation.organization_id.field_value()),
                    ("user_id", user_id.clone()),
                    ("role", invitation.role.field_value()),
                    ("created_at", FieldValue::Date((Utc::now()).into())),
                ]),
                Default::default(),
                &config.member,
                store.config().advanced.database.generate_id(),
                (
                    &store.model_fields,
                    better_auth_core::store::schema::EntityRole::Member,
                    "member",
                ),
            )
            .await?;
            let Some(session_token) = session_token else {
                return Ok((member, None));
            };
            let _ = transaction
                .update_session_with_writer_by_token_value(
                    session_token,
                    SessionUpdate {
                        additional_fields: [(
                            "activeOrganizationId".into(),
                            invitation.organization_id.field_value(),
                        )]
                        .into(),
                        ..Default::default()
                    },
                    effects
                        .secondary
                        .as_ref()
                        .map(|factory| factory.bind(session_token.clone())),
                )
                .await?;
            Ok((member, cookie_session))
        }
        .await;
        match result {
            Ok(value) => {
                tx.commit().await.map_err(map_db_err)?;
                self.finish_queued_transaction_effects(&pending).await?;
                Ok(value)
            }
            Err(error) => {
                tx.rollback().await.map_err(map_db_err)?;
                Err(error)
            }
        }
    }
}
