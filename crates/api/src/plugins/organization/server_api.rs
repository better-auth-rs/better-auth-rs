use super::{OrganizationPlugin, hooks::*, types::RoleInput};
use better_auth_core::entity::{AuthSession, AuthUser};
use better_auth_core::{AuthContext, AuthError, AuthRequest, AuthResult, AuthSchema, Member};

/// Trusted server-side member creation. This endpoint has no HTTP route upstream.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddMemberInput {
    #[serde(flatten)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
    pub user_id: String,
    pub organization_id: Option<String>,
    pub role: RoleInput,
    pub team_id: Option<String>,
}

impl OrganizationPlugin {
    /// Add a member from a trusted server context, optionally using an authenticated request.
    pub async fn add_member<S: AuthSchema>(
        &self,
        input: AddMemberInput,
        request: Option<&AuthRequest>,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Member> {
        // Upstream permits a supplied user ID even when session lookup fails.
        let session = match request {
            Some(request) => super::handlers::require_session(request, ctx).await.ok(),
            None => None,
        };
        let org_id = input
            .organization_id
            .as_deref()
            .filter(|id| !id.is_empty())
            .or_else(|| {
                session
                    .as_ref()
                    .and_then(|(_, session)| session.active_organization_id())
            })
            .ok_or_else(|| AuthError::bad_request("No active organization"))?;
        if input.team_id.is_some() && !self.config.teams.enabled {
            return Err(AuthError::bad_request("Teams are not enabled"));
        }
        let user = ctx
            .database
            .get_user_by_id(&input.user_id)
            .await?
            .ok_or_else(|| AuthError::bad_request("User not found"))?;
        if let Some(email) = user.email()
            && let Some(existing) = ctx.database.get_user_by_email(email).await?
            && ctx
                .database
                .get_member(org_id, &existing.id())
                .await?
                .is_some()
        {
            return Err(AuthError::bad_request(
                "User is already a member of this organization",
            ));
        }
        if let Some(team_id) = &input.team_id {
            let _ = super::handlers::team::find_team(team_id, org_id, ctx).await?;
        }
        let count = ctx.database.list_organization_members(org_id).await?.len();
        let organization = ctx
            .database
            .get_organization_by_id(org_id)
            .await?
            .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
        let organization_view =
            crate::plugins::organization::fields::organization(&organization, ctx);
        let user_view = better_auth_core::wire::UserView::with_internal_fields(
            &user,
            &ctx.config.user,
            &ctx.metadata,
        )?;
        let event = OrganizationUser {
            user: &user_view,
            organization: &organization_view,
        };
        if count >= self.config.member_limit(event).await? {
            return Err(AuthError::Upstream {
                status: 403,
                code: "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED",
                message: "Organization membership limit reached",
            });
        }
        let mut data = OrganizationMemberDraft {
            additional_fields: self.config.schema.member.parse_organization_input(
                &input.additional_fields,
                "body",
                false,
            )?,
            organization_id: org_id.to_owned(),
            user_id: input.user_id.clone(),
            role: input.role.joined(),
            team_id: input.team_id.clone(),
            created_at: None,
        };
        if let Some(hooks) = &self.config.hooks {
            hooks.before_add_member(&mut data, event).await?;
        }
        let member = ctx.database.create_member(data.into_create()).await?;
        if let Some(team_id) = input.team_id {
            let result = async {
                let maximum = if let Some((actor, session)) = &session {
                    let user_view = ctx.user_view(actor)?;
                    let session_view = better_auth_core::wire::SessionView::with_fields(
                        session,
                        &ctx.config.session,
                    )?;
                    self.config
                        .team_member_limit(OrganizationTeamMemberLimit {
                            team_id: &team_id,
                            organization_id: org_id,
                            session: OrganizationSession {
                                user: &user_view,
                                session: &session_view,
                            },
                        })
                        .await?
                } else if self
                    .config
                    .teams
                    .maximum_members_per_team_callback
                    .is_some()
                {
                    return Err(AuthError::Unauthenticated);
                } else {
                    self.config.teams.maximum_members_per_team
                };
                let _ = ctx
                    .database
                    .add_team_member(&team_id, &input.user_id, maximum)
                    .await?
                    .ok_or_else(|| AuthError::forbidden("Team member limit reached"))?;
                AuthResult::Ok(())
            }
            .await;
            if let Err(error) = result {
                ctx.database.delete_member(&member.id).await?;
                return Err(error);
            }
        }
        if let Some(hooks) = &self.config.hooks {
            hooks
                .after_add_member(OrganizationMemberEvent {
                    member: &member,
                    user: &user_view,
                    organization: &organization_view,
                })
                .await?;
        }
        Ok(member)
    }
}
