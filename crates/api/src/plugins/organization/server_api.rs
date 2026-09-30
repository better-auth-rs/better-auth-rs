use super::{OrganizationPlugin, hooks::*, types::RoleInput};
use better_auth_core::entity::{AuthSession, AuthUser};
use better_auth_core::{AuthContext, AuthError, AuthRequest, AuthResult, AuthSchema, Member};

#[cfg(test)]
#[path = "server_api_input_tests.rs"]
mod input_tests;

/// Trusted server-side member creation. This endpoint has no HTTP route upstream.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddMemberInput {
    #[serde(flatten)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
    #[serde(
        default,
        skip_serializing_if = "better_auth_core::SchemaValue::is_undefined"
    )]
    pub user_id: better_auth_core::SchemaValue<String>,
    #[serde(
        default,
        skip_serializing_if = "better_auth_core::SchemaValue::is_undefined"
    )]
    pub organization_id: better_auth_core::SchemaValue<String>,
    #[serde(
        default,
        skip_serializing_if = "better_auth_core::SchemaValue::is_undefined"
    )]
    pub role: better_auth_core::SchemaValue<RoleInput>,
    #[serde(
        default,
        skip_serializing_if = "better_auth_core::SchemaValue::is_undefined"
    )]
    pub team_id: better_auth_core::SchemaValue<String>,
}

impl OrganizationPlugin {
    /// Add a member from a trusted server context, optionally using an authenticated request.
    pub async fn add_member<S: AuthSchema>(
        &self,
        input: AddMemberInput,
        request: Option<&AuthRequest>,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Member> {
        use super::input::BaseField;
        let raw = serde_json::to_value(&input)?;
        let validated = super::input::validate(
            &self.config.schema.member,
            raw.as_object()
                .cloned()
                .ok_or_else(|| AuthError::config("Member input must be an object"))?,
            &[
                ("userId", BaseField::CoercedString, true),
                ("role", BaseField::Roles, true),
                ("organizationId", BaseField::String, false),
                ("teamId", BaseField::String, false),
            ],
        )?;
        let input: AddMemberInput = serde_json::from_value(serde_json::Value::Object(validated))?;
        let additional_fields = input.additional_fields.clone();
        let user_id = input
            .user_id
            .json()?
            .filter(better_auth_core::user_fields::is_truthy);
        // Upstream permits a supplied user ID even when session lookup fails.
        let session = match (request, user_id.is_some()) {
            (Some(request), true) => super::handlers::require_session(request, ctx).await.ok(),
            _ => None,
        };
        let org_value = input
            .organization_id
            .json()?
            .filter(better_auth_core::user_fields::is_truthy)
            .or_else(|| {
                session
                    .as_ref()
                    .and_then(|(_, session)| session.active_organization_id())
                    .map(|id| serde_json::json!(id))
            })
            .ok_or_else(|| AuthError::bad_request("No active organization"))?;
        let team_value = input
            .team_id
            .json()?
            .filter(better_auth_core::user_fields::is_truthy);
        if team_value.is_some() && !self.config.teams.enabled {
            return Err(AuthError::bad_request("Teams are not enabled"));
        }
        let user = ctx
            .database
            .get_user_by_id_value(&user_id.ok_or_else(|| AuthError::bad_request("User not found"))?)
            .await?
            .ok_or_else(|| AuthError::bad_request("User not found"))?;
        if let Some(email) = user.email()
            && let Some(existing) = ctx.database.get_user_by_email(email).await?
            && ctx
                .database
                .get_member_value(&org_value, &serde_json::json!(existing.id()))
                .await?
                .is_some()
        {
            return Err(AuthError::bad_request(
                "User is already a member of this organization",
            ));
        }
        let team = if let Some(team_id) = &team_value {
            let team = ctx
                .database
                .get_team_value(team_id)
                .await?
                .ok_or_else(|| AuthError::bad_request("Team not found"))?;
            if team.organization_id.json()?.as_ref() != Some(&org_value) {
                return Err(AuthError::bad_request("Team not found"));
            }
            Some(team)
        } else {
            None
        };
        let organization = ctx
            .database
            .get_organization_by_id_value(&org_value)
            .await?
            .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
        let org_id = organization.id.as_str();
        let count = ctx.database.list_organization_members(org_id).await?.len();
        let organization_view =
            crate::plugins::organization::fields::organization(&organization, ctx);
        let user_view = ctx.internal_user_view(&user)?;
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
            additional_fields,
            organization_id: org_id.to_owned(),
            user_id: user.id().into_owned(),
            role: super::input::parse_roles(&input.role)?,
            team_id: team.as_ref().map(|team| team.id.clone()),
            created_at: None,
        };
        if let Some(hooks) = &self.config.hooks {
            hooks.before_add_member(&mut data, event).await?;
        }
        let member = ctx.database.create_member(data.into_create()).await?;
        if let Some(team) = team {
            let team_id = team.id;
            let result = async {
                let maximum = if let Some((actor, session)) = &session {
                    let user_view = ctx.user_view(actor)?;
                    let session_view = ctx.session_view(session).await?;
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
                    .add_team_member(&team_id, &user.id(), maximum)
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
