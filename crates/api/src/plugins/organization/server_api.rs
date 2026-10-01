use super::{OrganizationPlugin, hooks::*, types::RoleInput};
use crate::plugins::endpoint_context::EndpointContext;
use better_auth_core::entity::{AuthSession, AuthUser};
use better_auth_core::{AuthContext, AuthError, AuthRequest, AuthResult, AuthSchema, Member};
mod native;
mod store;
pub use native::OrganizationApi;

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
        let response = OrganizationApi::with_plugin(self.clone(), ctx)
            .with_request(better_auth_core::NativeRequest {
                request,
                headers: request.map(|request| &request.headers),
            })
            .add_member(Some(serde_json::to_value(input)?))
            .await?;
        Ok(serde_json::from_value(response)?)
    }

    async fn add_member_core<S: AuthSchema>(
        &self,
        input: AddMemberInput,
        request: &AuthRequest,
        endpoint: &EndpointContext<'_, S>,
    ) -> AuthResult<Member> {
        let ctx = endpoint.auth;
        let store = store::MemberAdapter::new(endpoint);
        let additional_fields = input.additional_fields.clone();
        let user_id = input
            .user_id
            .json()?
            .filter(better_auth_core::user_fields::is_truthy);
        // Upstream permits a supplied user ID even when session lookup fails.
        let session = match user_id.is_some() {
            true => super::handlers::require_session(request, ctx).await.ok(),
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
            .ok_or(AuthError::Upstream {
                status: 400,
                code: "NO_ACTIVE_ORGANIZATION",
                message: "No active organization",
            })?;
        let team_value = input
            .team_id
            .json()?
            .filter(better_auth_core::user_fields::is_truthy);
        if team_value.is_some() && !self.config.teams.enabled {
            ctx.config.logger.error("Teams are not enabled", &[]);
            return Err(better_auth_core::AuthResponse::json(
                400,
                &serde_json::json!({"message":"Teams are not enabled"}),
            )?
            .into());
        }
        let user = store
            .get_user_by_id_value(&user_id.ok_or(AuthError::Upstream {
                status: 400,
                code: "USER_NOT_FOUND",
                message: "User not found",
            })?)
            .await?
            .ok_or(AuthError::Upstream {
                status: 400,
                code: "USER_NOT_FOUND",
                message: "User not found",
            })?;
        if let Some(email) = user.email()
            && let Some(existing) = store.get_user_by_email(email).await?
            && store
                .get_member_value(&org_value, &serde_json::json!(existing.id()))
                .await?
                .is_some()
        {
            return Err(AuthError::Upstream {
                status: 400,
                code: "USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION",
                message: "User is already a member of this organization",
            });
        }
        let team = if let Some(team_id) = &team_value {
            let team = store
                .get_team_value(team_id)
                .await?
                .ok_or(AuthError::Upstream {
                    status: 400,
                    code: "TEAM_NOT_FOUND",
                    message: "Team not found",
                })?;
            if team.organization_id.json()?.as_ref() != Some(&org_value) {
                return Err(AuthError::Upstream {
                    status: 400,
                    code: "TEAM_NOT_FOUND",
                    message: "Team not found",
                });
            }
            Some(team)
        } else {
            None
        };
        let count = store.count_organization_members(&org_value).await?;
        let organization = store
            .get_organization_by_id_value(&org_value)
            .await?
            .ok_or(AuthError::Upstream {
                status: 400,
                code: "ORGANIZATION_NOT_FOUND",
                message: "Organization not found",
            })?;
        let org_id = organization.id.typed()?.as_str();
        let organization_view =
            crate::plugins::organization::fields::organization(&organization, ctx);
        let user_view = ctx.internal_user_view(&user).await?;
        let event = OrganizationUser {
            user: &user_view,
            organization: &organization_view,
        };
        if count >= self.config.member_limit(event).await? as i64 {
            return Err(AuthError::Upstream {
                status: 403,
                code: "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED",
                message: "Organization membership limit reached",
            });
        }
        let mut data = OrganizationMemberDraft {
            additional_fields,
            organization_id: org_id.to_owned().into(),
            user_id: user.id().into_owned(),
            role: super::input::parse_roles(&input.role)?,
            team_id: team
                .as_ref()
                .map(|team| team.id.typed().cloned())
                .transpose()?,
            created_at: None,
        };
        if let Some(hooks) = &self.config.hooks {
            hooks.before_add_member(&mut data, event).await?;
        }
        let member = store.create_member(data.into_create()).await?;
        if let Some(team) = team {
            let team_id = team.id.typed()?.clone();
            let result = async {
                let maximum = if let Some((actor, session)) = &session {
                    let user_view = ctx.user_view(actor).await?;
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
                    return Err(better_auth_core::AuthResponse::new(401).into());
                } else {
                    self.config.teams.maximum_members_per_team
                };
                let _ = store
                    .add_team_member(&team_id.into(), user.id().typed()?, maximum)
                    .await?
                    .ok_or(AuthError::Upstream {
                        status: 403,
                        code: "TEAM_MEMBER_LIMIT_REACHED",
                        message: "Team member limit reached",
                    })?;
                AuthResult::Ok(())
            }
            .await;
            if let Err(error) = result {
                store
                    .delete_member_for_user(member.id.typed()?, org_id, user.id().typed()?)
                    .await?;
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
