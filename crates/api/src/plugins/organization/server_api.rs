use super::{OrganizationPlugin, hooks::*, types::RoleInput};
use crate::plugins::endpoint_context::EndpointContext;
use better_auth_core::entity::{AuthRecordFields, AuthUser};
use better_auth_core::{
    AuthContext, AuthError, AuthRequest, AuthResult, AuthSchema, FieldMap, FieldValue,
    FromFieldMap, Member,
};
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
    #[serde(with = "better_auth_core::field_value::serde::map")]
    pub additional_fields: better_auth_core::FieldMap,
    #[serde(
        default,
        skip_serializing_if = "better_auth_core::SchemaValue::is_json_omitted"
    )]
    pub user_id: better_auth_core::SchemaValue<String>,
    #[serde(
        default,
        skip_serializing_if = "better_auth_core::SchemaValue::is_json_omitted"
    )]
    pub organization_id: better_auth_core::SchemaValue<String>,
    #[serde(
        default,
        skip_serializing_if = "better_auth_core::SchemaValue::is_json_omitted"
    )]
    pub role: better_auth_core::SchemaValue<RoleInput>,
    #[serde(
        default,
        skip_serializing_if = "better_auth_core::SchemaValue::is_json_omitted"
    )]
    pub team_id: better_auth_core::SchemaValue<String>,
}

super::request::from_fields!(AddMemberInput {
    user_id: "userId", organization_id: "organizationId", role: "role", team_id: "teamId",
}; additional_fields);

impl AddMemberInput {
    fn into_field_values(self) -> FieldMap {
        let mut fields = self.additional_fields;
        for (name, value) in [
            ("userId", self.user_id.field_value()),
            ("organizationId", self.organization_id.field_value()),
            ("role", self.role.field_value()),
            ("teamId", self.team_id.field_value()),
        ] {
            if !value.is_undefined() {
                let _ = fields.insert(name.into(), value);
            }
        }
        fields
    }
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
            .add_member_value(input.into_field_values().into())
            .await?;
        match response {
            FieldValue::Object(fields) => Member::from_field_values(fields.snapshot_fields()?),
            _ => Err(AuthError::internal(
                "Native addMember did not return a member object",
            )),
        }
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
        let user_id = input.user_id.field_value();
        let user_id = user_id.is_truthy().then_some(user_id);
        // Upstream permits a supplied user ID even when session lookup fails.
        let session = match user_id.is_some() {
            true => super::handlers::require_native_session(request, ctx)
                .await
                .ok(),
            _ => None,
        };
        let org_value = input.organization_id.field_value();
        let org_value = org_value
            .is_truthy()
            .then_some(org_value)
            .or_else(|| {
                session
                    .as_ref()
                    .map(|session| session.session.active_organization_id.field_value())
                    .filter(FieldValue::is_truthy)
            })
            .ok_or(AuthError::Upstream {
                status: 400,
                code: "NO_ACTIVE_ORGANIZATION",
                message: "No active organization",
            })?;
        let team_value = input.team_id.field_value();
        let team_value = team_value.is_truthy().then_some(team_value);
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
        if let Some(existing) = store
            .get_user_by_email(&crate::plugins::helpers::user_email(&user)?)
            .await?
            && store
                .get_member_value(&org_value, &existing.id().field_value())
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
            if !team.organization_id.field_value().strict_equals(&org_value) {
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
        let org_id = organization.id.field_value();
        let organization_view =
            crate::plugins::organization::fields::organization(&organization, ctx);
        let user_value = FieldValue::from(user.field_values()?);
        let event = OrganizationUser {
            user: &user_value,
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
            organization_id: organization.id.clone(),
            user_id: user.id().into_owned(),
            role: super::input::parse_roles(&input.role)?,
            team_id: team
                .as_ref()
                .map(|team| team.id.clone())
                .unwrap_or_default(),
            created_at: None,
        };
        if let Some(hooks) = &self.config.hooks {
            hooks.before_add_member(&mut data, event).await?;
        }
        let member = store.create_member(data.into_create()).await?;
        if let Some(team) = team {
            let team_id = team.id.field_value();
            let result = async {
                let maximum = if let Some(session) = &session {
                    self.config
                        .team_member_limit(OrganizationTeamMemberLimit {
                            team_id: &team_id,
                            organization_id: &org_id,
                            session: OrganizationSession {
                                user: &session.user,
                                session: &session.session,
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
                    .add_team_member_value(&team_id, &user.id().field_value(), maximum)
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
                    .delete_member_for_user_value(
                        &member.id.field_value(),
                        &org_id,
                        &user.id().field_value(),
                    )
                    .await?;
                return Err(error);
            }
        }
        if let Some(hooks) = &self.config.hooks {
            hooks
                .after_add_member(OrganizationMemberEvent {
                    member: &member,
                    user: &user_value,
                    organization: &organization_view,
                })
                .await?;
        }
        Ok(member)
    }
}
