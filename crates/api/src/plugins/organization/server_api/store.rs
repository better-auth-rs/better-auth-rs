use super::EndpointContext;
use better_auth_core::FieldValue;
use better_auth_core::{
    AuthResult, AuthSchema, CreateMember, Member, Organization, TeamMember, UserView,
};

pub(super) struct MemberAdapter<'a, 'b, S: AuthSchema>(&'a EndpointContext<'b, S>);

impl<'a, 'b, S: AuthSchema> MemberAdapter<'a, 'b, S> {
    pub(super) fn new(endpoint: &'a EndpointContext<'b, S>) -> Self {
        Self(endpoint)
    }

    pub(super) async fn get_user_by_id_value(
        &self,
        id: &FieldValue,
    ) -> AuthResult<Option<UserView>> {
        match self.0.transaction {
            Some(transaction) => transaction.get_user_by_id_value(id).await,
            None => self.0.auth.database.get_user_by_id_value(id).await,
        }
    }
    pub(super) async fn get_user_by_email_value(
        &self,
        email: &FieldValue,
    ) -> AuthResult<Option<UserView>> {
        let selector = email.lowercase_method("data.email")?;
        match self.0.transaction {
            Some(transaction) => {
                transaction
                    .get_user_by_field_value("email", &selector)
                    .await
            }
            None => {
                self.0
                    .auth
                    .database
                    .get_user_by_field_value("email", &selector)
                    .await
            }
        }
    }
    pub(super) async fn get_member_value(
        &self,
        org: &FieldValue,
        user: &FieldValue,
    ) -> AuthResult<Option<Member>> {
        match self.0.transaction {
            Some(transaction) => transaction.get_member_value(org, user).await,
            None => self.0.auth.database.get_member_value(org, user).await,
        }
    }
    pub(super) async fn get_organization_by_id_value(
        &self,
        id: &FieldValue,
    ) -> AuthResult<Option<Organization>> {
        match self.0.transaction {
            Some(transaction) => transaction.get_organization_by_id_value(id).await,
            None => self.0.auth.database.get_organization_by_id_value(id).await,
        }
    }
    pub(super) async fn get_team_details_value(
        &self,
        id: &FieldValue,
        organization_id: &FieldValue,
    ) -> AuthResult<Option<better_auth_core::store::TeamDetails>> {
        match self.0.transaction {
            Some(transaction) => {
                transaction
                    .get_team_details_value(id, Some(organization_id), false)
                    .await
            }
            None => {
                self.0
                    .auth
                    .database
                    .get_team_details_value(id, Some(organization_id), false)
                    .await
            }
        }
    }
    pub(super) async fn count_organization_members(&self, id: &FieldValue) -> AuthResult<i64> {
        match self.0.transaction {
            Some(transaction) => transaction.count_organization_members_value(id).await,
            None => {
                self.0
                    .auth
                    .database
                    .count_organization_members_value(id)
                    .await
            }
        }
    }
    pub(super) async fn create_member(&self, input: CreateMember) -> AuthResult<Member> {
        match self.0.transaction {
            Some(transaction) => transaction.create_member(input).await,
            None => self.0.auth.database.create_member(input).await,
        }
    }
    pub(super) async fn add_team_member_value(
        &self,
        team: &FieldValue,
        user: &FieldValue,
        maximum: Option<usize>,
    ) -> AuthResult<Option<TeamMember>> {
        match self.0.transaction {
            Some(transaction) => transaction.add_team_member_value(team, user, maximum).await,
            None => {
                self.0
                    .auth
                    .database
                    .add_team_member_value(team, user, maximum)
                    .await
            }
        }
    }
    pub(super) async fn delete_member_for_user_value(
        &self,
        id: &FieldValue,
        organization_id: &FieldValue,
        user_id: &FieldValue,
    ) -> AuthResult<()> {
        match self.0.transaction {
            Some(transaction) => {
                transaction
                    .delete_member_for_user_value(id, organization_id, user_id)
                    .await
            }
            None => {
                self.0
                    .auth
                    .database
                    .delete_member_for_user_value(id, organization_id, user_id)
                    .await
            }
        }
    }
}
