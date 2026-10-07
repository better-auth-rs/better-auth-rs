use super::EndpointContext;
use better_auth_core::FieldValue;
use better_auth_core::{
    AuthResult, AuthSchema, CreateMember, Member, Organization, SchemaValue, Team, TeamMember,
    UserView,
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
    pub(super) async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<UserView>> {
        match self.0.transaction {
            Some(transaction) => transaction.get_user_by_email(email).await,
            None => self.0.auth.database.get_user_by_email(email).await,
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
    pub(super) async fn get_team_value(&self, id: &FieldValue) -> AuthResult<Option<Team>> {
        match self.0.transaction {
            Some(transaction) => transaction.get_team_value(id).await,
            None => self.0.auth.database.get_team_value(id).await,
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
    pub(super) async fn add_team_member(
        &self,
        team: &SchemaValue<String>,
        user: &str,
        maximum: Option<usize>,
    ) -> AuthResult<Option<TeamMember>> {
        match self.0.transaction {
            Some(transaction) => transaction.add_team_member(team, user, maximum).await,
            None => {
                self.0
                    .auth
                    .database
                    .add_team_member(team, user, maximum)
                    .await
            }
        }
    }
    pub(super) async fn delete_member_for_user(
        &self,
        id: &str,
        organization_id: &str,
        user_id: &str,
    ) -> AuthResult<()> {
        match self.0.transaction {
            Some(transaction) => {
                transaction
                    .delete_member_for_user(id, organization_id, user_id)
                    .await
            }
            None => {
                self.0
                    .auth
                    .database
                    .delete_member_for_user(id, organization_id, user_id)
                    .await
            }
        }
    }
}
