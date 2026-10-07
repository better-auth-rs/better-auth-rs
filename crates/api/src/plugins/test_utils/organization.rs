use super::{TestUtilsApi, random_lower};
use better_auth_core::{AuthResult, AuthSchema, Member, Organization, SchemaValue};
use chrono::Utc;

/// Direct organization adapter helpers. Organization application hooks do not run.
pub struct TestOrganizationApi<'a, S: AuthSchema> {
    pub(super) api: &'a TestUtilsApi<'a, S>,
}
impl<S: AuthSchema> TestOrganizationApi<'_, S> {
    /// Build a complete organization record without persisting it.
    pub fn create_organization(&self, mut overrides: Organization) -> AuthResult<Organization> {
        let id = self.api.generate_id("organization")?;
        if overrides.id.is_undefined() {
            overrides.id = id.into();
        }
        let name = overrides
            .name
            .as_str()
            .filter(|value| !value.is_empty())
            .unwrap_or("Test Organization");
        let mut slug = String::new();
        let mut previous_space = false;
        for character in name.to_lowercase().chars() {
            let space = super::super::helpers::oauth_scope_whitespace(character);
            if !space {
                slug.push(character);
            } else if !previous_space {
                slug.push('-');
            }
            previous_space = space;
        }
        slug.push('-');
        slug.push_str(&random_lower(4));
        if overrides.name.is_undefined() {
            overrides.name = "Test Organization".to_owned().into();
        }
        if overrides.slug.is_undefined() {
            overrides.slug = slug.into();
        }
        if overrides.logo.is_undefined() {
            overrides.logo = SchemaValue::Typed(None);
        }
        if overrides.metadata.is_undefined() {
            overrides.metadata = SchemaValue::Typed(None);
        }
        if overrides.created_at.is_undefined() {
            overrides.created_at = Utc::now().into();
        }
        Ok(overrides)
    }
    /// Insert the supplied record, including its ID and creation date.
    pub async fn save_organization(&self, organization: Organization) -> AuthResult<Organization> {
        self.api
            .auth
            .database
            .insert_organization(organization)
            .await
    }
    /// Delete members, invitations, and organization sequentially; a later error does not roll back earlier deletes.
    pub async fn delete_organization(&self, id: &str) -> AuthResult<()> {
        self.api.auth.database.delete_organization_records(id).await
    }
    /// Insert a membership directly, bypassing route permission and application-hook checks.
    pub async fn add_member(
        &self,
        organization_id: impl Into<String>,
        user_id: impl Into<String>,
        role: Option<&str>,
    ) -> AuthResult<Member> {
        let member = Member {
            id: self.api.generate_id("member")?.into(),
            organization_id: organization_id.into().into(),
            user_id: user_id.into().into(),
            role: role
                .filter(|value| !value.is_empty())
                .unwrap_or("member")
                .to_owned()
                .into(),
            created_at: Utc::now().into(),
            additional_fields: Default::default(),
        };
        self.api.auth.database.insert_member(member).await
    }
}
