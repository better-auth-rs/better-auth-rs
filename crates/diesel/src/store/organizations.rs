use async_trait::async_trait;
use better_auth_core::store::OrganizationStore;
use better_auth_core::{CreateOrganization, Organization, UpdateOrganization};
use chrono::Utc;
use diesel::prelude::*;
use diesel_async::{AsyncConnection, RunQueryDsl};

use crate::error::{AuthError, AuthResult};
use crate::models::{OrganizationChanges, OrganizationRow};
use crate::schema::{api_keys, member, organization};
use crate::sql_types::{JsonDocumentValue, UtcTimestampValue};

use super::{DieselStore, new_id};

#[async_trait]
impl OrganizationStore for DieselStore {
    async fn create_organization(&self, org: CreateOrganization) -> AuthResult<Organization> {
        let now = Utc::now();
        let row = OrganizationRow {
            id: org.id.unwrap_or_else(new_id),
            name: org.name,
            slug: org.slug,
            logo: org.logo,
            metadata: org.metadata.unwrap_or_else(|| serde_json::json!({})),
            created_at: now,
            updated_at: now,
        };

        run_query!(self, |c| {
            diesel::insert_into(organization::table)
                .values(row)
                .returning(OrganizationRow::as_returning())
                .get_result(c)
                .await
        })
        .map(Organization::from)
    }

    async fn get_organization_by_id(&self, id: &str) -> AuthResult<Option<Organization>> {
        run_query!(self, |c| {
            organization::table
                .find(id)
                .select(OrganizationRow::as_select())
                .first(c)
                .await
                .optional()
        })
        .map(|row| row.map(Organization::from))
    }

    async fn get_organization_by_slug(&self, slug: &str) -> AuthResult<Option<Organization>> {
        run_query!(self, |c| {
            organization::table
                .filter(organization::slug.eq(slug))
                .select(OrganizationRow::as_select())
                .first(c)
                .await
                .optional()
        })
        .map(|row| row.map(Organization::from))
    }

    async fn list_organizations_by_ids(&self, ids: &[String]) -> AuthResult<Vec<Organization>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }

        run_query!(self, |c| {
            organization::table
                .filter(organization::id.eq_any(ids))
                .select(OrganizationRow::as_select())
                .load(c)
                .await
        })
        .map(|rows| rows.into_iter().map(Organization::from).collect())
    }

    async fn update_organization(
        &self,
        id: &str,
        update: UpdateOrganization,
    ) -> AuthResult<Organization> {
        let changes = OrganizationChanges {
            name: update.name,
            slug: update.slug,
            logo: update.logo,
            metadata: update.metadata.map(JsonDocumentValue),
            updated_at: Some(UtcTimestampValue(Utc::now())),
        };

        run_query!(self, |c| {
            diesel::update(organization::table.find(id))
                .set(changes)
                .returning(OrganizationRow::as_returning())
                .get_result(c)
                .await
                .optional()
        })?
        .map(Organization::from)
        .ok_or_else(|| AuthError::not_found("Organization not found"))
    }

    async fn delete_organization(&self, id: &str) -> AuthResult<()> {
        // One transaction, so that an organization that cannot be deleted
        // keeps its keys.
        let _ = run_query!(self, |c| {
            c.transaction(async |c| {
                // Organization-owned API keys reference the organization
                // polymorphically and so have no foreign key to cascade from.
                let _ = diesel::delete(api_keys::table.filter(api_keys::reference_id.eq(id)))
                    .execute(c)
                    .await?;
                diesel::delete(organization::table.find(id))
                    .execute(c)
                    .await
            })
            .await
        })?;
        Ok(())
    }

    async fn list_user_organizations(&self, user_id: &str) -> AuthResult<Vec<Organization>> {
        run_query!(self, |c| {
            organization::table
                .filter(
                    organization::id.eq_any(
                        member::table
                            .filter(member::user_id.eq(user_id))
                            .select(member::organization_id),
                    ),
                )
                .order(organization::created_at.asc())
                .select(OrganizationRow::as_select())
                .load(c)
                .await
        })
        .map(|rows| rows.into_iter().map(Organization::from).collect())
    }
}
