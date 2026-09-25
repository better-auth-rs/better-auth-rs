use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, QueryOrder, Set,
};
use uuid::Uuid;

use better_auth_core::store::OrganizationStore;

use crate::error::AuthResult;
use crate::schema::AuthSchema;
use crate::types_org::{CreateOrganization, Organization, UpdateOrganization};

use super::entities;
use super::entities::organization::{ActiveModel, Column, Entity};
use super::{SeaOrmStore, map_db_err};

#[async_trait]
impl<S> OrganizationStore for SeaOrmStore<S>
where
    S: AuthSchema + Send + Sync,
{
    async fn create_organization(&self, org: CreateOrganization) -> AuthResult<Organization> {
        let now = Utc::now();
        ActiveModel {
            id: Set(org.id.unwrap_or_else(|| Uuid::new_v4().to_string())),
            name: Set(org.name),
            slug: Set(org.slug),
            logo: Set(org.logo),
            metadata: Set(org.metadata),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(self.connection())
        .await
        .map(|model| Organization::from(&model))
        .map_err(map_db_err)
    }

    async fn get_organization_by_id(&self, id: &str) -> AuthResult<Option<Organization>> {
        Entity::find_by_id(id.to_owned())
            .one(self.connection())
            .await
            .map(|model| model.map(|model| Organization::from(&model)))
            .map_err(map_db_err)
    }

    async fn get_organization_by_slug(&self, slug: &str) -> AuthResult<Option<Organization>> {
        Entity::find()
            .filter(Column::Slug.eq(slug))
            .one(self.connection())
            .await
            .map(|model| model.map(|model| Organization::from(&model)))
            .map_err(map_db_err)
    }

    async fn list_organizations_by_ids(&self, ids: &[String]) -> AuthResult<Vec<Organization>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }

        Entity::find()
            .filter(Column::Id.is_in(ids.iter().cloned()))
            .all(self.connection())
            .await
            .map(|models| models.iter().map(Organization::from).collect())
            .map_err(map_db_err)
    }

    async fn update_organization(
        &self,
        id: &str,
        update: UpdateOrganization,
    ) -> AuthResult<Organization> {
        let Some(model) = Entity::find_by_id(id.to_owned())
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(crate::error::AuthError::not_found("Organization not found"));
        };

        let mut active = model.into_active_model();
        if let Some(name) = update.name {
            active.name = Set(name);
        }
        if let Some(slug) = update.slug {
            active.slug = Set(slug);
        }
        if let Some(logo) = update.logo {
            active.logo = Set(Some(logo));
        }
        if let Some(metadata) = update.metadata {
            active.metadata = Set(Some(metadata));
        }
        active.updated_at = Set(Utc::now());

        active
            .update(self.connection())
            .await
            .map(|model| Organization::from(&model))
            .map_err(map_db_err)
    }

    async fn delete_organization(&self, id: &str) -> AuthResult<()> {
        // Organization-owned API keys reference the organization polymorphically
        // and so have no foreign key to cascade from.
        let _ = entities::api_key::Entity::delete_many()
            .filter(entities::api_key::Column::ReferenceId.eq(id))
            .exec(self.connection())
            .await
            .map_err(map_db_err)?;

        Entity::delete_by_id(id.to_owned())
            .exec(self.connection())
            .await
            .map(|_| ())
            .map_err(map_db_err)
    }

    async fn list_user_organizations(&self, user_id: &str) -> AuthResult<Vec<Organization>> {
        let member_models = entities::member::Entity::find()
            .filter(entities::member::Column::UserId.eq(user_id))
            .all(self.connection())
            .await
            .map_err(map_db_err)?;

        if member_models.is_empty() {
            return Ok(Vec::new());
        }

        let organization_ids: Vec<String> = member_models
            .into_iter()
            .map(|member| member.organization_id)
            .collect();

        Entity::find()
            .filter(Column::Id.is_in(organization_ids))
            .order_by_asc(Column::CreatedAt)
            .all(self.connection())
            .await
            .map(|models| models.iter().map(Organization::from).collect())
            .map_err(map_db_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::store::{MemberStore, UserStore};
    use better_auth_core::{AuthConfig, CreateMember, CreateUser};
    use sea_orm::Database;
    use serde_json::json;

    use crate::store::bundled_schema::BundledSchema;
    use crate::store::migrator::run_migrations;

    #[tokio::test]
    async fn organization_metadata_keeps_key_order_in_sqlite_storage()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect("sqlite::memory:").await?;
        run_migrations(&database).await?;
        let store = SeaOrmStore::<BundledSchema>::new(AuthConfig::default(), database);
        let original = r#"{"z":1,"a":2,"nested":{"y":3,"b":4},"items":[{"z":5,"a":6}]}"#;
        let replacement = r#"{"second":{"z":7,"a":8},"first":[{"y":9,"b":10}]}"#;
        let organization = store
            .create_organization(
                CreateOrganization::new("Ordered metadata", "ordered-metadata")
                    .with_metadata(serde_json::from_str(original)?),
            )
            .await?;

        assert_eq!(
            organization
                .metadata
                .as_ref()
                .map(ToString::to_string)
                .as_deref(),
            Some(original),
        );
        let persisted = Entity::find_by_id(organization.id.clone())
            .one(store.connection())
            .await?
            .ok_or("missing organization row")?;
        assert_eq!(
            persisted
                .metadata
                .as_ref()
                .map(ToString::to_string)
                .as_deref(),
            Some(original),
        );

        for (metadata, expected) in [
            (Some(serde_json::from_str(replacement)?), replacement),
            (None, replacement),
        ] {
            let updated = store
                .update_organization(
                    &organization.id,
                    UpdateOrganization {
                        name: Some("Renamed".to_string()),
                        metadata,
                        ..Default::default()
                    },
                )
                .await?;
            assert_eq!(
                updated
                    .metadata
                    .as_ref()
                    .map(ToString::to_string)
                    .as_deref(),
                Some(expected),
            );
            let loaded = store
                .get_organization_by_id(&organization.id)
                .await?
                .ok_or("missing updated organization")?;
            assert_eq!(
                loaded.metadata.as_ref().map(ToString::to_string).as_deref(),
                Some(expected),
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn organization_metadata_round_trips_through_all_store_reads()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect("sqlite::memory:").await?;
        run_migrations(&database).await?;
        let store = SeaOrmStore::<BundledSchema>::new(AuthConfig::default(), database);
        let user = store
            .create_user(CreateUser::new().with_email("metadata@example.com"))
            .await?;

        // Upstream metadata is optional; absence, an empty object, and a
        // populated object must remain distinct in persistence and conversion.
        for (index, metadata) in [
            None,
            Some(json!({})),
            Some(json!({"tier": "gold", "nested": {"enabled": true}})),
        ]
        .into_iter()
        .enumerate()
        {
            let mut input =
                CreateOrganization::new(format!("Metadata {index}"), format!("metadata-{index}"));
            input.metadata = metadata.clone();
            let organization = store.create_organization(input).await?;
            assert_eq!(organization.metadata, metadata);
            let persisted = Entity::find_by_id(organization.id.clone())
                .one(store.connection())
                .await?
                .ok_or("missing organization row")?;
            assert_eq!(Organization::from(&persisted).metadata, metadata);

            let _ = store
                .create_member(CreateMember {
                    organization_id: organization.id.clone(),
                    user_id: user.id.clone(),
                    role: "owner".to_string(),
                })
                .await?;

            let by_id = store
                .get_organization_by_id(&organization.id)
                .await?
                .ok_or("missing organization by id")?;
            let by_slug = store
                .get_organization_by_slug(&organization.slug)
                .await?
                .ok_or("missing organization by slug")?;
            let by_ids = store
                .list_organizations_by_ids(std::slice::from_ref(&organization.id))
                .await?;
            let by_user = store.list_user_organizations(&user.id).await?;
            assert_eq!(by_id.metadata, metadata);
            assert_eq!(by_slug.metadata, metadata);
            assert_eq!(by_ids.len(), 1);
            assert_eq!(
                by_ids
                    .first()
                    .ok_or("missing organization in id list")?
                    .metadata,
                metadata
            );
            assert_eq!(
                by_user
                    .iter()
                    .find(|org| org.id == organization.id)
                    .ok_or("missing user organization")?
                    .metadata,
                metadata
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn organization_metadata_updates_preserve_omitted_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect("sqlite::memory:").await?;
        run_migrations(&database).await?;
        let store = SeaOrmStore::<BundledSchema>::new(AuthConfig::default(), database);
        let organization = store
            .create_organization(CreateOrganization::new(
                "Metadata".to_string(),
                "metadata".to_string(),
            ))
            .await?;

        let renamed = store
            .update_organization(
                &organization.id,
                UpdateOrganization {
                    name: Some("Renamed".to_string()),
                    ..Default::default()
                },
            )
            .await?;
        assert_eq!(renamed.metadata, None);

        for metadata in [json!({"tier": "gold"}), json!({})] {
            let updated = store
                .update_organization(
                    &organization.id,
                    UpdateOrganization {
                        metadata: Some(metadata.clone()),
                        ..Default::default()
                    },
                )
                .await?;
            assert_eq!(updated.metadata, Some(metadata.clone()));

            let renamed = store
                .update_organization(
                    &organization.id,
                    UpdateOrganization {
                        name: Some("Renamed again".to_string()),
                        ..Default::default()
                    },
                )
                .await?;
            assert_eq!(renamed.metadata, Some(metadata.clone()));
            let persisted = store
                .get_organization_by_id(&organization.id)
                .await?
                .ok_or("missing updated organization")?;
            assert_eq!(persisted.metadata, Some(metadata));
        }

        Ok(())
    }
}
