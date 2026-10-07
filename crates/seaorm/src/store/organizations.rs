use super::id_filter::IdColumn;
use super::{
    SeaOrmStore, map_db_err,
    organization_models::{self as models, Entity, values},
};
use crate::schema::AuthSchema;
use crate::types_org::{CreateOrganization, Organization, UpdateOrganization};
use crate::{SeaOrmOrganizationModel, SeaOrmOrganizationSchema};
use async_trait::async_trait;
use better_auth_core::{
    AuthError, AuthResult, organization_fields::OrganizationFields, store::OrganizationStore,
};
use better_auth_core::{FieldValue, SchemaField};
use chrono::Utc;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QuerySelect, TransactionTrait};

impl<S: AuthSchema, O: SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    SeaOrmStore<S, O, P>
{
    pub(super) fn set_organization_fields(&self, fields: OrganizationFields) -> AuthResult<()> {
        models::validate_fields::<O::Organization>("organization", &fields.organization)?;
        models::validate_fields::<O::Member>("member", &fields.member)?;
        models::validate_fields::<O::Invitation>("invitation", &fields.invitation)?;
        models::validate_fields::<O::Team>("team", &fields.team)?;
        models::validate_fields::<O::OrganizationRole>(
            "organizationRole",
            &fields.organization_role,
        )?;
        *self
            .organization_fields
            .write()
            .map_err(|error| AuthError::internal(error.to_string()))? = fields;
        Ok(())
    }
}

#[async_trait]
impl<S: AuthSchema, O: SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> OrganizationStore
    for SeaOrmStore<S, O, P>
where
    S::User: crate::SeaOrmUserModel,
{
    async fn get_organization_details(
        &self,
        query: better_auth_core::store::OrganizationDetailsQuery<'_>,
    ) -> AuthResult<Option<better_auth_core::store::OrganizationDetails>> {
        self.read_organization_details(query).await
    }

    async fn insert_organization(&self, record: Organization) -> AuthResult<Organization> {
        let config = self.organization_fields()?.organization;
        let core = self.create_fields(
            "organization",
            if record.id.is_undefined() {
                None
            } else {
                Some(record.id.typed()?.clone())
            },
            values([
                ("name", record.name.into_field_value()),
                ("slug", record.slug.into_field_value()),
                ("logo", record.logo.into_field_value()),
                ("metadata", record.metadata.into_field_value()),
                ("created_at", record.created_at.into_field_value()),
                ("auth_updated_at", FieldValue::Date((Utc::now()).into())),
            ]),
        )?;
        models::active::<O::Organization>(
            core,
            record.additional_fields,
            &config,
            true,
            self.connection().get_database_backend(),
            self.config().advanced.database.generate_id(),
        )
        .await?
        .insert(self.connection())
        .await?
        .record(&config, self.connection().get_database_backend())
        .await
    }
    async fn delete_organization_records(&self, id: &str) -> AuthResult<()> {
        let _ = Entity::<O::Member>::delete_many()
            .filter(
                O::Member::column("organization_id")?
                    .eq_id(id, self.config().advanced.database.generate_id())?,
            )
            .exec(self.connection())
            .await
            .map_err(map_db_err)?;
        let _ = Entity::<O::Invitation>::delete_many()
            .filter(
                O::Invitation::column("organization_id")?
                    .eq_id(id, self.config().advanced.database.generate_id())?,
            )
            .exec(self.connection())
            .await
            .map_err(map_db_err)?;
        let _ = Entity::<O::Organization>::delete_many()
            .filter(
                O::Organization::column("id")?
                    .eq_id(id, self.config().advanced.database.generate_id())?,
            )
            .exec(self.connection())
            .await
            .map_err(map_db_err)?;
        Ok(())
    }

    fn configure_organization_fields(&self, fields: OrganizationFields) -> AuthResult<()> {
        self.set_organization_fields(fields.into_storage())
    }

    async fn create_organization(&self, org: CreateOrganization) -> AuthResult<Organization> {
        let config = self.organization_fields()?.organization;
        let now = Utc::now();
        let mut core = self.create_fields(
            "organization",
            org.id,
            values([
                ("created_at", FieldValue::Date((now).into())),
                ("auth_updated_at", FieldValue::Date((now).into())),
            ]),
        )?;
        for (name, value) in [
            (
                "name",
                Some(org.name.field_value()).filter(|value| !value.is_undefined()),
            ),
            (
                "slug",
                Some(org.slug.field_value()).filter(|value| !value.is_undefined()),
            ),
            (
                "logo",
                Some(org.logo.field_value()).filter(|value| !value.is_undefined()),
            ),
        ] {
            if let Some(value) = value {
                let _ = core.insert(name.into(), value);
            }
        }
        if let Some(value) = better_auth_core::organization_fields::metadata_input(
            Some(org.metadata.field_value()).filter(|value| !value.is_undefined()),
            true,
        )? {
            let _ = core.insert("metadata".into(), value);
        }
        let active = models::active::<O::Organization>(
            core,
            org.additional_fields,
            &config,
            true,
            self.connection().get_database_backend(),
            self.config().advanced.database.generate_id(),
        )
        .await?;
        active
            .insert(self.connection())
            .await?
            .record(&config, self.connection().get_database_backend())
            .await
    }

    async fn get_organization_by_id(&self, id: &str) -> AuthResult<Option<Organization>> {
        let config = self.organization_fields()?.organization;
        let row = models::find::<O::Organization, _>(
            self.connection(),
            id,
            self.config().advanced.database.generate_id(),
        )
        .await?;
        match row {
            Some(row) => row
                .record(&config, self.connection().get_database_backend())
                .await
                .map(Some),
            None => Ok(None),
        }
    }

    async fn get_organization_by_id_value(
        &self,
        id: &FieldValue,
    ) -> AuthResult<Option<Organization>> {
        self.get_organization_by_id_value_with_connection(self.connection(), id)
            .await
    }

    async fn get_organization_by_slug(&self, slug: &str) -> AuthResult<Option<Organization>> {
        self.get_organization_by_slug_value(&(slug).to_owned().into_field())
            .await
    }

    async fn get_organization_by_slug_value(
        &self,
        slug: &FieldValue,
    ) -> AuthResult<Option<Organization>> {
        let config = self.organization_fields()?.organization;
        let column = O::Organization::column("slug")?;
        let filter =
            super::value_filter::equals(column, slug, self.connection().get_database_backend())?;
        let row = Entity::<O::Organization>::find()
            .filter(filter)
            .one(self.connection())
            .await
            .map_err(map_db_err)?;
        match row {
            Some(row) => row
                .record(&config, self.connection().get_database_backend())
                .await
                .map(Some),
            None => Ok(None),
        }
    }

    async fn list_organizations_by_ids(&self, ids: &[String]) -> AuthResult<Vec<Organization>> {
        let config = self.organization_fields()?.organization;
        models::project::<O::Organization>(
            Entity::<O::Organization>::find()
                .filter(O::Organization::column("id")?.is_in_ids(
                    ids.iter().cloned(),
                    self.config().advanced.database.generate_id(),
                )?)
                .all(self.connection())
                .await
                .map_err(map_db_err)?,
            &config,
            self.connection().get_database_backend(),
        )
        .await
    }

    async fn update_organization(
        &self,
        id: &str,
        update: UpdateOrganization,
    ) -> AuthResult<Organization> {
        let config = self.organization_fields()?.organization;
        let mut core = values([("auth_updated_at", FieldValue::Date((Utc::now()).into()))]);
        for (name, value) in [
            ("id", update.id.as_ref().map(|v| v.to_owned().into_field())),
            ("name", update.name.map(|v| v.to_owned().into_field())),
            ("slug", update.slug.map(|v| v.to_owned().into_field())),
            ("logo", update.logo.map(|v| v.to_owned().into_field())),
            (
                "created_at",
                update.created_at.map(|v| v.to_owned().into_field()),
            ),
        ] {
            if let Some(value) = value {
                let _ = core.insert(name.into(), value);
            }
        }
        if let Some(value) =
            better_auth_core::organization_fields::metadata_input(update.metadata, false)?
        {
            let _ = core.insert("metadata".into(), value);
        }
        let active = models::active::<O::Organization>(
            core,
            update.additional_fields,
            &config,
            false,
            self.connection().get_database_backend(),
            self.config().advanced.database.generate_id(),
        )
        .await?;
        let _ = active
            .update(self.connection().get_database_backend())?
            .filter(
                O::Organization::column("id")?
                    .eq_id(id, self.config().advanced.database.generate_id())?,
            )
            .exec(self.connection())
            .await
            .map_err(map_db_err)?;
        self.get_organization_by_id(update.id.as_deref().unwrap_or(id))
            .await?
            .ok_or_else(|| AuthError::not_found("Organization not found"))
    }

    async fn delete_organization(&self, id: &str) -> AuthResult<()> {
        let tx = self.connection().begin().await.map_err(map_db_err)?;
        let _ = Entity::<O::Member>::delete_many()
            .filter(
                O::Member::column("organization_id")?
                    .eq_id(id, self.config().advanced.database.generate_id())?,
            )
            .exec(&tx)
            .await
            .map_err(map_db_err)?;
        let _ = Entity::<O::Invitation>::delete_many()
            .filter(
                O::Invitation::column("organization_id")?
                    .eq_id(id, self.config().advanced.database.generate_id())?,
            )
            .exec(&tx)
            .await
            .map_err(map_db_err)?;
        let _ = Entity::<O::Organization>::delete_many()
            .filter(
                O::Organization::column("id")?
                    .eq_id(id, self.config().advanced.database.generate_id())?,
            )
            .exec(&tx)
            .await
            .map_err(map_db_err)?;
        tx.commit().await.map_err(map_db_err)
    }

    async fn list_user_organizations(&self, user_id: &str) -> AuthResult<Vec<Organization>> {
        if self.config().advanced.database.joins == Some(true) {
            return self.joined_user_organizations(user_id).await;
        }
        let config = self.organization_fields()?;
        let rows = Entity::<O::Member>::find()
            .filter(
                O::Member::column("user_id")?
                    .eq_id(user_id, self.config().advanced.database.generate_id())?,
            )
            .limit(super::pagination::default_limit(
                self.config(),
                self.connection().get_database_backend(),
            )?)
            .all(self.connection())
            .await
            .map_err(map_db_err)?;
        let organizations = models::project_then::<O::Member, _, _>(
            &rows,
            &config.member,
            self.connection().get_database_backend(),
            |index, _| {
                let rows = &rows;
                let config = &config;
                async move {
                    let member = rows.get(index).ok_or_else(|| {
                        better_auth_core::AuthError::internal(
                            "Member projection lost its stored join index",
                        )
                    })?;
                    let row = Entity::<O::Organization>::find()
                        .filter(
                            O::Organization::column("id")?
                                .eq(models::join_value(member, "organization_id")?),
                        )
                        .one(self.connection())
                        .await
                        .map_err(map_db_err)?;
                    match row {
                        Some(row) => row
                            .record(
                                &config.organization,
                                self.connection().get_database_backend(),
                            )
                            .await
                            .map(Some),
                        None => Ok(None),
                    }
                }
            },
        )
        .await?;
        Ok(organizations.into_iter().flatten().collect())
    }
}

impl<
    S: better_auth_core::AuthSchema,
    O: crate::SeaOrmOrganizationSchema,
    P: crate::SeaOrmPluginSchema,
> SeaOrmStore<S, O, P>
{
    pub(super) async fn get_organization_by_id_value_with_connection<
        C: sea_orm::ConnectionTrait,
    >(
        &self,
        db: &C,
        id: &FieldValue,
    ) -> AuthResult<Option<Organization>> {
        let row = Entity::<O::Organization>::find()
            .filter(super::value_filter::equals_id(
                O::Organization::column("id")?,
                id,
                self.config().advanced.database.generate_id(),
                self.connection().get_database_backend(),
            )?)
            .one(db)
            .await
            .map_err(map_db_err)?;
        match row {
            Some(row) => row
                .record(
                    &self.organization_fields()?.organization,
                    db.get_database_backend(),
                )
                .await
                .map(Some),
            None => Ok(None),
        }
    }
}
