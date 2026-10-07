use super::*;

impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    SeaOrmStore<S, O, P>
{
    pub(in crate::store) fn validate_api_key_fields(&self) -> AuthResult<()> {
        let fields = self.model_fields.fields(EntityRole::ApiKey);
        super::super::plugin_models::validate_field_columns(
            "ApiKey schema",
            fields,
            P::ApiKey::column,
            P::ApiKey::core_field_name,
        )?;
        let mut extras = fields.clone();
        let _ = extras.fields_mut().shift_remove("name");
        super::super::plugin_models::validate_additional_field_columns::<P::ApiKey>(
            EntityRole::ApiKey,
            &extras,
        )
    }

    pub(super) async fn project_api_key_models(
        &self,
        models: Vec<P::ApiKey>,
    ) -> AuthResult<Vec<ApiKey>> {
        let fields = self.model_fields.fields(EntityRole::ApiKey);
        let records = models
            .iter()
            .map(|model| {
                super::super::plugin_models::record_fields(
                    model,
                    fields,
                    self.connection().get_database_backend(),
                )
            })
            .collect::<AuthResult<Vec<_>>>()?;
        let rows = models
            .iter()
            .map(SeaOrmPluginModel::record)
            .collect::<AuthResult<Vec<_>>>()?;
        self.model_fields
            .project_api_key_records(
                rows,
                records,
                super::super::field_output::capabilities(self.connection().get_database_backend()),
                self.connection().get_database_backend() != DbBackend::Sqlite,
            )
            .await
    }

    pub(super) async fn prepare_api_key_fields(
        &self,
        name: Option<better_auth_core::SchemaValue<Option<String>>>,
        mut extras: FieldMap,
        create: bool,
    ) -> AuthResult<super::super::plugin_models::Write<P::ApiKey>> {
        let _ = extras.remove("name");
        if let Some(name) = &name {
            let _ = extras.insert("name".into(), name.field_value());
        }
        let fields = self.model_fields.fields(EntityRole::ApiKey);
        let mut active = super::super::plugin_models::additional_fields::<P::ApiKey>(
            fields,
            extras,
            self.config().advanced.database.generate_id(),
            self.connection().get_database_backend(),
            create,
        )
        .await?;
        if !fields.fields().contains_key("name")
            && let Some(name) = name
        {
            set::<P::ApiKey>(
                &mut active,
                "name",
                name.into_field_value(),
                self.config().advanced.database.generate_id(),
            )?;
        }
        Ok(active)
    }
}
