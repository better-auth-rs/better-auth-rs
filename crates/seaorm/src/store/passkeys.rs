use super::id_filter::IdColumn;
use super::instrumentation::database_operation;
use super::plugin_models::Entity;
use crate::SeaOrmPluginModel;
use async_trait::async_trait;
use better_auth_core::{FieldMap, SchemaField};
use chrono::Utc;
use sea_orm::{ColumnTrait, DbBackend, EntityTrait, QueryFilter, QuerySelect};

use better_auth_core::store::{PasskeyStore, schema::EntityRole};
use better_auth_core::{PasskeyCredentialState, PasskeyStorage, UpdatePasskey};

use crate::error::{AuthError, AuthResult};
use crate::schema::AuthSchema;
use crate::types::{CreatePasskey, Passkey, UpdatePasskeyAuthentication};

use super::{SeaOrmStore, map_db_err};

#[async_trait]
impl<S, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema> PasskeyStore
    for SeaOrmStore<S, O, P>
where
    S: AuthSchema + Send + Sync,
{
    fn passkey_storage(&self) -> PasskeyStorage {
        P::Passkey::passkey_storage()
    }

    async fn create_passkey(&self, input: CreatePasskey) -> AuthResult<Passkey> {
        self.create_passkey_with_connection(self.connection(), input)
            .await
    }

    async fn get_passkey_by_id(&self, id: &str) -> AuthResult<Option<Passkey>> {
        let model = database_operation::<Entity<P::Passkey>, _>(self.config(), "findOne", async {
            Entity::<P::Passkey>::find()
                .filter(
                    P::Passkey::column("id")?
                        .eq_id(id, self.config().advanced.database.generate_id())?,
                )
                .one(self.connection())
                .await
                .map_err(map_db_err)
        })
        .await?;
        Ok(self
            .project_passkey_models(model.into_iter().collect())
            .await?
            .pop())
    }

    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> AuthResult<Option<Passkey>> {
        let model = database_operation::<Entity<P::Passkey>, _>(self.config(), "findOne", async {
            Entity::<P::Passkey>::find()
                .filter(P::Passkey::column("credential_id")?.eq(credential_id))
                .one(self.connection())
                .await
                .map_err(map_db_err)
        })
        .await?;
        Ok(self
            .project_passkey_models(model.into_iter().collect())
            .await?
            .pop())
    }

    async fn list_passkeys_by_user(&self, user_id: &str) -> AuthResult<Vec<Passkey>> {
        let models =
            database_operation::<Entity<P::Passkey>, _>(self.config(), "findMany", async {
                Entity::<P::Passkey>::find()
                    .filter(
                        P::Passkey::column("user_id")?
                            .eq_id(user_id, self.config().advanced.database.generate_id())?,
                    )
                    .limit(super::pagination::default_limit(
                        self.config(),
                        self.connection().get_database_backend(),
                    )?)
                    .all(self.connection())
                    .await
                    .map_err(map_db_err)
            })
            .await?;
        self.project_passkey_models(models).await
    }

    async fn update_passkey_authentication(
        &self,
        id: &better_auth_core::SchemaValue<String>,
        update: UpdatePasskeyAuthentication,
    ) -> AuthResult<Passkey> {
        let id = id.typed()?;
        let (counter, fields) = match (P::Passkey::passkey_storage(), update) {
            (PasskeyStorage::Native, UpdatePasskeyAuthentication::Native { counter }) => {
                (counter, FieldMap::new())
            }
            (
                PasskeyStorage::Legacy,
                UpdatePasskeyAuthentication::Legacy {
                    credential,
                    counter,
                    backed_up,
                    device_type,
                },
            ) => (
                counter,
                FieldMap::from_iter([
                    ("backed_up".into(), (backed_up).into_field()),
                    ("device_type".into(), (device_type).into_field()),
                    ("credential".into(), credential.to_owned().into_field()),
                    (
                        "updated_at".into(),
                        better_auth_core::FieldValue::Date((Utc::now()).into()),
                    ),
                ]),
            ),
            _ => {
                return Err(AuthError::config(
                    "Passkey authentication update does not match the model storage mode",
                ));
            }
        };
        let patch = self
            .prepare_passkey_fields(fields, FieldMap::new(), false)
            .await?;
        let model = database_operation::<Entity<P::Passkey>, _>(self.config(), "update", async {
            let Some(_model) = Entity::<P::Passkey>::find()
                .filter(
                    P::Passkey::column("id")?
                        .eq_id(id, self.config().advanced.database.generate_id())?,
                )
                .one(self.connection())
                .await
                .map_err(map_db_err)?
            else {
                return Ok(None);
            };
            let counter = i64::try_from(counter)
                .map_err(|_| AuthError::bad_request("Passkey counter exceeds i64 range"))?;
            let mut active = patch;
            super::plugin_models::set::<P::Passkey>(
                &mut active,
                "counter",
                counter,
                self.config().advanced.database.generate_id(),
            )?;
            let filter = P::Passkey::column("id")?
                .eq_id(id, self.config().advanced.database.generate_id())?;
            super::updates::update_record_returning_one(
                self.connection(),
                active,
                filter.clone(),
                filter,
            )
            .await
        })
        .await?
        .ok_or_else(|| AuthError::not_found("Passkey not found"))?;
        Ok(self.project_passkey_models(vec![model]).await?.remove(0))
    }
    async fn update_passkey(
        &self,
        id: &better_auth_core::SchemaValue<String>,
        update: UpdatePasskey,
    ) -> AuthResult<Passkey> {
        let mut fields = FieldMap::new();
        for (name, value) in [("name", update.name), ("aaguid", update.aaguid)] {
            if !value.is_undefined() {
                let _ = fields.insert(name.into(), value.into_field_value());
            }
        }
        if P::Passkey::passkey_storage() == PasskeyStorage::Legacy {
            let _ = fields.insert(
                "updated_at".into(),
                better_auth_core::FieldValue::Date((Utc::now()).into()),
            );
        }
        let patch = self
            .prepare_passkey_fields(fields, update.additional_fields, false)
            .await?;
        let model = database_operation::<Entity<P::Passkey>, _>(self.config(), "update", async {
            let policy = self.config().advanced.database.generate_id();
            let filter = super::value_filter::equals_id(
                P::Passkey::column("id")?,
                &policy.adapter_id_query(id.field_value())?,
                policy,
                self.connection().get_database_backend(),
            )?;
            let Some(_model) = Entity::<P::Passkey>::find()
                .filter(filter.clone())
                .one(self.connection())
                .await
                .map_err(map_db_err)?
            else {
                return Ok(None);
            };
            let mut active = patch;
            if let Some(counter) = update.counter {
                let counter = i64::try_from(counter)
                    .map_err(|_| AuthError::bad_request("Passkey counter exceeds i64 range"))?;
                super::plugin_models::set::<P::Passkey>(
                    &mut active,
                    "counter",
                    counter,
                    self.config().advanced.database.generate_id(),
                )?;
            }
            super::updates::update_record_returning_one(
                self.connection(),
                active,
                filter.clone(),
                filter,
            )
            .await
        })
        .await?
        .ok_or_else(|| AuthError::not_found("Passkey not found"))?;
        Ok(self.project_passkey_models(vec![model]).await?.remove(0))
    }
    async fn delete_passkey(&self, id: &str) -> AuthResult<()> {
        database_operation::<Entity<P::Passkey>, _>(self.config(), "delete", async {
            Entity::<P::Passkey>::delete_many()
                .filter(
                    P::Passkey::column("id")?
                        .eq_id(id, self.config().advanced.database.generate_id())?,
                )
                .exec(self.connection())
                .await
                .map(|_| ())
                .map_err(map_db_err)
        })
        .await
    }
}

impl<S: AuthSchema, O: crate::SeaOrmOrganizationSchema, P: crate::SeaOrmPluginSchema>
    SeaOrmStore<S, O, P>
{
    pub(super) fn validate_passkey_fields(&self) -> AuthResult<()> {
        let fields = self.model_fields.fields(EntityRole::Passkey);
        let storage = |name: &str| {
            fields.fields().get(name).map(|field| {
                better_auth_core::store::schema::resolve_field_name(
                    field.field_name.as_deref(),
                    name,
                )
                .to_owned()
            })
        };
        let name = storage("name");
        let aaguid = storage("aaguid");
        if let Some(column) = name.filter(|name| Some(name) == aaguid.as_ref()) {
            let column = P::Passkey::column(&column)?;
            if P::Passkey::core_field_name(&column)
                .is_some_and(|name| !matches!(name, "name" | "aaguid"))
            {
                return Err(AuthError::config(
                    "Passkey shared display fields cannot replace an identity or credential column",
                ));
            }
        } else {
            // Missing typed display slots are valid only when both policies resolve one physical column.
            for name in ["name", "aaguid"] {
                let _ = P::Passkey::column(name)?;
            }
            super::plugin_models::validate_field_columns(
                "Passkey schema",
                fields,
                P::Passkey::column,
                P::Passkey::core_field_name,
            )?;
        }
        let mut extras = fields.clone();
        extras
            .fields_mut()
            .retain(|name, _| !matches!(name.as_str(), "name" | "aaguid"));
        super::plugin_models::validate_additional_field_columns::<P::Passkey>(
            EntityRole::Passkey,
            &extras,
        )
    }

    async fn project_passkey_models(&self, models: Vec<P::Passkey>) -> AuthResult<Vec<Passkey>> {
        let fields = self.model_fields.fields(EntityRole::Passkey);
        let records = models
            .iter()
            .map(|model| {
                super::plugin_models::record_fields(
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
            .project_passkey_records(
                rows,
                records,
                super::field_output::capabilities(self.connection().get_database_backend()),
                self.connection().get_database_backend() != DbBackend::Sqlite,
            )
            .await
    }

    async fn prepare_passkey_fields(
        &self,
        mut native: FieldMap,
        mut extras: FieldMap,
        create: bool,
    ) -> AuthResult<super::plugin_models::Write<P::Passkey>> {
        let fields = self.model_fields.fields(EntityRole::Passkey);
        let _ = extras.remove("name");
        let _ = extras.remove("aaguid");
        extras.extend(native.clone());
        let mut active = super::plugin_models::additional_fields::<P::Passkey>(
            fields,
            extras,
            self.config().advanced.database.generate_id(),
            self.connection().get_database_backend(),
            create,
        )
        .await?;
        native.retain(|name, _| !fields.fields().contains_key(name));
        if create {
            native = self.create_fields("passkey", None, native)?;
        }
        super::plugin_models::apply::<P::Passkey>(
            &mut active,
            native,
            self.config().advanced.database.generate_id(),
        )?;
        Ok(active)
    }

    pub(super) async fn create_passkey_with_connection(
        &self,
        connection: &impl sea_orm::ConnectionTrait,
        input: CreatePasskey,
    ) -> AuthResult<Passkey> {
        let counter = i64::try_from(input.counter)
            .map_err(|_| AuthError::bad_request("Passkey counter exceeds i64 range"))?;
        let credential = match (P::Passkey::passkey_storage(), input.credential) {
            (PasskeyStorage::Native, PasskeyCredentialState::Native) => None,
            (PasskeyStorage::Legacy, PasskeyCredentialState::Legacy(value)) => Some(value),
            _ => {
                return Err(AuthError::config(
                    "Passkey creation does not match the model storage mode",
                ));
            }
        };

        let mut fields = FieldMap::from_iter([
            ("public_key".to_owned(), (input.public_key).into_field()),
            ("user_id".to_owned(), (input.user_id).into_field()),
            (
                "credential_id".to_owned(),
                (input.credential_id).into_field(),
            ),
            ("counter".to_owned(), (counter).into_field()),
            ("device_type".to_owned(), (input.device_type).into_field()),
            ("backed_up".to_owned(), (input.backed_up).into_field()),
            ("transports".to_owned(), (input.transports).into_field()),
        ]);
        if let Some(credential) = &credential {
            let _ = fields.insert("credential".into(), credential.to_owned().into_field());
        }
        let _ = fields.insert(
            "created_at".into(),
            better_auth_core::FieldValue::Date((Utc::now()).into()),
        );
        if credential.is_some() {
            let _ = fields.insert(
                "updated_at".into(),
                better_auth_core::FieldValue::Date((Utc::now()).into()),
            );
        }
        for (name, value) in [("name", input.name), ("aaguid", input.aaguid)] {
            if let Some(value) =
                Some(value.into_field_value()).filter(|value| !value.is_undefined())
            {
                let _ = fields.insert(name.into(), value);
            }
        }
        let active = self
            .prepare_passkey_fields(fields, input.additional_fields, true)
            .await?;
        let model = database_operation::<Entity<P::Passkey>, _>(self.config(), "create", async {
            active.insert(connection).await
        })
        .await?;
        Ok(self.project_passkey_models(vec![model]).await?.remove(0))
    }
}
