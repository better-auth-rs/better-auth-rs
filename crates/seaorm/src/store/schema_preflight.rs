//! Physical schema validation for the models selected by this store.

mod catalog;
mod mapping;
mod sqlite;

use super::SeaOrmStore;
use crate::{SeaOrmAccountModel, SeaOrmSessionModel, SeaOrmUserModel, SeaOrmVerificationModel};
use async_trait::async_trait;
use better_auth_core::{
    AuthResult, AuthSchema,
    store::schema::{
        SchemaCheck, SchemaConfiguration, SchemaFinding, SchemaInspector, SchemaTable, diff,
    },
};
use sea_orm::{DatabaseConnection, DbBackend};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

#[derive(Clone, Copy)]
enum Catalog {
    Sqlite,
    Postgres,
    Mysql,
}

struct Inspector {
    catalog: Catalog,
    db: DatabaseConnection,
    expected: Vec<SchemaTable>,
    revision: Arc<AtomicU64>,
}

#[async_trait]
impl SchemaInspector for Inspector {
    fn revision(&self) -> u64 {
        self.revision.load(Ordering::Acquire)
    }

    async fn findings(&self) -> AuthResult<Vec<SchemaFinding>> {
        let mut expected = self.expected.clone();
        let actual = match self.catalog {
            Catalog::Sqlite => sqlite::tables(&self.db, &expected).await?,
            Catalog::Postgres => catalog::postgres(&self.db, &mut expected).await?,
            Catalog::Mysql => catalog::mysql(&self.db).await?,
        };
        Ok(diff(&expected, &actual))
    }
}

impl<S, O, P> SeaOrmStore<S, O, P>
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
    S::Session: SeaOrmSessionModel,
    S::Account: SeaOrmAccountModel,
    S::Verification: SeaOrmVerificationModel,
    O: crate::SeaOrmOrganizationSchema,
    P: crate::SeaOrmPluginSchema,
{
    pub(super) fn create_schema_check(
        &self,
        config: &SchemaConfiguration,
    ) -> AuthResult<Option<Arc<SchemaCheck>>> {
        let catalog = match self.db.get_database_backend() {
            DbBackend::Sqlite => Catalog::Sqlite,
            DbBackend::Postgres => Catalog::Postgres,
            DbBackend::MySql => Catalog::Mysql,
            _ => return Ok(None),
        };
        Ok(Some(Arc::new(SchemaCheck::new(Arc::new(Inspector {
            catalog,
            db: self.db.clone(),
            expected: mapping::tables::<S, O, P>(config, &self.organization_fields()?)?,
            revision: self.schema_revision.clone(),
        })))))
    }
}
