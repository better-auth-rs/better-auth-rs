use super::*;
use crate::store::mysql_query::materialize_for_test;
use sea_orm::{
    Database, DbBackend,
    sea_query::{Alias, Expr},
};

#[expect(
    unreachable_pub,
    reason = "SeaORM derives require public fixture entity types"
)]
mod targets {
    use sea_orm::entity::prelude::*;
    use sea_orm::sea_query::{Expr, ExprTrait};

    #[derive(Copy, Clone, Default, Debug, DeriveEntity)]
    pub struct Entity;

    impl EntityName for Entity {
        fn table_name(&self) -> &'static str {
            "increment_targets"
        }
    }

    #[derive(Clone, Debug, PartialEq, DeriveModel, DeriveActiveModel)]
    pub struct Model {
        pub id: String,
        pub remaining: i32,
        pub enabled: bool,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveColumn)]
    pub enum Column {
        Id,
        Remaining,
        Enabled,
    }

    impl ColumnTrait for Column {
        type EntityName = Entity;

        fn def(&self) -> ColumnDef {
            match self {
                Self::Id => ColumnType::Text.def(),
                Self::Remaining => ColumnType::Integer.def(),
                Self::Enabled => ColumnType::Boolean.def(),
            }
        }

        fn into_expr(self) -> Expr {
            let expression = Expr::col(self.as_column_ref());
            match self {
                Self::Id => expression.cast_as("integer"),
                _ => expression,
            }
        }

        fn select_as(&self, expression: Expr) -> Expr {
            match self {
                Self::Id => Expr::col(self.as_column_ref()),
                _ => expression,
            }
        }
    }

    #[derive(Copy, Clone, Debug, EnumIter, DerivePrimaryKey)]
    pub enum PrimaryKey {
        Id,
    }

    impl PrimaryKeyTrait for PrimaryKey {
        type ValueType = String;

        fn auto_increment() -> bool {
            false
        }
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

fn predicates() -> Vec<QueryPredicate<targets::Column>> {
    vec![
        QueryPredicate::equals(targets::Column::Id, 1.0.into()),
        QueryPredicate::new(
            targets::Column::Remaining,
            better_auth_core::WhereOperator::Gt,
            better_auth_core::WhereMode::Sensitive,
            0.0.into(),
        ),
        QueryPredicate::equals(targets::Column::Enabled, true.into()),
    ]
}

fn decrement() -> RecordWrite<targets::Entity> {
    let mut write = RecordWrite::default();
    write.expression(
        targets::Column::Remaining,
        Expr::col(targets::Column::Remaining).sub(1),
    );
    write
}

fn guard() -> SimpleExpr {
    Expr::col((targets::Entity, targets::Column::Id))
        .cast_as(Alias::new("integer"))
        .eq(1)
        .and(targets::Column::Remaining.gt(0))
        .and(targets::Column::Enabled.eq(true))
}

#[tokio::test]
async fn numeric_id_matches_consume_one_quota_at_a_time() -> AuthResult<()> {
    let db = Database::connect("sqlite::memory:")
        .await
        .map_err(map_db_err)?;
    let _ = db.execute_unprepared(
        "CREATE TABLE increment_targets (id TEXT PRIMARY KEY, remaining INTEGER NOT NULL, enabled BOOLEAN NOT NULL);
         INSERT INTO increment_targets VALUES ('1', 1, true), ('01', 1, true), ('001', 1, false);",
    ).await.map_err(map_db_err)?;

    for expected in [1, 0] {
        let row = increment_returning_raw::<targets::Entity>(&db, decrement(), predicates())
            .await?
            .ok_or_else(|| AuthError::internal("Expected one eligible quota record"))?;
        assert_eq!(row.try_get::<i32>("", "remaining").map_err(map_db_err)?, 0);
        let rows = targets::Entity::find().all(&db).await.map_err(map_db_err)?;
        assert_eq!(
            rows.iter()
                .filter(|row| row.enabled)
                .map(|row| row.remaining)
                .sum::<i32>(),
            expected
        );
        assert_eq!(
            rows.iter()
                .find(|row| row.id == "001")
                .map(|row| row.remaining),
            Some(1)
        );
        assert!(rows.iter().all(|row| row.remaining >= 0));
    }
    assert!(
        increment_returning_raw::<targets::Entity>(&db, decrement(), predicates(),)
            .await?
            .is_none()
    );
    Ok(())
}

#[test]
fn target_selection_keeps_all_guards_and_limits_the_locked_row() -> AuthResult<()> {
    let target = increment_target::<targets::Entity>(targets::Column::Id, guard());
    let mysql = target
        .clone()
        .lock_exclusive()
        .compile(DbBackend::MySql)
        .and_then(materialize_for_test)?
        .to_string();
    assert!(
        mysql.starts_with("select `increment_targets`.`id` from "),
        "{mysql}"
    );
    assert!(
        mysql.contains("cast(`increment_targets`.`id` as integer) = 1"),
        "{mysql}"
    );
    assert!(
        mysql.contains("`increment_targets`.`remaining` > 0"),
        "{mysql}"
    );
    assert!(
        mysql.contains("`increment_targets`.`enabled` = true"),
        "{mysql}"
    );
    assert!(mysql.ends_with("limit 1 for update"), "{mysql}");
    Ok(())
}
