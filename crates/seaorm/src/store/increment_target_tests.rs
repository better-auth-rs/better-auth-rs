use super::*;
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

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "increment_targets")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub remaining: i32,
        pub enabled: bool,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
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
        let filter = guard();
        let row = increment_returning_raw::<targets::Entity>(
            &db,
            targets::Entity::update_many()
                .col_expr(
                    targets::Column::Remaining,
                    Expr::col(targets::Column::Remaining).sub(1),
                )
                .filter(filter.clone()),
            filter,
            targets::Column::Id.eq(1),
        )
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
    let filter = guard();
    assert!(
        increment_returning_raw::<targets::Entity>(
            &db,
            targets::Entity::update_many()
                .col_expr(
                    targets::Column::Remaining,
                    Expr::col(targets::Column::Remaining).sub(1)
                )
                .filter(filter.clone()),
            filter,
            targets::Column::Id.eq(1),
        )
        .await?
        .is_none()
    );
    Ok(())
}

#[test]
fn target_selection_keeps_all_guards_and_limits_the_locked_row() {
    let target = increment_target::<targets::Entity>(targets::Column::Id, guard());
    let mysql = target
        .clone()
        .lock_exclusive()
        .build(DbBackend::MySql)
        .to_string();
    assert!(
        mysql.starts_with("SELECT `increment_targets`.`id` FROM "),
        "{mysql}"
    );
    assert!(
        mysql.contains("CAST(`increment_targets`.`id` AS integer) = 1"),
        "{mysql}"
    );
    assert!(
        mysql.contains("`increment_targets`.`remaining` > 0"),
        "{mysql}"
    );
    assert!(
        mysql.contains("`increment_targets`.`enabled` = TRUE"),
        "{mysql}"
    );
    assert!(mysql.ends_with("LIMIT 1 FOR UPDATE"), "{mysql}");
}
