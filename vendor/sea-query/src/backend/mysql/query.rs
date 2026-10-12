use super::*;
use crate::extension::mysql::*;

macro_rules! impl_mysql_query_builder {
    ($builder:ty, { $($extra:item)* }) => {
impl QueryBuilder for $builder {
    $($extra)*
    fn values_list_tuple_prefix(&self) -> &str {
        "ROW"
    }

    fn prepare_select_distinct(&self, select_distinct: &SelectDistinct, sql: &mut impl SqlWriter) {
        match select_distinct {
            SelectDistinct::All => self.write_keyword("ALL", sql).unwrap(),
            SelectDistinct::Distinct => self.write_keyword("DISTINCT", sql).unwrap(),
            SelectDistinct::DistinctRow => self.write_keyword("DISTINCTROW", sql).unwrap(),
            _ => {}
        };
    }

    fn prepare_select_into(&self, _: &SelectInto, _: &mut impl SqlWriter) {
        // MySQL doesn't support SELECT INOT table clause (only into variable but that is
        // different).
    }

    fn prepare_index_hints(
        &self,
        table_ref: &TableRef,
        select: &SelectStatement,
        sql: &mut impl SqlWriter,
    ) {
        let Some(hints) = select.index_hints.get(&table_ref.into()) else {
            return;
        };
        sql.write_str(" ").unwrap();

        let mut hints = hints.iter();
        join_io!(
            hints,
            hint,
            join {
                sql.write_str(" ").unwrap();
            },
            do {
                match hint.r#type {
                    IndexHintType::Use => {
                        self.write_keyword("USE INDEX ", sql).unwrap();
                        self.prepare_index_hint_scope(&hint.scope, sql);
                        sql.write_str("(").unwrap();
                        self.prepare_iden(&hint.index, sql);
                    }
                    IndexHintType::Ignore => {
                        self.write_keyword("IGNORE INDEX ", sql).unwrap();
                        self.prepare_index_hint_scope(&hint.scope, sql);
                        sql.write_str("(").unwrap();
                        self.prepare_iden(&hint.index, sql);
                    }
                    IndexHintType::Force => {
                        self.write_keyword("FORCE INDEX ", sql).unwrap();
                        self.prepare_index_hint_scope(&hint.scope, sql);
                        sql.write_str("(").unwrap();
                        self.prepare_iden(&hint.index, sql);
                    }
                }
                sql.write_str(")").unwrap();
            }
        );
    }

    fn prepare_query_statement(&self, query: &SubQueryStatement, sql: &mut impl SqlWriter) {
        query.prepare_statement(self, sql);
    }

    fn prepare_with_clause_recursive_options(&self, _: &WithClause, _: &mut impl SqlWriter) {
        // MySQL doesn't support sql recursive with query 'SEARCH' and 'CYCLE' options.
    }

    fn prepare_with_query_clause_materialization(
        &self,
        _: &CommonTableExpression,
        _: &mut impl SqlWriter,
    ) {
        // MySQL doesn't support declaring materialization in SQL for with query.
    }

    fn prepare_update_join(
        &self,
        from: &[TableRef],
        condition: &ConditionHolder,
        sql: &mut impl SqlWriter,
    ) {
        if from.is_empty() {
            return;
        }

        self.write_keyword(" JOIN ", sql).unwrap();

        // TODO what if we have multiple from?
        self.prepare_table_ref(&from[0], sql);

        self.prepare_condition(condition, "ON", sql);
    }

    fn prepare_update_from(&self, _: &[TableRef], _: &mut impl SqlWriter) {}

    fn prepare_update_column(
        &self,
        table: &Option<Box<TableRef>>,
        from: &[TableRef],
        column: &DynIden,
        sql: &mut impl SqlWriter,
    ) {
        use std::ops::Deref;

        if !from.is_empty() {
            if let Some(table) = table {
                // Support only "naked" table names with no schema or alias.
                if let TableRef::Table(TableName(None, table), None) = table.deref() {
                    let column_name = ColumnName::from((table.clone(), column.clone()));
                    self.prepare_column_ref(&ColumnRef::Column(column_name), sql);
                    return;
                }
            }
        }
        self.prepare_iden(column, sql)
    }

    fn prepare_update_condition(
        &self,
        from: &[TableRef],
        condition: &ConditionHolder,
        sql: &mut impl SqlWriter,
    ) {
        if !from.is_empty() {
            return;
        }
        self.prepare_condition(condition, "WHERE", sql);
    }

    fn prepare_join_type(&self, join_type: &JoinType, sql: &mut impl SqlWriter) {
        match join_type {
            JoinType::FullOuterJoin => panic!("Mysql does not support FULL OUTER JOIN"),
            _ => self.prepare_join_type_common(join_type, sql),
        }
    }

    fn prepare_order_expr(&self, order_expr: &OrderExpr, sql: &mut impl SqlWriter) {
        match order_expr.nulls {
            None => (),
            Some(NullOrdering::Last) => {
                self.prepare_expr(&order_expr.expr, sql);
                self.write_keyword(" IS NULL ASC, ", sql).unwrap()
            }
            Some(NullOrdering::First) => {
                self.prepare_expr(&order_expr.expr, sql);
                self.write_keyword(" IS NULL DESC, ", sql).unwrap()
            }
        }
        if !matches!(order_expr.order, Order::Field(_)) {
            self.prepare_expr(&order_expr.expr, sql);
        }
        self.prepare_order(order_expr, sql);
    }

    fn prepare_value(&self, value: Value, sql: &mut impl SqlWriter) {
        assert!(
            !matches!(value, Value::PostgresUnspecifiedText(_)),
            "PostgresUnspecifiedText requires the PostgreSQL query builder"
        );
        sql.push_param(value, self as _);
    }

    fn prepare_on_conflict_target(&self, _: &OnConflictTarget, _: &mut impl SqlWriter) {
        // MySQL doesn't support declaring ON CONFLICT target.
    }

    fn prepare_on_conflict_action(
        &self,
        on_conflict_action: &Option<OnConflictAction>,
        sql: &mut impl SqlWriter,
    ) {
        match on_conflict_action {
            Some(OnConflictAction::DoNothing(pk_cols)) => {
                if !pk_cols.is_empty() {
                    self.prepare_on_conflict_do_update_keywords(sql);
                    let mut pk_cols_iter = pk_cols.iter();
                    join_io!(
                        pk_cols_iter,
                        pk_col,
                        join {
                            sql.write_str(", ").unwrap();
                        },
                        do {
                            self.prepare_iden(pk_col, sql);
                            sql.write_str(" = ").unwrap();
                            self.prepare_iden(pk_col, sql);
                        }
                    );
                } else {
                    self.write_keyword(" IGNORE", sql).unwrap();
                }
            }
            _ => self.prepare_on_conflict_action_common(on_conflict_action, sql),
        }
    }

    fn prepare_on_conflict_keywords(&self, sql: &mut impl SqlWriter) {
        self.write_keyword(" ON DUPLICATE KEY", sql).unwrap();
    }

    fn prepare_on_conflict_do_update_keywords(&self, sql: &mut impl SqlWriter) {
        self.write_keyword(" UPDATE ", sql).unwrap();
    }

    fn prepare_on_conflict_excluded_table(&self, col: &DynIden, sql: &mut impl SqlWriter) {
        self.write_keyword("VALUES(", sql).unwrap();
        self.prepare_iden(col, sql);
        sql.write_str(")").unwrap();
    }

    fn prepare_on_conflict_condition(&self, _: &ConditionHolder, _: &mut impl SqlWriter) {}

    fn prepare_returning(&self, _returning: &Option<ReturningClause>, _sql: &mut impl SqlWriter) {}

    fn random_function(&self) -> &str {
        "RAND"
    }

    fn lock_phrase(&self, lock_type: LockType) -> &'static str {
        match lock_type {
            LockType::Update => "FOR UPDATE",
            LockType::NoKeyUpdate => "FOR NO KEY UPDATE",
            LockType::Share => "LOCK IN SHARE MODE",
            LockType::KeyShare => "FOR KEY SHARE",
        }
    }

    fn insert_default_keyword(&self) -> &str {
        "()"
    }
}

    };
}

impl_mysql_query_builder!(MysqlQueryBuilder, {});
impl_mysql_query_builder!(KyselyMysqlQueryBuilder, {
    fn prepare_external_parameter(&self, parameter: &ExternalParameter, sql: &mut impl SqlWriter) {
        sql.push_external_parameter(parameter);
    }

    fn prepare_expr(&self, expression: &Expr, sql: &mut impl SqlWriter) {
        // Kysely emits empty IN lists without SeaQuery's boolean rewrite.
        match expression {
            Expr::Binary(left, operator @ (BinOper::In | BinOper::NotIn), right) if matches!(right.as_ref(), Expr::Tuple(values) if values.is_empty()) =>
            {
                self.binary_expr(left, operator, right, sql);
            }
            _ => self.prepare_expr_common(expression, sql),
        }
    }

    fn prepare_constant(&self, value: &Value, sql: &mut impl SqlWriter) {
        if value == &value.as_null() {
            sql.write_str("null").unwrap();
        } else if let Value::Bool(Some(value)) = value {
            sql.write_str(if *value { "true" } else { "false" })
                .unwrap();
        } else {
            self.write_value(sql, value).unwrap();
        }
    }
});

trait MysqlIndexHints: QueryBuilder {
    fn prepare_index_hint_scope(
        &self,
        index_hint_scope: &IndexHintScope,
        sql: &mut impl SqlWriter,
    ) {
        match index_hint_scope {
            IndexHintScope::Join => {
                self.write_keyword("FOR JOIN ", sql).unwrap();
            }
            IndexHintScope::OrderBy => {
                self.write_keyword("FOR ORDER BY ", sql).unwrap();
            }
            IndexHintScope::GroupBy => {
                self.write_keyword("FOR GROUP BY ", sql).unwrap();
            }
            IndexHintScope::All => {}
        }
    }
}

impl MysqlIndexHints for MysqlQueryBuilder {}
impl MysqlIndexHints for KyselyMysqlQueryBuilder {}
