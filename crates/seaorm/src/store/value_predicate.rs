use better_auth_core::{AuthResult, FieldValue, WhereMode, WhereOperator};
use sea_orm::{
    ColumnTrait, Condition, DbBackend,
    sea_query::{BinOper, ExprTrait, Func, SimpleExpr, extension::postgres::PgBinOper},
};

use super::super::record_bindings::{Binding, ParsedBinding};

#[derive(Clone)]
pub(in crate::store) struct QueryPredicate<C> {
    column: C,
    operator: WhereOperator,
    mode: WhereMode,
    value: FieldValue,
    save_as: bool,
}

pub(in crate::store) struct ParsedPredicate<C> {
    column: C,
    operator: WhereOperator,
    insensitive: bool,
    null: bool,
    value: Operand,
    save_as: bool,
}

enum Operand {
    Single(ParsedBinding),
    List(Vec<ParsedBinding>),
}

impl<C: ColumnTrait> QueryPredicate<C> {
    pub(in crate::store) fn new(
        column: C,
        operator: WhereOperator,
        mode: WhereMode,
        value: FieldValue,
    ) -> Self {
        Self {
            column,
            operator,
            mode,
            value,
            save_as: false,
        }
    }

    pub(in crate::store) fn equals(column: C, value: FieldValue) -> Self {
        Self::new(column, WhereOperator::Eq, WhereMode::Sensitive, value).with_save_as()
    }

    pub(in crate::store) fn is_in(column: C, value: FieldValue) -> Self {
        Self::new(column, WhereOperator::In, WhereMode::Sensitive, value).with_save_as()
    }

    pub(in crate::store) fn with_save_as(mut self) -> Self {
        self.save_as = true;
        self
    }

    pub(in crate::store) fn parse(self) -> AuthResult<ParsedPredicate<C>> {
        let insensitive = self.mode == WhereMode::Insensitive
            && match self.operator {
                WhereOperator::In | WhereOperator::NotIn => {
                    self.value.is_string()
                        || match self.value.as_array() {
                            Some(values) => values.every(|value| Ok(value.is_string()))?,
                            None => false,
                        }
                }
                WhereOperator::Eq
                | WhereOperator::Ne
                | WhereOperator::Contains
                | WhereOperator::StartsWith
                | WhereOperator::EndsWith => self.value.is_string(),
                _ => false,
            };
        let lower = |value: FieldValue| match value {
            FieldValue::String(value) if insensitive => FieldValue::String(value.to_lowercase()),
            FieldValue::Utf16String(value) if insensitive => value.to_lowercase().into(),
            value => value,
        };
        let null = self.value.is_null();
        let value = match self.operator {
            WhereOperator::In | WhereOperator::NotIn => {
                let values = match self.value {
                    FieldValue::Array(values) => values.snapshot()?,
                    value => vec![value],
                };
                Operand::List(
                    values
                        .into_iter()
                        .map(lower)
                        .map(|value| Binding::Raw(value).parse_expression())
                        .collect::<AuthResult<_>>()?,
                )
            }
            WhereOperator::Contains | WhereOperator::StartsWith | WhereOperator::EndsWith => {
                let (prefix, suffix) = match self.operator {
                    WhereOperator::Contains => ("%", "%"),
                    WhereOperator::StartsWith => ("", "%"),
                    _ => ("%", ""),
                };
                Operand::Single(
                    Binding::Raw(super::like_value(&self.value, prefix, suffix)?)
                        .parse_expression()?,
                )
            }
            operator => {
                let value = if matches!(operator, WhereOperator::Eq | WhereOperator::Ne) {
                    lower(self.value)
                } else {
                    self.value
                };
                match value {
                    FieldValue::Array(values) => Operand::List(
                        values
                            .iter()?
                            .map(|value| Binding::Raw(value?).parse_expression())
                            .collect::<AuthResult<_>>()?,
                    ),
                    value => Operand::Single(Binding::Raw(value).parse_expression()?),
                }
            }
        };
        Ok(ParsedPredicate {
            column: self.column,
            operator: self.operator,
            insensitive,
            null,
            value,
            save_as: self.save_as,
        })
    }

    pub(in crate::store) fn bind(self, backend: DbBackend) -> AuthResult<SimpleExpr> {
        self.parse()?.encode(backend)
    }
}

impl<C: ColumnTrait> ParsedPredicate<C> {
    pub(in crate::store) fn encode(self, backend: DbBackend) -> AuthResult<SimpleExpr> {
        let column = self.column.into_expr();
        if self.null && matches!(self.operator, WhereOperator::Eq | WhereOperator::Ne) {
            return Ok(if self.operator == WhereOperator::Eq {
                column.is_null()
            } else {
                column.is_not_null()
            });
        }
        let membership = matches!(self.operator, WhereOperator::In | WhereOperator::NotIn);
        let value = match self.value {
            Operand::Single(value) => value.encode(backend)?,
            Operand::List(values) => SimpleExpr::Tuple(
                values
                    .into_iter()
                    .map(|value| {
                        let value = value.encode(backend)?;
                        Ok(if self.save_as && membership {
                            self.column.save_as(value)
                        } else {
                            value
                        })
                    })
                    .collect::<AuthResult<_>>()?,
            ),
        };
        let value = if self.save_as && !membership {
            self.column.save_as(value)
        } else {
            value
        };
        let comparison_column = if self.insensitive && backend == DbBackend::MySql {
            SimpleExpr::cust_with_expr("LOWER(?)", column.clone())
        } else if self.insensitive {
            Func::lower(column.clone()).into()
        } else {
            column.clone()
        };
        Ok(match self.operator {
            WhereOperator::Eq => comparison_column.eq(value),
            WhereOperator::Ne => comparison_column.ne(value),
            WhereOperator::In | WhereOperator::NotIn => {
                let values = match value {
                    SimpleExpr::Tuple(values) => values,
                    value => vec![value],
                };
                super::membership(
                    comparison_column,
                    values,
                    self.operator == WhereOperator::NotIn,
                    backend,
                )
            }
            WhereOperator::Lt => column.lt(value),
            WhereOperator::Lte => column.lte(value),
            WhereOperator::Gt => column.gt(value),
            WhereOperator::Gte => column.gte(value),
            WhereOperator::Contains | WhereOperator::StartsWith | WhereOperator::EndsWith => {
                if self.insensitive && backend == DbBackend::Postgres {
                    column.binary(PgBinOper::ILike, value)
                } else if self.insensitive && backend == DbBackend::MySql {
                    SimpleExpr::cust_with_exprs("LOWER(?) LIKE LOWER(?)", [column, value])
                } else if self.insensitive {
                    Func::lower(column).binary(BinOper::Like, Func::lower(value))
                } else {
                    column.binary(BinOper::Like, value)
                }
            }
        })
    }
}

pub(in crate::store) fn all<C: ColumnTrait>(
    predicates: impl IntoIterator<Item = QueryPredicate<C>>,
    backend: DbBackend,
) -> AuthResult<Condition> {
    // Resolve all field names before this boundary. Driver encoding starts after every expression parses.
    let parsed = predicates
        .into_iter()
        .map(QueryPredicate::parse)
        .collect::<AuthResult<Vec<_>>>()?;
    parsed
        .into_iter()
        .try_fold(Condition::all(), |condition, predicate| {
            Ok(condition.add(predicate.encode(backend)?))
        })
}

#[cfg(test)]
#[path = "value_predicate_tests.rs"]
mod tests;
