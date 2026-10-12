//! Opt-in query spelling for the pinned Kysely MySQL compiler.

use super::*;

/// Compile query ASTs with Kysely's keyword spelling and literal escaping.
///
/// Identifiers, aliases, raw SQL, and explicit AST grouping remain unchanged.
/// Use a mysql2-compatible formatter for bound values before text execution.
#[derive(Default, Debug)]
pub struct KyselyMysqlQueryBuilder;

impl QuotedBuilder for KyselyMysqlQueryBuilder {
    fn quote(&self) -> Quote {
        QUOTE
    }

    fn write_keyword(&self, keyword: &str, sql: &mut impl Write) -> std::fmt::Result {
        for character in keyword.chars() {
            sql.write_char(character.to_ascii_lowercase())?;
        }
        Ok(())
    }

    fn prepare_iden(&self, iden: &DynIden, sql: &mut impl SqlWriter) {
        sql.write_char('`').unwrap();
        for character in iden.0.chars() {
            if character == '`' {
                sql.write_char('`').unwrap();
            }
            sql.write_char(character).unwrap();
        }
        sql.write_char('`').unwrap();
    }
}

impl EscapeBuilder for KyselyMysqlQueryBuilder {
    fn write_escaped(&self, buffer: &mut impl Write, string: &str) {
        for character in string.chars() {
            match character {
                '\\' => buffer.write_str("\\\\"),
                '\'' => buffer.write_str("''"),
                _ => buffer.write_char(character),
            }
            .unwrap();
        }
    }
}

impl TableRefBuilder for KyselyMysqlQueryBuilder {}

impl PrecedenceDecider for KyselyMysqlQueryBuilder {
    fn inner_expr_well_known_greater_precedence(&self, inner: &Expr, outer: &Oper) -> bool {
        common_inner_expr_well_known_greater_precedence(inner, outer)
    }
}

impl OperLeftAssocDecider for KyselyMysqlQueryBuilder {
    fn well_known_left_associative(&self, operator: &BinOper) -> bool {
        common_well_known_left_associative(operator)
    }
}

#[cfg(all(test, feature = "with-json"))]
mod tests;
