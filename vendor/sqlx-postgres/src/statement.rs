use super::{PgColumn, PgTypeInfo};
use crate::column::ColumnIndex;
use crate::error::Error;
use crate::ext::ustr::UStr;
use crate::{PgArguments, Postgres};
use std::borrow::Cow;
use std::sync::Arc;

pub(crate) use sqlx_core::statement::Statement;
use sqlx_core::{Either, HashMap};

#[derive(Debug, Clone)]
pub struct PgStatement<'q> {
    pub(crate) sql: Cow<'q, str>,
    pub(crate) metadata: Arc<PgStatementMetadata>,
}

#[derive(Debug, Default)]
pub(crate) struct PgStatementMetadata {
    pub(crate) columns: Vec<PgColumn>,
    // This `Arc` is not redundant; it's used to avoid deep-copying this map for the `Any` backend.
    // See `sqlx-postgres/src/any.rs`
    pub(crate) column_names: Arc<HashMap<UStr, usize>>,
    pub(crate) parameters: Vec<PgTypeInfo>,
    // Inferred server types cannot distinguish OID 0 from an explicitly requested type.
    pub(crate) requested_parameters: Vec<PgTypeInfo>,
}

impl PgStatementMetadata {
    pub(crate) fn matches_parameters(&self, parameters: &[PgTypeInfo]) -> bool {
        self.requested_parameters.len() == parameters.len()
            && self
                .requested_parameters
                .iter()
                .zip(parameters)
                .all(|(requested, parameter)| requested.type_eq(parameter))
    }
}

impl<'q> Statement<'q> for PgStatement<'q> {
    type Database = Postgres;

    fn to_owned(&self) -> PgStatement<'static> {
        PgStatement::<'static> {
            sql: Cow::Owned(self.sql.clone().into_owned()),
            metadata: self.metadata.clone(),
        }
    }

    fn sql(&self) -> &str {
        &self.sql
    }

    fn parameters(&self) -> Option<Either<&[PgTypeInfo], usize>> {
        Some(Either::Left(&self.metadata.parameters))
    }

    fn columns(&self) -> &[PgColumn] {
        &self.metadata.columns
    }

    impl_statement_query!(PgArguments);
}

impl ColumnIndex<PgStatement<'_>> for &'_ str {
    fn index(&self, statement: &PgStatement<'_>) -> Result<usize, Error> {
        statement
            .metadata
            .column_names
            .get(*self)
            .ok_or_else(|| Error::ColumnNotFound((*self).into()))
            .copied()
    }
}

// #[cfg(feature = "any")]
// impl<'q> From<PgStatement<'q>> for crate::any::AnyStatement<'q> {
//     #[inline]
//     fn from(statement: PgStatement<'q>) -> Self {
//         crate::any::AnyStatement::<'q> {
//             columns: statement
//                 .metadata
//                 .columns
//                 .iter()
//                 .map(|col| col.clone().into())
//                 .collect(),
//             column_names: statement.metadata.column_names.clone(),
//             parameters: Some(Either::Left(
//                 statement
//                     .metadata
//                     .parameters
//                     .iter()
//                     .map(|ty| ty.clone().into())
//                     .collect(),
//             )),
//             sql: statement.sql,
//         }
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Oid;

    #[test]
    fn requested_signature_remains_distinct_from_inferred_parameter_types() {
        let metadata = PgStatementMetadata {
            requested_parameters: vec![PgTypeInfo::with_oid(Oid(0)), PgTypeInfo::INT4],
            parameters: vec![PgTypeInfo::TEXT, PgTypeInfo::INT4],
            ..Default::default()
        };
        assert!(metadata.matches_parameters(&[PgTypeInfo::with_oid(Oid(0)), PgTypeInfo::INT4]));
        assert!(!metadata.matches_parameters(&[PgTypeInfo::TEXT, PgTypeInfo::INT4]));
        assert!(!metadata.matches_parameters(&[PgTypeInfo::with_oid(Oid(0)), PgTypeInfo::INT8]));
        assert!(!metadata.matches_parameters(&[PgTypeInfo::with_oid(Oid(0))]));
    }

    #[test]
    fn unresolved_names_do_not_match_oid_only_cache_signatures() {
        let unspecified = PgTypeInfo::with_oid(Oid(0));
        let named = PgTypeInfo::with_name("custom_type");
        assert_eq!(unspecified, named);
        let metadata = PgStatementMetadata {
            requested_parameters: vec![unspecified],
            ..Default::default()
        };
        assert!(!metadata.matches_parameters(&[named]));
    }

    #[test]
    fn prefix_type_names_do_not_match_requested_signatures() {
        let metadata = PgStatementMetadata {
            requested_parameters: vec![PgTypeInfo::with_name("int")],
            ..Default::default()
        };
        assert!(!metadata.matches_parameters(&[PgTypeInfo::with_name("int8")]));
    }
}
