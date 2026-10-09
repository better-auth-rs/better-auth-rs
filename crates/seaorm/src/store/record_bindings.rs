//! Preserve runtime values until the selected SQL driver encodes each parameter.

use better_auth_core::{AuthError, AuthResult, FieldDate, FieldValue};
use chrono::Datelike;
use sea_orm::{
    ColumnTrait, DbBackend,
    sea_query::{SimpleExpr, Value},
};

#[derive(Clone)]
pub(super) enum Binding {
    Native(Value),
    Raw(FieldValue),
    Date(FieldDate),
    Json(FieldValue),
}

impl Binding {
    pub(super) fn is_null(&self) -> bool {
        match self {
            Self::Native(value) => *value == value.as_null(),
            Self::Raw(value) | Self::Json(value) => value.is_null(),
            // An invalid Date encodes as SQL NULL but remains a non-null source value.
            Self::Date(_) => false,
        }
    }

    pub(super) fn for_column(column: impl ColumnTrait, value: FieldValue) -> Self {
        if matches!(
            column.def().get_column_type(),
            sea_orm::ColumnType::Json | sea_orm::ColumnType::JsonBinary
        ) && !matches!(
            value,
            FieldValue::Undefined
                | FieldValue::Null
                | FieldValue::String(_)
                | FieldValue::Utf16String(_)
        ) {
            Self::Json(value)
        } else {
            // Preserve SQL NULL and JSON text that the declared field policy has already encoded.
            Self::Raw(value)
        }
    }

    pub(super) fn bind(self, backend: DbBackend) -> AuthResult<SimpleExpr> {
        self.parse_expression()?.encode(backend)
    }

    fn parse_expression(self) -> AuthResult<Self> {
        if let Self::Raw(value) | Self::Json(value) = &self {
            parse_expression(value)?;
        }
        Ok(self)
    }

    fn encode(self, backend: DbBackend) -> AuthResult<SimpleExpr> {
        match self {
            Self::Native(value) => native_parameter(value, backend),
            Self::Json(value) if backend == DbBackend::Postgres => driver_parameter(value, backend),
            Self::Json(value) => {
                native_parameter(Value::Json(value.json()?.map(Box::new)), backend)
            }
            Self::Raw(value) => driver_parameter(value, backend),
            Self::Date(date) => {
                let value = if backend == DbBackend::Sqlite {
                    sqlite_date(date)?
                } else {
                    FieldValue::Date(date)
                };
                driver_parameter(value, backend)
            }
        }
    }
}

pub(super) fn bind(backend: DbBackend, values: Vec<Binding>) -> AuthResult<Vec<SimpleExpr>> {
    // Kysely parses every expression before the driver encodes any parameter.
    values
        .into_iter()
        .map(Binding::parse_expression)
        .collect::<AuthResult<Vec<_>>>()?
        .into_iter()
        .map(|value| value.encode(backend))
        .collect()
}

pub(super) fn parameter(value: FieldValue, backend: DbBackend) -> AuthResult<SimpleExpr> {
    parse_expression(&value)?;
    driver_parameter(value, backend)
}

fn parse_expression(value: &FieldValue) -> AuthResult<()> {
    let FieldValue::Function(function) = value else {
        return Ok(());
    };
    // Ordinary factory results are values, not Kysely operation-node sources.
    let message = match function.call()? {
        FieldValue::Undefined => {
            "undefined is not an object (evaluating 'exp(expressionBuilder()).toOperationNode')"
        }
        FieldValue::Null => {
            "null is not an object (evaluating 'exp(expressionBuilder()).toOperationNode')"
        }
        _ => {
            "exp(expressionBuilder()).toOperationNode is not a function. (In 'exp(expressionBuilder()).toOperationNode()', 'exp(expressionBuilder()).toOperationNode' is undefined)"
        }
    };
    Err(AuthError::internal(message))
}

fn native_parameter(value: Value, backend: DbBackend) -> AuthResult<SimpleExpr> {
    if backend != DbBackend::Sqlite {
        return Ok(SimpleExpr::Value(value));
    }
    let text = match value {
        Value::String(Some(value)) => value,
        Value::Char(Some(value)) => value.to_string(),
        Value::Json(Some(value)) => value.to_string(),
        value => return Ok(SimpleExpr::Value(value)),
    };
    driver_parameter(text.into(), backend)
}

fn driver_parameter(value: FieldValue, backend: DbBackend) -> AuthResult<SimpleExpr> {
    if backend == DbBackend::Postgres {
        // pg sends OID-unspecified text parameters. A quoted unknown literal preserves column inference.
        return Ok(SimpleExpr::Constant(Value::String(postgres_parameter(
            &value,
        )?)));
    }
    let value = match value {
        FieldValue::Undefined | FieldValue::Null => Value::String(None),
        FieldValue::Bool(value) if backend == DbBackend::Sqlite => {
            Value::BigInt(Some(i64::from(value)))
        }
        FieldValue::Bool(value) => Value::Bool(Some(value)),
        FieldValue::String(value)
            if backend == DbBackend::Sqlite
                && (value.starts_with('\u{feff}')
                    || value
                        .chars()
                        .any(|unit| matches!(unit, '\u{fffe}' | '\u{ffff}'))) =>
        {
            return Ok(sqlite_text_parameter(&value.into()));
        }
        FieldValue::String(value) => Value::String(Some(value)),
        FieldValue::Utf16String(value) if backend == DbBackend::Sqlite => {
            return Ok(sqlite_text_parameter(&value));
        }
        FieldValue::Utf16String(value) => Value::String(Some(utf16_string(&value, backend))),
        FieldValue::Array(values) if backend == DbBackend::MySql => {
            let parameters = values
                .iter()
                .cloned()
                .map(|value| {
                    if let FieldValue::Array(nested) = value {
                        nested
                            .iter()
                            .cloned()
                            .map(|value| driver_parameter(value, backend))
                            .collect::<AuthResult<Vec<_>>>()
                            .map(SimpleExpr::Tuple)
                    } else {
                        driver_parameter(value, backend)
                    }
                })
                .collect::<AuthResult<Vec<_>>>()?;
            return Ok(SimpleExpr::cust_with_exprs(
                vec!["?"; parameters.len()].join(", "),
                parameters,
            ));
        }
        FieldValue::Number(value) if backend == DbBackend::MySql => {
            // mysql2 emits numeric literals; DOUBLE parameters change MySQL's integer rounding.
            return Ok(SimpleExpr::Custom(
                better_auth_core::schema_value::number_string(value).into(),
            ));
        }
        FieldValue::Number(value) => {
            crate::reference_id::binding(Value::Double(Some(value)), backend)?
        }
        FieldValue::Date(date) if backend == DbBackend::MySql => {
            // sql-escaper converts an invalid Date to SQL NULL without changing the comparison operator.
            Value::String(date.to_datetime()?.map(|date| {
                date.with_timezone(&chrono::Local)
                    .format("%Y-%m-%d %H:%M:%S%.3f")
                    .to_string()
            }))
        }
        FieldValue::Date(_) | FieldValue::Array(_) | FieldValue::Object(_)
            if backend == DbBackend::Sqlite =>
        {
            return Err(AuthError::internal(
                "Binding expected string, TypedArray, boolean, number, bigint or null",
            ));
        }
        value => Value::String(Some(utf16_string(&value.display_utf16()?, backend))),
    };
    Ok(SimpleExpr::Value(value))
}

fn postgres_parameter(value: &FieldValue) -> AuthResult<Option<String>> {
    Ok(match value {
        FieldValue::Undefined | FieldValue::Null => None,
        FieldValue::String(value) => Some(value.clone()),
        FieldValue::Utf16String(value) => Some(utf16_string(value, DbBackend::Postgres)),
        FieldValue::Date(date) => Some(postgres_date(date)?),
        FieldValue::Array(values) => {
            let mut text = String::from("{");
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    text.push(',');
                }
                if matches!(value, FieldValue::Array(_)) {
                    text.push_str(&postgres_parameter(value)?.ok_or_else(|| {
                        AuthError::internal("PostgreSQL array encoding lost a nested array")
                    })?);
                } else if let Some(value) = postgres_parameter(value)? {
                    text.push('"');
                    text.push_str(&value.replace('\\', "\\\\").replace('"', "\\\""));
                    text.push('"');
                } else {
                    text.push_str("NULL");
                }
            }
            text.push('}');
            Some(text)
        }
        FieldValue::Object(_) => value.stringify()?,
        value => Some(utf16_string(&value.display_utf16()?, DbBackend::Postgres)),
    })
}

fn postgres_date(date: &FieldDate) -> AuthResult<String> {
    let Some(date) = date.to_datetime()? else {
        // pg 8 dateToString pads the invalid Date getters, then lets PostgreSQL reject the parameter.
        let nan = better_auth_core::schema_value::number_string(date.milliseconds());
        return Ok(format!(
            "{nan:0>4}-{nan:0>2}-{nan:0>2}T{nan:0>2}:{nan:0>2}:{nan:0>2}.{nan:0>3}+{nan:0>2}:{nan:0>2}"
        ));
    };
    let local = date.with_timezone(&chrono::Local);
    let year = local.year();
    let year = if year < 1 { 1 - year } else { year };
    Ok(format!(
        "{year:04}{}{}",
        local.format("-%m-%dT%H:%M:%S%.3f%:z"),
        if local.year() < 1 { " BC" } else { "" }
    ))
}

fn sqlite_utf16_units(value: &better_auth_core::Utf16String) -> Vec<u16> {
    let (units, swap) = match value.as_utf16() {
        [0xfeff, rest @ ..] => (rest, false),
        [0xfffe, rest @ ..] => (rest, true),
        units => (units, false),
    };
    // sqlite3_bind_text16 consumes one BOM and uses its byte order for the remaining units.
    units
        .iter()
        .map(|unit| if swap { unit.swap_bytes() } else { *unit })
        .collect()
}

fn sqlite_utf8_bytes(units: &[u16]) -> Vec<u8> {
    let mut input = units.iter().copied();
    let mut paired = Vec::with_capacity(units.len());
    while let Some(unit) = input.next() {
        // SQLite combines any surrogate with the next unit only when converting UTF-16 to UTF-8.
        if (0xd800..0xe000).contains(&unit)
            && let Some(next) = input.next()
        {
            paired.extend([0xd800 | (unit & 0x3ff), 0xdc00 | (next & 0x3ff)]);
        } else {
            paired.push(unit);
        }
    }
    better_auth_core::Utf16String::from_units(paired).to_wtf8()
}

fn sqlite_text_parameter(value: &better_auth_core::Utf16String) -> SimpleExpr {
    let units = sqlite_utf16_units(value);
    let bytes = [
        sqlite_utf8_bytes(&units),
        units.iter().flat_map(|unit| unit.to_le_bytes()).collect(),
        units.iter().flat_map(|unit| unit.to_be_bytes()).collect(),
    ];
    // Concatenation tags BLOB bytes with the database encoding without adding CAST's TEXT affinity.
    // SQLite 3.46 interprets bound BLOBs as UTF-8 during CAST, even in a UTF-16 database.
    SimpleExpr::cust_with_exprs(
        "(CASE (SELECT encoding FROM pragma_encoding) \
         WHEN 'UTF-8' THEN ? WHEN 'UTF-16le' THEN ? WHEN 'UTF-16be' THEN ? END || X'')",
        bytes.map(|bytes| SimpleExpr::Value(Value::Bytes(Some(bytes)))),
    )
}

pub(super) fn utf16_string(value: &better_auth_core::Utf16String, backend: DbBackend) -> String {
    match backend {
        DbBackend::Sqlite => {
            String::from_utf8_lossy(&sqlite_utf8_bytes(&sqlite_utf16_units(value))).into_owned()
        }
        _ => String::from_utf16_lossy(value.as_utf16()),
    }
}

pub(crate) fn sqlite_date(date: FieldDate) -> AuthResult<FieldValue> {
    let value = date
        .to_datetime()?
        .ok_or_else(|| AuthError::internal("Invalid Date"))?;
    Ok(FieldValue::String(
        value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    ))
}

#[cfg(test)]
#[path = "record_function_tests.rs"]
mod function_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::sea_query::{MysqlQueryBuilder, Query};

    #[test]
    fn sqlite_utf16_binding_retains_the_driver_surrogate_pairing() {
        for (units, expected) in [
            (vec![0xd800, 0x40], "\u{10040}"),
            (vec![0xdc00, 0x41], "\u{10041}"),
            (vec![0xd83d, 0xde00], "\u{1f600}"),
            (vec![0xdfff, 0xffff], "\u{10ffff}"),
            (vec![0xd800, 0xd800, 0x40], "\u{10000}@"),
            (vec![0xd800], "\u{fffd}\u{fffd}\u{fffd}"),
            (vec![0xdc00], "\u{fffd}\u{fffd}\u{fffd}"),
            (vec![0x61, 0, 0x62], "a\0b"),
            (vec![0xfeff], ""),
            (vec![0xfffe], ""),
            (vec![0xfeff, 0x41], "A"),
            (vec![0xfffe, 0x4100], "A"),
            (vec![0xfffe, 0x41], "\u{4100}"),
            (vec![0xfeff, 0xd800, 0x40], "\u{10040}"),
            (vec![0x41, 0xfeff], "A\u{feff}"),
            (vec![0xfeff, 0xfffe], "\u{fffe}"),
        ] {
            let value = better_auth_core::Utf16String::from_units(units);
            assert_eq!(utf16_string(&value, DbBackend::Sqlite), expected);
            for backend in [DbBackend::MySql, DbBackend::Postgres] {
                assert_eq!(
                    utf16_string(&value, backend),
                    String::from_utf16_lossy(value.as_utf16())
                );
            }
        }
    }

    #[tokio::test]
    async fn sqlite_parameters_preserve_bom_conversion_for_both_string_representations()
    -> AuthResult<()> {
        use sea_orm::{ConnectionTrait, Database, sea_query::Alias};

        let database = Database::connect("sqlite::memory:")
            .await
            .map_err(crate::store::map_db_err)?;
        for (input, expected, hex) in [
            ("\u{feff}", "", ""),
            ("\u{feff}A", "A", "41"),
            ("\u{fffe}\u{4100}", "A", "41"),
            ("\u{fffe}A", "\u{4100}", "E48480"),
            ("A\u{feff}", "A\u{feff}", "41EFBBBF"),
            ("\u{feff}\u{fffe}", "\u{fffe}", "EFBFBE"),
        ] {
            for value in [
                FieldValue::from(input),
                FieldValue::Utf16String(input.into()),
            ] {
                let expression = parameter(value, DbBackend::Sqlite)?;
                let query = Query::select()
                    .expr_as(expression.clone(), Alias::new("value"))
                    .expr_as(
                        SimpleExpr::cust_with_exprs("hex(?)", [expression]),
                        Alias::new("hex"),
                    )
                    .to_owned();
                let row = database
                    .query_one_raw(DbBackend::Sqlite.build(&query))
                    .await
                    .map_err(crate::store::map_db_err)?
                    .ok_or_else(|| {
                        AuthError::internal("SQLite parameter observation is missing")
                    })?;
                assert_eq!(
                    super::super::plugin_rows::value(&row, "value")?,
                    expected.into()
                );
                assert_eq!(
                    row.try_get::<String>("", "hex")
                        .map_err(crate::store::map_db_err)?,
                    hex
                );
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_text_output_decodes_invalid_utf8_after_preserving_storage_bytes()
    -> AuthResult<()> {
        use sea_orm::{ConnectionTrait, Database, Statement};

        let database = Database::connect("sqlite::memory:")
            .await
            .map_err(crate::store::map_db_err)?;
        let _ = database
            .execute_unprepared("CREATE TABLE observations (value TEXT)")
            .await
            .map_err(crate::store::map_db_err)?;
        for (hex, expected) in [
            ("EDA080", "\u{fffd}\u{fffd}\u{fffd}"),
            ("EDB080", "\u{fffd}\u{fffd}\u{fffd}"),
            ("F09F98", "\u{fffd}"),
            ("EFBFBD", "\u{fffd}"),
            ("610062", "a\0b"),
        ] {
            let _ = database
                .execute_unprepared("DELETE FROM observations")
                .await
                .map_err(crate::store::map_db_err)?;
            let _ = database
                .execute_unprepared(&format!(
                    "INSERT INTO observations VALUES (CAST(X'{hex}' AS TEXT))"
                ))
                .await
                .map_err(crate::store::map_db_err)?;
            let row = database
                .query_one_raw(Statement::from_string(
                    DbBackend::Sqlite,
                    "SELECT value, hex(value) AS bytes FROM observations",
                ))
                .await
                .map_err(crate::store::map_db_err)?
                .ok_or_else(|| AuthError::internal("SQLite stored-text observation is missing"))?;
            assert_eq!(
                super::super::plugin_rows::value(&row, "value")?,
                expected.into()
            );
            assert_eq!(
                row.try_get::<String>("", "bytes")
                    .map_err(crate::store::map_db_err)?,
                hex
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_text_parameters_preserve_storage_and_comparisons_in_each_encoding()
    -> AuthResult<()> {
        use sea_orm::{ConnectOptions, ConnectionTrait, Database, sea_query::Alias};

        let cases: &[(&[u16], &str, [&str; 3])] = &[
            (&[], "", ["", "", ""]),
            (
                &[0xd800, 0x40],
                "\u{10040}",
                ["F0908180", "00D84000", "D8000040"],
            ),
            (
                &[0xdc00, 0x41],
                "\u{10041}",
                ["F0908181", "00DC4100", "DC000041"],
            ),
            (
                &[0xd83d, 0xde00],
                "\u{1f600}",
                ["F09F9880", "3DD800DE", "D83DDE00"],
            ),
            (
                &[0xdfff, 0xffff],
                "\u{10ffff}",
                ["F48FBFBF", "FFDFFFFF", "DFFFFFFF"],
            ),
            (
                &[0xd800, 0xd800, 0x40],
                "\u{10000}@",
                ["F090808040", "00D800D84000", "D800D8000040"],
            ),
            (
                &[0xd800],
                "\u{fffd}\u{fffd}\u{fffd}",
                ["EDA080", "00D8", "D800"],
            ),
            (
                &[0xdc00],
                "\u{fffd}\u{fffd}\u{fffd}",
                ["EDB080", "00DC", "DC00"],
            ),
            (
                &[0x61, 0, 0x62],
                "a\0b",
                ["610062", "610000006200", "006100000062"],
            ),
            (&[0xfeff], "", ["", "", ""]),
            (&[0xfffe], "", ["", "", ""]),
            (&[0xfeff, 0x41], "A", ["41", "4100", "0041"]),
            (&[0xfffe, 0x4100], "A", ["41", "4100", "0041"]),
            (&[0xfffe, 0x41], "\u{4100}", ["E48480", "0041", "4100"]),
            (
                &[0xfeff, 0xd800, 0x40],
                "\u{10040}",
                ["F0908180", "00D84000", "D8000040"],
            ),
            (
                &[0x41, 0xfeff],
                "A\u{feff}",
                ["41EFBBBF", "4100FFFE", "0041FEFF"],
            ),
            (&[0xfeff, 0xfffe], "\u{fffe}", ["EFBFBE", "FEFF", "FFFE"]),
            (
                &[0x41, 0xfffe],
                "A\u{fffe}",
                ["41EFBFBE", "4100FEFF", "0041FFFE"],
            ),
            (
                &[0x41, 0xfffe, 0x42],
                "A\u{fffe}B",
                ["41EFBFBE42", "4100FEFF4200", "0041FFFE0042"],
            ),
            (&[0xffff], "\u{ffff}", ["EFBFBF", "FFFF", "FFFF"]),
            (
                &[0x41, 0xffff],
                "A\u{ffff}",
                ["41EFBFBF", "4100FFFF", "0041FFFF"],
            ),
            (
                &[0x41, 0xffff, 0x42],
                "A\u{ffff}B",
                ["41EFBFBF42", "4100FFFF4200", "0041FFFF0042"],
            ),
            (
                &[0x22, 0x41, 0xffff, 0x42, 0x22],
                "\"A\u{ffff}B\"",
                [
                    "2241EFBFBF4222",
                    "22004100FFFF42002200",
                    "00220041FFFF00420022",
                ],
            ),
            (
                &[0xfffe, 0x00d8],
                "\u{fffd}\u{fffd}\u{fffd}",
                ["EDA080", "00D8", "D800"],
            ),
        ];
        for (encoding_index, encoding) in ["UTF-8", "UTF-16le", "UTF-16be"].into_iter().enumerate()
        {
            let mut options = ConnectOptions::new("sqlite::memory:");
            let _ = options.max_connections(1);
            let database = Database::connect(options)
                .await
                .map_err(crate::store::map_db_err)?;
            let _ = database
                .execute_unprepared(&format!("PRAGMA encoding = '{encoding}'"))
                .await
                .map_err(crate::store::map_db_err)?;
            let _ = database
                .execute_unprepared("CREATE TABLE observations (value TEXT)")
                .await
                .map_err(crate::store::map_db_err)?;
            for (units, expected, bytes) in cases {
                let bytes = bytes
                    .get(encoding_index)
                    .ok_or_else(|| AuthError::internal("SQLite fixture encoding is missing"))?;
                let input = better_auth_core::Utf16String::from_units(units.to_vec());
                let mut representations = vec![FieldValue::Utf16String(input.clone())];
                if let Ok(text) = input.to_utf8() {
                    representations.push(FieldValue::String(text));
                }
                for input in representations {
                    sqlite_write_and_read(
                        &database,
                        Binding::Raw(input.clone()),
                        &input,
                        expected,
                        bytes,
                    )
                    .await?;
                    if let FieldValue::String(text) = &input {
                        sqlite_write_and_read(
                            &database,
                            Binding::Native(Value::String(Some(text.clone()))),
                            &input,
                            expected,
                            bytes,
                        )
                        .await?;
                    }
                }
            }
            for binding in [
                Binding::Json(FieldValue::from("A\u{ffff}B")),
                Binding::Native(Value::Json(Some(Box::new(serde_json::json!("A\u{ffff}B"))))),
            ] {
                sqlite_write_and_read(
                    &database,
                    binding,
                    &FieldValue::from("\"A\u{ffff}B\""),
                    "\"A\u{ffff}B\"",
                    [
                        "2241EFBFBF4222",
                        "22004100FFFF42002200",
                        "00220041FFFF00420022",
                    ]
                    .get(encoding_index)
                    .ok_or_else(|| {
                        AuthError::internal("SQLite JSON fixture encoding is missing")
                    })?,
                )
                .await?;
            }
            sqlite_write_and_read(
                &database,
                Binding::Native(Value::Char(Some('\u{ffff}'))),
                &FieldValue::from("\u{ffff}"),
                "\u{ffff}",
                ["EFBFBF", "FFFF", "FFFF"]
                    .get(encoding_index)
                    .ok_or_else(|| {
                        AuthError::internal("SQLite character fixture encoding is missing")
                    })?,
            )
            .await?;
            let _ = database
                .execute_unprepared(
                    "CREATE TABLE affinities (untyped, numeric_value NUMERIC, text_value TEXT)",
                )
                .await
                .map_err(crate::store::map_db_err)?;
            let _ = database
                .execute_unprepared("INSERT INTO affinities VALUES (7, 7, '7')")
                .await
                .map_err(crate::store::map_db_err)?;
            for input in [
                FieldValue::from("\u{feff}7"),
                FieldValue::Utf16String("\u{feff}7".into()),
            ] {
                let expression = parameter(input, DbBackend::Sqlite)?;
                let mut query = Query::select();
                let _ = query.from(Alias::new("affinities"));
                for (name, sql) in [
                    ("untyped", "untyped = ?"),
                    ("numeric_value", "numeric_value = ?"),
                    ("text_value", "text_value = ?"),
                    ("literal_number", "7 = ?"),
                    ("literal_text", "'7' = ?"),
                ] {
                    let _ = query.expr_as(
                        SimpleExpr::cust_with_exprs(sql, [expression.clone()]),
                        Alias::new(name),
                    );
                }
                let row = database
                    .query_one_raw(DbBackend::Sqlite.build(&query))
                    .await
                    .map_err(crate::store::map_db_err)?
                    .ok_or_else(|| AuthError::internal("SQLite affinity observation is missing"))?;
                for (name, expected) in [
                    ("untyped", 0),
                    ("numeric_value", 1),
                    ("text_value", 1),
                    ("literal_number", 0),
                    ("literal_text", 1),
                ] {
                    assert_eq!(
                        row.try_get::<i64>("", name)
                            .map_err(crate::store::map_db_err)?,
                        expected,
                        "{encoding}: {name}"
                    );
                }
            }
        }
        Ok(())
    }

    async fn sqlite_write_and_read(
        database: &sea_orm::DatabaseConnection,
        binding: Binding,
        input: &FieldValue,
        expected: &str,
        bytes: &str,
    ) -> AuthResult<()> {
        use sea_orm::{ConnectionTrait, sea_query::Alias};

        let _ = database
            .execute_unprepared("DELETE FROM observations")
            .await
            .map_err(crate::store::map_db_err)?;
        let query = Query::insert()
            .into_table(Alias::new("observations"))
            .columns([Alias::new("value")])
            .values_panic([binding.clone().bind(DbBackend::Sqlite)?])
            .to_owned();
        let inserted = database
            .execute_raw(DbBackend::Sqlite.build(&query))
            .await
            .map_err(crate::store::map_db_err)?;
        assert_eq!(inserted.rows_affected(), 1);
        sqlite_stored_text(database, input, expected, bytes).await?;
        for (previous, next) in [
            (input.clone(), Binding::Raw(FieldValue::from("sentinel"))),
            (FieldValue::from("sentinel"), binding),
        ] {
            let query = Query::update()
                .table(Alias::new("observations"))
                .value(Alias::new("value"), next.bind(DbBackend::Sqlite)?)
                .and_where(SimpleExpr::cust_with_exprs(
                    "value = ?",
                    [parameter(previous, DbBackend::Sqlite)?],
                ))
                .to_owned();
            let updated = database
                .execute_raw(DbBackend::Sqlite.build(&query))
                .await
                .map_err(crate::store::map_db_err)?;
            assert_eq!(updated.rows_affected(), 1);
        }
        sqlite_stored_text(database, input, expected, bytes).await
    }

    async fn sqlite_stored_text(
        database: &sea_orm::DatabaseConnection,
        input: &FieldValue,
        expected: &str,
        bytes: &str,
    ) -> AuthResult<()> {
        use sea_orm::{ConnectionTrait, sea_query::Alias};

        let query = Query::select()
            .column(Alias::new("value"))
            .expr_as(
                SimpleExpr::Custom("typeof(value)".into()),
                Alias::new("storage_type"),
            )
            .expr_as(
                SimpleExpr::Custom("hex(CAST(value AS BLOB))".into()),
                Alias::new("bytes"),
            )
            .from(Alias::new("observations"))
            .and_where(SimpleExpr::cust_with_exprs(
                "value = ?",
                [parameter(input.clone(), DbBackend::Sqlite)?],
            ))
            .to_owned();
        let row = database
            .query_one_raw(DbBackend::Sqlite.build(&query))
            .await
            .map_err(crate::store::map_db_err)?
            .ok_or_else(|| {
                AuthError::internal("SQLite stored parameter did not match its source")
            })?;
        assert_eq!(
            super::super::plugin_rows::value(&row, "value")?,
            expected.into()
        );
        assert_eq!(
            row.try_get::<String>("", "storage_type")
                .map_err(crate::store::map_db_err)?,
            "text"
        );
        assert_eq!(
            row.try_get::<String>("", "bytes")
                .map_err(crate::store::map_db_err)?,
            bytes
        );
        Ok(())
    }

    #[test]
    fn mysql_numbers_keep_literal_types_while_strings_remain_bound() -> AuthResult<()> {
        for (number, literal) in [
            (1.5, "1.5"),
            (2.5, "2.5"),
            (-2.5, "-2.5"),
            (-0.0, "0"),
            (1e-6, "0.000001"),
            (1e-7, "1e-7"),
            (1e20, "100000000000000000000"),
            (1e21, "1e+21"),
            (f64::NAN, "NaN"),
            (f64::INFINITY, "Infinity"),
            (f64::NEG_INFINITY, "-Infinity"),
        ] {
            let (sql, parameters) = Query::select()
                .expr(parameter(number.into(), DbBackend::MySql)?)
                .build(MysqlQueryBuilder);
            assert_eq!(sql, format!("SELECT {literal}"));
            assert!(parameters.0.is_empty());
        }
        for text in ["2.5", "NaN", "2.5); DROP TABLE users; --"] {
            let (sql, parameters) = Query::select()
                .expr(parameter(text.into(), DbBackend::MySql)?)
                .build(MysqlQueryBuilder);
            assert_eq!(sql, "SELECT ?");
            assert_eq!(parameters.0, vec![Value::String(Some(text.into()))]);
        }
        Ok(())
    }
}
