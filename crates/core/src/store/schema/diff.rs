use serde::Serialize;
use std::{collections::HashSet, fmt};

/// Physical fields written by one configured logical model.
#[derive(Clone, Debug)]
pub struct SchemaTable {
    pub name: String,
    pub schema: Option<String>,
    /// Include the physical primary-key column; custom adapters need not name it `id`.
    pub columns: Vec<String>,
    pub disable_migrations: bool,
}

#[derive(Debug)]
pub struct SchemaColumn {
    pub name: String,
    pub nullable: bool,
    /// Includes generated values, such as a SQLite rowid alias.
    pub has_default: bool,
}

#[derive(Debug)]
pub struct StoredSchemaTable {
    pub name: String,
    pub schema: Option<String>,
    pub columns: Vec<SchemaColumn>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SchemaFinding {
    MissingTable { table: String },
    MissingColumn { table: String, column: String },
    UnexpectedRequiredColumn { table: String, column: String },
}

/// Merge models sharing a physical table before checking whether an insert can omit extra columns.
pub fn diff(expected: &[SchemaTable], actual: &[StoredSchemaTable]) -> Vec<SchemaFinding> {
    let mut merged: Vec<SchemaTable> = Vec::new();
    for table in expected {
        if let Some(existing) = merged
            .iter_mut()
            .find(|entry| entry.name == table.name && entry.schema == table.schema)
        {
            existing.disable_migrations &= table.disable_migrations;
            for name in &table.columns {
                if !existing.columns.contains(name) {
                    existing.columns.push(name.clone());
                }
            }
        } else {
            merged.push(table.clone());
        }
    }
    let mut findings = Vec::new();
    for table in merged.iter().filter(|table| !table.disable_migrations) {
        let Some(stored) = actual.iter().find(|stored| {
            stored.name == table.name && (table.schema.is_none() || stored.schema == table.schema)
        }) else {
            findings.push(SchemaFinding::MissingTable {
                table: table.name.clone(),
            });
            continue;
        };
        for column in &table.columns {
            if !stored.columns.iter().any(|stored| stored.name == *column) {
                findings.push(SchemaFinding::MissingColumn {
                    table: table.name.clone(),
                    column: column.clone(),
                });
            }
        }
        for column in &stored.columns {
            if !table.columns.contains(&column.name) && !column.nullable && !column.has_default {
                findings.push(SchemaFinding::UnexpectedRequiredColumn {
                    table: table.name.clone(),
                    column: column.name.clone(),
                });
            }
        }
    }
    findings
}

#[derive(Debug, Serialize)]
pub struct SchemaMismatch {
    pub code: &'static str,
    pub source: &'static str,
    pub findings: Vec<SchemaFinding>,
}

impl SchemaMismatch {
    pub fn new(findings: Vec<SchemaFinding>) -> Self {
        Self {
            code: "SCHEMA_MISMATCH",
            source: "database",
            findings,
        }
    }
}

impl std::error::Error for SchemaMismatch {}

impl fmt::Display for SchemaMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut tables = Vec::new();
        let mut columns = Vec::new();
        let mut required = Vec::new();
        let mut affected = Vec::new();
        let mut seen = HashSet::new();
        let mut issuer = false;
        for finding in &self.findings {
            match finding {
                SchemaFinding::MissingTable { table } => tables.push(table.as_str()),
                SchemaFinding::MissingColumn { table, column } => {
                    columns.push(format!("{table}.{column}"))
                }
                SchemaFinding::UnexpectedRequiredColumn { table, column } => {
                    required.push(format!("{table}.{column}"));
                    if seen.insert(table) {
                        affected.push(table.as_str());
                    }
                    issuer |= column == "issuer";
                }
            }
        }
        let mut sections = vec!["Database schema mismatch".to_owned()];
        if !tables.is_empty() {
            sections.push(format!("  Missing tables\n    {}", tables.join(", ")));
        }
        if !columns.is_empty() {
            sections.push(format!("  Missing columns\n    {}", columns.join("\n    ")));
        }
        if !required.is_empty() {
            sections.push(format!(
                "  Required columns Better Auth never writes\n    {}",
                required.join("\n    ")
            ));
            sections.push(format!("  Inserts into {} will fail.", affected.join(", ")));
        }
        let mut help = Vec::new();
        if !required.is_empty() {
            help.push("Make the listed columns nullable, give them defaults, or remove them.");
        }
        if !tables.is_empty() || !columns.is_empty() {
            help.push("Run `npx auth migrate` to add the missing tables and columns.");
        }
        if !help.is_empty() {
            sections.push(format!("  help: {}", help.join("\n        ")));
        }
        if issuer {
            sections.push("  note: If this column came from Better Auth 1.7.0 through 1.7.2,\n        follow the upgrade guide before removing it:\n        https://www.better-auth.com/docs/guides/1-7-upgrade-guide".to_owned());
        }
        f.write_str(&sections.join("\n\n"))
    }
}
