use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

mod generate;
mod schema_config;

#[derive(Parser)]
#[command(name = "better-auth-rs", about = "CLI tools for better-auth-rs")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate SeaORM entities and an initial database creation scaffold.
    ///
    /// Use application-owned versioned migrations to upgrade an existing database.
    Generate {
        /// Write output to a new file instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Replace an existing output file.
        #[arg(long, requires = "output")]
        force: bool,

        /// Include plugin fields and tables. Use "all" for every supported plugin.
        #[arg(short, long, value_delimiter = ',', value_parser = parse_plugin)]
        plugins: Vec<String>,

        /// Read Organization table, column, and additional field definitions from JSON.
        #[arg(long)]
        schema_config: Option<PathBuf>,
    },
}

fn parse_plugin(value: &str) -> Result<String, String> {
    let plugins = generate::list_plugins();
    if value == "all" || plugins.contains(&value) {
        Ok(value.to_owned())
    } else {
        Err(format!(
            "unknown plugin `{value}`; available: {}, all",
            plugins.join(", ")
        ))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Cli {
        command:
            Command::Generate {
                output,
                force,
                mut plugins,
                schema_config,
            },
    } = Cli::parse();
    if plugins.iter().any(|plugin| plugin == "all") {
        plugins = generate::list_plugins()
            .into_iter()
            .map(String::from)
            .collect();
    }
    plugins.sort();
    plugins.dedup();
    let config = if let Some(path) = schema_config {
        let bytes = fs::read(&path).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("cannot read {}: {error}", path.display()),
            )
        })?;
        serde_json::from_slice(&bytes).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid schema config {}: {error}", path.display()),
            )
        })?
    } else {
        schema_config::SchemaConfig::default()
    };
    let schema = generate::generate_schema(&plugins, &config)?;
    if let Some(path) = output {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create(force)
            .truncate(force)
            .create_new(!force)
            .open(&path)
            .map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!(
                        "cannot write {}: {error}; use --force to replace an existing file",
                        path.display()
                    ),
                )
            })?;
        file.write_all(schema.as_bytes())?;
        eprintln!("wrote initial auth schema to {}", path.display());
    } else {
        print!("{schema}");
    }
    Ok(())
}
