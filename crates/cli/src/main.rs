use std::fs;
use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};

mod generate;

#[derive(Parser)]
#[command(name = "better-auth-rs", about = "CLI tools for better-auth-rs")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate the auth schema file with SeaORM entity definitions.
    ///
    /// By default generates core-only entities. Use --plugins to include
    /// plugin-specific fields (e.g. username, admin ban fields).
    Generate {
        /// Write output to a file instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Comma-separated list of plugins whose fields to include.
        /// Available: username, two-factor, device-authorization, api-key, admin, organization, passkey.
        /// Use "all" to include every plugin's fields.
        #[arg(short, long, value_delimiter = ',')]
        plugins: Vec<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Generate { output, plugins } => {
            let plugins = if plugins.iter().any(|p| p == "all") {
                generate::list_plugins()
                    .into_iter()
                    .map(String::from)
                    .collect()
            } else {
                plugins
            };

            let schema = generate::generate_schema(&plugins);

            match output {
                Some(path) => {
                    if let Some(parent) = path.parent()
                        && !parent.exists()
                        && let Err(e) = fs::create_dir_all(parent)
                    {
                        eprintln!("failed to create directory {}: {e}", parent.display());
                        process::exit(1);
                    }
                    if let Err(e) = fs::write(&path, &schema) {
                        eprintln!("failed to write {}: {e}", path.display());
                        process::exit(1);
                    }
                    eprintln!("wrote auth schema to {}", path.display());
                }
                None => print!("{schema}"),
            }
        }
    }
}
