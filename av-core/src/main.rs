use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use av_core::{scan_file, scan_directory, ScanResult};

#[derive(Parser)]
#[command(name = "av-scan", version, about = "Antivirus scanner CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a single file
    File {
        /// Path to file
        path: PathBuf,
        /// VirusTotal API key
        #[arg(long, short)]
        vt_key: Option<String>,
    },
    /// Scan a directory recursively
    Dir {
        /// Path to directory
        path: PathBuf,
        /// VirusTotal API key
        #[arg(long, short)]
        vt_key: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let results: Vec<ScanResult> = match cli.command {
        Commands::File { path, vt_key } => {
            vec![scan_file(&path, vt_key.as_deref())?]
        }
        Commands::Dir { path, vt_key } => {
            scan_directory(&path, vt_key.as_deref())?
        }
    };

    // Output JSON for Python wrapper
    println!("{}", serde_json::to_string(&results)?);
    Ok(())
}