//! custody — tamper-evident chain-of-custody log for digital evidence.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "custody",
    version,
    about = "Tamper-evident chain-of-custody log for digital evidence",
    long_about = "custody maintains an append-only, hash-chained JSONL log of evidence intake and \
                  custodian transfers. Local-first: no network calls, no telemetry."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a .custody/ directory in the current directory with an empty log
    Init {
        /// Case identifier
        #[arg(value_name = "CASEID")]
        case_id: String,
    },
    /// Hash a file and log it into custody
    Intake {
        /// File to take into custody
        #[arg(value_name = "FILE")]
        file: String,
        /// Name of the custodian receiving the file
        #[arg(long, value_name = "NAME")]
        custodian: String,
        /// Optional notes for this entry
        #[arg(long, value_name = "TEXT")]
        notes: Option<String>,
    },
    /// Log a custodian-to-custodian transfer of a file already in custody
    Transfer {
        /// File being transferred
        #[arg(value_name = "FILE")]
        file: String,
        /// Name of the custodian handing off the file
        #[arg(long, value_name = "NAME")]
        from: String,
        /// Name of the custodian receiving the file
        #[arg(long, value_name = "NAME")]
        to: String,
        /// Optional notes for this entry
        #[arg(long, value_name = "TEXT")]
        notes: Option<String>,
    },
    /// Re-hash every logged file and verify the hash chain
    Verify,
    /// Print a human-readable markdown custody report
    Report,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let root = PathBuf::from(".");

    match cli.command {
        Commands::Init { case_id } => {
            custody::init_case(&root, &case_id)?;
            println!("Initialized custody log for case '{case_id}' in .custody/");
        }
        Commands::Intake {
            file,
            custodian,
            notes,
        } => {
            let e = custody::intake(&root, &file, &custodian, notes.as_deref())?;
            println!(
                "Logged intake #{} of '{}' (sha256: {}) custodian: {}",
                e.seq, e.file, e.sha256, custodian
            );
        }
        Commands::Transfer {
            file,
            from,
            to,
            notes,
        } => {
            let e = custody::transfer(&root, &file, &from, &to, notes.as_deref())?;
            println!(
                "Logged transfer #{} of '{}' from {} to {} (sha256: {})",
                e.seq, e.file, from, to, e.sha256
            );
        }
        Commands::Verify => {
            let v = custody::verify(&root)?;
            for f in &v.files {
                println!(
                    "{}  {}  ({})",
                    if f.ok { "PASS" } else { "FAIL" },
                    f.file,
                    f.detail
                );
            }
            println!("Hash chain: {}", if v.chain_ok { "PASS" } else { "FAIL" });
            for err in &v.chain_errors {
                println!("  - {err}");
            }
            println!("Overall: {}", if v.ok() { "PASS" } else { "FAIL" });
            if !v.ok() {
                std::process::exit(1);
            }
        }
        Commands::Report => {
            print!("{}", custody::report(&root)?);
        }
    }
    Ok(())
}
