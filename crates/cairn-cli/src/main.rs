use cairn_core::{POSITIONING_LINE, PRODUCT_NAME};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "cairn",
    version,
    about = "Passwords, recovery, and control in one local vault.",
    long_about = "Cairn is an early-stage local-first password vault project. This CLI is a Milestone 0 scaffold and does not store or retrieve secrets yet."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Create a new local vault file.
    Init,
    /// Add an item to the vault.
    Add,
    /// Retrieve an item from the vault.
    Get,
    /// List vault item summaries.
    List,
    /// Search vault item summaries.
    Search,
    /// Generate a password.
    Generate,
    /// Create an encrypted export.
    Export,
    /// Prepare recovery material guidance.
    RecoveryKit,
    /// Rehearse the recovery flow.
    RehearseRecovery,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Init) => print_placeholder("init"),
        Some(Commands::Add) => print_placeholder("add"),
        Some(Commands::Get) => print_placeholder("get"),
        Some(Commands::List) => print_placeholder("list"),
        Some(Commands::Search) => print_placeholder("search"),
        Some(Commands::Generate) => print_placeholder("generate"),
        Some(Commands::Export) => print_placeholder("export"),
        Some(Commands::RecoveryKit) => print_placeholder("recovery-kit"),
        Some(Commands::RehearseRecovery) => print_placeholder("rehearse-recovery"),
        None => {
            println!("{PRODUCT_NAME}");
            println!("{POSITIONING_LINE}");
            println!("Run `cairn --help` to see available placeholder commands.");
        }
    }
}

fn print_placeholder(command: &str) {
    println!(
        "`cairn {command}` is not implemented yet. This Milestone 0 CLI does not ask for, store, or print secrets."
    );
}
