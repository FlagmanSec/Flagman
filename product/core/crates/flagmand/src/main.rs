//! `flagmand`, the Flagman daemon.
//!
//! - `flagmand run` watches a network interface, detects attacks, stores the
//!   results and serves the dashboard. See `run.rs`.
//! - `flagmand replay capture.pcap` does the same work on a capture file and
//!   prints what it found. See `replay.rs`.
//! - `flagmand extract capture.pcap --out flows.parquet` writes the features
//!   of every flow for machine learning (builds with `--features parquet`
//!   only). See `extract.rs`.
//! - `flagmand interfaces` lists the interfaces that can be watched.
//! - `flagmand token` prints the dashboard link with its access token.
//!
//! Reading order: `cli.rs`, `config.rs`, `pipeline.rs`, then `run.rs`.

mod cli;
mod config;
#[cfg(feature = "parquet")]
mod extract;
mod pipeline;
mod replay;
mod run;
mod server;
mod shutdown;
mod suricata;
mod token;
mod writer;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Command, ExtractArgs};
use tracing_subscriber::EnvFilter;

fn main() -> std::process::ExitCode {
    // Log level: `RUST_LOG=debug flagmand run` for more detail.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    match dispatch(Cli::parse()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            // `{:#}` prints the whole chain: "could not open X: permission denied".
            eprintln!("flagmand: {error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Run { config, interface } => run::run(config.as_deref(), interface),
        Command::Replay(options) => replay::replay(&options),
        Command::Extract(options) => extract_features(&options),
        Command::Interfaces => run::print_interfaces(),
        Command::Token { config } => run::print_token(config.as_deref()),
    }
}

#[cfg(feature = "parquet")]
fn extract_features(options: &ExtractArgs) -> Result<()> {
    extract::extract(options)
}

#[cfg(not(feature = "parquet"))]
fn extract_features(_options: &ExtractArgs) -> Result<()> {
    anyhow::bail!(
        "this flagmand was built without Parquet support; build it with \
         `cargo build --release -p flagmand --features parquet`"
    )
}
