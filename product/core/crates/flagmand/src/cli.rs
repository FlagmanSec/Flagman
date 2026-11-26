//! The command line, described with `clap`. `flagmand --help` prints it.

use clap::{Args, Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "flagmand",
    version,
    about = "Flagman: a network intrusion detection sensor for home and small office networks"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Watch a network interface and serve the dashboard (needs CAP_NET_RAW).
    Run {
        /// Configuration file. Default: /etc/flagman/flagman.toml if it exists.
        #[arg(long, short)]
        config: Option<PathBuf>,
        /// Interface to watch, overriding the configuration file.
        #[arg(long, short)]
        interface: Option<String>,
    },
    /// Analyse a .pcap capture file, print what was found, and optionally
    /// open the results in the dashboard.
    Replay(ReplayArgs),
    /// List the network interfaces Flagman can watch.
    Interfaces,
    /// Print the dashboard link, with its access token.
    Token {
        /// Configuration file. Default: /etc/flagman/flagman.toml if it exists.
        #[arg(long, short)]
        config: Option<PathBuf>,
    },
}

#[derive(Debug, Args)]
pub struct ReplayArgs {
    /// The capture file to analyse (.pcap, as written by tcpdump or Wireshark).
    pub pcap: PathBuf,
    /// Where to save the results.
    #[arg(long, default_value = "flagman-replay.db")]
    pub db: PathBuf,
    /// Replace the results file if it already exists.
    #[arg(long)]
    pub overwrite: bool,
    /// Configuration file, for the detector thresholds. Default: built-in values.
    #[arg(long, short)]
    pub config: Option<PathBuf>,
    /// After the analysis, serve the dashboard until Ctrl-C.
    #[arg(long)]
    pub serve: bool,
    /// Address of the dashboard. Port 8751, so it can run next to the live sensor.
    #[arg(long, default_value = "127.0.0.1:8751")]
    pub listen: SocketAddr,
    /// Folder holding the built dashboard (product/ui/dist).
    #[arg(long)]
    pub ui_dir: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_command_line_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn replay_defaults_are_safe() {
        let cli = Cli::parse_from(["flagmand", "replay", "scan.pcap"]);
        let Command::Replay(args) = cli.command else {
            panic!("expected replay");
        };
        assert!(!args.overwrite, "never replace results without being asked");
        assert!(args.listen.ip().is_loopback());
    }
}
