use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use sidecar_orchestrator::{OrchestratorConfig, admin, server};

/// The orchestrator of the co-SNARK sidecar: serves the public HTTPS API and
/// drives the three nodes.
#[derive(Parser)]
#[command(name = "sidecar-orchestrator")]
struct Cli {
    /// The config file (TOML).
    #[arg(long, env = "ORCHESTRATOR_CONFIG")]
    config: PathBuf,
    /// Listen on this address instead of the config's `listen`.
    #[arg(long, env = "ORCHESTRATOR_LISTEN")]
    listen: Option<SocketAddr>,
    /// Rebuild the registry copy from the three nodes before serving.
    #[arg(long)]
    sync_registry: bool,
    /// Start with scheduling paused (a restart in the middle of a node
    /// replacement); `resume` starts it.
    #[arg(long)]
    paused: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Rebuild the registry copy (`[registry] path`) from the three nodes,
    /// print what was written as one JSON line, and exit. Refuses while a
    /// running orchestrator holds the copy.
    SyncRegistry,
    /// Pause scheduling between rounds through the running orchestrator's
    /// admin socket: no execute, REGISTER or DISABLE session starts and no
    /// scheduler computes; returns once the session in flight has ended.
    /// Run it before a node replacement.
    Pause,
    /// Resume scheduling, once the registry check finds the three nodes'
    /// registries alike (refused, still paused, otherwise).
    Resume,
    /// Print whether scheduling is paused and the latest registry check,
    /// with the rows that differ.
    Status,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();
    let mut config = OrchestratorConfig::load(&cli.config)?;
    if let Some(listen) = cli.listen {
        config.listen = listen;
    }
    match cli.command {
        Some(Command::SyncRegistry) => {
            let crs = tokio::task::block_in_place(|| sidecar_core::crs::Crs::load(&config.crs))?;
            let synced = server::sync_registry(&config, &crs).await?;
            println!(
                "{}",
                serde_json::json!({
                    "registry": config.registry.path,
                    "namespaces": synced.namespaces,
                    "packages": synced.packages,
                })
            );
            Ok(())
        }
        Some(Command::Pause) | Some(Command::Resume) | Some(Command::Status) => {
            let req = match cli.command {
                Some(Command::Pause) => admin::AdminRequest::Pause,
                Some(Command::Resume) => admin::AdminRequest::Resume,
                _ => admin::AdminRequest::Status,
            };
            let path = config.admin_socket();
            let answer = tokio::task::spawn_blocking(move || admin::call(&path, &req)).await??;
            println!("{}", serde_json::to_string(&answer)?);
            match answer.refusal {
                Some(refusal) => eyre::bail!("refused: {refusal}"),
                None => Ok(()),
            }
        }
        None => server::run(config, cli.sync_registry, cli.paused).await,
    }
}
