use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use eyre::{bail, ensure};
use sidecar_core::Fr;
use sidecar_core::executor::round_state;
use sidecar_core::field::{FieldHex, RequestId};
use sidecar_core::handshake::Handshake;
use sidecar_node::admin::{self, AdminRequest, AdminResponse};
use sidecar_node::backup;
use sidecar_node::config::ConfigArgs;
use sidecar_node::{Mesh, MeshConfig, NodeConfig, certs, open_session, server, setup};

/// The node process of the co-SNARK sidecar.
#[derive(Parser)]
#[command(name = "sidecar-node")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the HTTPS API (mutual TLS), the admin socket and the pruning
    /// job, until interrupted.
    Serve {
        #[command(flatten)]
        config: ConfigArgs,
    },
    /// Generate this node's enc and sig keys and sample its master share over
    /// one mesh session with the other two nodes (run it on all three at
    /// once); prints the public keys to publish and pin.
    Setup {
        /// The node config (its key directory and mesh config). With
        /// `--dealer`, give all three nodes' configs.
        #[arg(long, env = "NODE_CONFIG", required = true)]
        config: Vec<PathBuf>,
        /// Move the mesh to ports base, base + 1, base + 2.
        #[arg(long, env = "NODE_MESH_BASE_PORT")]
        mesh_base_port: Option<u16>,
        /// Development only: write all three nodes' keys and a consistent
        /// sharing of a random master in this one process (no mesh).
        #[arg(long)]
        dealer: bool,
        /// Overwrite existing key files (on all three nodes together).
        #[arg(long)]
        force: bool,
        /// A newcomer replacing a departed node: draw the enc and sig keys
        /// only, with no mesh session; `replace-node` installs the master
        /// share from the two remaining nodes.
        #[arg(long, conflicts_with = "dealer")]
        newcomer: bool,
    },
    /// Roll back one committed request on this node through its admin socket
    /// (run it on all three nodes, newest request first).
    Restore {
        #[command(flatten)]
        config: ConfigArgs,
        /// The request's namespace.
        #[arg(long)]
        namespace: FieldHex,
        /// The request id.
        #[arg(long)]
        request_id: RequestId,
    },
    /// Prune the `requests` rows older than the retention window now, and the
    /// receipts past `expiry_block + stale_blocks` whose request never
    /// reached the queue or is done (read through the node's own `[tip]
    /// aztec_node`), and record or retire the secret-shared on-chain epoch scalars
    /// against each contract's stored key, through the running node's admin
    /// socket.
    Prune {
        #[command(flatten)]
        config: ConfigArgs,
    },
    /// Rotate this node's enc key through the running node's admin socket: a
    /// new enc scalar becomes current, the old one is kept for the config's
    /// `enc_grace_days` and then retired. Prints the new public keys for the
    /// clients' and the orchestrator's pins.
    RotateEnc {
        #[command(flatten)]
        config: ConfigArgs,
        /// Rotate even while the previous key is inside its grace window,
        /// dropping it and every third still sealed only under it.
        #[arg(long)]
        force: bool,
    },
    /// Secret-shared on-chain intake: keep this node's current enc scalar pending
    /// as `--epoch`'s in the app contract `--namespace` (the key directory's
    /// enc.epochs.json) and sign the contract's rotation to its public key,
    /// through the running node's admin socket. Prints the arguments of the
    /// contract's `rotate_enc_key(i, key, signature)` as one JSON line; the
    /// operator submits that transaction, and the pruning job records the
    /// scalar once it has landed. The epoch is the contract's stored epoch
    /// for this node + 1 (1 for its first key).
    SignEncKey {
        #[command(flatten)]
        config: ConfigArgs,
        /// The app contract's address.
        #[arg(long)]
        namespace: FieldHex,
        /// The epoch the key takes in the contract.
        #[arg(long)]
        epoch: u32,
    },
    /// Resync node `lost`'s store from its two neighbours through this node's
    /// admin socket (run it on all three nodes at once: the lost node, whose
    /// store is empty and whose key directory survived, and both
    /// neighbours), then check every namespace's npk_app_hash and `values`
    /// pairs and audit every canonical version. With `--namespace` and
    /// `--key`, resync that one tip key into the lost node's store instead
    /// (its versions and clear tree replace the node's) and audit it. Prints
    /// the report; fails if any key fails the audit.
    Resync {
        #[command(flatten)]
        config: ConfigArgs,
        /// The index of the node resynced (0, 1 or 2).
        #[arg(long)]
        lost: usize,
        /// The three nodes' pinned public keys, as `GET /v1/nodes` answers
        /// them (the deployment's published keys, not the orchestrator's
        /// answer).
        #[arg(long)]
        pins: PathBuf,
        /// The namespace of the one key to resync (with `--key`).
        #[arg(long, requires = "key")]
        namespace: Option<FieldHex>,
        /// The one tip key to resync (with `--namespace`).
        #[arg(long, requires = "namespace")]
        key: Option<String>,
    },
    /// Audit the canonical version of every node-held tip key through this
    /// node's admin socket (run it on all three nodes at once). Prints the
    /// findings; fails if any key fails.
    Audit {
        #[command(flatten)]
        config: ConfigArgs,
        /// Audit this namespace only.
        #[arg(long)]
        namespace: Option<FieldHex>,
    },
    /// With `--check`: compare this node's registry rows (namespace owner,
    /// seq and npk_app_hash; each package's vk_hash, manifest, disabled flag
    /// and seq) with the other two nodes' over one mesh session, writing
    /// nothing; prints the report and fails naming every row that differs.
    /// With `--lost` and `--from`: resync node `lost`'s registry rows from
    /// node `from` once `from` and the third node are seen to hold the same
    /// rows (node `lost` keeps its nsk_app shares, builds each vk itself and
    /// advances its seq); prints the report. Either runs through this node's
    /// admin socket, on all three nodes at once.
    SyncRegistry {
        #[command(flatten)]
        config: ConfigArgs,
        /// Compare only.
        #[arg(long, conflicts_with_all = ["lost", "from"])]
        check: bool,
        /// Compare this namespace only (with `--check`).
        #[arg(long, requires = "check")]
        namespace: Option<FieldHex>,
        /// The index of the node whose registry is resynced (0, 1 or 2).
        #[arg(long, requires = "from")]
        lost: Option<usize>,
        /// The index of the neighbour it takes the rows from.
        #[arg(long, requires = "lost")]
        from: Option<usize>,
    },
    /// Write a fresh backup key (64 hex digits) to a new file. Move it
    /// offline: it is never kept on a node's disk, and every backup and
    /// restore takes it.
    BackupKey {
        /// The new key file (on removable media).
        #[arg(long)]
        out: PathBuf,
    },
    /// Back up this node's store through its admin socket to a new file,
    /// encrypted under the backup key (the running node reads each
    /// namespace under its lock, between rounds).
    Backup {
        #[command(flatten)]
        config: ConfigArgs,
        /// The backup key file, held offline, or `-` to read it from
        /// standard input; refused inside the node's own directories.
        #[arg(long)]
        backup_key: PathBuf,
        /// The new backup file.
        #[arg(long)]
        out: PathBuf,
    },
    /// Back up this node's key directory to a new file, encrypted under the
    /// backup key (read by this command from the config's key directory;
    /// not during an enc rotation). Take one after setup and after every
    /// enc rotation.
    BackupKeys {
        #[command(flatten)]
        config: ConfigArgs,
        /// The backup key file, held offline, or `-` for standard input.
        #[arg(long)]
        backup_key: PathBuf,
        /// The new backup file.
        #[arg(long)]
        out: PathBuf,
    },
    /// Restore this node's lost key directory from its backup, with the node
    /// stopped; refused when the directory holds any key file.
    RestoreKeys {
        #[command(flatten)]
        config: ConfigArgs,
        /// The backup key file, held offline, or `-` for standard input.
        #[arg(long)]
        backup_key: PathBuf,
        /// The key directory backup.
        #[arg(long)]
        backup: PathBuf,
    },
    /// Restore node `lost`'s store from its backup through this node's admin
    /// socket (run it on all three nodes at once: the restored node, started
    /// on an empty store with its key directory, gives `--backup` and
    /// `--backup-key`; both neighbours give neither), with a delta resync
    /// from the neighbours for everything written since the backup; then
    /// check every namespace's npk_app_hash and `values` pairs and audit
    /// every canonical version. Prints the report; fails if any key fails the
    /// audit.
    RestoreBackup {
        #[command(flatten)]
        config: ConfigArgs,
        /// The index of the node restored (0, 1 or 2).
        #[arg(long)]
        lost: usize,
        /// The three nodes' pinned public keys, as for `resync`.
        #[arg(long)]
        pins: PathBuf,
        /// The store backup (the restored node only).
        #[arg(long, requires = "backup_key")]
        backup: Option<PathBuf>,
        /// The backup key file, held offline, or `-` for standard input (the
        /// restored node only).
        #[arg(long, requires = "backup")]
        backup_key: Option<PathBuf>,
    },
    /// Replace node `--departed` by a newcomer (docs/ARCHITECTURE.md
    /// section 6, "Node replacement and key epochs"), run on all three at
    /// once while the orchestrator is paused: on each remaining node, through
    /// its admin socket (restarted first with the newcomer's mesh address and
    /// certificate in its place); on the newcomer itself (its config's party
    /// is `--departed`, keys from `setup --newcomer`, an empty store, not yet
    /// served), directly. The two remaining nodes refresh their shares, the
    /// newcomer imports its pairs from them, all three check the namespaces
    /// and audit every canonical version; then the remaining nodes sign the
    /// new key set for every `[tip]` namespace whose contract manifest says
    /// `node_keys: rotating`. Prints the report, one `rotate_keys` line per
    /// such namespace (the arguments, the two signatures, null for the
    /// departed node's) to submit, and one `redeploy` line per registered
    /// tip namespace whose manifest says `fixed`; fails if any key fails the
    /// audit.
    ReplaceNode {
        #[command(flatten)]
        config: ConfigArgs,
        /// The index of the node replaced (0, 1 or 2).
        #[arg(long)]
        departed: usize,
        /// The newcomer's public keys, as `setup --newcomer` printed them.
        #[arg(long)]
        newcomer: PathBuf,
        /// The current key set, as `GET /v1/nodes` answers it (the departed
        /// node's keys in its place); the newcomer's replace them.
        #[arg(long)]
        pins: PathBuf,
    },
    /// Write development TLS material: the three mesh key and certificate
    /// pairs (DER) and the HTTPS dev CA, three node server certificates and
    /// the orchestrator's client certificate (PEM). Keeps a complete set.
    GenCerts {
        /// The output directory.
        #[arg(long, env = "SIDECAR_KEYS_DIR")]
        out: PathBuf,
        /// Regenerate everything, even a complete set.
        #[arg(long)]
        force: bool,
    },
    /// Open one MPC session with the other two nodes (run it on all three),
    /// run the empty handshake and set up the round's randomness: a check that
    /// the mesh config, the certificates and the ports work.
    MeshCheck {
        /// The party mesh config.
        #[arg(long, env = "NODE_MESH_CONFIG")]
        mesh_config: PathBuf,
        /// Move the mesh to ports base, base + 1, base + 2.
        #[arg(long, env = "NODE_MESH_BASE_PORT")]
        mesh_base_port: Option<u16>,
    },
}

fn main() -> eyre::Result<()> {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    match Cli::parse().command {
        Command::Serve { config } => {
            let config = config.load()?;
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(server::run(config))?;
        }
        Command::Setup {
            config,
            mesh_base_port,
            dealer,
            force,
            newcomer,
        } => {
            let configs = config
                .iter()
                .map(|p| NodeConfig::load(p))
                .collect::<eyre::Result<Vec<_>>>()?;
            if newcomer {
                let [config] = <[NodeConfig; 1]>::try_from(configs)
                    .map_err(|_| eyre::eyre!("setup --newcomer takes the newcomer's config"))?;
                let keys = setup::setup_newcomer(&config.key_files(), force)?;
                print_keys(config.party, &keys)?;
                eprintln!(
                    "party {}: newcomer keys written (no master share); give these public keys \
                     to the remaining nodes' operators, then run `replace-node` on all three",
                    config.party
                );
            } else if dealer {
                ensure!(
                    configs.len() == sidecar_core::request::NODES,
                    "setup --dealer takes the three nodes' configs (--config three times)"
                );
                for (i, c) in configs.iter().enumerate() {
                    ensure!(c.party == i, "config {} is party {}, not {i}", i, c.party);
                }
                let files = [0, 1, 2].map(|i| configs[i].key_files());
                eprintln!("setup --dealer: development keys only; one process saw every secret");
                let keys = setup::setup_dealer([&files[0], &files[1], &files[2]], force)?;
                for (party, k) in keys.iter().enumerate() {
                    print_keys(party, k)?;
                }
            } else {
                let [mut config] = <[NodeConfig; 1]>::try_from(configs).map_err(|_| {
                    eyre::eyre!("setup takes one node config (three only with --dealer)")
                })?;
                if let Some(base) = mesh_base_port {
                    config.mesh_base_port = Some(base);
                }
                let mesh = Mesh::new(config.mesh()?);
                let keys = setup::setup(&config.key_files(), &mesh, force)?;
                print_keys(config.party, &keys)?;
            }
        }
        Command::Restore {
            config,
            namespace,
            request_id,
        } => {
            let config = config.load()?;
            let answer = admin::call(
                &config.admin_socket(),
                &AdminRequest::Restore {
                    namespace,
                    request_id,
                },
            )?;
            report(answer, || format!("request {request_id} rolled back"))?;
        }
        Command::Prune { config } => {
            let config = config.load()?;
            let answer = admin::call(&config.admin_socket(), &AdminRequest::Prune)?;
            let pruned = answer.pruned.unwrap_or(0);
            let receipts = match (
                answer.pruned_receipts,
                answer.kept_receipts,
                &answer.receipts_not_pruned,
            ) {
                (Some(n), kept, _) => format!(
                    "{n} receipt row(s) (kept {} past their window: request queued)",
                    kept.unwrap_or(0)
                ),
                (None, _, Some(why)) => format!("no receipt ({why})"),
                (None, _, None) => "no receipt".to_string(),
            };
            let versions = answer.pruned_versions.unwrap_or(0);
            let epochs: String = answer
                .enc_epochs
                .iter()
                .flatten()
                .filter(|o| !o.recorded.is_empty() || !o.retired.is_empty())
                .map(|o| {
                    format!(
                        "; {}: enc epoch(s) {:?} recorded, {:?} retired (stored epoch {})",
                        o.namespace, o.recorded, o.retired, o.stored_epoch
                    )
                })
                .collect();
            let key_sets: String = answer
                .key_sets
                .iter()
                .flatten()
                .map(|o| {
                    format!(
                        "; {}: key set epoch {} {} (stored epoch {})",
                        o.namespace,
                        o.epoch,
                        if o.landed { "landed" } else { "pending" },
                        o.stored_epoch
                    )
                })
                .collect();
            report(answer, || {
                format!(
                    "pruned {pruned} request row(s), {receipts} and {versions} node-held \
                     version(s){epochs}{key_sets}"
                )
            })?;
        }
        Command::RotateEnc { config, force } => {
            let config = config.load()?;
            let answer = admin::call(&config.admin_socket(), &AdminRequest::RotateEnc { force })?;
            let rotated = match (answer.ok, answer.rotated, answer.refusal) {
                (true, Some(rotated), _) => rotated,
                (false, _, Some(refusal)) => bail!("refused: {refusal}"),
                _ => bail!("the node answered no keys"),
            };
            let mut line = serde_json::to_value(&rotated)?;
            line["party"] = config.party.into();
            println!("{line}");
            eprintln!(
                "party {}: enc rotated; pin the new enc key in every client and in the \
                 orchestrator's config; the previous key (key id {}) is retired at {} (unix \
                 seconds), after which records sealed only under it no longer open",
                config.party, rotated.previous_key_id, rotated.previous_retires_at
            );
        }
        Command::SignEncKey {
            config,
            namespace,
            epoch,
        } => {
            let config = config.load()?;
            let answer = admin::call(
                &config.admin_socket(),
                &AdminRequest::SignEncKey { namespace, epoch },
            )?;
            let signed = match (answer.ok, answer.enc_key, answer.refusal) {
                (true, Some(signed), _) => signed,
                (false, _, Some(refusal)) => bail!("refused: {refusal}"),
                _ => bail!("the node answered no signed key"),
            };
            println!("{}", serde_json::to_string(&signed)?);
            eprintln!(
                "party {}: enc key pending at epoch {epoch} of {namespace}; submit the \
                 contract's rotate_enc_key with the printed index, key and signature (the \
                 node records it once its pruning job sees it land)",
                config.party
            );
        }
        Command::Resync {
            config,
            lost,
            pins,
            namespace,
            key,
        } => {
            let config = config.load()?;
            let pins = read_pins(&pins)?;
            let request = match (namespace, key) {
                (Some(namespace), Some(key)) => AdminRequest::ResyncKey {
                    lost,
                    namespace,
                    key,
                    pins,
                },
                _ => AdminRequest::Resync { lost, pins },
            };
            let answer = admin::call(&config.admin_socket(), &request)?;
            let report = match (answer.ok, answer.resync, answer.refusal) {
                (true, Some(report), _) => report,
                (false, _, Some(refusal)) => bail!("refused: {refusal}"),
                _ => bail!("the node answered no report"),
            };
            println!("{}", serde_json::to_string(&report)?);
            audited(config.party, &report.audit)?;
        }
        Command::ReplaceNode {
            config,
            departed,
            newcomer,
            pins,
        } => {
            let config = config.load()?;
            let pins = read_pins(&pins)?;
            let newcomer = read_public_keys(&newcomer)?;
            let keys = sidecar_node::replace::new_key_set(&pins, departed, newcomer)
                .map_err(|r| eyre::eyre!("{r}"))?;
            let report = if config.party == departed {
                let app = sidecar_node::server::load_newcomer(&config)?;
                sidecar_node::replace::replace(&app, departed, &keys)
                    .map_err(|r| eyre::eyre!("refused: {r}"))?
            } else {
                let answer = admin::call(
                    &config.admin_socket(),
                    &AdminRequest::ReplaceNode {
                        departed,
                        pins: Box::new(keys),
                    },
                )?;
                match (answer.ok, answer.replaced, answer.refusal) {
                    (true, Some(report), _) => *report,
                    (false, _, Some(refusal)) => bail!("refused: {refusal}"),
                    _ => bail!("the node answered no report"),
                }
            };
            println!("{}", serde_json::to_string(&report)?);
            for rotation in &report.rotations {
                println!("{}", serde_json::json!({ "rotate_keys": rotation }));
            }
            for namespace in &report.redeploy {
                println!("{}", serde_json::json!({ "redeploy": namespace }));
            }
            audited(config.party, &report.resync.audit)?;
            eprintln!(
                "party {}: node {departed} replaced; submit the {} rotate_keys line(s), set the \
                 new key set in the orchestrator's [[nodes]] and resume it{}",
                config.party,
                report.rotations.len(),
                if config.party == departed {
                    "; start this node with `serve`"
                } else {
                    ""
                }
            );
            for namespace in &report.redeploy {
                eprintln!(
                    "party {}: namespace {namespace}: its contract manifest says node_keys \
                     fixed, so its contract has no rotate_keys and no rotation can land: \
                     redeploy its app (a new salt, REGISTER and configure)",
                    config.party
                );
            }
        }
        Command::Audit { config, namespace } => {
            let config = config.load()?;
            let answer = admin::call(&config.admin_socket(), &AdminRequest::Audit { namespace })?;
            let keys = match (answer.ok, answer.audit, answer.refusal) {
                (true, Some(keys), _) => keys,
                (false, _, Some(refusal)) => bail!("refused: {refusal}"),
                _ => bail!("the node answered no findings"),
            };
            println!("{}", serde_json::to_string(&keys)?);
            audited(config.party, &keys)?;
        }
        Command::SyncRegistry {
            config,
            lost: Some(lost),
            from: Some(from),
            ..
        } => {
            let config = config.load()?;
            let answer = admin::call(
                &config.admin_socket(),
                &AdminRequest::ResyncRegistry { lost, from },
            )?;
            let report = match (answer.ok, answer.registry_resync, answer.refusal) {
                (true, Some(report), _) => report,
                (false, _, Some(refusal)) => bail!("refused: {refusal}"),
                _ => bail!("the node answered no report"),
            };
            println!("{}", serde_json::to_string(&report)?);
            eprintln!(
                "party {}: node {lost}'s registry resynced from node {from}: {} row(s) \
                 differed; {} namespace(s), {} package(s) written, {} vk(s) built here",
                config.party,
                report.repaired.len(),
                report.namespaces,
                report.packages,
                report.vks_built
            );
        }
        Command::SyncRegistry {
            config,
            check,
            namespace,
            ..
        } => {
            ensure!(
                check,
                "sync-registry takes --check (compare the three nodes' registries, writing \
                 nothing) or --lost and --from (resync one node's registry from a neighbour)"
            );
            let config = config.load()?;
            let answer = admin::call(
                &config.admin_socket(),
                &AdminRequest::CheckRegistry { namespace },
            )?;
            let found = match (answer.ok, answer.registry, answer.refusal) {
                (true, Some(found), _) => found,
                (false, _, Some(refusal)) => bail!("refused: {refusal}"),
                _ => bail!("the node answered no report"),
            };
            println!("{}", serde_json::to_string(&found)?);
            if !found.divergences.is_empty() {
                let rows: Vec<String> = found.divergences.iter().map(ToString::to_string).collect();
                bail!(
                    "the nodes' registries differ in {} row(s):\n{}",
                    rows.len(),
                    rows.join("\n")
                );
            }
            eprintln!(
                "party {}: the three nodes hold the same registry rows ({} namespace(s), {} \
                 package(s))",
                config.party, found.namespaces, found.packages
            );
        }
        Command::BackupKey { out } => {
            backup::write_new_key(&out)?;
            eprintln!(
                "wrote a backup key to {}; keep it offline (it is never kept on a node's disk)",
                out.display()
            );
        }
        Command::Backup {
            config,
            backup_key,
            out,
        } => {
            let config = config.load()?;
            let key = backup::read_key(&backup_key, &config.own_dirs())?;
            let out = std::path::absolute(&out)?;
            let answer = admin::call(
                &config.admin_socket(),
                &AdminRequest::Backup {
                    out: out.clone(),
                    key,
                },
            )?;
            let counts = match (answer.ok, answer.backed_up, answer.refusal) {
                (true, Some(counts), _) => counts,
                (false, _, Some(refusal)) => bail!("refused: {refusal}"),
                _ => bail!("the node answered no backup"),
            };
            println!("{}", serde_json::to_string(&counts)?);
            eprintln!(
                "party {}: store backed up to {}",
                config.party,
                out.display()
            );
        }
        Command::BackupKeys {
            config,
            backup_key,
            out,
        } => {
            let config = config.load()?;
            let key = backup::read_key(&backup_key, &config.own_dirs())?;
            let files = backup::write_keys(
                &config.key_files(),
                config.party,
                &out,
                &key,
                sidecar_core::pipeline::unix_now(),
            )?;
            eprintln!(
                "party {}: key directory ({}) backed up to {}",
                config.party,
                files.join(", "),
                out.display()
            );
        }
        Command::RestoreKeys {
            config,
            backup_key,
            backup: from,
        } => {
            let config = config.load()?;
            let key = backup::read_key(&backup_key, &config.own_dirs())?;
            let files = backup::restore_keys(&config.key_files(), config.party, &from, &key)?;
            eprintln!(
                "party {}: restored {} into {}",
                config.party,
                files.join(", "),
                config.key_dir.display()
            );
        }
        Command::RestoreBackup {
            config,
            lost,
            pins,
            backup: from,
            backup_key,
        } => {
            let config = config.load()?;
            let pins = read_pins(&pins)?;
            let (from, key) = match (from, backup_key) {
                (Some(from), Some(path)) => (
                    Some(std::path::absolute(&from)?),
                    Some(backup::read_key(&path, &config.own_dirs())?),
                ),
                _ => (None, None),
            };
            let answer = admin::call(
                &config.admin_socket(),
                &AdminRequest::RestoreBackup {
                    lost,
                    pins,
                    backup: from,
                    key,
                },
            )?;
            let report = match (answer.ok, answer.resync, answer.refusal) {
                (true, Some(report), _) => report,
                (false, _, Some(refusal)) => bail!("refused: {refusal}"),
                _ => bail!("the node answered no report"),
            };
            println!("{}", serde_json::to_string(&report)?);
            audited(config.party, &report.audit)?;
        }
        Command::GenCerts { out, force } => {
            let done = certs::generate(&out, force)?;
            for path in &done.written {
                println!("wrote {}", path.display());
            }
            if !done.kept.is_empty() {
                println!(
                    "kept {} existing files in {}",
                    done.kept.len(),
                    out.display()
                );
            }
        }
        Command::MeshCheck {
            mesh_config,
            mesh_base_port,
        } => {
            let mut config = MeshConfig::load(&mesh_config)?;
            if let Some(base) = mesh_base_port {
                config = config.with_base_port(base)?;
            }
            let mesh = Mesh::new(config);
            let request_id = "0x0000000000006d6573682d636865636b"
                .parse()
                .map_err(|e: String| eyre::eyre!(e))?;
            let handshake = Handshake::build(request_id, Fr::from(0u64), &[], &[]);
            let held = mesh.lock().acquire();
            let session = open_session(&mesh, &held, &handshake).map_err(|r| eyre::eyre!("{r}"))?;
            round_state(&session).map_err(|r| eyre::eyre!("{r}"))?;
            println!("party {}: the mesh session opened", session.party());
        }
    }
    Ok(())
}

/// The three nodes' pinned public keys from `path` (`GET /v1/nodes` form).
fn read_pins(path: &Path) -> eyre::Result<Box<sidecar_core::NodesResponse>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| eyre::eyre!("reading the pinned keys {}: {e}", path.display()))?;
    Ok(Box::new(
        sidecar_core::NodesResponse::from_json(&text)
            .map_err(|r| eyre::eyre!("{}: {r}", path.display()))?,
    ))
}

/// A node's public keys from `path`: `{"enc": .., "sig": ..}`, as `setup`
/// prints them (a `party` field beside them is ignored).
fn read_public_keys(path: &Path) -> eyre::Result<sidecar_core::response::NodePublicKeys> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| eyre::eyre!("reading the newcomer's keys {}: {e}", path.display()))?;
    let mut value: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| eyre::eyre!("{}: {e}", path.display()))?;
    if let Some(map) = value.as_object_mut() {
        map.remove("party");
    }
    serde_json::from_value(value).map_err(|e| eyre::eyre!("{}: {e}", path.display()))
}

/// Print `party`'s public keys as one JSON line.
fn print_keys(party: usize, keys: &sidecar_core::response::NodePublicKeys) -> eyre::Result<()> {
    let mut line = serde_json::to_value(keys)?;
    line["party"] = party.into();
    println!("{line}");
    Ok(())
}

/// Name every key the audit did not cover; fail naming every key that
/// failed it.
fn audited(party: usize, keys: &[sidecar_core::audit::KeyAudit]) -> eyre::Result<()> {
    use sidecar_core::audit::Outcome;
    let named = |want: fn(&Outcome) -> Option<&String>| -> Vec<String> {
        keys.iter()
            .filter_map(|k| want(&k.outcome).map(|why| format!("{} {}: {why}", k.namespace, k.key)))
            .collect()
    };
    let failed = named(|o| match o {
        Outcome::Failed(why) => Some(why),
        _ => None,
    });
    let skipped = named(|o| match o {
        Outcome::NotAudited(why) => Some(why),
        _ => None,
    });
    if !skipped.is_empty() {
        eprintln!(
            "party {party}: {} key(s) not audited:\n{}",
            skipped.len(),
            skipped.join("\n")
        );
    }
    if failed.is_empty() {
        eprintln!(
            "party {party}: {} key(s) audited, all passed",
            keys.len() - skipped.len()
        );
        return Ok(());
    }
    bail!(
        "{} key(s) failed the audit:\n{}",
        failed.len(),
        failed.join("\n")
    )
}

fn report(answer: AdminResponse, done: impl FnOnce() -> String) -> eyre::Result<()> {
    match (answer.ok, answer.refusal) {
        (true, _) => {
            println!("{}", done());
            Ok(())
        }
        (false, Some(refusal)) => bail!("refused: {refusal}"),
        (false, None) => bail!("refused"),
    }
}
