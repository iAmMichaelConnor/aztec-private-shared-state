//! Node setup: the two key scalars and the master nullifier share, written to
//! the key directory beside the TLS material (ARCHITECTURE.md section 2,
//! setup and rotation).
//!
//! ```text
//! <key_dir>/enc.key        enc_i, a fresh Grumpkin scalar (OS CSPRNG)
//! <key_dir>/sig.key        sig_i, another, drawn independently
//! <key_dir>/master.share   node i's replicated share of the master, {"a": "0x..", "b": "0x.."}
//! ```
//!
//! [`setup`] draws both scalars and samples the master share over one mesh
//! session with the other two nodes (all three run it at once): the session
//! handshake, then Rep3's correlated randomness, from which each node takes
//! its pair of a value nobody knows. [`setup_dealer`] is the development
//! shortcut that writes all three nodes' files in one process.

use std::path::Path;

use eyre::{Context, bail};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sidecar_core::bind::Share;
use sidecar_core::executor::{round_state, sample_share};
use sidecar_core::field::{FieldHex, Fr, RequestId};
use sidecar_core::handshake::Handshake;
use sidecar_core::keys::{KeyFiles, NodeKeys, label_field};
use sidecar_core::request::NODES;
use sidecar_core::response::NodePublicKeys;

use crate::files::{create_private_dir, write_file};
use crate::mesh::Mesh;
use crate::session::open_session;

/// The master share file's content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MasterShareFile {
    a: FieldHex,
    b: FieldHex,
}

/// The request id of the setup session: ASCII "sidecar.setup".
pub fn setup_request_id() -> RequestId {
    RequestId::from(label_field(b"sidecar.setup"))
}

/// Write node `files`' master share (mode 0600).
pub fn write_master_share(files: &KeyFiles, share: Share) -> eyre::Result<()> {
    create_private_dir(files.dir())
        .with_context(|| format!("creating {}", files.dir().display()))?;
    let body = MasterShareFile {
        a: FieldHex(share.a),
        b: FieldHex(share.b),
    };
    let mut text = serde_json::to_string(&body).expect("a share serialises");
    text.push('\n');
    write_file(&files.master_share_path(), text.as_bytes(), true)
}

/// Read node `files`' master share.
pub fn read_master_share(files: &KeyFiles) -> eyre::Result<Share> {
    let path = files.master_share_path();
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading {} (run `sidecar-node setup`)", path.display()))?;
    let file: MasterShareFile =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    Ok(Share::new(file.a.fr(), file.b.fr()))
}

// Key-file handling. `setup` draws enc and sig as two
// independent uniform Grumpkin scalars from the OS CSPRNG (no common root, so
// the ECDH key and the signing key never share a secret), samples the master
// share over the mesh, and only then writes enc.key, sig.key and master.share
// into the key directory (mode 0700; files 0600, each through a temporary
// file and a rename), so a session that fails writes nothing. It refuses to
// overwrite any existing key file unless `--force`: a new sig key is a new
// deployment of every namespace that pins it, and a new master share on one
// node alone breaks the sharing, so `--force` must be run on all three nodes
// together, and only before any namespace is registered (every nsk_app share
// derives from the master). If one node fails after the session while the
// other two wrote their files, run setup again with `--force` on all three.
// The node reads the files at start and writes them only to rotate its enc key
// (`sidecar-node rotate-enc`) and to retire the previous one when its grace
// window lapses (the `rotation` module); backing a node up means backing up
// the whole key directory (both scalars, during a window the previous enc
// scalar and its rotation time, and the master share), and
// a lost master share cannot be read back from the other two nodes' files:
// the node is then replaced (`sidecar-node replace-node`, which reshares the
// master to the newcomer). The public keys are printed for the deployment to
// publish and pin; `GET /v1/nodes` answers the same pair.
/// Set this node up: fresh `enc` and `sig` scalars, and the master share
/// sampled over one mesh session with the other two nodes, which must run
/// setup at the same time. Returns the public keys.
pub fn setup(files: &KeyFiles, mesh: &Mesh, force: bool) -> eyre::Result<NodePublicKeys> {
    refuse_existing(files, force)?;
    let keys = NodeKeys::generate(&mut OsRng);
    let body_hash = label_field(b"sidecar.setup");
    let handshake = Handshake::build(setup_request_id(), body_hash, &[], &[]);
    let held = mesh.lock().acquire();
    let session = open_session(mesh, &held, &handshake)
        .map_err(|r| eyre::eyre!("the setup session did not open: {r}"))?;
    let mut state =
        round_state(&session).map_err(|r| eyre::eyre!("the setup session failed: {r}"))?;
    let master = sample_share(&mut state);
    drop(session);
    write(files, &keys, master)?;
    tracing::info!(party = mesh.party(), "setup: keys and master share written");
    Ok(keys.public_keys())
}

// A newcomer replacing a departed node (`setup --newcomer`, ARCHITECTURE.md
// section 6, "Node replacement and key epochs") draws its own enc and sig
// scalars and nothing else: its master share and every pair come from the two
// remaining nodes in `sidecar-node replace-node`, after their share refresh.
// It opens no mesh session, so it runs alone, before the replacement.
/// Set a newcomer up: fresh `enc` and `sig` scalars only, no master share
/// (the replacement installs it). Returns the public keys, which the
/// remaining nodes' operators pin for the newcomer's place.
pub fn setup_newcomer(files: &KeyFiles, force: bool) -> eyre::Result<NodePublicKeys> {
    refuse_existing(files, force)?;
    if force {
        let master = files.master_share_path();
        if master.exists() {
            std::fs::remove_file(&master)
                .with_context(|| format!("removing {}", master.display()))?;
        }
    }
    let keys = NodeKeys::generate(&mut OsRng);
    files
        .write(&keys)
        .with_context(|| format!("writing the keys into {}", files.dir().display()))?;
    Ok(keys.public_keys())
}

// `setup --dealer` is development only. It generates the three
// nodes' enc and sig scalars and a random master in one process, splits the
// master into a consistent replicated sharing and writes each node's files
// into its key directory, so a development deployment on one machine needs no
// mesh session to start. The process that ran it saw the master and every
// node's keys, so the nodes are not independent: never use it for a
// deployment (`sidecar-node setup` on each node, at once, samples the master
// over the mesh so that nobody learns it).
/// The development dealer: keys for all three nodes and a consistent sharing
/// of a random master, written to `files[i]`. Returns the public keys.
pub fn setup_dealer(
    files: [&KeyFiles; NODES],
    force: bool,
) -> eyre::Result<[NodePublicKeys; NODES]> {
    for f in files {
        refuse_existing(f, force)?;
    }
    use ark_ff::UniformRand;
    let mut rng = OsRng;
    let parts: [Fr; NODES] = [0; NODES].map(|_| Fr::rand(&mut rng));
    let keys: [NodeKeys; NODES] = [0; NODES].map(|_| NodeKeys::generate(&mut rng));
    for i in 0..NODES {
        let share = Share::new(parts[i], parts[(i + NODES - 1) % NODES]);
        write(files[i], &keys[i], share)?;
    }
    Ok([0, 1, 2].map(|i| keys[i].public_keys()))
}

fn refuse_existing(files: &KeyFiles, force: bool) -> eyre::Result<()> {
    if force {
        return Ok(());
    }
    for path in [
        files.enc_path(),
        files.sig_path(),
        files.master_share_path(),
    ] {
        if path.exists() {
            bail!(
                "{} exists; setup never overwrites node keys without --force (a new sig key is a \
                 new deployment, and a new master share must be sampled on all three nodes)",
                path.display()
            );
        }
    }
    Ok(())
}

fn write(files: &KeyFiles, keys: &NodeKeys, master: Share) -> eyre::Result<()> {
    files
        .write(keys)
        .with_context(|| format!("writing the keys into {}", files.dir().display()))?;
    write_master_share(files, master)
}

/// The keys of a newcomer's key directory, which holds no master share
/// yet (`setup --newcomer`); refused when it holds one (a node that already
/// joined a network is never a newcomer).
pub fn load_newcomer(dir: &Path) -> eyre::Result<NodeKeys> {
    let files = KeyFiles::new(dir);
    if files.master_share_path().exists() {
        bail!(
            "{} exists: this node already holds a master share, so it is not a newcomer (a \
             newcomer runs `sidecar-node setup --newcomer` into an empty key directory)",
            files.master_share_path().display()
        );
    }
    files.read().with_context(|| {
        format!(
            "reading the newcomer's keys in {} (run `sidecar-node setup --newcomer`)",
            dir.display()
        )
    })
}

/// The keys and master share of a key directory, as the node loads them.
pub fn load(dir: &Path) -> eyre::Result<(NodeKeys, Share)> {
    let files = KeyFiles::new(dir);
    let keys = files.read().with_context(|| {
        format!(
            "reading the node keys in {} (run `sidecar-node setup`)",
            dir.display()
        )
    })?;
    Ok((keys, read_master_share(&files)?))
}
