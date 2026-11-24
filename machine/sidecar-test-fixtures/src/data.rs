//! The prepared circuits and CRS (`scripts/prepare-data.sh`), and the
//! manifests, read from their files.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use serde_json::Value;
use sidecar_core::crs::{self, Artifact, Circuit, Crs};
use sidecar_core::field::Fr;
use sidecar_core::registry;
use sidecar_core::testing::artifacts;

use crate::dirs::{data_dir, repo};

/// The prepared artifact of circuit `name`.
pub fn circuit_path(name: &str) -> PathBuf {
    data_dir().join("circuits").join(format!("{name}.json"))
}

/// A compiled circuit of the data directory, as JSON.
pub fn circuit_json(name: &str) -> Value {
    read_json(circuit_path(name))
}

pub use sidecar_core::testing::manifest;

/// The manifest of the machine's own test circuit `name`
/// (machine/circuits/manifests).
pub fn machine_manifest(name: &str) -> Value {
    read_json(repo().join(format!("machine/circuits/manifests/{name}.json")))
}

fn read_json(path: PathBuf) -> Value {
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The CRS files and the named circuits' artifacts that are missing.
fn missing(circuits: &[&str]) -> Vec<PathBuf> {
    let dir = data_dir();
    circuits
        .iter()
        .map(|c| circuit_path(c))
        .chain([dir.join("bn254_g1.dat"), dir.join("bn254_g2.dat")])
        .filter(|p| !p.exists())
        .collect()
}

/// The CRS sized for the machine's own circuits and the named ones.
fn read_crs(circuits: &[&str]) -> Crs {
    let dir = data_dir();
    let mut artifacts = registry::machine_artifacts().unwrap();
    artifacts.extend(
        circuits
            .iter()
            .map(|c| Artifact::read(&circuit_path(c)).unwrap()),
    );
    Crs::read(
        &dir.join("bn254_g1.dat"),
        &dir.join("bn254_g2.dat"),
        crs::crs_circuit_size(&artifacts),
    )
    .unwrap()
}

/// The CRS sized for the machine's own circuits and the named ones, read
/// from the prepared data directory. Panics naming every missing file, so no
/// suite passes without its circuits, and naming a circuit older than its
/// source.
pub fn require_crs(circuits: &[&str]) -> Crs {
    let missing: Vec<String> = missing(circuits)
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    assert!(
        missing.is_empty(),
        "circuits missing: {}; run scripts/prepare-data.sh (or set DATA_DIR)",
        missing.join(", ")
    );
    for c in circuits {
        artifacts::require_prepared_fresh(&circuit_path(c), c);
    }
    read_crs(circuits)
}

/// The vk hash of the prepared circuit `name`, built under a CRS sized for it
/// as a node builds it at REGISTER, once per process: what a test's contract
/// manifest declares for the circuit.
pub fn vk_hash(name: &str) -> Fr {
    static BUILT: OnceLock<Mutex<BTreeMap<String, Fr>>> = OnceLock::new();
    let built = BUILT.get_or_init(Default::default);
    if let Some(hash) = built.lock().unwrap().get(name) {
        return *hash;
    }
    let crs = require_crs(&[name]);
    let circuit = Circuit::new(Artifact::read(&circuit_path(name)).unwrap(), &crs.prover)
        .unwrap_or_else(|e| panic!("circuit {name}: no verification key: {e:#}"));
    built
        .lock()
        .unwrap()
        .insert(name.to_string(), circuit.vk_hash);
    circuit.vk_hash
}
