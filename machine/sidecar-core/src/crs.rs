//! The CRS (its `[crs]` config entry and its loader), compiled circuits and
//! their verification keys, and proof verification.
//!
//! Shared by the node (which proves and self-verifies) and the orchestrator (which
//! verifies every answer again).

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use co_builder::prelude::AcirFormat;
use co_noir::{
    Bn254, Bn254G1, HonkProof, Poseidon2Sponge, ProgramArtifact, UltraHonk,
    get_constraint_system_from_artifact, program_artifact_from_reader,
};
use co_noir_common::constants::PAIRING_POINT_ACCUMULATOR_SIZE;
use co_noir_common::crs::ProverCrs;
use co_noir_common::crs::parse::CrsParser;
use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::honk_proof::TranscriptFieldType;
use co_noir_common::keys::verification_key::{VerifyingKey, VerifyingKeyBarretenberg};
use co_noir_common::types::ZeroKnowledge;
use eyre::Context;
use serde::Deserialize;

use crate::field::Fr;
use crate::hash::vk_hash;

/// The verifier's G2 point (`[x]_2` of the CRS).
pub type G2 = ark_bn254::G2Affine;

/// The bb-format verification key of a circuit.
pub type BbVerifyingKey = VerifyingKeyBarretenberg<Bn254G1>;

// The proving scheme. Every round is proved as zero-knowledge
// UltraHonk with the Poseidon2 transcript (bb `--scheme ultra_honk --oracle_hash
// poseidon2`, ZK on), because that is the proof the contract's verifier checks
// and the verification key whose poseidon2 hash the contract pins. ZK on also
// sizes the CRS (the masking needs more points than the circuit size alone).
// Turning ZK off would leak witness information through the proof; another
// oracle hash (keccak) gives proofs and keys the Aztec verifier rejects.
/// ZK on, for every proof, key and CRS read in the machine.
pub const ZK: ZeroKnowledge = ZeroKnowledge::Yes;

/// A compiled Noir circuit (the nargo output JSON) with its constraint system and
/// size, before any CRS is read.
pub struct Artifact {
    pub name: String,
    pub program: ProgramArtifact,
    pub constraint_system: AcirFormat<Fr>,
    /// The circuit size the prover CRS must cover.
    pub circuit_size: usize,
}

impl Artifact {
    /// Parse a nargo artifact: the ABI and the bytecode, decoded to the ACIR program.
    pub fn from_json(name: &str, json: &[u8]) -> eyre::Result<Artifact> {
        let program = program_artifact_from_reader(json)
            .with_context(|| format!("parsing the compiled circuit `{name}`"))?;
        Self::from_program(name, program)
    }

    /// Read `<dir>/<name>.json`; the circuit is named after the file stem.
    pub fn read(path: &Path) -> eyre::Result<Artifact> {
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| eyre::eyre!("{} has no file name", path.display()))?;
        let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let program = program_artifact_from_reader(file)
            .with_context(|| format!("parsing {}", path.display()))?;
        Self::from_program(name, program)
    }

    fn from_program(name: &str, program: ProgramArtifact) -> eyre::Result<Artifact> {
        let constraint_system = get_constraint_system_from_artifact(&program);
        let circuit_size = co_noir::compute_circuit_size::<Bn254G1>(&constraint_system)
            .with_context(|| format!("computing the size of `{name}`"))?;
        Ok(Artifact {
            name: name.to_string(),
            program,
            constraint_system,
            circuit_size,
        })
    }
}

/// The circuit size the prover CRS is read for: that of the largest circuit.
pub fn crs_circuit_size<'a>(artifacts: impl IntoIterator<Item = &'a Artifact>) -> usize {
    artifacts
        .into_iter()
        .map(|a| a.circuit_size)
        .max()
        .unwrap_or(0)
}

/// The number of G1 points read for a circuit of `circuit_size`: with ZK, at least
/// twice the curve's subgroup size, as co-noir's CRS parser reads.
pub fn crs_points(circuit_size: usize) -> usize {
    circuit_size.max(2 * <Bn254G1 as HonkCurve<TranscriptFieldType>>::SUBGROUP_SIZE)
}

/// The CRS files and the circuits it is sized for.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrsFiles {
    /// The prover CRS (bn254_g1.dat).
    pub g1: PathBuf,
    /// The verifier's G2 point (bn254_g2.dat).
    pub g2: PathBuf,
    /// The compiled circuits (`<name>.json`) the deployment will register;
    /// the CRS is read for the largest of them and the registration circuit.
    #[serde(default)]
    pub circuits_dir: Option<PathBuf>,
    /// A circuit size to read the CRS for instead, when it is larger.
    #[serde(default)]
    pub circuit_size: Option<usize>,
}

/// The prover CRS and the verifier's G2 point.
#[derive(Clone)]
pub struct Crs {
    pub prover: Arc<ProverCrs<Bn254G1>>,
    pub g2: G2,
}

impl Crs {
    // Operator knob: DESIGN.md, "Configuration reference" ([crs] g1, g2).
    // Reads only the points the largest registered circuit needs (crs_points
    // of crs_circuit_size), so a file too short for a circuit fails here, at
    // start-up, not in a round.
    /// Read the first [`crs_points`]`(circuit_size)` G1 points and the G2 point.
    pub fn read(g1_path: &Path, g2_path: &Path, circuit_size: usize) -> eyre::Result<Crs> {
        let points = crs_points(circuit_size);
        let prover =
            CrsParser::<Bn254G1>::get_crs_g1(g1_path, circuit_size, ZK).with_context(|| {
                format!(
                    "reading {points} G1 points (circuit size {circuit_size}) from {}",
                    g1_path.display()
                )
            })?;
        Ok(Crs {
            prover: Arc::new(prover),
            g2: read_g2(g2_path)?,
        })
    }

    // Operator knob: DESIGN.md, "Configuration reference" ([crs]
    // circuits_dir, circuit_size). The CRS is sized for the largest circuit in
    // `circuits_dir` and the embedded registration and audit circuits, or for
    // `circuit_size` when that is larger.
    /// Read the CRS for the circuits of `files`.
    pub fn load(files: &CrsFiles) -> eyre::Result<Crs> {
        let mut artifacts = crate::registry::machine_artifacts()?;
        if let Some(dir) = &files.circuits_dir {
            let entries =
                std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?;
            for entry in entries {
                let path = entry?.path();
                if path.extension().is_some_and(|e| e == "json") {
                    artifacts.push(Artifact::read(&path)?);
                }
            }
        }
        let size = crs_circuit_size(&artifacts).max(files.circuit_size.unwrap_or(0));
        Self::read(&files.g1, &files.g2, size)
    }
}

/// Read the verifier's G2 point.
pub fn read_g2(path: &Path) -> eyre::Result<G2> {
    CrsParser::<Bn254G1>::get_crs_g2::<Bn254>(path)
        .with_context(|| format!("reading the G2 point from {}", path.display()))
}

/// A circuit ready to prove and verify: the artifact plus its bb-format verification
/// key and the key's hash.
pub struct Circuit {
    pub name: String,
    pub program: ProgramArtifact,
    pub constraint_system: AcirFormat<Fr>,
    /// The bb-format verification key (the ZK prover derives its masking from it).
    pub vk: BbVerifyingKey,
    /// poseidon2 over the vk fields: what a contract pins.
    pub vk_hash: Fr,
}

/// The verification key a `packages` row stores for circuit `name`: `vk` in
/// bb's byte format, decoded (canonical fields, points on the curve,
/// consistent metadata) and checked against the row's `vk_hash`, without
/// building it.
pub fn stored_vk(name: &str, vk: &[u8], vk_hash: Fr) -> eyre::Result<BbVerifyingKey> {
    let vk = BbVerifyingKey::from_buffer(vk)
        .map_err(|e| eyre::eyre!("decoding the stored verification key of `{name}`: {e:?}"))?;
    let stored = crate::hash::vk_hash(&vk);
    eyre::ensure!(
        stored == vk_hash,
        "the stored verification key of `{name}` hashes to {}, its row says {}",
        crate::field::fr_to_hex(stored),
        crate::field::fr_to_hex(vk_hash)
    );
    Ok(vk)
}

impl Circuit {
    /// The circuit with the verification key a `packages` row stores: `vk` in bb's
    /// byte format, decoded (canonical fields, points on the curve, consistent
    /// metadata) and checked against the row's `vk_hash`, without building it.
    /// REGISTER computed both from this circuit, so a row whose key does not hash
    /// to its vk_hash is a damaged store and is refused.
    pub fn with_stored_vk(artifact: Artifact, vk: &[u8], vk_hash: Fr) -> eyre::Result<Circuit> {
        let vk = stored_vk(&artifact.name, vk, vk_hash)?;
        Ok(Circuit {
            name: artifact.name,
            program: artifact.program,
            constraint_system: artifact.constraint_system,
            vk_hash,
            vk,
        })
    }

    /// Compute the verification key with the prover CRS (sized for this circuit or a
    /// larger one).
    pub fn new(artifact: Artifact, crs: &Arc<ProverCrs<Bn254G1>>) -> eyre::Result<Circuit> {
        let vk = verification_key(&artifact.constraint_system, crs)
            .with_context(|| format!("computing the verification key of `{}`", artifact.name))?;
        Ok(Circuit {
            name: artifact.name,
            program: artifact.program,
            constraint_system: artifact.constraint_system,
            vk_hash: vk_hash(&vk),
            vk,
        })
    }

    /// The number of public inputs a proof carries (parameters, then the return
    /// value; the pairing-point accumulator is not counted).
    pub fn public_input_count(&self) -> usize {
        public_input_count(&self.vk)
    }

    /// [`verify`] against this circuit's key.
    pub fn verify(&self, g2: G2, proof: &[u8], public_inputs: &[Fr]) -> eyre::Result<bool> {
        verify(&self.vk, g2, proof, public_inputs)
    }
}

// The tests' count of the verification keys built per thread.
#[cfg(any(test, feature = "testing"))]
thread_local! {
    static VK_BUILDS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// How many verification keys [`verification_key`] has built on the calling
/// thread: tests use it to show that a path reads a stored key instead.
#[cfg(any(test, feature = "testing"))]
pub fn vk_builds_on_this_thread() -> u64 {
    VK_BUILDS.with(std::cell::Cell::get)
}

/// The bb-format verification key of a constraint system, as `bb write_vk --scheme
/// ultra_honk --oracle_hash poseidon2` computes it.
pub fn verification_key(
    constraint_system: &AcirFormat<Fr>,
    crs: &Arc<ProverCrs<Bn254G1>>,
) -> eyre::Result<BbVerifyingKey> {
    #[cfg(any(test, feature = "testing"))]
    VK_BUILDS.with(|n| n.set(n.get() + 1));
    co_noir::generate_vk_barretenberg::<Bn254G1>(constraint_system, Arc::clone(crs))
}

/// The number of public inputs a proof under `vk` carries.
pub fn public_input_count(vk: &BbVerifyingKey) -> usize {
    (vk.num_public_inputs as usize).saturating_sub(PAIRING_POINT_ACCUMULATOR_SIZE as usize)
}

/// Verify a bb-format ZK UltraHonk proof (32-byte big-endian fields, no length
/// prefix) against a verification key and the G2 point. `Ok(false)`: a well-formed
/// proof whose constraints do not hold. `Err`: bytes that do not decode
/// canonically, or a public-input count that does not match the key.
pub fn verify(
    vk: &BbVerifyingKey,
    g2: G2,
    proof: &[u8],
    public_inputs: &[Fr],
) -> eyre::Result<bool> {
    let proof = HonkProof::<Fr>::from_buffer(proof).context("decoding the proof")?;
    verify_proof(vk, g2, proof, public_inputs)
}

pub(crate) fn verify_proof(
    vk: &BbVerifyingKey,
    g2: G2,
    proof: HonkProof<Fr>,
    public_inputs: &[Fr],
) -> eyre::Result<bool> {
    let expected = public_input_count(vk);
    eyre::ensure!(
        public_inputs.len() == expected,
        "{} public inputs given, the verification key has {expected}",
        public_inputs.len()
    );
    let key = VerifyingKey::<Bn254>::from_barretenberg_and_crs(vk.clone(), g2);
    UltraHonk::<Bn254G1, Poseidon2Sponge>::verify::<Bn254>(proof, public_inputs, &key, ZK)
}
