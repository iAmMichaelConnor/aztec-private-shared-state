//! Embeds the machine's own circuits, the registration circuit and the audit
//! circuit, from the prepared data directory.
//!
//! `scripts/prepare-data.sh` compiles both (machine/circuits/circuits.env,
//! EMBEDDED) into `<data dir>/circuits/`, the same compile path as every round
//! circuit. This script finds the two artifacts there and hands their absolute
//! paths to the crate as `PSS_REGISTRATION_ARTIFACT` and `PSS_AUDIT_ARTIFACT`,
//! which `registry` and `audit` embed with `include_bytes!`. A node therefore
//! needs no compiler and no extra file at run time, and the orchestrator embeds
//! the same bytes as the nodes it checks.
//!
//! Each artifact's `bytecode` must hash (SHA-256) to its line of
//! `embedded.sha256`, checked in beside this script: a node built from a
//! stale or different data directory would otherwise embed another circuit
//! than its peers and fail only at run time. The pin covers the bytecode,
//! not the whole file, whose `file_map` holds the build machine's paths.
//!
//! The data directory is `DATA_DIR` (the variable `scripts/prepare-data.sh`
//! writes to and the tests read), else `machine/data`; the variable must be
//! an absolute path. Cargo reruns this script when either artifact, the pin
//! file or the variable changes.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

const PINS: &str = "embedded.sha256";

const ARTIFACTS: [(&str, &str); 2] = [
    ("PSS_REGISTRATION_ARTIFACT", "sidecar_register"),
    ("PSS_AUDIT_ARTIFACT", "sidecar_audit"),
];

fn main() {
    // `cargo::error` fails the build with the message after the script ends.
    if let Err(message) = embed() {
        println!("cargo::error={message}");
    }
}

fn embed() -> Result<(), String> {
    println!("cargo:rerun-if-env-changed=DATA_DIR");
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("set by cargo"));
    let (data, from) = match std::env::var_os("DATA_DIR").map(PathBuf::from) {
        Some(dir) if dir.is_absolute() => (dir, "DATA_DIR"),
        Some(dir) => {
            return Err(format!(
                "DATA_DIR={} is not an absolute path; set it to the data directory scripts/prepare-data.sh wrote",
                dir.display()
            ));
        }
        None => (manifest.join("../data"), "the default machine/data"),
    };
    let data = data.canonicalize().unwrap_or(data);
    let pins = pins(&manifest.join(PINS))?;
    let mut missing = Vec::new();
    for (env, circuit) in ARTIFACTS {
        let path = data.join("circuits").join(format!("{circuit}.json"));
        println!("cargo:rerun-if-changed={}", path.display());
        if path.is_file() {
            check_pin(&path, circuit, &pins)?;
            println!("cargo:rustc-env={env}={}", path.display());
        } else {
            missing.push(path.display().to_string());
        }
    }
    if !missing.is_empty() {
        return Err(format!(
            "the embedded circuits are missing from the prepared data directory ({from}): {}. \
             Run scripts/prepare-data.sh (at least `scripts/prepare-data.sh machine`), \
             with DATA_DIR set to the same directory if it is not machine/data",
            missing.join(", ")
        ));
    }
    Ok(())
}

// The pinned digests by circuit: `<circuit> <64 hex digits>` per line,
// `#` comments and blank lines skipped.
fn pins(path: &Path) -> Result<BTreeMap<String, String>, String> {
    println!("cargo:rerun-if-changed={}", path.display());
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(
            |line| match line.split_whitespace().collect::<Vec<_>>()[..] {
                [circuit, digest] => Ok((circuit.to_string(), digest.to_string())),
                _ => Err(format!(
                    "{}: `{line}` is not `<circuit> <sha256>`",
                    path.display()
                )),
            },
        )
        .collect()
}

// Refuse an artifact whose bytecode does not hash to its pin.
fn check_pin(path: &Path, circuit: &str, pins: &BTreeMap<String, String>) -> Result<(), String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let artifact: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("{} is not a nargo artifact: {e}", path.display()))?;
    let bytecode = artifact["bytecode"]
        .as_str()
        .ok_or_else(|| format!("{} has no `bytecode`", path.display()))?;
    let digest: String = Sha256::digest(bytecode.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let pinned = pins
        .get(circuit)
        .ok_or_else(|| format!("machine/sidecar-core/{PINS} pins no `{circuit}`"))?;
    if digest != *pinned {
        return Err(format!(
            "{} is not the pinned {circuit}: its bytecode hashes to {digest}, \
             machine/sidecar-core/{PINS} pins {pinned}. Rerun scripts/prepare-data.sh \
             (FORCE=1 recompiles) with the pinned toolchain (scripts/bootstrap.sh); if \
             machine/circuits/{circuit} changed on purpose, put the new digest on its line \
             of {PINS}",
            path.display()
        ));
    }
    Ok(())
}
