//! Whether a compiled circuit artifact on disk is older than its Noir source.
//!
//! The tests that read an example's compiled circuits
//! (`examples/<example>/circuits/<circuit>/target/<circuit>.json`, written by
//! `scripts/check-noir.sh examples/<example>`) or the prepared data directory
//! (`machine/data/circuits/<circuit>.json`, written by
//! `scripts/prepare-data.sh`) skip with a message when the artifact is
//! missing, and fail naming the artifact, the newer source file and the
//! refresh command when the artifact is older than its source: an artifact
//! compiled from an older source otherwise fails further in with a confusing
//! message (a parameter missing, a missing witness).
//!
//! A missing artifact skips through [`missing`], which fails the test
//! instead under `PSS_REQUIRE_DATA=1` ([`REQUIRE_DATA`]), so a run that
//! prepared the data (CI) cannot pass by skipping.
//!
//! A prepared copy's package is the one `scripts/prepare-data.sh` compiles it
//! from by default ([`prepared_package`]).
//!
//! A circuit's source is every `.nr` file under its package's `src/`, its
//! `Nargo.toml`, and the same of each package it names by `path = "..."`
//! inside this repository (round logic is in a library package; deps/ links
//! out of the repository and is pinned by toolchain.json, so it is not
//! followed). That is a subset of what `scripts/prepare-data.sh` compares
//! against, so it recompiles and copies a circuit this check calls stale;
//! `scripts/check-noir.sh` touches every artifact it compiled, as nargo keeps
//! an unchanged program's artifact with its old mtime.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// The environment variable that turns a test's skip for missing prepared
/// data (the data directory of `scripts/prepare-data.sh`, an example's
/// compiled circuits) into a failure: `PSS_REQUIRE_DATA=1`.
pub const REQUIRE_DATA: &str = "PSS_REQUIRE_DATA";

/// A test's prepared data is missing (`what`: the file and the command that
/// writes it). Panics under `PSS_REQUIRE_DATA=1`; otherwise prints a SKIPPED
/// line, and the caller returns without asserting anything.
pub fn missing(what: impl std::fmt::Display) {
    if std::env::var_os(REQUIRE_DATA).is_some_and(|v| v == "1") {
        panic!("{what} ({REQUIRE_DATA}=1 requires it)");
    }
    eprintln!("SKIPPED: {what}");
}

/// The repository root, without `..` steps so messages name readable paths.
pub fn repo() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    root.canonicalize().unwrap_or(root)
}

/// The prepared data directory: DATA_DIR, or machine/data, without `..`
/// steps so messages name readable paths.
pub fn data_dir() -> PathBuf {
    let dir = std::env::var_os("DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../data"));
    dir.canonicalize().unwrap_or(dir)
}

/// Every manifest file the repository ships (testvectors/manifests,
/// machine/circuits/manifests and each example's manifests/), sorted.
pub fn shipped_manifests() -> Vec<PathBuf> {
    let root = repo();
    let mut dirs = vec![
        root.join("testvectors/manifests"),
        root.join("machine/circuits/manifests"),
    ];
    for example in std::fs::read_dir(root.join("examples")).unwrap() {
        dirs.push(example.unwrap().path().join("manifests"));
    }
    let mut paths: Vec<PathBuf> = dirs
        .iter()
        .filter_map(|dir| std::fs::read_dir(dir).ok())
        .flatten()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|e| e == "json"))
        .collect();
    paths.sort();
    paths
}

/// An example's circuit package, `examples/<example>/circuits/<circuit>`.
pub fn package(example: &str, circuit: &str) -> PathBuf {
    repo()
        .join("examples")
        .join(example)
        .join("circuits")
        .join(circuit)
}

/// The artifact `scripts/check-noir.sh examples/<example>` compiles from
/// [`package`].
pub fn compiled(example: &str, circuit: &str) -> PathBuf {
    package(example, circuit).join(format!("target/{circuit}.json"))
}

/// The examples `scripts/prepare-data.sh` prepares by default, in its order:
/// the data directory holds the artifact of the first whose
/// `circuits/circuits.env` names a circuit.
const PREPARED: [&str; 5] = [
    "examples/amm",
    "examples/monty-hall",
    "examples/amm-tip",
    "examples/lending-tip",
    "machine",
];

/// The circuit package `scripts/prepare-data.sh` compiles the data
/// directory's `circuits/<circuit>.json` from, or `None` for a circuit none of
/// its default examples names (in `CIRCUITS`, or the machine's `EMBEDDED`).
pub fn prepared_package(circuit: &str) -> Option<PathBuf> {
    let root = repo();
    PREPARED.iter().map(|e| root.join(e)).find_map(|example| {
        let env = std::fs::read_to_string(example.join("circuits/circuits.env")).ok()?;
        env.lines()
            .filter_map(|l| {
                let l = l.trim();
                l.strip_prefix("CIRCUITS=")
                    .or_else(|| l.strip_prefix("EMBEDDED="))
            })
            .flat_map(|v| v.trim_matches('"').split_whitespace())
            .any(|c| c == circuit)
            .then(|| example.join("circuits").join(circuit))
    })
}

/// Panics naming `artifact`, the newer source file and
/// `scripts/prepare-data.sh` when `artifact`, the data directory's copy of
/// `circuit`, is older than the source of its [`prepared_package`].
pub fn require_prepared_fresh(artifact: &Path, circuit: &str) {
    let Some(package) = prepared_package(circuit) else {
        return;
    };
    if let Freshness::Stale {
        artifact,
        newest_source,
    } = freshness(artifact, &package)
    {
        stale(&artifact, &newest_source, "scripts/prepare-data.sh");
    }
}

/// An artifact against its source.
#[derive(Debug, PartialEq, Eq)]
pub enum Freshness {
    Fresh,
    /// `newest_source` was modified after `artifact` was written.
    Stale {
        artifact: PathBuf,
        newest_source: PathBuf,
    },
    Missing {
        artifact: PathBuf,
    },
}

/// `artifact` against the source of the circuit package `package`.
pub fn freshness(artifact: &Path, package: &Path) -> Freshness {
    let Ok(written) = std::fs::metadata(artifact).and_then(|m| m.modified()) else {
        return Freshness::Missing {
            artifact: artifact.to_path_buf(),
        };
    };
    match newest_source(package) {
        Some((modified, newest_source)) if modified > written => Freshness::Stale {
            artifact: artifact.to_path_buf(),
            newest_source,
        },
        _ => Freshness::Fresh,
    }
}

/// Whether a test may read `artifact`: true when it is fresh; false, through
/// [`missing`] naming it and `refresh`, when it is missing. Panics naming
/// it, the newer source file and `refresh` when it is stale.
pub fn usable(artifact: &Path, package: &Path, refresh: &str) -> bool {
    match freshness(artifact, package) {
        Freshness::Fresh => true,
        Freshness::Missing { artifact } => {
            missing(format!("{} is missing; run {refresh}", artifact.display()));
            false
        }
        Freshness::Stale {
            artifact,
            newest_source,
        } => stale(&artifact, &newest_source, refresh),
    }
}

fn stale(artifact: &Path, newest_source: &Path, refresh: &str) -> ! {
    panic!(
        "{} is older than its source {}; run {refresh}",
        artifact.display(),
        newest_source.display()
    )
}

/// The newest source file of `package` and the packages it depends on by
/// path inside the repository, with its modification time.
fn newest_source(package: &Path) -> Option<(SystemTime, PathBuf)> {
    let root = repo();
    let mut seen = BTreeSet::new();
    let mut pending = vec![package.to_path_buf()];
    let mut newest: Option<(SystemTime, PathBuf)> = None;
    let mut consider = |path: PathBuf| {
        if let Ok(modified) = std::fs::metadata(&path).and_then(|m| m.modified())
            && newest.as_ref().is_none_or(|(t, _)| modified > *t)
        {
            newest = Some((modified, path));
        }
    };
    while let Some(dir) = pending.pop() {
        let Ok(dir) = dir.canonicalize() else {
            continue;
        };
        if !dir.starts_with(&root) || !seen.insert(dir.clone()) {
            continue;
        }
        let nargo = dir.join("Nargo.toml");
        if let Ok(text) = std::fs::read_to_string(&nargo) {
            pending.extend(path_dependencies(&text).map(|p| dir.join(p)));
        }
        consider(nargo);
        let mut dirs = vec![dir.join("src")];
        while let Some(d) = dirs.pop() {
            for entry in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    dirs.push(path);
                } else if path.extension().is_some_and(|e| e == "nr") {
                    consider(path);
                }
            }
        }
    }
    newest
}

/// The `path = "..."` values of a Nargo.toml's dependency tables, skipping
/// comment lines.
fn path_dependencies(nargo: &str) -> impl Iterator<Item = &str> {
    nargo
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .flat_map(|l| l.match_indices("path").map(move |(i, _)| &l[i + 4..]))
        .filter_map(|rest| {
            let rest = rest.trim_start().strip_prefix('=')?.trim_start();
            let rest = rest.strip_prefix('"')?;
            Some(&rest[..rest.find('"')?])
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn path_dependencies_are_read_from_the_dependency_tables() {
        let nargo = "[package]\nname = \"x\"\n\n[dependencies]\n\
                     # a = { path = \"../commented\" }\n\
                     amm_tip = { path = \"../amm_tip\" }\n\
                     xpath = { path = \"../xpath\" }\n\
                     pss_core = { path = \"../../../../noir/pss_core\" }\n\
                     schnorr = { tag = \"v0.4.0\", git = \"https://example.org/schnorr\" }\n";
        assert_eq!(
            path_dependencies(nargo).collect::<Vec<_>>(),
            ["../amm_tip", "../xpath", "../../../../noir/pss_core"]
        );
    }

    // A round's source takes in the library packages it names by path inside
    // the repository (amm_tip, amm_total, pss_core, pss_utils), never deps/.
    #[test]
    fn a_rounds_source_is_its_package_and_its_path_dependencies_in_the_repository() {
        let (_, newest) = newest_source(&package("amm-tip", "amm_swap_tip")).unwrap();
        let newest = newest.canonicalize().unwrap();
        assert!(newest.starts_with(repo()), "{}", newest.display());
        assert!(newest_source(&package("amm-tip", "no_such_circuit")).is_none());
    }

    // A prepared copy's package is the first default example's that names it,
    // as prepare-data.sh keeps the first example's artifact.
    #[test]
    fn a_prepared_circuit_comes_from_the_first_example_that_names_it() {
        let root = repo();
        assert_eq!(
            prepared_package("pss_seed"),
            Some(root.join("examples/amm/circuits/pss_seed"))
        );
        assert_eq!(
            prepared_package("amm_swap_tip"),
            Some(root.join("examples/amm-tip/circuits/amm_swap_tip"))
        );
        assert_eq!(
            prepared_package("tip_counter"),
            Some(root.join("machine/circuits/tip_counter"))
        );
        assert_eq!(prepared_package("no_such_circuit"), None);
    }

    // An artifact written after its source is fresh; moved back before it,
    // stale, naming the newer source; absent, missing.
    #[test]
    fn an_artifact_older_than_its_source_is_stale() {
        let package = package("amm-tip", "amm_swap_tip");
        let dir = sidecar_test_fixtures::dirs::TempDir::new("artifact");
        let artifact = dir.path().join("artifact.json");
        assert_eq!(
            freshness(&artifact, &package),
            Freshness::Missing {
                artifact: artifact.clone()
            }
        );
        let file = std::fs::File::create(&artifact).unwrap();
        assert_eq!(freshness(&artifact, &package), Freshness::Fresh);
        file.set_modified(UNIX_EPOCH + Duration::from_secs(1))
            .unwrap();
        let state = freshness(&artifact, &package);
        let newest = newest_source(&package).map(|(_, p)| p).unwrap();
        assert_eq!(
            state,
            Freshness::Stale {
                artifact,
                newest_source: newest
            }
        );
    }
}
