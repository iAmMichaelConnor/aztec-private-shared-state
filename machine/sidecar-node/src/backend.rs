//! The node's store behind one type: [`NodeStore`] is whichever backend the
//! config names (`[store] backend`) as a `Box<dyn Store>`, so the HTTP layer,
//! the admin socket and the pruning job are written once.

use sidecar_core::store::{MemoryStore, Store};

use crate::config::StoreConfig;
use crate::local::LocalStore;
use crate::postgres::PostgresStore;

/// A node's store, whatever its backend: a boxed store is a store
/// (sidecar-core's blanket impl), so nothing forwards by hand.
pub type NodeStore = Box<dyn Store>;

/// Open the backend the config names.
pub fn open(config: &StoreConfig) -> eyre::Result<NodeStore> {
    Ok(match config {
        StoreConfig::Memory => Box::new(MemoryStore::new()),
        StoreConfig::Postgres { url } => Box::new(PostgresStore::connect(url)?),
        StoreConfig::Local { path } => Box::new(LocalStore::open(path)?),
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn every_backend_is_wired_and_a_bad_location_is_refused() {
        assert!(open(&StoreConfig::Memory).is_ok());
        let postgres = StoreConfig::Postgres {
            url: "not a url".into(),
        };
        let err = open(&postgres).err().unwrap();
        assert!(format!("{err:#}").contains("does not parse"), "{err:#}");
        // A directory below a regular file cannot be created; nothing is written.
        let local = StoreConfig::Local {
            path: Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml/store"),
        };
        let err = open(&local).err().unwrap();
        assert!(
            format!("{err:#}").contains("creating the local store"),
            "{err:#}"
        );
    }
}
