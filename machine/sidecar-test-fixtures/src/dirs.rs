//! Where the tests read and write: scratch directories under TXE_TMP_ROOT,
//! the repository root and the prepared data directory.

use std::path::{Path, PathBuf};

// Where the tests put their files. Every temporary directory,
// key directory, certificate set, store directory and admin socket of the
// machine's tests lives under TXE_TMP_ROOT (default .runs/tmp in the
// repository, gitignored), never the system temp directory, which is shared
// and may be small or wiped; each test makes its own short-named directory
// there and removes it when it ends. The root must be short: an admin
// socket's path is limited to 107 bytes, so a checkout at a deep path sets
// TXE_TMP_ROOT to a short directory.
/// The root of every temporary file the tests write.
pub fn tmp_root() -> PathBuf {
    std::env::var_os("TXE_TMP_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .ancestors()
                .nth(2)
                .expect("the repository root")
                .join(".runs/tmp")
        })
}

/// A directory under [`tmp_root`] named for its test and process, emptied
/// when made and removed on drop.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(label: &str) -> Self {
        let dir = tmp_root().join(format!("{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub use sidecar_core::testing::artifacts::{data_dir, repo, shipped_manifests};
