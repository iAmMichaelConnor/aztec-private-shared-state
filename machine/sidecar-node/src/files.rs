//! The node's own files: its private directories (0700) and the files it
//! writes whole (keys, certificates, journals), each through a temporary
//! file and a rename.

use std::path::Path;

use eyre::Context;

pub(crate) use sidecar_core::keys::create_private_dir;

/// Write `bytes` to `path` whole ([`sidecar_core::keys::write_atomic`]);
/// a secret gets mode 0600, anything else 0644.
pub(crate) fn write_file(path: &Path, bytes: &[u8], secret: bool) -> eyre::Result<()> {
    sidecar_core::keys::write_atomic(path, bytes, if secret { 0o600 } else { 0o644 })
        .with_context(|| format!("writing {}", path.display()))
}
