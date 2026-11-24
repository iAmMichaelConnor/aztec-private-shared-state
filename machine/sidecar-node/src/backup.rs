//! Node backups (docs/ARCHITECTURE.md section 6, "Node-held state",
//! recovery; DESIGN.md, "Recovery"): the node's store and, separately, its
//! key directory, each written as one file encrypted under a backup key the
//! node's operator holds offline. The key is never derived from the node's
//! keys and never kept on the node's disk: the operator hands it to each
//! command (from removable media, or on standard input) and the node keeps
//! it in memory for that command only.
//!
//! ```text
//! file      MAGIC (8 bytes) ‖ kind (1: store, 2: key directory) ‖ party ‖
//!           created_at (u64, unix seconds) ‖ nonce (12 bytes) ‖ sealed
//! sealed    ChaCha20-Poly1305 under the backup key and the nonce, the header
//!           (everything before it) as associated data, of the plaintext
//! store     STORE_FORMAT (6), then per namespace every row of
//!           sidecar_core::backup's export, this node's pairs and holder blobs
//!           included, in the node's codec
//! keys      KEYS_FORMAT (1), then each key file of the key directory by name
//!           and bytes
//! ```
//!
//! A store backup of another format is refused, naming both formats: take
//! a new one. The two formats are numbered apart, so a store format change
//! leaves every key directory backup readable.
//!
//! The store backup is taken through the admin socket ([`write_store`]),
//! each namespace read under its lock, while the node serves rounds; it is
//! restored by a delta resync (`recovery::restore`). The key directory's is
//! read and written by the CLI itself ([`write_keys`], [`restore_keys`]),
//! with the node stopped for a restore.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sidecar_core::Refusal;
use sidecar_core::backup::{ExportCounts, NamespaceExport, StoreExport};
use sidecar_core::field::RequestId;
use sidecar_core::keys::KeyFiles;
use sidecar_core::pipeline::Node;
use sidecar_core::state::VersionViews;
use sidecar_core::store::{Store, ValueRow};
use zeroize::Zeroize;

use crate::codec::{Decoded, Reader, Writer};

/// The first bytes of every backup file.
pub const MAGIC: &[u8; 8] = b"pssbkup1";
/// A store backup's plaintext format; its first byte.
const STORE_FORMAT: u8 = 6;
/// A key directory backup's plaintext format; its first byte.
const KEYS_FORMAT: u8 = 1;
/// The header's length: magic, kind, party, created_at, nonce.
const HEADER_LEN: usize = 8 + 1 + 1 + 8 + NONCE_LEN;
/// The key's length in bytes.
pub const KEY_LEN: usize = 32;

/// What a backup file holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Store = 1,
    Keys = 2,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Store => "a store backup",
            Kind::Keys => "a key directory backup",
        }
    }
}

/// The operator's backup key: 32 random bytes, written as 64 hex digits.
/// Its `Debug` hides it, and its bytes are overwritten when it is dropped
/// (as is every text form of it this module makes or reads).
#[derive(Clone, PartialEq, Eq)]
pub struct BackupKey([u8; KEY_LEN]);

impl Drop for BackupKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl BackupKey {
    /// A fresh key from the OS's random source.
    pub fn generate() -> eyre::Result<Self> {
        let mut key = BackupKey([0u8; KEY_LEN]);
        SystemRandom::new()
            .fill(&mut key.0)
            .map_err(|_| eyre::eyre!("the OS random source failed"))?;
        Ok(key)
    }

    /// The key from its text form (64 hex digits, `0x` optional, surrounding
    /// whitespace ignored).
    pub fn parse(text: &str) -> Result<Self, String> {
        let digits = text.trim();
        let digits = digits.strip_prefix("0x").unwrap_or(digits);
        if digits.len() != 2 * KEY_LEN || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("a backup key is {} hex digits", 2 * KEY_LEN));
        }
        let mut key = BackupKey([0u8; KEY_LEN]);
        for (i, byte) in key.0.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&digits[2 * i..2 * i + 2], 16).map_err(|e| e.to_string())?;
        }
        Ok(key)
    }

    /// The key's text form, 64 lowercase hex digits.
    pub fn to_text(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn aead(&self) -> LessSafeKey {
        LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, &self.0).expect("a 32-byte ChaCha20 key"),
        )
    }
}

impl fmt::Debug for BackupKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BackupKey(..)")
    }
}

impl Serialize for BackupKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut text = self.to_text();
        let out = s.serialize_str(&text);
        text.zeroize();
        out
    }
}

impl<'de> Deserialize<'de> for BackupKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut text = String::deserialize(d)?;
        let key = BackupKey::parse(&text);
        text.zeroize();
        key.map_err(serde::de::Error::custom)
    }
}

/// Read the backup key the operator gives: the file at `path`, or standard
/// input for `-`. Refuses a file inside any of `node_dirs` (the node's key
/// directory, run directory and store directory): the key is held offline,
/// never on the node's disk.
pub fn read_key(path: &Path, node_dirs: &[&Path]) -> eyre::Result<BackupKey> {
    let mut text = if path == Path::new("-") {
        let mut text = String::new();
        io::stdin().read_to_string(&mut text)?;
        text
    } else {
        let full = fs::canonicalize(path)
            .map_err(|e| eyre::eyre!("reading the backup key {}: {e}", path.display()))?;
        for dir in node_dirs {
            if let Ok(dir) = fs::canonicalize(dir)
                && full.starts_with(&dir)
            {
                eyre::bail!(
                    "the backup key {} is inside the node's directory {}: keep it offline \
                     (removable media, or `-` for standard input), never on the node's disk",
                    path.display(),
                    dir.display()
                );
            }
        }
        fs::read_to_string(&full)
            .map_err(|e| eyre::eyre!("reading the backup key {}: {e}", path.display()))?
    };
    let key = BackupKey::parse(&text);
    text.zeroize();
    key.map_err(|e| eyre::eyre!("the backup key {}: {e}", path.display()))
}

/// Write a fresh backup key to `out` (mode 0600, never over an existing
/// file).
pub fn write_new_key(out: &Path) -> eyre::Result<()> {
    let key = BackupKey::generate()?;
    let mut text = format!("{}\n", key.to_text());
    let written = write_new(out, text.as_bytes());
    text.zeroize();
    written.map_err(|e| eyre::eyre!("writing the backup key {}: {e}", out.display()))
}

/// Create `path` (mode 0600) and write `bytes`, refusing an existing file.
fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Seal `plaintext` as a backup file of `kind` for node `party`.
pub fn seal(
    key: &BackupKey,
    kind: Kind,
    party: usize,
    created_at: u64,
    plaintext: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let party = u8::try_from(party).map_err(|_| format!("party {party} is not a node index"))?;
    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| "the OS random source failed".to_string())?;
    let mut out = Vec::with_capacity(HEADER_LEN + plaintext.len() + 16);
    out.extend_from_slice(MAGIC);
    out.push(kind as u8);
    out.push(party);
    out.extend_from_slice(&created_at.to_le_bytes());
    out.extend_from_slice(&nonce);
    let mut sealed = plaintext;
    key.aead()
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&out[..HEADER_LEN]),
            &mut sealed,
        )
        .map_err(|_| "sealing the backup failed".to_string())?;
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// A backup file's header, read before it is opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub kind: Kind,
    pub party: usize,
    pub created_at: u64,
}

/// Open the backup file `bytes` under `key`: its header and plaintext.
/// Refuses another kind than `kind`, and a file that is not a backup, is
/// cut short, or does not open under the key (another key, or changed).
pub fn open(key: &BackupKey, kind: Kind, bytes: &[u8]) -> Result<(Header, Vec<u8>), String> {
    if bytes.len() < HEADER_LEN || &bytes[..8] != MAGIC {
        return Err("not a sidecar-node backup file".into());
    }
    let found = match bytes[8] {
        1 => Kind::Store,
        2 => Kind::Keys,
        k => return Err(format!("unknown backup kind {k}")),
    };
    if found != kind {
        return Err(format!("{}, not {}", found.name(), kind.name()));
    }
    let header = Header {
        kind,
        party: bytes[9] as usize,
        created_at: u64::from_le_bytes(bytes[10..18].try_into().expect("8 bytes")),
    };
    let nonce: [u8; NONCE_LEN] = bytes[18..HEADER_LEN].try_into().expect("12 bytes");
    let mut sealed = bytes[HEADER_LEN..].to_vec();
    let plain = key
        .aead()
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&bytes[..HEADER_LEN]),
            &mut sealed,
        )
        .map_err(|_| {
            "the backup does not open under this backup key (another key, or the file changed)"
                .to_string()
        })?;
    let len = plain.len();
    sealed.truncate(len);
    Ok((header, sealed))
}

// ---------------------------------------------------------------------------
// The store backup
// ---------------------------------------------------------------------------

/// The store backup's plaintext.
pub fn encode_export(export: &StoreExport) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(STORE_FORMAT);
    w.count(export.namespaces.len());
    for ns in &export.namespaces {
        w.fr(ns.namespace);
        w.namespace_row(&ns.row);
        w.count(ns.manifests.len());
        ns.manifests.iter().for_each(|m| w.manifest_row(m));
        w.count(ns.packages.len());
        ns.packages.iter().for_each(|p| w.package_row(p));
        w.count(ns.versions.len());
        ns.versions.iter().for_each(|v| w.tip_version(v));
        w.count(ns.nodes.len());
        for (key, hash, node) in &ns.nodes {
            w.str(key);
            w.fr(*hash);
            w.tree_node(node);
        }
        w.count(ns.values.len());
        for (key, v) in &ns.values {
            w.str(key);
            w.vec(&v.vec);
            w.fr(v.note_hash);
            w.fr(v.request_id.fr());
        }
        w.count(ns.consumed.len());
        ns.consumed.iter().for_each(|c| w.consumed_row(c));
        w.count(ns.receipts.len());
        ns.receipts.iter().for_each(|r| w.receipt_row(r));
        w.count(ns.requests.len());
        ns.requests.iter().for_each(|r| w.request_row(r));
        w.count(ns.blobs.len());
        for (key, name, bytes) in &ns.blobs {
            w.str(key);
            w.str(name);
            w.bytes(bytes);
        }
    }
    w.out
}

fn many<T>(
    r: &mut Reader<'_>,
    mut f: impl FnMut(&mut Reader<'_>) -> Decoded<T>,
) -> Decoded<Vec<T>> {
    (0..r.count()?).map(|_| f(r)).collect()
}

/// Read a store backup's plaintext back, for node `party`. Refuses another
/// format than `STORE_FORMAT`, naming both.
pub fn decode_export(party: usize, bytes: &[u8]) -> Decoded<StoreExport> {
    let mut r = Reader::new(bytes);
    let format = r.u8()?;
    if format != STORE_FORMAT {
        return Err(format!(
            "a store backup of format {format}; this node reads format {STORE_FORMAT} \
             only: take a new store backup"
        ));
    }
    let namespaces = many(&mut r, |r| {
        Ok(NamespaceExport {
            namespace: r.fr()?,
            row: r.namespace_row()?,
            manifests: many(r, |r| r.manifest_row())?,
            packages: many(r, |r| r.package_row())?,
            versions: many(r, |r| r.tip_version())?,
            nodes: many(r, |r| Ok((r.str()?, r.fr()?, r.tree_node()?)))?,
            values: many(r, |r| {
                let key = r.str()?;
                Ok((
                    key,
                    ValueRow {
                        vec: r.vec()?,
                        note_hash: r.fr()?,
                        request_id: RequestId(r.fr()?),
                    },
                ))
            })?,
            consumed: many(r, |r| r.consumed_row())?,
            receipts: many(r, |r| r.receipt_row())?,
            requests: many(r, |r| r.request_row())?,
            blobs: many(r, |r| Ok((r.str()?, r.str()?, r.bytes()?)))?,
        })
    })?;
    r.finish()?;
    Ok(StoreExport { party, namespaces })
}

/// Back up `node`'s store to `out`, sealed under `key`: every namespace,
/// each read under its lock right after its versions are marked against
/// the node's own chain view `views` (`sidecar_core::backup::export`). 409
/// if `out` exists; 500 if it cannot be written. Returns what it holds.
pub fn write_store<S: Store>(
    node: &Node<S>,
    views: &VersionViews<'_>,
    out: &Path,
    key: &BackupKey,
    now: u64,
) -> Result<ExportCounts, Refusal> {
    if out.exists() {
        return Err(Refusal::conflict(format!(
            "backup: {} exists; a backup never overwrites a file",
            out.display()
        )));
    }
    let export = sidecar_core::backup::export(node, views)?;
    let sealed = seal(key, Kind::Store, node.index, now, encode_export(&export))
        .map_err(|e| Refusal::mpc_failure(format!("backup: {e}")))?;
    write_new(out, &sealed)
        .map_err(|e| Refusal::mpc_failure(format!("backup: writing {}: {e}", out.display())))?;
    Ok(export.counts())
}

/// Read the store backup at `path` for node `party` under `key`. 400 when
/// it is not one, does not open, or is another node's.
pub fn read_store(path: &Path, key: &BackupKey, party: usize) -> Result<StoreExport, Refusal> {
    let refuse = |why: String| Refusal::bad_request(format!("restore: {}: {why}", path.display()));
    let bytes = fs::read(path).map_err(|e| refuse(e.to_string()))?;
    let (header, plain) = open(key, Kind::Store, &bytes).map_err(refuse)?;
    if header.party != party {
        return Err(refuse(format!(
            "the backup is node {}'s, not this node's ({party})",
            header.party
        )));
    }
    decode_export(party, &plain).map_err(|e| refuse(format!("does not decode: {e}")))
}

// ---------------------------------------------------------------------------
// The key directory backup
// ---------------------------------------------------------------------------

/// The key directory's files a backup carries, those present.
const KEY_FILE_NAMES: [&str; 7] = [
    KeyFiles::ENC,
    KeyFiles::PREVIOUS_ENC,
    KeyFiles::ROTATED_AT,
    KeyFiles::SIG,
    KeyFiles::MASTER_SHARE,
    KeyFiles::EPOCHS,
    crate::replace::KEY_SETS_FILE,
];

/// The key files a directory may lack: those of a rotation window, the
/// secret-shared on-chain epochs of a node that holds none, and the declared
/// key-set rotations of a node that never took part in a replacement.
const OPTIONAL_KEY_FILES: [&str; 4] = [
    KeyFiles::PREVIOUS_ENC,
    KeyFiles::ROTATED_AT,
    KeyFiles::EPOCHS,
    crate::replace::KEY_SETS_FILE,
];

/// Back up the key directory of `files` (node `party`) to `out`, sealed
/// under `key`. Refuses a directory without its enc, sig and master files,
/// and an existing `out`. Returns the names of the files it holds.
pub fn write_keys(
    files: &KeyFiles,
    party: usize,
    out: &Path,
    key: &BackupKey,
    now: u64,
) -> eyre::Result<Vec<String>> {
    let mut w = Writer::new();
    w.u8(KEYS_FORMAT);
    let mut held = Vec::new();
    for name in KEY_FILE_NAMES {
        let path = files.dir().join(name);
        match fs::read(&path) {
            Ok(bytes) => held.push((name.to_string(), bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                eyre::ensure!(
                    OPTIONAL_KEY_FILES.contains(&name),
                    "the key directory has no {}",
                    path.display()
                );
            }
            Err(e) => eyre::bail!("reading {}: {e}", path.display()),
        }
    }
    w.count(held.len());
    for (name, bytes) in &held {
        w.str(name);
        w.bytes(bytes);
    }
    let sealed = seal(key, Kind::Keys, party, now, w.out).map_err(|e| eyre::eyre!(e))?;
    write_new(out, &sealed).map_err(|e| eyre::eyre!("writing {}: {e}", out.display()))?;
    Ok(held.into_iter().map(|(name, _)| name).collect())
}

/// Restore the key directory backup at `backup` (node `party`'s) under
/// `key` into the directory of `files`: creates it (mode 0700) and writes
/// each file (mode 0600). Refuses another node's backup and a directory
/// that already holds any of the files (run it with the node stopped, into
/// the lost directory). Returns the names of the files written.
pub fn restore_keys(
    files: &KeyFiles,
    party: usize,
    backup: &Path,
    key: &BackupKey,
) -> eyre::Result<Vec<String>> {
    let bytes = fs::read(backup).map_err(|e| eyre::eyre!("reading {}: {e}", backup.display()))?;
    let (header, plain) =
        open(key, Kind::Keys, &bytes).map_err(|e| eyre::eyre!("{}: {e}", backup.display()))?;
    eyre::ensure!(
        header.party == party,
        "{}: the backup is node {}'s key directory, not this node's ({party})",
        backup.display(),
        header.party
    );
    let mut r = Reader::new(&plain);
    let decoded = (|| -> Decoded<Vec<(String, Vec<u8>)>> {
        let format = r.u8()?;
        if format != KEYS_FORMAT {
            return Err(format!("unknown key backup format {format}"));
        }
        let files = many(&mut r, |r| Ok((r.str()?, r.bytes()?)))?;
        r.finish()?;
        Ok(files)
    })()
    .map_err(|e| eyre::eyre!("{}: does not decode: {e}", backup.display()))?;
    let dir: PathBuf = files.dir().to_path_buf();
    for (name, _) in &decoded {
        eyre::ensure!(
            KEY_FILE_NAMES.contains(&name.as_str()),
            "{}: names a file `{name}` that is not a key file",
            backup.display()
        );
        let path = dir.join(name);
        eyre::ensure!(
            !path.exists(),
            "{} exists: a key restore writes into a lost key directory only",
            path.display()
        );
    }
    crate::files::create_private_dir(&dir)
        .map_err(|e| eyre::eyre!("creating {}: {e}", dir.display()))?;
    for (name, bytes) in &decoded {
        let path = dir.join(name);
        write_new(&path, bytes).map_err(|e| eyre::eyre!("writing {}: {e}", path.display()))?;
    }
    Ok(decoded.into_iter().map(|(name, _)| name).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> BackupKey {
        BackupKey([b; KEY_LEN])
    }

    #[test]
    fn a_key_round_trips_as_text_and_hides_in_debug() {
        let k = BackupKey::generate().unwrap();
        assert_eq!(
            BackupKey::parse(&format!("0x{}\n", k.to_text())).unwrap(),
            k
        );
        assert_eq!(format!("{k:?}"), "BackupKey(..)");
        assert!(BackupKey::parse("abcd").is_err());
        assert!(BackupKey::parse(&"zz".repeat(KEY_LEN)).is_err());
        let json = serde_json::to_string(&k).unwrap();
        assert_eq!(serde_json::from_str::<BackupKey>(&json).unwrap(), k);
    }

    #[test]
    fn a_sealed_backup_opens_under_its_key_only_and_unchanged() {
        let sealed = seal(&key(1), Kind::Store, 2, 77, b"rows".to_vec()).unwrap();
        let (header, plain) = open(&key(1), Kind::Store, &sealed).unwrap();
        assert_eq!(
            header,
            Header {
                kind: Kind::Store,
                party: 2,
                created_at: 77
            }
        );
        assert_eq!(plain, b"rows");
        let err = open(&key(2), Kind::Store, &sealed).unwrap_err();
        assert!(err.contains("does not open"), "{err}");
        let err = open(&key(1), Kind::Keys, &sealed).unwrap_err();
        assert!(err.contains("not a key directory backup"), "{err}");
        // the header is bound: another party or time does not open
        let mut moved = sealed.clone();
        moved[9] = 1;
        assert!(open(&key(1), Kind::Store, &moved).is_err());
        let mut flipped = sealed.clone();
        *flipped.last_mut().unwrap() ^= 1;
        assert!(open(&key(1), Kind::Store, &flipped).is_err());
        assert!(open(&key(1), Kind::Store, b"pssbkup").is_err());
        // two seals of one plaintext differ (a fresh nonce each)
        let again = seal(&key(1), Kind::Store, 2, 77, b"rows".to_vec()).unwrap();
        assert_ne!(again, sealed);
    }
}
