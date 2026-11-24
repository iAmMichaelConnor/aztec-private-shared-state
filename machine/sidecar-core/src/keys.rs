//! A node's long-term keys: two independently generated Grumpkin scalars, the
//! record key `K_i` and the key id derived from the encryption scalar, and the
//! files a node keeps them in.
//!
//! ```text
//! enc     uniform mod q, generated at setup     ECDH: INPUT_SHARED envelopes; names K_i
//! sig     uniform mod q, generated at setup     Schnorr: result, registry and receipt signatures
//! enc_pk  = enc · G,  sig_pk = sig · G          both published and pinned
//! K_i     = poseidon2([enc.lo, enc.hi, SIDECAR_SEAL_KEY])   the record key, never leaves the node
//! key_id  = poseidon2([enc_pk.x, enc_pk.y]) as 32 bytes big-endian, first 8 bytes
//! ```
//!
//! `q` is the Grumpkin scalar modulus. `(enc.lo, enc.hi)` are the low and high
//! 128 bits of the scalar, Noir's `EmbeddedCurveScalar` limbs: the scalar does
//! not fit one BN254 field element, the limbs do.
//!
//! Only `enc` rotates. During a rotation's grace window the node also holds the
//! previous `enc` scalar and the time it was replaced: record thirds open
//! under either key id, envelopes under either scalar, and everything is
//! sealed under the current one. The window's length is the node's
//! configuration; [`NodeKeys::grace_ends_at`] says when it ends.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use ark_ff::{BigInteger, PrimeField, UniformRand, Zero};
use ark_std::rand::{CryptoRng, RngCore};

use crate::epochs::EpochKeys;
use crate::field::{Fr, fr_to_be_bytes};
use crate::grumpkin::{
    Fq, Point, coordinates, fixed_base_mul, mul, point_to_wire, scalar_to_limbs,
};
use crate::hash::poseidon2_hash;
use crate::response::NodePublicKeys;

/// The record-key separator: ASCII "sidecar.seal_key" read as a big-endian
/// integer (17 bytes, below the field modulus).
pub const SIDECAR_SEAL_KEY: &[u8] = b"sidecar.seal_key";

/// Bytes of a record key id.
pub const KEY_ID_LEN: usize = 8;

/// A short ASCII label as a field element: its bytes read as a big-endian
/// integer, as the machine's other separators (`SIDECAR_NSK_APP`) are written.
/// Panics on a label longer than 31 bytes.
pub fn label_field(label: &[u8]) -> Fr {
    assert!(label.len() <= 31, "a label field holds at most 31 bytes");
    Fr::from_be_bytes_mod_order(label)
}

// The record key K_i = poseidon2([enc.lo, enc.hi,
// SIDECAR_SEAL_KEY]). It is a field element because the record cipher is the
// field-native Poseidon2 AE; it is derived from the encryption scalar, so the
// published enc_pk names it through the key id and rotating enc rotates it. The
// separator keeps K_i distinct from any other Poseidon2 use of the scalar's
// limbs. Changing the separator is a record-key rotation: old records no longer
// open.
/// The record key of an encryption scalar.
pub fn record_key(enc: Fq) -> Fr {
    let (lo, hi) = scalar_to_limbs(enc);
    poseidon2_hash(&[lo, hi, label_field(SIDECAR_SEAL_KEY)])
}

// The record key id is the first 8 bytes of poseidon2([enc_pk.x,
// enc_pk.y]) written as 32 bytes big-endian. Every sealed third starts with it,
// so a node picks the right key during an enc rotation's grace window and
// refuses a third sealed under another node's key (or a retired key of its own)
// with a clear message instead of a tag failure. 8 bytes are a label, not a
// security parameter: the tag authenticates. Poseidon2 keeps the machine to one
// hash family; a client computes the id from the enc_pk it pins.
/// The 8-byte key id of an encryption public key.
pub fn key_id(enc_pk: Point) -> [u8; KEY_ID_LEN] {
    let (x, y) = coordinates(enc_pk);
    fr_to_be_bytes(poseidon2_hash(&[x, y]))[..KEY_ID_LEN]
        .try_into()
        .expect("a field element is 32 bytes")
}

/// One encryption scalar with everything derived from it.
#[derive(Clone)]
struct EncKey {
    scalar: Fq,
    pk: Point,
    seal_key: Fr,
    key_id: [u8; KEY_ID_LEN],
}

// Every copy of an encryption scalar, and the record key derived from it,
// is overwritten when dropped: the previous scalar when its grace window
// ends (`NodeKeys::retire_previous_enc`) and with it every clone of the key
// set that held it.
impl Drop for EncKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.scalar.zeroize();
        self.seal_key.zeroize();
    }
}

impl EncKey {
    fn new(scalar: Fq) -> Result<Self, String> {
        if scalar.is_zero() {
            return Err("the encryption scalar is zero".into());
        }
        let pk = fixed_base_mul(scalar);
        Ok(EncKey {
            scalar,
            pk,
            seal_key: record_key(scalar),
            key_id: key_id(pk),
        })
    }
}

/// One node's keys: the current encryption scalar, during a rotation's grace
/// window the previous one with the time (unix seconds) it was replaced, and
/// the signing scalar. `Debug` prints the public half only.
#[derive(Clone)]
pub struct NodeKeys {
    enc: EncKey,
    previous: Option<(EncKey, u64)>,
    sig: Fq,
    sig_pk: Point,
    /// The `enc` scalars secret-shared on-chain intake contracts name by epoch.
    epochs: EpochKeys,
}

/// A uniform non-zero scalar mod q: a fresh `enc` or `sig` scalar.
pub fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Fq {
    loop {
        let scalar = Fq::rand(rng);
        if !scalar.is_zero() {
            return scalar;
        }
    }
}

impl NodeKeys {
    // A node holds two scalars, enc and sig, each drawn uniformly
    // mod q from the OS CSPRNG at node setup, with no common root. The same
    // secret never serves both an ECDH oracle (envelopes, records) and a Schnorr
    // signing oracle (results, registry answers, receipts), so no
    // cross-protocol argument is needed, and the two keys have separate
    // lifetimes: enc rotates with a grace window (`rotate_enc`), sig never
    // rotates, because contracts and clients pin sig_pk and a new sig key is a
    // new deployment of every namespace that pins it. Backing up a node means
    // backing up both scalars and the master share (`KeyFiles`).
    /// Fresh keys from `rng` (the OS CSPRNG at node setup).
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let enc = random_scalar(rng);
        let sig = random_scalar(rng);
        Self::from_scalars(enc, sig).expect("both scalars are non-zero")
    }

    /// Keys from stored scalars. Refuses a zero scalar.
    pub fn from_scalars(enc: Fq, sig: Fq) -> Result<Self, String> {
        if sig.is_zero() {
            return Err("the signing scalar is zero".into());
        }
        Ok(NodeKeys {
            enc: EncKey::new(enc)?,
            previous: None,
            sig,
            sig_pk: fixed_base_mul(sig),
            epochs: EpochKeys::default(),
        })
    }

    /// These keys with `previous` as the previous encryption scalar, replaced
    /// at `rotated_at` (unix seconds) and still accepted for opening during the
    /// grace window. Refuses zero and a previous scalar equal to the current
    /// one.
    pub fn with_previous_enc(mut self, previous: Fq, rotated_at: u64) -> Result<Self, String> {
        if previous == self.enc.scalar {
            return Err("the previous encryption scalar equals the current one".into());
        }
        self.previous = Some((EncKey::new(previous)?, rotated_at));
        Ok(self)
    }

    // Operator knob: DESIGN.md, "Configuration reference" (sidecar-node
    // `enc_grace_days`). The node keeps exactly one previous scalar, with
    // `now` as its rotation time, until it is retired (`retire_previous_enc`),
    // the end of the window; `grace_ends_at` gives the end from the rotation
    // time. Within the window record thirds open under either key id and
    // envelopes under either scalar, the tag deciding, and every new third is
    // sealed under the new key. A second rotation inside the window retires
    // the older key at once.
    /// Rotate the encryption key at `now` (unix seconds): `enc` becomes
    /// current and the current scalar becomes the previous one, rotated at
    /// `now`; an earlier previous scalar is dropped.
    pub fn rotate_enc(&self, enc: Fq, now: u64) -> Result<Self, String> {
        let mut next = NodeKeys::from_scalars(enc, self.sig)?;
        if enc == self.enc.scalar {
            return Err("the new encryption scalar equals the current one".into());
        }
        next.previous = Some((self.enc.clone(), now));
        next.epochs = self.epochs.clone();
        Ok(next)
    }

    /// These keys with `epochs` as the scalars by contract and epoch.
    pub fn with_epochs(mut self, epochs: EpochKeys) -> Self {
        self.epochs = epochs;
        self
    }

    /// The `enc` scalars by contract and epoch (secret-shared on-chain intake),
    /// which the epoch rule, not the grace window, retires.
    pub fn epochs(&self) -> &EpochKeys {
        &self.epochs
    }

    /// As [`Self::epochs`], to record a rotation or apply the rule.
    pub fn epochs_mut(&mut self) -> &mut EpochKeys {
        &mut self.epochs
    }

    /// End the grace window: forget the previous encryption scalar.
    pub fn retire_previous_enc(mut self) -> Self {
        self.previous = None;
        self
    }

    /// The current ECDH scalar.
    pub fn enc_scalar(&self) -> Fq {
        self.enc.scalar
    }

    /// The previous ECDH scalar, during a grace window.
    pub fn previous_enc_scalar(&self) -> Option<Fq> {
        self.previous.as_ref().map(|(k, _)| k.scalar)
    }

    /// When the previous scalar was replaced (unix seconds), during a grace
    /// window.
    pub fn rotated_at(&self) -> Option<u64> {
        self.previous.as_ref().map(|(_, at)| *at)
    }

    /// When a grace window of `grace_secs` ends for the previous scalar (unix
    /// seconds): its rotation time plus the window. `None` outside a window.
    pub fn grace_ends_at(&self, grace_secs: u64) -> Option<u64> {
        self.rotated_at().map(|at| at.saturating_add(grace_secs))
    }

    /// The Schnorr signing scalar.
    pub fn sig_scalar(&self) -> Fq {
        self.sig
    }

    /// `enc · G`: the key clients encrypt INPUT_SHARED envelopes to, and the
    /// owner of the records this node seals for itself.
    pub fn enc_pk(&self) -> Point {
        self.enc.pk
    }

    /// The previous encryption public key, during a grace window.
    pub fn previous_enc_pk(&self) -> Option<Point> {
        self.previous.as_ref().map(|(k, _)| k.pk)
    }

    /// The previous record key id, during a grace window.
    pub fn previous_key_id(&self) -> Option<[u8; KEY_ID_LEN]> {
        self.previous.as_ref().map(|(k, _)| k.key_id)
    }

    // The current key, then the previous one during a grace window.
    fn enc_keys(&self) -> impl Iterator<Item = &EncKey> {
        std::iter::once(&self.enc).chain(self.previous.as_ref().map(|(k, _)| k))
    }

    /// `sig · G`: the key results, registry answers and receipts verify under.
    pub fn sig_pk(&self) -> Point {
        self.sig_pk
    }

    /// Both public keys in the `GET /v1/nodes` wire form.
    pub fn public_keys(&self) -> NodePublicKeys {
        NodePublicKeys {
            enc: point_to_wire(self.enc.pk),
            sig: point_to_wire(self.sig_pk),
        }
    }

    /// K_i of the current encryption key: what new thirds are sealed under.
    pub fn seal_key(&self) -> Fr {
        self.enc.seal_key
    }

    /// The current record key id: what new thirds start with.
    pub fn key_id(&self) -> [u8; KEY_ID_LEN] {
        self.enc.key_id
    }

    /// The record key a third with key id `id` opens under: the current key's,
    /// or the previous key's during a grace window; `None` for any other id.
    pub fn seal_key_for(&self, id: &[u8]) -> Option<Fr> {
        self.enc_keys()
            .find(|k| k.key_id[..] == *id)
            .map(|k| k.seal_key)
    }

    /// The encryption public key a third with key id `id` was sealed under:
    /// the current key's, or the previous key's during a grace window; `None`
    /// for any other id. A record this node sealed for itself names that key
    /// as its owner, so it opens only with the owner this returns.
    pub fn enc_pk_for(&self, id: &[u8]) -> Option<Point> {
        self.enc_keys().find(|k| k.key_id[..] == *id).map(|k| k.pk)
    }

    /// The ECDH shared secret with an ephemeral public key under the current
    /// scalar: `(enc · eph).x`, the x-coordinate pss_utils' `ecdh_x` gives
    /// from the ephemeral secret and this node's public key.
    pub fn shared_secret(&self, eph: Point) -> Fr {
        coordinates(mul(eph, self.enc.scalar)).0
    }

    /// The shared secrets to try when opening an envelope: the current
    /// scalar's, then the previous scalar's during a grace window.
    pub fn shared_secrets(&self, eph: Point) -> Vec<Fr> {
        self.enc_keys()
            .map(|k| coordinates(mul(eph, k.scalar)).0)
            .collect()
    }
}

// The signing scalar is overwritten when a key set is dropped, as every
// encryption scalar is (`EncKey`'s drop): no copy outlives the key set.
impl Drop for NodeKeys {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.sig.zeroize();
    }
}

impl fmt::Debug for NodeKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeKeys")
            .field("enc_pk", &coordinates(self.enc.pk))
            .field("sig_pk", &coordinates(self.sig_pk))
            .field("key_id", &self.enc.key_id)
            .field("previous_key_id", &self.previous_key_id())
            .field("rotated_at", &self.rotated_at())
            .finish_non_exhaustive()
    }
}

/// A Grumpkin scalar as a key file holds it: `0x` + 64 lowercase hex digits,
/// big-endian.
pub fn scalar_to_hex(scalar: Fq) -> String {
    let mut out = String::with_capacity(66);
    out.push_str("0x");
    crate::field::push_hex(&mut out, &scalar.into_bigint().to_bytes_be());
    out
}

/// The inverse of [`scalar_to_hex`]. Refuses anything but `0x` + 64 hex digits,
/// a value at or above the Grumpkin scalar modulus, and zero.
pub fn scalar_from_hex(text: &str) -> Result<Fq, String> {
    let bytes = text
        .strip_prefix("0x")
        .filter(|d| d.len() == 64)
        .and_then(|d| crate::field::bytes_from_hex(d).ok())
        .ok_or_else(|| "a key scalar is 0x followed by 64 hex digits".to_string())?;
    let scalar = Fq::from_be_bytes_mod_order(&bytes);
    if scalar.into_bigint().to_bytes_be() != bytes {
        return Err("a key scalar is not below the Grumpkin scalar modulus".into());
    }
    if scalar.is_zero() {
        return Err("a key scalar is zero".into());
    }
    Ok(scalar)
}

// The key directory layout and how it is written. One directory
// per node holds six files with fixed names: `enc.key` (the current enc
// scalar), `enc.previous.key` (the previous enc scalar, present only during a
// rotation's grace window), `sig.key` (the sig scalar), each `0x` plus 64
// hex digits on one line, `enc.rotated_at` (when the previous scalar was
// replaced, unix seconds in decimal on one line, beside the previous key so
// the window survives a restart), `master.share` (the master nullifier
// share, in the encoding the node's setup defines), and `enc.epochs.json`
// (secret-shared on-chain intake: the enc scalar of each epoch a contract may still
// name, per contract, present only while one is held). Files are mode 0600 in a
// directory of mode 0700, readable by the node's user only, and every write
// goes through a temporary file in the same directory, synced, then renamed
// over the old one, so a crash leaves the old file or the new one and never
// half a key. A rotation writes the rotation time, then the previous key,
// then the new current key, so a crash part-way leaves the old current key in
// one of the two key files: a previous key equal to the current one is read
// as no window, and a rotation time without a previous key is ignored. A
// previous key without a rotation time (copied in by hand) counts from the
// file's modification time. Operators and backup scripts depend on these
// names and modes: backing up a node is copying the whole directory (losing
// `enc.previous.key` inside a window loses the thirds still sealed under
// it). Renaming a file or changing the scalar encoding makes every existing
// key directory unreadable to the new code; relaxing the modes exposes the
// node's secrets to other local users.
/// The layout of a node's key directory:
///
/// ```text
/// <dir>/enc.key            the current encryption scalar (scalar_to_hex, one line)
/// <dir>/enc.previous.key   the previous encryption scalar; present only in a grace window
/// <dir>/enc.rotated_at     when the previous scalar was replaced, unix seconds; beside it
/// <dir>/sig.key            the signing scalar
/// <dir>/master.share       this node's share of the master nullifier secret
/// <dir>/enc.epochs.json    the enc scalars by contract and epoch (secret-shared on-chain intake)
/// ```
///
/// The master share is sampled over the mesh by the node's setup, which also
/// defines its encoding; this type only names its path. Files are written with
/// mode 0600 in a directory of mode 0700, each through a temporary file and a
/// rename, so a crash leaves either the old file or the new one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyFiles {
    dir: PathBuf,
}

impl KeyFiles {
    pub const ENC: &'static str = "enc.key";
    pub const PREVIOUS_ENC: &'static str = "enc.previous.key";
    pub const ROTATED_AT: &'static str = "enc.rotated_at";
    pub const SIG: &'static str = "sig.key";
    pub const MASTER_SHARE: &'static str = "master.share";
    pub const EPOCHS: &'static str = "enc.epochs.json";

    pub fn new(dir: impl Into<PathBuf>) -> Self {
        KeyFiles { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn enc_path(&self) -> PathBuf {
        self.dir.join(Self::ENC)
    }

    pub fn previous_enc_path(&self) -> PathBuf {
        self.dir.join(Self::PREVIOUS_ENC)
    }

    pub fn rotated_at_path(&self) -> PathBuf {
        self.dir.join(Self::ROTATED_AT)
    }

    pub fn sig_path(&self) -> PathBuf {
        self.dir.join(Self::SIG)
    }

    pub fn master_share_path(&self) -> PathBuf {
        self.dir.join(Self::MASTER_SHARE)
    }

    pub fn epochs_path(&self) -> PathBuf {
        self.dir.join(Self::EPOCHS)
    }

    /// Write both scalars, and the previous encryption scalar with its
    /// rotation time when `keys` has one (removing stale previous and time
    /// files when it has none). Creates the directory. Leaves the master share
    /// alone. With a previous scalar the rotation time and the previous key are
    /// written before the current key, so a crash part-way never loses the key
    /// that was current (see the layout above).
    pub fn write(&self, keys: &NodeKeys) -> io::Result<()> {
        create_private_dir(&self.dir)?;
        if *keys.epochs() == EpochKeys::default() {
            remove_if_present(&self.epochs_path())?;
        } else {
            write_private(&self.epochs_path(), &keys.epochs().to_json())?;
        }
        if let (Some(previous), Some(at)) = (keys.previous_enc_scalar(), keys.rotated_at()) {
            write_private(&self.rotated_at_path(), &at.to_string())?;
            write_private(&self.previous_enc_path(), &scalar_to_hex(previous))?;
            write_private(&self.enc_path(), &scalar_to_hex(keys.enc_scalar()))?;
            return write_private(&self.sig_path(), &scalar_to_hex(keys.sig_scalar()));
        }
        write_private(&self.enc_path(), &scalar_to_hex(keys.enc_scalar()))?;
        write_private(&self.sig_path(), &scalar_to_hex(keys.sig_scalar()))?;
        remove_if_present(&self.previous_enc_path())?;
        remove_if_present(&self.rotated_at_path())
    }

    /// Read the keys back. A missing or malformed scalar file is an error
    /// naming the file; a missing previous file means no grace window, and so
    /// does a previous scalar equal to the current one (a rotation that
    /// stopped before writing its new key). The rotation time comes from
    /// `enc.rotated_at`, or the previous file's modification time without it.
    pub fn read(&self) -> io::Result<NodeKeys> {
        let enc = read_scalar(&self.enc_path())?;
        let sig = read_scalar(&self.sig_path())?;
        let keys = NodeKeys::from_scalars(enc, sig)
            .map_err(invalid(&self.enc_path()))?
            .with_epochs(self.read_epochs()?);
        let previous_path = self.previous_enc_path();
        if !previous_path.exists() {
            return Ok(keys);
        }
        let previous = read_scalar(&previous_path)?;
        if previous == enc {
            return Ok(keys);
        }
        let rotated_at = self.read_rotated_at(&previous_path)?;
        keys.with_previous_enc(previous, rotated_at)
            .map_err(invalid(&previous_path))
    }

    fn read_epochs(&self) -> io::Result<EpochKeys> {
        let path = self.epochs_path();
        match fs::read_to_string(&path) {
            Ok(text) => EpochKeys::from_json(&text).map_err(invalid(&path)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(EpochKeys::default()),
            Err(e) => Err(io::Error::new(e.kind(), format!("{}: {e}", path.display()))),
        }
    }

    fn read_rotated_at(&self, previous_path: &Path) -> io::Result<u64> {
        let path = self.rotated_at_path();
        match fs::read_to_string(&path) {
            Ok(text) => text
                .trim()
                .parse::<u64>()
                .map_err(|e| invalid(&path)(format!("not unix seconds: {e}"))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let modified = fs::metadata(previous_path)?.modified()?;
                Ok(modified
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0))
            }
            Err(e) => Err(io::Error::new(e.kind(), format!("{}: {e}", path.display()))),
        }
    }
}

fn remove_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

fn invalid(path: &Path) -> impl Fn(String) -> io::Error + '_ {
    move |why| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: {why}", path.display()),
        )
    }
}

fn read_scalar(path: &Path) -> io::Result<Fq> {
    let text = fs::read_to_string(path)
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
    scalar_from_hex(text.trim()).map_err(invalid(path))
}

#[cfg(unix)]
/// Create `dir` and its missing parents with mode 0700 (on Unix), and
/// tighten `dir` itself to 0700 when it exists with group or other access.
/// A shared directory (the sticky bit set, as on /tmp) is refused, not
/// changed.
pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    if dir.as_os_str().is_empty() {
        return Ok(());
    }
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let mode = fs::metadata(dir)?.permissions().mode();
    if mode & 0o077 == 0 {
        return Ok(());
    }
    if mode & 0o1000 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is a shared directory (sticky bit); use a private one",
                dir.display()
            ),
        ));
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)
}

/// Write `bytes` to `path` whole: into a new temporary file beside it
/// (created exclusively under a name no other writer uses, with `mode` on
/// Unix), synced, renamed over `path`, then the directory synced, so a crash
/// leaves the old file or the new one, never a torn or shared temporary.
pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} names no file", path.display()),
        )
    })?;
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(format!(
        ".{}.{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let tmp = dir.join(tmp_name);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let written = (|| {
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written?;
    #[cfg(unix)]
    fs::File::open(dir)?.sync_all()?;
    Ok(())
}

fn write_private(path: &Path, line: &str) -> io::Result<()> {
    write_atomic(path, format!("{line}\n").as_bytes(), 0o600)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::field::fr_to_hex;
    use crate::grumpkin::scalar_from_field;
    use ark_std::rand::SeedableRng;
    use ark_std::rand::rngs::StdRng;
    use serde_json::{Value, json};

    /// Deterministic test keys for node `i` of a sample deployment: the keys
    /// testvectors/keys.json lists.
    pub(crate) fn sample_keys(i: usize) -> NodeKeys {
        let mut rng = StdRng::seed_from_u64(0x5c4e_6b00 + i as u64);
        NodeKeys::generate(&mut rng)
    }

    #[test]
    fn labels_are_big_endian_ascii() {
        assert_eq!(
            label_field(SIDECAR_SEAL_KEY),
            crate::field::fr_from_hex("0x736964656361722e7365616c5f6b6579").unwrap()
        );
    }

    #[test]
    fn the_two_scalars_are_independent_and_reproducible() {
        let keys = sample_keys(0);
        assert_ne!(keys.enc_scalar(), keys.sig_scalar());
        assert_eq!(keys.enc_pk(), fixed_base_mul(keys.enc_scalar()));
        assert_eq!(keys.sig_pk(), fixed_base_mul(keys.sig_scalar()));
        // The same draw gives the same keys; another draw other keys.
        let again = sample_keys(0);
        assert_eq!(again.enc_scalar(), keys.enc_scalar());
        assert_eq!(again.sig_scalar(), keys.sig_scalar());
        let other = sample_keys(1);
        assert_ne!(other.enc_scalar(), keys.enc_scalar());
        assert_ne!(other.sig_scalar(), keys.sig_scalar());
        // Stored scalars rebuild the same keys.
        let stored = NodeKeys::from_scalars(keys.enc_scalar(), keys.sig_scalar()).unwrap();
        assert_eq!(stored.key_id(), keys.key_id());
        assert_eq!(stored.seal_key(), keys.seal_key());
        let zero = Fq::zero();
        assert!(NodeKeys::from_scalars(zero, keys.sig_scalar()).is_err());
        assert!(NodeKeys::from_scalars(keys.enc_scalar(), zero).is_err());
    }

    #[test]
    fn the_record_key_and_key_id_come_from_enc_only() {
        let keys = sample_keys(0);
        let (lo, hi) = scalar_to_limbs(keys.enc_scalar());
        assert_eq!(
            keys.seal_key(),
            poseidon2_hash(&[lo, hi, label_field(SIDECAR_SEAL_KEY)])
        );
        let (x, y) = coordinates(keys.enc_pk());
        assert_eq!(
            keys.key_id()[..],
            fr_to_be_bytes(poseidon2_hash(&[x, y]))[..8]
        );
        // Another sig scalar changes neither; another enc scalar changes both.
        let other_sig = NodeKeys::from_scalars(keys.enc_scalar(), Fq::from(5u64)).unwrap();
        assert_eq!(other_sig.seal_key(), keys.seal_key());
        assert_eq!(other_sig.key_id(), keys.key_id());
        let other_enc = NodeKeys::from_scalars(Fq::from(5u64), keys.sig_scalar()).unwrap();
        assert_ne!(other_enc.seal_key(), keys.seal_key());
        assert_ne!(other_enc.key_id(), keys.key_id());
    }

    #[test]
    fn rotation_keeps_the_previous_enc_key_for_opening() {
        let keys = sample_keys(0);
        let new_enc = sample_keys(1).enc_scalar();
        let rotated = keys.rotate_enc(new_enc, 1_000).unwrap();
        assert_eq!(rotated.enc_scalar(), new_enc);
        assert_eq!(rotated.rotated_at(), Some(1_000));
        assert_eq!(rotated.grace_ends_at(86_400), Some(87_400));
        assert_eq!(rotated.previous_key_id(), Some(keys.key_id()));
        assert_eq!(keys.grace_ends_at(86_400), None);
        assert_eq!(rotated.sig_scalar(), keys.sig_scalar(), "sig never rotates");
        assert_eq!(rotated.previous_enc_scalar(), Some(keys.enc_scalar()));
        assert_eq!(rotated.previous_enc_pk(), Some(keys.enc_pk()));
        assert_eq!(
            rotated.seal_key_for(&rotated.key_id()),
            Some(rotated.seal_key())
        );
        assert_eq!(rotated.seal_key_for(&keys.key_id()), Some(keys.seal_key()));
        assert_eq!(rotated.seal_key_for(&sample_keys(2).key_id()), None);
        assert_eq!(
            rotated.enc_pk_for(&rotated.key_id()),
            Some(rotated.enc_pk())
        );
        assert_eq!(rotated.enc_pk_for(&keys.key_id()), Some(keys.enc_pk()));
        assert_eq!(rotated.enc_pk_for(&sample_keys(2).key_id()), None);
        let eph = fixed_base_mul(Fq::from(77u64));
        assert_eq!(
            rotated.shared_secrets(eph),
            [rotated.shared_secret(eph), keys.shared_secret(eph)]
        );
        // A second rotation drops the oldest key; retiring ends the window.
        let twice = rotated
            .rotate_enc(sample_keys(2).enc_scalar(), 2_000)
            .unwrap();
        assert_eq!(twice.seal_key_for(&keys.key_id()), None);
        assert_eq!(twice.rotated_at(), Some(2_000));
        let retired = rotated.retire_previous_enc();
        assert_eq!(retired.previous_enc_scalar(), None);
        assert_eq!(retired.rotated_at(), None);
        assert_eq!(retired.seal_key_for(&keys.key_id()), None);
        assert_eq!(retired.enc_pk_for(&keys.key_id()), None);
        assert_eq!(retired.shared_secrets(eph).len(), 1);
        assert!(keys.rotate_enc(keys.enc_scalar(), 0).is_err());
        assert!(
            keys.clone()
                .with_previous_enc(keys.enc_scalar(), 0)
                .is_err()
        );
    }

    #[test]
    fn ecdh_agrees_with_the_sender() {
        let node = sample_keys(2);
        let eph = scalar_from_field(Fr::from(123u64));
        let sender = coordinates(mul(node.enc_pk(), eph)).0;
        assert_eq!(node.shared_secret(fixed_base_mul(eph)), sender);
    }

    #[test]
    fn debug_hides_the_secrets() {
        let keys = sample_keys(0);
        let text = format!("{keys:?}");
        assert!(text.contains("enc_pk") && !text.contains("scalar") && !text.contains("seal_key"));
        assert!(!text.contains(&scalar_to_hex(keys.enc_scalar())[2..10]));
    }

    #[test]
    fn scalar_hex_round_trips_and_refuses_junk() {
        let keys = sample_keys(1);
        for scalar in [
            keys.enc_scalar(),
            keys.sig_scalar(),
            Fq::from(1u64),
            -Fq::from(1u64),
        ] {
            let text = scalar_to_hex(scalar);
            assert_eq!(text.len(), 66);
            assert_eq!(scalar_from_hex(&text).unwrap(), scalar);
        }
        let q: String = Fq::MODULUS
            .to_bytes_be()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let q = format!("0x{q}");
        for bad in [
            "0x".to_string(),
            "0x1".to_string(),
            format!("0x{}", "0".repeat(64)),
            q,
            format!("0x{}", "f".repeat(64)),
            "1".repeat(64),
            format!("0x{}g", "1".repeat(63)),
        ] {
            assert!(scalar_from_hex(&bad).is_err(), "{bad}");
        }
    }

    /// A whole-file write leaves no temporary behind and gives the file its
    /// mode; an existing directory open to others is tightened to 0700, a
    /// shared (sticky) one refused.
    #[cfg(unix)]
    #[test]
    fn private_files_and_directories() {
        use std::os::unix::fs::PermissionsExt;
        let dir = sidecar_test_fixtures::dirs::TempDir::new("sidecar-core-private");
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        let loose = dir.path().join("loose");
        fs::create_dir(&loose).unwrap();
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o755)).unwrap();
        create_private_dir(&loose).unwrap();
        assert_eq!(mode(&loose), 0o700);
        let file = loose.join("sig.key");
        write_atomic(&file, b"one", 0o600).unwrap();
        write_atomic(&file, b"two", 0o600).unwrap();
        assert_eq!(fs::read(&file).unwrap(), b"two");
        assert_eq!(mode(&file), 0o600);
        let names: Vec<_> = fs::read_dir(&loose)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["sig.key"]);
        let shared = dir.path().join("shared");
        fs::create_dir(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(create_private_dir(&shared).is_err());
        assert_eq!(mode(&shared), 0o1777);
    }

    #[test]
    fn key_files_round_trip_with_and_without_a_grace_window() {
        let dir = sidecar_test_fixtures::dirs::TempDir::new("sidecar-core-keys-files");
        let files = KeyFiles::new(dir.path().join("keys"));
        let keys = sample_keys(0);
        files.write(&keys).unwrap();
        let back = files.read().unwrap();
        assert_eq!(back.enc_scalar(), keys.enc_scalar());
        assert_eq!(back.sig_scalar(), keys.sig_scalar());
        assert_eq!(back.previous_enc_scalar(), None);
        let text = fs::read_to_string(files.enc_path()).unwrap();
        assert_eq!(text, scalar_to_hex(keys.enc_scalar()) + "\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&files.enc_path()), 0o600);
            assert_eq!(mode(&files.sig_path()), 0o600);
            assert_eq!(mode(files.dir()), 0o700);
        }

        let rotated = keys
            .rotate_enc(sample_keys(1).enc_scalar(), 1_700_000_000)
            .unwrap();
        files.write(&rotated).unwrap();
        let back = files.read().unwrap();
        assert_eq!(back.previous_enc_scalar(), Some(keys.enc_scalar()));
        assert_eq!(back.enc_scalar(), rotated.enc_scalar());
        assert_eq!(back.rotated_at(), Some(1_700_000_000));
        assert_eq!(
            fs::read_to_string(files.rotated_at_path()).unwrap(),
            "1700000000\n"
        );

        // A previous key without its time counts from the file's mtime; a
        // malformed time is refused naming the file.
        fs::remove_file(files.rotated_at_path()).unwrap();
        let mtime = files.read().unwrap().rotated_at().unwrap();
        assert!(mtime > 1_700_000_000, "{mtime}");
        fs::write(files.rotated_at_path(), "yesterday\n").unwrap();
        let err = files.read().unwrap_err();
        assert!(err.to_string().contains("enc.rotated_at"), "{err}");

        // A rotation that stopped after writing the previous key but before the
        // new current one: both files hold the old key, read as no window.
        files.write(&keys).unwrap();
        write_private(
            &files.previous_enc_path(),
            &scalar_to_hex(keys.enc_scalar()),
        )
        .unwrap();
        let stopped = files.read().unwrap();
        assert_eq!(stopped.enc_scalar(), keys.enc_scalar());
        assert_eq!(stopped.previous_enc_scalar(), None);

        files.write(&rotated).unwrap();
        files.write(&rotated.clone().retire_previous_enc()).unwrap();
        assert!(!files.previous_enc_path().exists());
        assert!(!files.rotated_at_path().exists());
        assert_eq!(files.read().unwrap().previous_enc_scalar(), None);

        assert_eq!(
            files.master_share_path(),
            dir.path().join("keys/master.share")
        );
        fs::write(files.sig_path(), "0x12\n").unwrap();
        let err = files.read().unwrap_err();
        assert!(err.to_string().contains("sig.key"), "{err}");
        fs::remove_file(files.sig_path()).unwrap();
        assert!(files.read().unwrap_err().to_string().contains("sig.key"));
    }

    pub(crate) fn vectors_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testvectors/keys.json")
    }

    fn vectors_json() -> Value {
        let nodes: Vec<Value> = (0..3)
            .map(|i| {
                let keys = sample_keys(i);
                let (lo, hi) = scalar_to_limbs(keys.enc_scalar());
                let id: String = keys.key_id().iter().map(|b| format!("{b:02x}")).collect();
                json!({
                    "node": i,
                    "enc": scalar_to_hex(keys.enc_scalar()),
                    "enc_limbs": {"lo": fr_to_hex(lo), "hi": fr_to_hex(hi)},
                    "sig": scalar_to_hex(keys.sig_scalar()),
                    "enc_pk": point_to_wire(keys.enc_pk()),
                    "sig_pk": point_to_wire(keys.sig_pk()),
                    "key_id": format!("0x{id}"),
                    "record_key": fr_to_hex(keys.seal_key()),
                })
            })
            .collect();
        json!({
            "rules": {
                "scalars": "enc and sig are independent uniform Grumpkin scalars, written 0x + 64 hex digits big-endian (the key files' form)",
                "public_keys": "enc_pk = enc·G, sig_pk = sig·G on Grumpkin",
                "record_key": "poseidon2([enc.lo, enc.hi, SIDECAR_SEAL_KEY]), enc.lo and enc.hi the low and high 128 bits, SIDECAR_SEAL_KEY = ASCII \"sidecar.seal_key\" as a big-endian integer",
                "key_id": "the first 8 bytes of poseidon2([enc_pk.x, enc_pk.y]) written as 32 bytes big-endian",
            },
            "sidecar_seal_key": fr_to_hex(label_field(SIDECAR_SEAL_KEY)),
            "nodes": nodes,
        })
    }

    // Regenerates testvectors/keys.json:
    // cargo test -p sidecar-core keys::tests::write_keys_json -- --ignored
    #[test]
    #[ignore = "writes testvectors/; run on purpose"]
    fn write_keys_json() {
        let text = serde_json::to_string_pretty(&vectors_json()).unwrap() + "\n";
        fs::write(vectors_path(), text).unwrap();
    }
}
