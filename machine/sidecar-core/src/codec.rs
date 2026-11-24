//! The byte encodings the node's store backends and its store backup share:
//! field elements, points, shares and signatures as Postgres columns, every
//! row as a record of the local store's log, and the tip rows of the node's
//! store backup.
//!
//! Integers are little-endian; a variable-length item is a `u32` length and
//! its bytes. A field element is its 32-byte big-endian integer (the digits
//! of its `0x` hex), refused at or above the modulus. Points and shares are
//! ark's uncompressed serialisation, checked on reading. Stored vectors keep
//! the core's tag-prefixed encoding ([`crate::store::encode_vec`]).

use crate::bind::Elem;
use crate::bind::Share;
use crate::field::{Fr, RequestId, fr_to_be_bytes};
use crate::grumpkin::Point;
use crate::register::Signature;
use crate::request::{GrumpkinPoint, NodeSharedInput, ShareCiphertext};
use crate::store::{
    ConsumedRow, ManifestRow, NamespaceRow, PackageRow, ReceiptRow, RequestRow, RequestStatus,
    Sealed, SealedKind, TipVersion, VersionStatus, VersionTree, decode_vec, encode_vec,
};
use crate::tree::TreeNode;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// Appends items to a byte buffer.
#[derive(Default)]
pub struct Writer {
    pub out: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn u8(&mut self, v: u8) {
        self.out.push(v);
    }

    pub fn u32(&mut self, v: u32) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    pub fn u64(&mut self, v: u64) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    pub fn count(&mut self, n: usize) {
        self.u32(u32::try_from(n).expect("a stored item is under 4 GiB"));
    }

    pub fn bytes(&mut self, v: &[u8]) {
        self.count(v.len());
        self.out.extend_from_slice(v);
    }

    pub fn str(&mut self, v: &str) {
        self.bytes(v.as_bytes());
    }

    pub fn strs(&mut self, v: &[String]) {
        self.count(v.len());
        for s in v {
            self.str(s);
        }
    }

    pub fn fr(&mut self, v: Fr) {
        self.out.extend_from_slice(&fr_bytes(v));
    }

    pub fn frs(&mut self, v: &[Fr]) {
        self.count(v.len());
        for f in v {
            self.fr(*f);
        }
    }

    pub fn point(&mut self, v: &Point) {
        self.bytes(&point_bytes(v));
    }

    pub fn share(&mut self, v: &Share) {
        self.bytes(&share_bytes(v));
    }

    pub fn signature(&mut self, v: &Signature) {
        self.out.extend_from_slice(&signature_bytes(v));
    }

    pub fn namespace_row(&mut self, row: &NamespaceRow) {
        self.point(&row.owner_pubkey);
        self.share(&row.nsk_app);
        self.fr(row.npk_app_hash);
        self.u64(row.seq);
    }

    pub fn manifest_row(&mut self, row: &ManifestRow) {
        self.fr(row.manifest_hash);
        self.str(&row.document.to_string());
        self.u64(row.seq);
    }

    pub fn package_row(&mut self, row: &PackageRow) {
        self.str(&row.name);
        self.fr(row.manifest_hash);
        self.bytes(&row.circuit_json);
        self.str(&row.manifest.to_string());
        self.bytes(&row.vk);
        self.fr(row.vk_hash);
        self.u8(row.disabled as u8);
        self.u64(row.seq);
    }

    pub fn consumed_row(&mut self, row: &ConsumedRow) {
        self.fr(row.note_hash);
        self.fr(row.circuit);
        self.fr(row.request_id.fr());
    }

    pub fn sealed(&mut self, sealed: &[Sealed]) {
        self.count(sealed.len());
        for s in sealed {
            match s.kind {
                SealedKind::Record => self.u8(0),
                SealedKind::Replaced { prior_request_id } => {
                    self.u8(1);
                    self.fr(prior_request_id.fr());
                }
            }
            self.str(&s.key);
            self.fr(s.note_hash);
            self.bytes(&s.c_i);
        }
    }

    /// A `requests` row (the local store's log write 4).
    pub fn request_row(&mut self, row: &RequestRow) {
        self.fr(row.request_id.fr());
        self.fr(row.body_hash);
        self.fr(row.vk_hash);
        self.bytes(&row.proof);
        self.frs(&row.public_inputs);
        self.strs(&row.stored_keys);
        self.strs(&row.created_keys);
        self.sealed(&row.sealed);
        match &row.signature {
            None => self.u8(0),
            Some(sig) => {
                self.u8(1);
                self.signature(sig);
            }
        }
        self.u8(status_tag(row.status));
        self.u64(row.created_at);
        match row.chain_request_id {
            None => self.u8(0),
            Some(chain) => {
                self.u8(1);
                self.fr(chain);
            }
        }
    }

    /// An optional field element: a flag, then the element.
    pub fn opt_fr(&mut self, v: Option<Fr>) {
        match v {
            None => self.u8(0),
            Some(v) => {
                self.u8(1);
                self.fr(v);
            }
        }
    }

    /// A receipt's shared inputs as node i holds them: per input its name,
    /// its own envelope (`eph.x, eph.y, ct0, ct1, tag`) and the three share
    /// hashes.
    pub fn shares(&mut self, v: &[NodeSharedInput]) {
        self.count(v.len());
        for input in v {
            self.str(&input.name);
            let e = &input.share;
            for f in [e.eph.x, e.eph.y, e.ct[0], e.ct[1], e.tag] {
                self.fr(f.fr());
            }
            for h in &input.share_hashes {
                self.fr(h.fr());
            }
        }
    }

    /// A `receipts` row (the local store's log write 8).
    pub fn receipt_row(&mut self, row: &ReceiptRow) {
        self.fr(row.request_id);
        self.str(&row.circuit);
        self.fr(row.vk_hash);
        self.frs(&row.inputs);
        self.fr(row.inputs_hash);
        self.opt_fr(row.user_nonce);
        self.shares(&row.shares);
        self.u64(row.expiry_block);
        match row.stale_blocks {
            None => self.u8(0),
            Some(stale) => {
                self.u8(1);
                self.u64(stale);
            }
        }
        self.signature(&row.signature);
    }

    /// A stored vector, in the core's tag-prefixed encoding.
    pub fn vec(&mut self, vec: &[Elem]) {
        self.bytes(&encode_vec(vec));
    }

    /// A `tip_versions` row (the node's store backup).
    pub fn tip_version(&mut self, v: &TipVersion) {
        self.str(&v.key);
        self.fr(v.commitment);
        self.fr(v.parent);
        self.u64(v.index);
        self.fr(v.request_id.fr());
        self.vec(&v.vec);
        match v.tree {
            None => self.u8(0),
            Some(t) => {
                let (root, next) = t.stored();
                self.u8(1);
                self.fr(root);
                self.u64(next);
            }
        }
        self.u8(match v.status {
            VersionStatus::Canonical => 0,
            VersionStatus::Live => 1,
            VersionStatus::Orphan => 2,
        });
        self.u64(v.block);
        self.fr(v.block_hash);
    }

    /// A clear tree's node (the node's store backup).
    pub fn tree_node(&mut self, node: &TreeNode) {
        match node {
            TreeNode::Inner { left, right } => {
                self.u8(0);
                self.fr(*left);
                self.fr(*right);
            }
            TreeNode::Leaf { index, vec } => {
                self.u8(1);
                self.u64(*index);
                self.vec(vec);
            }
        }
    }
}

/// Reads items back in the order a [`Writer`] wrote them.
pub struct Reader<'a> {
    rest: &'a [u8],
}

pub type Decoded<T> = Result<T, String>;

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Reader { rest: bytes }
    }

    /// Refuse trailing bytes.
    pub fn finish(&self) -> Decoded<()> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(format!("{} trailing bytes", self.rest.len()))
        }
    }

    fn take(&mut self, n: usize) -> Decoded<&'a [u8]> {
        if self.rest.len() < n {
            return Err(format!(
                "truncated: {n} bytes wanted, {} left",
                self.rest.len()
            ));
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }

    pub fn u8(&mut self) -> Decoded<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn u32(&mut self) -> Decoded<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub fn u64(&mut self) -> Decoded<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    pub fn u128(&mut self) -> Decoded<u128> {
        Ok(u128::from_le_bytes(self.take(16)?.try_into().unwrap()))
    }

    /// How many bytes are left.
    pub fn remaining(&self) -> usize {
        self.rest.len()
    }

    pub fn count(&mut self) -> Decoded<usize> {
        Ok(self.u32()? as usize)
    }

    pub fn bytes(&mut self) -> Decoded<Vec<u8>> {
        let n = self.count()?;
        Ok(self.take(n)?.to_vec())
    }

    pub fn str(&mut self) -> Decoded<String> {
        String::from_utf8(self.bytes()?).map_err(|e| e.to_string())
    }

    pub fn strs(&mut self) -> Decoded<Vec<String>> {
        (0..self.count()?).map(|_| self.str()).collect()
    }

    pub fn fr(&mut self) -> Decoded<Fr> {
        fr_from_bytes(self.take(32)?)
    }

    pub fn frs(&mut self) -> Decoded<Vec<Fr>> {
        (0..self.count()?).map(|_| self.fr()).collect()
    }

    pub fn point(&mut self) -> Decoded<Point> {
        point_from_bytes(&self.bytes()?)
    }

    pub fn share(&mut self) -> Decoded<Share> {
        share_from_bytes(&self.bytes()?)
    }

    pub fn signature(&mut self) -> Decoded<Signature> {
        signature_from_bytes(self.take(SIGNATURE_LEN)?)
    }

    pub fn bool(&mut self) -> Decoded<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            t => Err(format!("bad flag {t}")),
        }
    }

    pub fn namespace_row(&mut self) -> Decoded<NamespaceRow> {
        Ok(NamespaceRow {
            owner_pubkey: self.point()?,
            nsk_app: self.share()?,
            npk_app_hash: self.fr()?,
            seq: self.u64()?,
        })
    }

    pub fn manifest_row(&mut self) -> Decoded<ManifestRow> {
        Ok(ManifestRow {
            manifest_hash: self.fr()?,
            document: manifest_from_text(&self.str()?)?,
            seq: self.u64()?,
        })
    }

    pub fn package_row(&mut self) -> Decoded<PackageRow> {
        Ok(PackageRow {
            name: self.str()?,
            manifest_hash: self.fr()?,
            circuit_json: self.bytes()?,
            manifest: manifest_from_text(&self.str()?)?,
            vk: self.bytes()?,
            vk_hash: self.fr()?,
            disabled: self.bool()?,
            seq: self.u64()?,
        })
    }

    pub fn consumed_row(&mut self) -> Decoded<ConsumedRow> {
        Ok(ConsumedRow {
            note_hash: self.fr()?,
            circuit: self.fr()?,
            request_id: RequestId(self.fr()?),
        })
    }

    pub fn sealed(&mut self) -> Decoded<Vec<Sealed>> {
        (0..self.count()?)
            .map(|_| {
                let kind = match self.u8()? {
                    0 => SealedKind::Record,
                    1 => SealedKind::Replaced {
                        prior_request_id: RequestId(self.fr()?),
                    },
                    t => return Err(format!("bad sealed kind {t}")),
                };
                Ok(Sealed {
                    kind,
                    key: self.str()?,
                    note_hash: self.fr()?,
                    c_i: self.bytes()?,
                })
            })
            .collect()
    }

    /// A row as [`Writer::request_row`] wrote it.
    pub fn request_row(&mut self) -> Decoded<RequestRow> {
        Ok(RequestRow {
            request_id: RequestId(self.fr()?),
            body_hash: self.fr()?,
            vk_hash: self.fr()?,
            proof: self.bytes()?,
            public_inputs: self.frs()?,
            stored_keys: self.strs()?,
            created_keys: self.strs()?,
            sealed: self.sealed()?,
            signature: if self.bool()? {
                Some(self.signature()?)
            } else {
                None
            },
            status: status_from_tag(self.u8()?)?,
            created_at: self.u64()?,
            chain_request_id: if self.bool()? { Some(self.fr()?) } else { None },
        })
    }

    pub fn opt_fr(&mut self) -> Decoded<Option<Fr>> {
        Ok(if self.bool()? { Some(self.fr()?) } else { None })
    }

    /// Shared inputs as [`Writer::shares`] wrote them.
    pub fn shares(&mut self) -> Decoded<Vec<NodeSharedInput>> {
        (0..self.count()?)
            .map(|_| {
                let name = self.str()?;
                let mut f = || self.fr().map(Into::into);
                let share = ShareCiphertext {
                    eph: GrumpkinPoint { x: f()?, y: f()? },
                    ct: [f()?, f()?],
                    tag: f()?,
                };
                let share_hashes = [f()?, f()?, f()?];
                Ok(NodeSharedInput {
                    name,
                    share,
                    share_hashes,
                })
            })
            .collect()
    }

    /// A row as [`Writer::receipt_row`] wrote it (log write 8).
    pub fn receipt_row(&mut self) -> Decoded<ReceiptRow> {
        let head = self.receipt_head()?;
        let (user_nonce, shares) = (self.opt_fr()?, self.shares()?);
        Ok(ReceiptRow {
            user_nonce,
            shares,
            ..self.receipt_tail(head)?
        })
    }

    // The fields of a receipts row before the nonce.
    fn receipt_head(&mut self) -> Decoded<(Fr, String, Fr, Vec<Fr>, Fr)> {
        Ok((self.fr()?, self.str()?, self.fr()?, self.frs()?, self.fr()?))
    }

    // The fields of a receipts row after the nonce and shares.
    fn receipt_tail(
        &mut self,
        (request_id, circuit, vk_hash, inputs, inputs_hash): (Fr, String, Fr, Vec<Fr>, Fr),
    ) -> Decoded<ReceiptRow> {
        Ok(ReceiptRow {
            request_id,
            circuit,
            vk_hash,
            inputs,
            inputs_hash,
            user_nonce: None,
            shares: vec![],
            expiry_block: self.u64()?,
            stale_blocks: if self.bool()? {
                Some(self.u64()?)
            } else {
                None
            },
            signature: self.signature()?,
        })
    }

    /// A vector as [`Writer::vec`] wrote it.
    pub fn vec(&mut self) -> Decoded<Vec<Elem>> {
        decode_vec(&self.bytes()?)
    }

    /// A row as [`Writer::tip_version`] wrote it.
    pub fn tip_version(&mut self) -> Decoded<TipVersion> {
        Ok(TipVersion {
            key: self.str()?,
            commitment: self.fr()?,
            parent: self.fr()?,
            index: self.u64()?,
            request_id: RequestId(self.fr()?),
            vec: self.vec()?,
            tree: match self.u8()? {
                0 => None,
                1 => Some(VersionTree::from_stored(self.fr()?, self.u64()?)),
                t => return Err(format!("bad tree flag {t}")),
            },
            status: match self.u8()? {
                0 => VersionStatus::Canonical,
                1 => VersionStatus::Live,
                2 => VersionStatus::Orphan,
                t => return Err(format!("bad version status {t}")),
            },
            block: self.u64()?,
            block_hash: self.fr()?,
        })
    }

    /// A node as [`Writer::tree_node`] wrote it.
    pub fn tree_node(&mut self) -> Decoded<TreeNode> {
        match self.u8()? {
            0 => Ok(TreeNode::Inner {
                left: self.fr()?,
                right: self.fr()?,
            }),
            1 => Ok(TreeNode::Leaf {
                index: self.u64()?,
                vec: self.vec()?,
            }),
            t => Err(format!("bad tree node tag {t}")),
        }
    }
}

/// A field element's 32-byte big-endian integer.
pub fn fr_bytes(v: Fr) -> [u8; 32] {
    fr_to_be_bytes(v)
        .try_into()
        .expect("a field element is 32 bytes")
}

/// The inverse of [`fr_bytes`]; refuses another length or a value at or
/// above the modulus.
pub fn fr_from_bytes(bytes: &[u8]) -> Decoded<Fr> {
    if bytes.len() != 32 {
        return Err(format!("a field element is 32 bytes, not {}", bytes.len()));
    }
    let v = Fr::from_be_bytes_mod_order(bytes);
    if fr_bytes(v)[..] != *bytes {
        return Err("a field element at or above the modulus".into());
    }
    Ok(v)
}

pub fn point_bytes(v: &Point) -> Vec<u8> {
    let mut out = Vec::new();
    v.serialize_uncompressed(&mut out)
        .expect("writing to a Vec cannot fail");
    out
}

pub fn point_from_bytes(bytes: &[u8]) -> Decoded<Point> {
    Point::deserialize_uncompressed(bytes).map_err(|e| format!("a stored point: {e}"))
}

pub fn share_bytes(v: &Share) -> Vec<u8> {
    let mut out = Vec::new();
    v.serialize_uncompressed(&mut out)
        .expect("writing to a Vec cannot fail");
    out
}

pub fn share_from_bytes(bytes: &[u8]) -> Decoded<Share> {
    Share::deserialize_uncompressed(bytes).map_err(|e| format!("a stored share: {e}"))
}

/// `s.lo ‖ s.hi ‖ e.lo ‖ e.hi`, four field elements.
pub const SIGNATURE_LEN: usize = 4 * 32;

pub fn signature_bytes(v: &Signature) -> Vec<u8> {
    let mut out = Vec::with_capacity(SIGNATURE_LEN);
    for f in v.s.iter().chain(&v.e) {
        out.extend_from_slice(&fr_bytes(f.fr()));
    }
    out
}

pub fn signature_from_bytes(bytes: &[u8]) -> Decoded<Signature> {
    if bytes.len() != SIGNATURE_LEN {
        return Err(format!("a signature is {SIGNATURE_LEN} bytes"));
    }
    let f = |i: usize| fr_from_bytes(&bytes[32 * i..32 * (i + 1)]).map(Into::into);
    Ok(Signature {
        s: [f(0)?, f(1)?],
        e: [f(2)?, f(3)?],
    })
}

pub fn manifest_from_text(text: &str) -> Decoded<serde_json::Value> {
    serde_json::from_str(text).map_err(|e| format!("a stored manifest: {e}"))
}

pub fn status_tag(status: RequestStatus) -> u8 {
    match status {
        RequestStatus::Committed => 0,
        RequestStatus::RolledBack => 1,
    }
}

pub fn status_from_tag(tag: u8) -> Decoded<RequestStatus> {
    match tag {
        0 => Ok(RequestStatus::Committed),
        1 => Ok(RequestStatus::RolledBack),
        t => Err(format!("bad request status {t}")),
    }
}

/// The stored name (`committed`, `rolled_back`) back to the status.
pub fn status_from_str(text: &str) -> Decoded<RequestStatus> {
    match text {
        "committed" => Ok(RequestStatus::Committed),
        "rolled_back" => Ok(RequestStatus::RolledBack),
        t => Err(format!("bad request status `{t}`")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_elements_are_big_endian_and_canonical() {
        let b = fr_bytes(Fr::from(0x0102u64));
        assert_eq!(&b[30..], [1, 2]);
        assert_eq!(fr_from_bytes(&b).unwrap(), Fr::from(0x0102u64));
        assert!(fr_from_bytes(&[0xff; 32]).is_err());
        assert!(fr_from_bytes(&[0; 31]).is_err());
    }

    #[test]
    fn a_truncated_item_is_refused() {
        let mut w = Writer::new();
        w.str("pool");
        let mut r = Reader::new(&w.out[..5]);
        assert!(r.str().is_err());
    }
}
