//! Key epochs, the machine's side (docs/ARCHITECTURE.md section 6, "Node
//! replacement and key epochs"): the message two of the three current nodes
//! sign to move an app contract to its next key epoch, the contract's
//! `rotate_keys(epoch, keys, signatures)` (pss_public_contract `key_epoch`).
//!
//! A key set is the three nodes' `sig` and `enc` public keys, node 0 first,
//! as `GET /v1/nodes` lists them ([`NodesResponse`]); an epoch is a number
//! and a key set. The contract checks two signatures, each under its own
//! place's `sig` key of the current epoch, over
//!
//! ```text
//! poseidon2([PSS_ROTATE_KEYS, namespace, epoch, H(keys)])
//! H(keys) = poseidon2([sig_0.x, sig_0.y, enc_0.x, enc_0.y, sig_1.x, ..., enc_2.y])
//! ```
//!
//! The contract stores its key epoch at one slot of its own,
//! [`NODE_KEYS_SLOT`], with the layout of [`StoredNodeKeys`], so the chain
//! readers find every contract's key set at the same place.

use ark_std::rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::field::{FieldHex, Fr};
use crate::grumpkin::Fq;
use crate::hash::poseidon2_hash;
use crate::keys::label_field;
use crate::register::Signature;
use crate::request::{GrumpkinPoint, NODES};
use crate::response::{NodePublicKeys, NodesResponse};
use crate::schnorr;

/// The rotation message's first element, ASCII "pss.rotate_keys" read
/// big-endian (pss_public_contract `PSS_ROTATE_KEYS`).
pub const PSS_ROTATE_KEYS_LABEL: &[u8] = b"pss.rotate_keys";

/// The public-storage slot of a contract's key epoch, ASCII "pss.node_keys"
/// read big-endian (pss_public_contract `NODE_KEYS_SLOT`).
pub const NODE_KEYS_SLOT_LABEL: &[u8] = b"pss.node_keys";

/// The packed length of the contract's `NodeKeys`; its hash is the next
/// slot.
pub const NODE_KEYS_LEN: u64 = 21;

/// [`NODE_KEYS_SLOT_LABEL`] as a field.
pub fn node_keys_slot() -> Fr {
    label_field(NODE_KEYS_SLOT_LABEL)
}

/// Where a contract keeps key epoch 0's `sig` keys: the constructor's
/// `node_sig_keys` (pss_public_contract `TipPins`, and `TipConfig` alike),
/// which follow `stale_blocks` (`enabled`, `blocks`: two fields) in the
/// packing, two fields per key (x, y), node 0 first. Node i's key is at
/// `stale_blocks_slot + 2 + 2i` and the slot after it, `stale_blocks_slot`
/// being the namespace's `TipConfig.stale_blocks` slot, which the chain
/// verifier and the scheduler already read.
pub fn epoch0_sig_slots(stale_blocks_slot: Fr) -> [Fr; 2 * NODES] {
    std::array::from_fn(|k| stale_blocks_slot + Fr::from(2 + k as u64))
}

/// `H(keys)`: the Poseidon2 of the six points' coordinates, node by node,
/// `sig` before `enc`.
pub fn keys_hash(keys: &NodesResponse) -> Fr {
    let mut fields = Vec::with_capacity(4 * NODES);
    for k in &keys.nodes {
        fields.extend([k.sig.x.fr(), k.sig.y.fr(), k.enc.x.fr(), k.enc.y.fr()]);
    }
    poseidon2_hash(&fields)
}

/// The message two of the current nodes sign to move `namespace` to
/// `epoch` under `keys`.
pub fn rotation_message(namespace: Fr, epoch: u32, keys: &NodesResponse) -> Fr {
    poseidon2_hash(&[
        label_field(PSS_ROTATE_KEYS_LABEL),
        namespace,
        Fr::from(u64::from(epoch)),
        keys_hash(keys),
    ])
}

/// Node `sig`'s signature of the rotation of `namespace` to `epoch` under
/// `keys`.
pub fn sign_rotation<R: RngCore + CryptoRng>(
    sig: Fq,
    namespace: Fr,
    epoch: u32,
    keys: &NodesResponse,
    rng: &mut R,
) -> Signature {
    schnorr::sign(sig, rotation_message(namespace, epoch, keys), rng)
}

/// The contract's `rotate_keys` arguments for one namespace, as the
/// replacement prints them: the epoch, the key set (`KeySet { sig, enc }`,
/// node 0 first) and node i's signature at index i, `None` for the node that
/// did not sign (the departed node). The operator submits
/// `rotate_keys(epoch, keys, signatures)` with a missing signature as all
/// zeros.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rotation {
    pub namespace: FieldHex,
    pub epoch: u32,
    pub keys: KeySetWire,
    pub signatures: [Option<Signature>; NODES],
}

/// A key set as the contract's `KeySet` takes it: the `sig` keys, then the
/// `enc` keys, node 0 first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeySetWire {
    pub sig: [GrumpkinPoint; NODES],
    pub enc: [GrumpkinPoint; NODES],
}

impl From<&NodesResponse> for KeySetWire {
    fn from(keys: &NodesResponse) -> Self {
        KeySetWire {
            sig: keys.nodes.map(|k| k.sig),
            enc: keys.nodes.map(|k| k.enc),
        }
    }
}

impl From<KeySetWire> for NodesResponse {
    fn from(keys: KeySetWire) -> Self {
        NodesResponse {
            nodes: [0, 1, 2].map(|i| NodePublicKeys {
                enc: keys.enc[i],
                sig: keys.sig[i],
            }),
        }
    }
}

impl Rotation {
    /// Whether the signatures present verify under `current` (the epoch's
    /// `sig` keys, node 0 first) and at least two are present: what the
    /// contract checks.
    pub fn verifies(&self, current: &NodesResponse) -> bool {
        let keys = NodesResponse::from(self.keys);
        let message = rotation_message(self.namespace.fr(), self.epoch, &keys);
        let mut signed = 0;
        for (i, s) in self.signatures.iter().enumerate() {
            if let Some(s) = s {
                if !schnorr::verify_wire(&current.nodes[i].sig, *s, message) {
                    return false;
                }
                signed += 1;
            }
        }
        signed >= 2
    }
}

/// A contract's key epoch as stored at [`NODE_KEYS_SLOT_LABEL`]: the
/// fields in the contract's packing order (epoch, `rotated_at`, `grace`,
/// the three `sig` points, the three `enc` points, the previous three `sig`
/// points). Nothing stored reads as all zeros: epoch 0, whose `sig` keys
/// are the constructor's pins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredNodeKeys {
    pub epoch: u32,
    pub rotated_at: u64,
    pub grace: u64,
    pub sig: [(Fr, Fr); NODES],
    pub enc: [(Fr, Fr); NODES],
    pub previous: [(Fr, Fr); NODES],
}

impl StoredNodeKeys {
    /// Unpack the [`NODE_KEYS_LEN`] fields read from the slot onwards; 500
    /// text when the length is wrong or a number does not fit.
    pub fn unpack(fields: &[Fr]) -> Result<Self, String> {
        if fields.len() as u64 != NODE_KEYS_LEN {
            return Err(format!(
                "a key epoch is {NODE_KEYS_LEN} fields, not {}",
                fields.len()
            ));
        }
        let small = |f: Fr, what: &str| -> Result<u64, String> {
            let hex = crate::field::fr_to_hex(f);
            u64::from_str_radix(hex.trim_start_matches("0x"), 16)
                .map_err(|_| format!("the key epoch's {what} is not a number: {hex}"))
        };
        let point = |k: usize| (fields[k], fields[k + 1]);
        let epoch = small(fields[0], "epoch")?;
        Ok(StoredNodeKeys {
            epoch: u32::try_from(epoch).map_err(|_| format!("epoch {epoch} is not a u32"))?,
            rotated_at: small(fields[1], "rotated_at")?,
            grace: small(fields[2], "grace")?,
            sig: [point(3), point(5), point(7)],
            enc: [point(9), point(11), point(13)],
            previous: [point(15), point(17), point(19)],
        })
    }

    /// Key epoch 0 under `sig`, the constructor's keys as read at
    /// [`epoch0_sig_slots`]: no `enc` keys on record and no previous set.
    pub fn epoch0(sig: [(Fr, Fr); NODES]) -> Self {
        let zero = (Fr::from(0u64), Fr::from(0u64));
        StoredNodeKeys {
            epoch: 0,
            rotated_at: 0,
            grace: 0,
            sig,
            enc: [zero; NODES],
            previous: [zero; NODES],
        }
    }

    /// Whether the current `sig` keys are `pins`' (the machine's pinned key
    /// set).
    pub fn sig_is(&self, pins: &NodesResponse) -> bool {
        (0..NODES).all(|i| self.sig[i] == (pins.nodes[i].sig.x.fr(), pins.nodes[i].sig.y.fr()))
    }
}

// Record-on-landing of a key set, the rule of the enc rotation
// (crate::epochs): a node keeps each contract's declared key-set rotation
// pending from the replacement that signed it until its own chain view shows
// the contract at that epoch under that key set (or past it), and only then
// records it as landed. A rotation that never lands leaves a pending entry
// that the next declaration replaces; nothing has to be cleared. The pruning
// job observes the pending entries, and the replacement's report and the
// prune answer say per contract what is still pending.
/// One contract's declared key-set rotation, as a node keeps it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredKeySet {
    pub epoch: u32,
    /// `H(keys)` of the declared set.
    pub keys_hash: FieldHex,
    /// Signed, not yet seen landing.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pending: bool,
}

/// Every contract's declared key-set rotation this node signed or awaits, by
/// contract: `{"<contract>": {"epoch", "keys_hash", "pending"}}`
/// (`key_epochs.json` in the key directory).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeySetEpochs(std::collections::BTreeMap<FieldHex, DeclaredKeySet>);

impl KeySetEpochs {
    /// Keep the rotation of `contract` to `epoch` under `keys` pending,
    /// replacing whatever the contract held.
    pub fn declare(&mut self, contract: Fr, epoch: u32, keys: &NodesResponse) {
        self.0.insert(
            FieldHex(contract),
            DeclaredKeySet {
                epoch,
                keys_hash: FieldHex(keys_hash(keys)),
                pending: true,
            },
        );
    }

    /// The contracts whose rotation is pending, with its epoch.
    pub fn pending(&self) -> Vec<(Fr, u32)> {
        self.0
            .iter()
            .filter(|(_, d)| d.pending)
            .map(|(c, d)| (c.fr(), d.epoch))
            .collect()
    }

    /// Observe `contract`'s stored key epoch: record its pending rotation
    /// when the contract is at that epoch under that key set, or past it.
    /// Returns the epoch recorded, if one was.
    pub fn land(&mut self, contract: Fr, stored: &StoredNodeKeys) -> Option<u32> {
        let d = self.0.get_mut(&FieldHex(contract))?;
        let landed = d.pending
            && (stored.epoch > d.epoch
                || (stored.epoch == d.epoch && stored.keys_hash() == d.keys_hash.fr()));
        if landed {
            d.pending = false;
            Some(d.epoch)
        } else {
            None
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("key-set epochs serialise")
    }

    pub fn from_json(text: &str) -> Result<Self, String> {
        serde_json::from_str(text).map_err(|e| e.to_string())
    }
}

impl StoredNodeKeys {
    /// `H(keys)` of the stored current set.
    pub fn keys_hash(&self) -> Fr {
        let mut fields = Vec::with_capacity(4 * NODES);
        for i in 0..NODES {
            fields.extend([self.sig[i].0, self.sig[i].1, self.enc[i].0, self.enc[i].1]);
        }
        poseidon2_hash(&fields)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::fr_to_hex;

    fn point(k: u64) -> GrumpkinPoint {
        GrumpkinPoint {
            x: FieldHex(Fr::from(k)),
            y: FieldHex(Fr::from(k + 1)),
        }
    }

    fn keys() -> NodesResponse {
        NodesResponse {
            nodes: [
                NodePublicKeys {
                    sig: point(1),
                    enc: point(7),
                },
                NodePublicKeys {
                    sig: point(3),
                    enc: point(9),
                },
                NodePublicKeys {
                    sig: point(5),
                    enc: point(11),
                },
            ],
        }
    }

    // The contract's layout (pss_public_contract key_epoch
    // `the_rotation_message_layout`) and its value, which the contract's
    // unit test holds as a constant: the two sides agree on the message.
    #[test]
    fn the_rotation_message_is_the_contracts() {
        let h = poseidon2_hash(&[1u64, 2, 7, 8, 3, 4, 9, 10, 5, 6, 11, 12].map(Fr::from));
        assert_eq!(keys_hash(&keys()), h);
        let message = rotation_message(Fr::from(0x2au64), 1, &keys());
        assert_eq!(
            message,
            poseidon2_hash(&[
                label_field(PSS_ROTATE_KEYS_LABEL),
                Fr::from(0x2au64),
                Fr::from(1u64),
                h
            ])
        );
        assert_eq!(
            label_field(PSS_ROTATE_KEYS_LABEL),
            crate::field::fr_from_hex("0x7073732e726f746174655f6b657973").unwrap()
        );
        assert_eq!(
            node_keys_slot(),
            crate::field::fr_from_hex("0x7073732e6e6f64655f6b657973").unwrap()
        );
        assert_eq!(fr_to_hex(message), ROTATION_MESSAGE_VECTOR);
    }

    /// The rotation message of `keys()` for namespace 0x2a at epoch 1, the
    /// constant pss_public_contract's key_epoch unit test holds.
    const ROTATION_MESSAGE_VECTOR: &str =
        "0x1731f2cc82d3d4f8a29ccbe697a04bf1ba45a6a681ce23b7c9aa16b5144bf05b";

    #[test]
    fn a_rotation_needs_two_signatures_under_the_current_set() {
        use ark_std::rand::SeedableRng;
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(7);
        let secrets: Vec<Fq> = (0..3)
            .map(|_| crate::keys::random_scalar(&mut rng))
            .collect();
        let current = NodesResponse {
            nodes: [0, 1, 2].map(|i| NodePublicKeys {
                sig: crate::grumpkin::point_to_wire(schnorr::public_key(secrets[i])),
                enc: point(20 + i as u64),
            }),
        };
        let next = keys();
        let ns = Fr::from(9u64);
        let sign = |i: usize, rng: &mut ark_std::rand::rngs::StdRng| {
            Some(sign_rotation(secrets[i], ns, 1, &next, rng))
        };
        let rotation = |signatures| Rotation {
            namespace: FieldHex(ns),
            epoch: 1,
            keys: KeySetWire::from(&next),
            signatures,
        };
        let two = rotation([sign(0, &mut rng), sign(1, &mut rng), None]);
        assert!(two.verifies(&current));
        assert!(!rotation([sign(0, &mut rng), None, None]).verifies(&current));
        // a signature in another node's place
        let swapped = rotation([sign(1, &mut rng), sign(0, &mut rng), None]);
        assert!(!swapped.verifies(&current));
        // another epoch
        let mut other = two.clone();
        other.epoch = 2;
        assert!(!other.verifies(&current));
    }

    #[test]
    fn a_declared_key_set_is_recorded_once_it_lands() {
        let mut held = KeySetEpochs::default();
        let ns = Fr::from(5u64);
        held.declare(ns, 2, &keys());
        assert_eq!(held.pending(), [(ns, 2)]);
        let at = |epoch: u32, k: &NodesResponse| StoredNodeKeys {
            epoch,
            rotated_at: 0,
            grace: 0,
            sig: k.nodes.map(|n| (n.sig.x.fr(), n.sig.y.fr())),
            enc: k.nodes.map(|n| (n.enc.x.fr(), n.enc.y.fr())),
            previous: [(Fr::from(0u64), Fr::from(0u64)); NODES],
        };
        // not yet, and another set at the epoch
        assert_eq!(held.land(ns, &at(1, &keys())), None);
        let mut other = keys();
        other.nodes[0].sig = point(40);
        assert_eq!(held.land(ns, &at(2, &other)), None);
        assert_eq!(held.land(ns, &at(2, &keys())), Some(2));
        assert!(held.pending().is_empty());
        assert_eq!(held.land(ns, &at(3, &keys())), None);
        let back = KeySetEpochs::from_json(&held.to_json()).unwrap();
        assert_eq!(back, held);
        // a contract past the declared epoch lands it
        held.declare(ns, 4, &keys());
        assert_eq!(held.land(ns, &at(5, &other)), Some(4));
    }

    #[test]
    fn the_stored_layout_unpacks() {
        let fields: Vec<Fr> = (0..NODE_KEYS_LEN).map(Fr::from).collect();
        let k = StoredNodeKeys::unpack(&fields).unwrap();
        assert_eq!(k.epoch, 0);
        assert_eq!((k.rotated_at, k.grace), (1, 2));
        assert_eq!(k.sig[0], (Fr::from(3u64), Fr::from(4u64)));
        assert_eq!(k.enc[2], (Fr::from(13u64), Fr::from(14u64)));
        assert_eq!(k.previous[1], (Fr::from(17u64), Fr::from(18u64)));
        assert!(StoredNodeKeys::unpack(&fields[1..]).is_err());
    }
}
