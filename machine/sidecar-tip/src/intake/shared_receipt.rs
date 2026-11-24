//! Secret-shared receipt intake (`intake: shared_receipt`): each node stored
//! the clear inputs, the inputs commitment C and its own envelope of every
//! shared value when it signed the receipt.

use sidecar_core::envelope::{EnvelopeAd, open_envelope, open_envelope_current};
use sidecar_core::keys::NodeKeys;
use sidecar_core::register::Signature;
use sidecar_core::request::{NodeSharedInput, ShareCiphertext, SharedInput};

use super::*;
use crate::intake::route::{
    ReceiptSigning, SUMMAND_SALT, commitment_layout, intake_inputs, shared_names,
};

/// Secret-shared receipt intake's shares: the envelopes of every shared
/// input, carried as the synthesised request's `shared_inputs`.
impl CarriedShares for Vec<SharedInput> {
    fn carry(&self, request: &mut Request<Full>) {
        request.shared_inputs = self.clone();
    }
}

/// Secret-shared receipt intake (`intake: shared_receipt`): each node stored, when
/// it signed the receipt, the clear app inputs, the inputs commitment `C`
/// and its own envelope of every INPUT_SHARED value with the three share
/// hashes; the chain request id commits to `C` alone.
#[derive(Clone, Copy, Debug)]
pub struct SharedReceipt;

impl SharedReceipt {
    /// The inputs of chain request `chain` under `package` from the three
    /// nodes' stored receipts; why not, when a node holds none, the rows
    /// differ in anything but each node's own envelopes and signature, or
    /// they give no request ([`shared_inputs`]).
    pub(super) fn agreed(
        held: &[Option<StoredReceipt>; NODES],
        namespace: Fr,
        package: &TipPackage,
        chain: Fr,
    ) -> Result<SharedReceiptFound, String> {
        let mut rows = Vec::with_capacity(NODES);
        for (i, row) in held.iter().enumerate() {
            rows.push(row.as_ref().ok_or_else(|| {
                format!(
                    "node {i} holds no stored receipt (never signed, pruned, or not answering), \
                     and the round needs every node's envelopes"
                )
            })?);
        }
        let common = |r: &StoredReceipt| StoredReceipt {
            shared_inputs: r
                .shared_inputs
                .iter()
                .map(|s| NodeSharedInput {
                    share: ShareCiphertext::default(),
                    ..s.clone()
                })
                .collect(),
            signature: Signature::default(),
            ..r.clone()
        };
        let first = common(rows[0]);
        if let Some(i) = (1..NODES).find(|&i| common(rows[i]) != first) {
            return Err(format!(
                "node {i}'s stored receipt differs from node 0's in more than its envelopes and \
                 signature"
            ));
        }
        let mut envelopes = [None; NODES];
        for (i, row) in rows.iter().enumerate() {
            envelopes[i] = Some(row.shared_inputs.as_slice());
        }
        shared_inputs(rows[0], envelopes, namespace, package, chain)
    }
}

/// The inputs of chain request `chain` under `package` from a stored secret-shared
/// receipt row (`receipt`, any node's: the rows agree on everything but the
/// envelopes) and the envelopes of the nodes whose rows are held
/// (`envelopes[i]`, node i's row's; the chain verifier holds only its
/// own). Why not, when the row names another package or request, holds a
/// nonce, or its `C` does not give `chain`, or the envelopes do not fit
/// ([`stored_shares`]).
fn shared_inputs(
    receipt: &StoredReceipt,
    envelopes: [Option<&[NodeSharedInput]>; NODES],
    namespace: Fr,
    package: &TipPackage,
    chain: Fr,
) -> Result<SharedReceiptFound, String> {
    check_origin(receipt, namespace, package, chain).map_err(|e| e.message)?;
    if receipt.user_nonce.is_some() {
        return Err(format!(
            "the stored receipt of chain request {} holds a user_nonce (a receipt intake row)",
            fr_to_hex(chain)
        ));
    }
    let inputs = SharedReceiptFound::new(
        receipt.inputs.iter().map(|f| f.fr()).collect(),
        receipt.inputs_hash.fr(),
        stored_shares(package, envelopes)?,
    );
    let derived = package.chain_request_id(namespace, &inputs);
    if derived != chain {
        return Err(format!(
            "the stored inputs commitment {} gives chain request {} under circuit `{}`, not {}",
            receipt.inputs_hash,
            fr_to_hex(derived),
            package.name,
            fr_to_hex(chain)
        ));
    }
    Ok(inputs)
}

/// The shared inputs a synthesised request of `package` carries, from the
/// envelopes the nodes stored (`envelopes[i]`, node i's row's): one entry
/// per INPUT_SHARED name of the circuit in ABI order ([`shared_names`]),
/// with node i's envelope at `shares[i]` and the three share hashes, which
/// every held row gives alike. A node whose row is not held leaves an empty
/// envelope at its place, which the projection to any other node drops.
/// Why not, when a row lacks a name, holds one twice or one the circuit
/// does not take, the rows' share hashes differ, or an envelope does not
/// hash to its share hash.
fn stored_shares(
    package: &TipPackage,
    envelopes: [Option<&[NodeSharedInput]>; NODES],
) -> Result<Vec<SharedInput>, String> {
    let names = shared_names(&package.shape, &package.tip);
    for (i, row) in envelopes.iter().enumerate() {
        if let Some(extra) = row
            .iter()
            .flat_map(|r| r.iter())
            .find(|s| !names.contains(&s.name))
        {
            return Err(format!(
                "node {i}'s row holds an envelope of `{}`, not a shared input of circuit `{}`",
                extra.name, package.name
            ));
        }
    }
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let mut shares = [ShareCiphertext::default(); NODES];
        let mut share_hashes = None;
        for (i, row) in envelopes.iter().enumerate() {
            let Some(row) = row else {
                continue;
            };
            let mut found = row.iter().enumerate().filter(|(_, s)| s.name == name);
            let (Some((k, own)), None) = (found.next(), found.next()) else {
                return Err(format!(
                    "node {i}'s row holds {} envelope(s) of `{name}`, not one",
                    row.iter().filter(|s| s.name == name).count()
                ));
            };
            own.check_hash(i, k)
                .map_err(|e| format!("node {i}'s stored receipt: {}", e.message))?;
            match share_hashes {
                None => share_hashes = Some(own.share_hashes),
                Some(h) if h != own.share_hashes => {
                    return Err(format!(
                        "node {i}'s share hashes of `{name}` differ from another node's"
                    ));
                }
                Some(_) => {}
            }
            shares[i] = own.share;
        }
        let share_hashes = share_hashes.ok_or_else(|| "no node's row is held".to_string())?;
        out.push(SharedInput {
            name,
            shares,
            share_hashes,
        });
    }
    Ok(out)
}

/// REGISTER's check of a secret-shared receipt package against node `node`'s
/// `enc` grace window (400): the intake seals the inputs to `enc` when it
/// takes them, and a queued request's envelopes open only when its round
/// runs, so the namespace's stale period, `stale_blocks` (the contract
/// manifest's `queue.stale_blocks`), must be finite (null, a head never
/// skipped, is refused) and the receipt life with it, the node's life with
/// its stale term replaced by it, must fit the window
/// ([`crate::check_enc_grace`]). A node's config check covers the default
/// stale period only; this check is each namespace's.
pub(crate) fn stale_period_fits(
    stale_blocks: Option<u64>,
    node: &RegisterNode,
) -> Result<(), Refusal> {
    let Some(stale_blocks) = stale_blocks else {
        return Err(Refusal::bad_request(format!(
            "field `manifest.queue.stale_blocks`: null (a head never skipped) is refused \
             under {}: a queued request's envelopes must open within this node's enc grace \
             window ({} s); give a stale period",
            QueuedIntake::SharedReceipt.name(),
            node.enc_grace_secs
        )));
    };
    crate::check_enc_grace(
        node.enc_grace_secs,
        crate::ReceiptLife {
            stale_blocks,
            ..node.life
        },
    )
    .map_err(|e| Refusal::bad_request(format!("field `manifest.queue.stale_blocks`: {e:#}")))
}

impl IntakeSource for SharedReceipt {
    fn intake(&self) -> QueuedIntake {
        QueuedIntake::SharedReceipt
    }

    fn reads_nodes(&self) -> bool {
        true
    }

    /// An envelope of the row to node `node` that opens under the previous
    /// `enc` scalar and not the current one: the row's request needs the
    /// previous scalar until the head has passed it.
    fn holds_previous_enc(
        &self,
        keys: &NodeKeys,
        node: usize,
        namespace: Fr,
        row: &ReceiptRow,
    ) -> bool {
        row.shares.iter().any(|input| {
            let ad = EnvelopeAd::for_intake(namespace, row.request_id, &row.circuit, &input.name);
            open_envelope_current(keys, node, &ad, &input.share).is_err()
                && open_envelope(keys, node, &ad, &input.share).is_ok()
        })
    }

    /// The stale period against this node's `enc` grace window
    /// ([`stale_period_fits`]).
    fn check_register(
        &self,
        _shape: &CircuitShape,
        tip: &TipManifest,
        node: &RegisterNode,
    ) -> Result<(), Refusal> {
        stale_period_fits(tip.stale_blocks(), node)
    }

    /// The three nodes' stored receipts, which must agree on everything but
    /// each node's own envelopes and signature, with the three envelopes of
    /// every shared input. Rows of another circuit (or none at all) are
    /// another package's entry; rows of this circuit that give no request
    /// are logged.
    fn find<'a>(
        &'a self,
        at: &'a dyn IntakeLookup,
        package: &'a TipPackage,
        chain: Fr,
    ) -> TipFuture<'a, Result<Option<Found>, ReadError>> {
        Box::pin(async move {
            let held = at.stored_receipts(chain).await;
            if !held.iter().flatten().any(|r| r.circuit == package.name) {
                return Ok(None);
            }
            match Self::agreed(&held, at.namespace(), package, chain) {
                Ok(inputs) => Ok(Some(found(inputs))),
                Err(why) => {
                    tracing::warn!(
                        circuit = %package.name,
                        chain_request_id = %fr_to_hex(chain),
                        "scheduler: the nodes' stored receipts give no secret-shared request: {why}"
                    );
                    Ok(None)
                }
            }
        })
    }

    /// This node's own stored receipt, with its own envelope of every shared
    /// input (the others empty: the received request is this node's
    /// projection, which carries only its own).
    fn node_view(&self, at: &NodeInputs<'_>) -> Result<Found, Refusal> {
        let row = at
            .rows
            .receipt(at.namespace, at.chain_request_id)?
            .ok_or_else(|| {
                refused(format!(
                    "this node holds no receipt for chain request {} (never signed, or pruned)",
                    fr_to_hex(at.chain_request_id)
                ))
            })?;
        let receipt = StoredReceipt::new(at.namespace, &row);
        let mut envelopes = [None; NODES];
        envelopes[at.node] = Some(receipt.shared_inputs.as_slice());
        let inputs = shared_inputs(
            &receipt,
            envelopes,
            at.namespace,
            at.package,
            at.chain_request_id,
        )
        .map_err(refused)?;
        Ok(found(inputs))
    }

    fn check_receipt(
        &self,
        package: &TipPackage,
        req: &ReceiptRequest,
    ) -> Result<CheckedReceipt, Refusal> {
        let intake = self.intake();
        if req.user_nonce.is_some() {
            return Err(not_taken(
                "user_nonce",
                intake,
                "its chain request id commits to the inputs commitment",
            ));
        }
        let c = req
            .inputs_hash
            .ok_or_else(|| {
                Refusal::bad_request(format!(
                    "field `inputs_hash`: missing; {} signs the inputs commitment C",
                    intake.name()
                ))
            })?
            .fr();
        let clear = intake_inputs(&package.shape, &package.tip, &req.inputs)?;
        let names = shared_names(&package.shape, &package.tip);
        let mut given = std::collections::BTreeSet::new();
        let mut salt = None;
        let mut shares = Vec::with_capacity(names.len());
        for (k, input) in req.shared_inputs.iter().enumerate() {
            if input.name == SUMMAND_SALT && salt.is_none() {
                salt = Some((k, input.clone()));
                continue;
            }
            if !names.contains(&input.name) {
                return Err(Refusal::bad_request(format!(
                    "field `shared_inputs[{k}].name`: `{}` is not a shared input of circuit `{}` \
                     (it takes {names:?}, then `{SUMMAND_SALT}`)",
                    input.name, package.name
                )));
            }
            if !given.insert(input.name.as_str()) {
                return Err(Refusal::bad_request(format!(
                    "field `shared_inputs[{k}].name`: `{}` is duplicated",
                    input.name
                )));
            }
            shares.push(input.clone());
        }
        if let Some(name) = names.iter().find(|n| !given.contains(n.as_str())) {
            return Err(Refusal::bad_request(format!(
                "field `shared_inputs`: missing `{name}`"
            )));
        }
        let salt = salt.ok_or_else(|| {
            Refusal::bad_request(format!(
                "field `shared_inputs`: missing `{SUMMAND_SALT}`, the envelopes of the summand \
                 salts"
            ))
        })?;
        let commitments = req
            .summand_commitments
            .ok_or_else(|| {
                Refusal::bad_request(format!(
                    "field `summand_commitments`: missing; {} signs the sharing digest over them",
                    intake.name()
                ))
            })?
            .map(|f| f.fr());
        let digest = req
            .sharing_digest
            .ok_or_else(|| {
                Refusal::bad_request(format!(
                    "field `sharing_digest`: missing; {} signs it",
                    intake.name()
                ))
            })?
            .fr();
        let layout = commitment_layout(&package.shape, &package.tip);
        if crate::sharing_digest(&commitments, &layout.value_kinds(), &clear) != digest {
            return Err(Refusal::bad_request(
                "field `sharing_digest`: not poseidon2([SHARING_DOMAIN, S_0, S_1, S_2, kinds..., \
                 clear values...]) of `summand_commitments`, the circuit's layout and the clear \
                 `inputs`; the digest covers the clear values C commits to, so send the nodes \
                 those",
            ));
        }
        let inputs = SharedReceiptFound::new(clear, c, vec![]);
        let (salt_at, salt) = salt;
        Ok(CheckedReceipt {
            request_id: package.chain_request_id(req.namespace.fr(), &inputs),
            inputs_hash: c,
            inputs: inputs.inputs,
            user_nonce: None,
            shares,
            vk_hash: package.vk_hash,
            stale_blocks: package.tip.stale_blocks(),
            signing: Arc::new(SharingCheck {
                order: layout.summand_names(),
                salt,
                salt_at,
                commitments,
                digest,
            }),
        })
    }
}

/// A secret-shared receipt request's sharing as a node checks it before it
/// signs: the order of the summand vectors' elements
/// ([`crate::CommitmentLayout::summand_names`]), this node's envelope of the
/// salts ([`SUMMAND_SALT`]) and its index in the request's
/// `shared_inputs`, the three summand commitments and the sharing digest
/// the request carries, which the intake's check found to be the digest of
/// the commitments, the circuit's layout and the clear inputs
/// ([`crate::sharing_digest`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SharingCheck {
    pub order: Vec<String>,
    pub salt: NodeSharedInput,
    pub salt_at: usize,
    pub commitments: [Fr; NODES],
    pub digest: Fr,
}

impl ReceiptSigning for SharingCheck {
    /// The receipt message over `C` and the sharing digest
    /// ([`crate::shared_receipt_message`]).
    fn message(&self, receipt: &CheckedReceipt, expiry_block: u32) -> Fr {
        crate::shared_receipt_message(
            receipt.request_id,
            receipt.inputs_hash,
            expiry_block,
            self.digest,
        )
    }

    /// Each envelope `receipt` keeps, and the salts' envelope, hashes to
    /// `share_hashes[node]` and opens under the node's current `enc` scalar
    /// and the intake associated data over the receipt's chain request id,
    /// `namespace`, `circuit` and the input's name (400 naming the input
    /// otherwise, and an envelope that opens only under the previous scalar
    /// of a rotation is refused too); then the pairs it opened, `[a, b] =
    /// [x_i, x_{i-1}]` of each value in summand order with the salts'
    /// `[salt_i, salt_{i-1}]`, must be the summand vectors `s_i` and
    /// `s_{i-1}` the request commits to: `summand_commitment(a…, salt_i) =
    /// S_i` and `summand_commitment(b…, salt_{i-1}) = S_{i-1}` (400
    /// otherwise). The node checks alone; node i+1 checks `S_i` against the
    /// same `s_i`, so three receipts over one `D` mean the three nodes hold
    /// one sharing. The pairs are dropped: the node keeps the envelopes,
    /// never a share in the clear.
    fn check_own_envelopes(
        &self,
        receipt: &CheckedReceipt,
        keys: &NodeKeys,
        node: usize,
        namespace: Fr,
        circuit: &str,
    ) -> Result<(), Refusal> {
        // The request's index of the k-th kept envelope: the salts' envelope
        // is not kept.
        let at = |k: usize| if k < self.salt_at { k } else { k + 1 };
        for (k, input) in receipt.shares.iter().enumerate() {
            input.check_hash(node, at(k))?;
        }
        self.salt.check_hash(node, self.salt_at)?;
        let open = |input: &NodeSharedInput| {
            let ad = EnvelopeAd::for_intake(namespace, receipt.request_id, circuit, &input.name);
            open_envelope_current(keys, node, &ad, &input.share)
        };
        let mut own = Vec::with_capacity(self.order.len());
        let mut prev = Vec::with_capacity(self.order.len());
        for name in &self.order {
            let input = receipt
                .shares
                .iter()
                .find(|s| &s.name == name)
                .ok_or_else(|| {
                    Refusal::bad_request(format!("field `shared_inputs`: missing `{name}`"))
                })?;
            let [a, b] = open(input)?;
            own.push(a);
            prev.push(b);
        }
        let [salt_own, salt_prev] = open(&self.salt)?;
        let before = (node + NODES - 1) % NODES;
        for (j, summands, salt) in [(node, &own, salt_own), (before, &prev, salt_prev)] {
            if crate::summand_commitment(summands, salt) != self.commitments[j] {
                return Err(Refusal::bad_request(format!(
                    "field `summand_commitments[{j}]`: the summands and salt node {node}'s \
                     envelopes open to do not hash to it; seal node i the pairs [x_i, x_(i-1)] \
                     of the summand vectors the commitments are over"
                )));
            }
        }
        Ok(())
    }
}
