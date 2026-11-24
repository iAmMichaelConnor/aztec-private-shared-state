//! Secret-shared on-chain intake as every tip suite tests it, contract by
//! contract: the nodes' `enc` scalars and their signed rotations, the
//! request function's expected private log (recomputed with pss_core's
//! `tip::derived`, as the client builds it), and each node's pair of every
//! shared value re-derived from the landed log (`node_pair`, as the machine
//! derives it). A suite keeps only its own layout, values and calls.
use crate::nodes::{NODE_SIG, sign};
use aztec::protocol::address::AztecAddress;
use aztec::test::helpers::txe_oracles;
use pss_core::tip::derived::{
    CHOSEN, CLEAR, key_exchange, Layout, node_pair, pack_epochs, request_log, REQUEST_LOG_HEADER,
    REQUEST_LOG_LEN, shares_of, wraps,
};
use pss_core::tip::intake::{commit, shared};
use pss_public_contract::{enc_rotation_message, EncKey, Receipt};
use pss_utils::dh::{ecdh_x, public_key};

/// The nodes' first `enc` scalars and the ones they rotate to.
pub global ENC: [Field; 3] = [0x0e1e1, 0x0e2e2, 0x0e3e3];
pub global ENC_NEXT: [Field; 3] = [0x0f1f1, 0x0f2f2, 0x0f3f3];

/// The requester's ephemeral secret.
pub global EPH: Field = 0x0e9e9e9;

/// The `EncKey` of scalar `sk` at `epoch`.
pub unconstrained fn enc_key(sk: Field, epoch: u32) -> EncKey {
    let p = public_key(sk);
    EncKey { x: p.x, y: p.y, epoch }
}

/// Node i's rotation of `app` to `sk` at `epoch`, signed by the scalar
/// `signer`: the key and the signature its `rotate_enc_key` takes.
pub unconstrained fn enc_rotation(app: AztecAddress, i: u32, sk: Field, epoch: u32, signer: Field) -> (EncKey, Receipt) {
    let key = enc_key(sk, epoch);
    (key, sign(signer, enc_rotation_message(app, i, key)))
}

/// Node i's rotation signed under its own pinned `sig` key.
pub unconstrained fn node_rotation(app: AztecAddress, i: u32, sk: Field, epoch: u32) -> (EncKey, Receipt) {
    enc_rotation(app, i, sk, epoch, NODE_SIG[i])
}

/// What the request function computes from C's `values` under `eph` and
/// the node scalars `scalars` at `epochs`: C, the chain request id, the log
/// after its tag, C's values, the blinding, the corrections and the three
/// key-exchange secrets.
pub struct Expected<let M: u32, let X: u32> {
    pub c: Field,
    pub id: Field,
    pub log: [Field; REQUEST_LOG_LEN],
    pub values: [Field; M],
    pub blinding: Field,
    pub corrections: [Field; X],
    pub secrets: [Field; 3],
}

/// `Expected` for a request of `namespace` under the round's `vk_hash`, its
/// values encoded under `layout`.
pub unconstrained fn expected<let M: u32, let Q: u32, let X: u32>(
    layout: Layout<M, Q, X>,
    namespace: Field,
    vk_hash: Field,
    values: [Field; M],
    eph: Field,
    scalars: [Field; 3],
    epochs: [u32; 3],
) -> Expected<M, X> {
    let (secrets, eph_x) = key_exchange(eph, scalars.map(|k| public_key(k)));
    let enc = shares_of(layout, values, secrets);
    let c = commit(values, enc.blinding);
    let id = shared(namespace, vk_hash, c);
    let log = request_log(
        enc.blinding,
        c,
        pack_epochs(epochs),
        eph_x,
        wraps(secrets),
        enc.clear,
        enc.corrections,
    );
    Expected {
        c,
        id,
        log,
        values,
        blinding: enc.blinding,
        corrections: enc.corrections,
        secrets,
    }
}

/// The last transaction's one private log: `[siloed tag, fields…]`.
pub unconstrained fn the_request_log() -> BoundedVec<Field, 16> {
    let effects = txe_oracles::get_last_tx_effects();
    assert_eq(effects.private_logs.len(), 1);
    effects.private_logs.get(0)
}

/// A request log's fields after its tag.
pub unconstrained fn body(log: BoundedVec<Field, 16>) -> [Field; REQUEST_LOG_LEN] {
    let mut out = [0; REQUEST_LOG_LEN];
    for i in 0..REQUEST_LOG_LEN {
        out[i] = log.get(1 + i);
    }
    out
}

/// The j-th shared value as the three nodes hold it: each node's Rep3 pair
/// from its key-exchange secret, the wrap before it and the value's
/// correction (`node_pair`, the machine's derivation). Asserts the pairs are
/// replicated (node i's second share is node i - 1's first) and returns the
/// value they reconstruct.
pub unconstrained fn reconstruct(
    log: BoundedVec<Field, 16>,
    secrets: [Field; 3],
    j: u32,
    correction: Field,
) -> Field {
    let pairs = [0, 1, 2].map(|i| node_pair(i, secrets[i], log.get(1 + 3 + (i + 2) % 3), j, correction));
    for i in 0..3 {
        assert_eq(pairs[i][1], pairs[(i + 2) % 3][0]);
    }
    pairs[0][0] + pairs[1][0] + pairs[2][0]
}

/// What the nodes open from the landed log under the kinds vector `kinds`,
/// node i using its scalar `scalars[i]` with the log's E (from `eph`): C's
/// values in order (a CLEAR one read from the log, a CHOSEN one with the
/// next correction) and then the blinding.
pub unconstrained fn opened<let M: u32>(
    log: BoundedVec<Field, 16>,
    eph: Field,
    scalars: [Field; 3],
    kinds: [u8; M],
) -> ([Field; M], Field) {
    let e = public_key(eph);
    assert_eq(log.get(3), e.x);
    let secrets = scalars.map(|sk| ecdh_x(sk, e));
    let mut q = 0;
    for k in kinds {
        if k == CLEAR {
            q += 1;
        }
    }
    let (mut cq, mut x) = (0, 0);
    let mut out = [0; M];
    for p in 0..M {
        if kinds[p] == CLEAR {
            out[p] = log.get(1 + REQUEST_LOG_HEADER + cq);
            cq += 1;
        } else {
            assert_eq(kinds[p], CHOSEN, "a value kind is CLEAR or CHOSEN");
            out[p] = reconstruct(log, secrets, x, log.get(1 + REQUEST_LOG_HEADER + q + x));
            x += 1;
        }
    }
    (out, reconstruct(log, secrets, x, 0))
}
