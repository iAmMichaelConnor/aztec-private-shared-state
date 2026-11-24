//! A keyed map at the tip over three real nodes with real MPC proofs
//! (docs/ARCHITECTURE.md section 6, "The oblivious sparse map";
//! examples/credits-tip): the manifests of `credits_init`, `pay`, `claim` and
//! `view` as committed, whose map has `access: oblivious, keyed: true` (depth
//! 64), REGISTERed at the three nodes; every request under secret-shared receipt
//! intake with its key a shared input, so the nodes read the slot's path from
//! their oblivious RAM (step 10b over the mesh), write the round's leaf and path
//! nodes into it at the next session's start, and never see a key.
//!
//! - The init round creates the map.
//! - A pay to an absent key inserts it; a second pay to it adds; a view
//!   reports it present with the sum; a claim takes part of the balance.
//! - A view of a key never paid reports it absent (present 0, a zero
//!   balance) and a claim of it is the non-membership outcome (code 4);
//!   both write the key's slot under a fresh blinding (entering it with a
//!   zero balance, which reads as absent), so the commitment changes on
//!   every round and the chain cannot tell a no-op from an effect.
//! - The outcome of every round opens under its outcome key, and the
//!   completed note is the completion of the request's partial note.
//! - No key, amount or partial note appears in what the nodes receive, a
//!   receipt row or the proof's public inputs; the three nodes agree on
//!   every version.
//! - A node's store deleted (its key directory kept) is resynced from its
//!   two neighbours through the admin sockets, the map's DORAM and journals
//!   with it (rebuilt from the components the neighbours share with it and
//!   compared by the blob handshake), and the next round reads the key at
//!   the three nodes; the node's store backed up, a pay run after the
//!   backup, the store deleted and restored by a delta resync, and a view
//!   reads the sum with that pay.
//!
//! Needs `scripts/prepare-data.sh` (the credits-tip circuits under
//! machine/data, or DATA_DIR); fails naming the missing files if they are
//! absent. Run with `--release`.

mod common;
mod shared_intake;

use std::sync::Arc;
use std::time::Instant;

use serde_json::Value;
use shared_intake::*;

use common::tip::*;
use common::*;
use sidecar_core::field::{Fr, fr_from_hex};
use sidecar_core::resync::Scope;
use sidecar_core::store::Store;
use sidecar_node::admin::{self, AdminRequest};
use sidecar_node::backup::BackupKey;
use sidecar_orchestrator::scheduler::Scheduler;
use sidecar_tip::testing::MemoryChain;

const TIP: u64 = 0x7c2d;
// the slot as the contract manifest writes it (fr_to_hex)
const MAP: &str = "0x000000000000000000000000000000000000000000000000000000000000a0c1";
const SEED: &str = "pss_seed";
const INIT: &str = "credits_init";
const PAY: &str = "pay";
const CLAIM: &str = "claim";
const VIEW: &str = "view";
const CIRCUITS: [&str; 5] = [SEED, INIT, PAY, CLAIM, VIEW];
/// credits_tip shared.nr `OUTCOME_SLOT`.
const OUTCOME_SLOT: u64 = 1;
/// The public parameters (namespace, vk_hash, in_slots[0], out_slots[0])
/// and the ciphertext's length (four outcome fields and the tag).
const PARAMS: usize = 4;
const CIPHERTEXT: usize = 5;
/// credits_tip ledger.nr `ROUND_PAY`, `ROUND_CLAIM`, `ROUND_VIEW`: the
/// round an outcome names.
const ROUND_PAY: u64 = 1;
const ROUND_CLAIM: u64 = 2;
const ROUND_VIEW: u64 = 3;
/// credits_tip ledger.nr `CODE_ABSENT`.
const CODE_ABSENT: u64 = 4;

fn ns() -> Fr {
    Fr::from(TIP)
}

fn map() -> Fr {
    fr_from_hex(MAP).unwrap()
}

fn namespace() -> TipEntry {
    tip_namespace(ns(), MAP, &CIRCUITS[1..], &[INIT])
}

struct Ledger {
    net: Net,
    clock: Clock,
    chain: Chain,
    s: Scheduler<Arc<MemoryChain>>,
    hidden: Hidden,
}

impl Ledger {
    /// A request of `circuit` with `inputs` (each shared) and `owner`'s
    /// partial note.
    fn request(&self, circuit: &str, inputs: Vec<Input>, owner: Fr) -> SharedRequest {
        let mut inputs = inputs;
        inputs.push(shared("$partial_note", partial_commitment(owner, random())));
        SharedRequest::new(
            ns(),
            circuit,
            self.net.package(ns(), circuit).vk_hash,
            &self.net.enc_pks,
            inputs,
        )
        .owned_by(owner)
    }

    /// Take the receipts of `req`, queue it, run the step, land the result:
    /// the outcome `[code, round, a, b]` and the result's old and new
    /// commitment.
    async fn run(&mut self, req: &SharedRequest, label: &str) -> ([u64; 4], Fr, Fr) {
        self.hidden.add(req);
        let receipt = self.net.receipt(self.clock.block, req, &self.hidden).await;
        let vk = self.net.package(ns(), &req.circuit).vk_hash;
        let index = self.chain.ids.len() as u64;
        self.chain
            .intake_shared(&self.clock, vk, req, &receipt, &self.hidden);
        let r = step(&mut self.s, self.clock.next(), label).await;
        assert_eq!(computed(&r), [index], "{label}: {r:?}");
        assert_eq!(self.net.audit_received(req, &self.hidden), 3);
        let result = self.net.latest(ns(), req.chain).await;
        let pi: Vec<Fr> = result.public_inputs.iter().map(|f| f.fr()).collect();
        self.hidden.assert_absent("the proof's public inputs", &pi);
        let out = private_outputs(&result, PARAMS, 0, CIPHERTEXT);
        let plain = req.open(&out, fr(OUTCOME_SLOT), &[]);
        assert_eq!(plain.len(), 4, "{label}: [code, round, a, b]");
        self.chain
            .apply(
                &self.clock,
                &result,
                out.request_id,
                out.old_c,
                out.new_c,
                true,
            )
            .unwrap_or_else(|e| panic!("{label}: apply: {e}"));
        (
            [
                small(plain[0]),
                small(plain[1]),
                small(plain[2]),
                small(plain[3]),
            ],
            out.old_c,
            out.new_c,
        )
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn keyed_map_rounds_run_on_three_nodes() {
    let tmp = TempDir::new("creditsmap");
    let mem = Arc::new(MemoryChain::new(100));
    let net = start(&tmp, mem.clone(), &CIRCUITS, &[namespace()]).await;
    let started = Instant::now();
    let mut clock = Clock::new(100, mem.clone());
    let mut chain = Chain::new(&clock, ns(), map(), net.sig_pks);
    // pss_seed (CIRCUITS[0]) and the credits packages, in one manifest
    let credits: Vec<(&str, &str, Value)> = CIRCUITS[1..]
        .iter()
        .map(|name| (*name, *name, manifest("credits-tip", name)))
        .collect();
    let init_vk = net.register_entry(&namespace(), &credits).await[INIT];
    let mut s = scheduler(&net, &mem, &namespace());

    // ---- the init round creates the map ---------------------------------------
    let c0 = chain.intake_onchain(&clock, init_vk, &[], 0);
    let r = step(&mut s, clock.next(), "the init").await;
    assert_eq!(computed(&r), [0], "{r:?}");
    let init = net.latest(ns(), c0).await;
    let pi: Vec<Fr> = init.public_inputs.iter().map(|f| f.fr()).collect();
    // [namespace, vk_hash, out_slots[0], request_id, old_c, new_c,
    // npk_app_hash]
    assert_eq!(pi.len(), 7);
    chain
        .apply(&clock, &init, pi[3], pi[4], pi[5], true)
        .unwrap();
    let v0 = chain.slot;
    let mut l = Ledger {
        net,
        clock,
        chain,
        s,
        hidden: Hidden::default(),
    };

    let (payer, payee) = (random(), random());
    let key = random();
    let stranger = random();

    // ---- a pay inserts an absent key, a second pay adds -----------------------
    let pay = l.request(
        PAY,
        vec![shared("key", key), shared("amount", fr(5_003))],
        payer,
    );
    let (o, old, v1) = l.run(&pay, "a pay to an absent key").await;
    assert_eq!(
        o,
        [0, ROUND_PAY, 5_003, 0],
        "the payer learns nothing of the balance"
    );
    assert_eq!(old, v0);
    assert_ne!(v1, v0);
    let pay2 = l.request(
        PAY,
        vec![shared("key", key), shared("amount", fr(2_011))],
        payer,
    );
    let (o, _, v2) = l.run(&pay2, "a pay to a present key").await;
    assert_eq!(o, [0, ROUND_PAY, 2_011, 0]);
    assert_ne!(v2, v1);

    // ---- a view of the key, and of a key never paid ---------------------------
    let view = l.request(VIEW, vec![shared("key", key)], payee);
    let (o, _, v3) = l.run(&view, "a view of a present key").await;
    assert_eq!(
        o,
        [0, ROUND_VIEW, 1, 7_014],
        "present, the sum of the two pays"
    );
    assert_ne!(v3, v2, "a present leaf is re-blinded");
    let absent = l.request(VIEW, vec![shared("key", stranger)], payee);
    let (o, _, v4) = l.run(&absent, "a view of an absent key").await;
    assert_eq!(
        o,
        [0, ROUND_VIEW, 0, 0],
        "absent: present 0, a zero balance"
    );
    assert_ne!(
        v4, v3,
        "a fresh blinding on every round: the commitment moves"
    );

    // ---- a claim takes part of the balance; a claim of an absent key ----------
    let claim = l.request(
        CLAIM,
        vec![shared("key", key), shared("amount", fr(6_007))],
        payee,
    );
    let (o, _, v5) = l.run(&claim, "a claim").await;
    assert_eq!(o, [0, ROUND_CLAIM, 6_007, 1_007], "the balance left");
    assert_ne!(v5, v4);
    let none = l.request(
        CLAIM,
        vec![shared("key", stranger), shared("amount", fr(1_009))],
        payee,
    );
    let (o, _, v6) = l.run(&none, "a claim of an absent key").await;
    assert_eq!(o[0], CODE_ABSENT, "{o:?}");
    assert_ne!(v6, v5, "a refused claim moves the commitment too");

    // ---- the absent key a view entered still reads as absent ------------------
    let again = l.request(VIEW, vec![shared("key", stranger)], payee);
    let (o, _, v6b) = l.run(&again, "a view of the entered absent key").await;
    assert_eq!(o, [0, ROUND_VIEW, 0, 0], "a zero balance is absent");
    assert_ne!(v6b, v6);

    // ---- what is left is what the next round reads ----------------------------
    let view2 = l.request(VIEW, vec![shared("key", key)], payee);
    let (o, _, v7) = l.run(&view2, "a view after the claim").await;
    assert_eq!(o, [0, ROUND_VIEW, 1, 1_007]);
    for v in [v0, v1, v2, v3, v4, v5, v6, v6b, v7] {
        assert!(l.net.holds(ns(), MAP, v));
    }

    // ---- a lost store, resynced from the two neighbours with the DORAM -------
    let lost = 1;
    let blobs = l.net.real.apps[lost].node.store.blob_keys(ns()).unwrap();
    assert_eq!(blobs, [MAP], "the map's state is held in blobs");
    l.net.real.apps[lost].node.store.clear();
    let answers = l
        .net
        .real
        .admin_all(AdminRequest::Resync {
            lost,
            pins: Box::new(l.net.real.pins()),
        })
        .await;
    for (i, answer) in answers.into_iter().enumerate() {
        assert!(answer.ok, "resync at node {i}: {:?}", answer.refusal);
        let report = answer.resync.unwrap();
        assert!(report.passed(), "node {i}: {:?}", report.audit);
        assert!(report.blobs_checked >= 3, "node {i}: {report:?}");
    }
    let view3 = l.request(VIEW, vec![shared("key", key)], payee);
    let (o, _, _) = l.run(&view3, "a view after the resync").await;
    assert_eq!(
        o,
        [0, ROUND_VIEW, 1, 1_007],
        "the resynced node reads the key with the others"
    );

    // ---- a backup, a pay since, the store lost and restored ------------------
    let backup_key = BackupKey::generate().unwrap();
    let file = tmp.path().join("node-backup.store");
    let sockets: Vec<_> = (0..3)
        .map(|i| l.net.real.running[i].admin_socket.clone())
        .collect();
    let socket = |i: usize| sockets[i].clone();
    let answer = admin::call_async(
        socket(lost),
        AdminRequest::Backup {
            out: file.clone(),
            key: backup_key.clone(),
        },
    )
    .await
    .unwrap();
    assert!(answer.ok, "backup: {:?}", answer.refusal);
    let pay3 = l.request(
        PAY,
        vec![shared("key", key), shared("amount", fr(30))],
        payer,
    );
    let (o, _, _) = l.run(&pay3, "a pay after the backup").await;
    assert_eq!(o, [0, ROUND_PAY, 30, 0]);
    l.net.real.apps[lost].node.store.clear();
    let restore = |i: usize| {
        let (backup, key) = if i == lost {
            (Some(file.clone()), Some(backup_key.clone()))
        } else {
            (None, None)
        };
        admin::call_async(
            socket(i),
            AdminRequest::RestoreBackup {
                lost,
                pins: Box::new(l.net.real.pins()),
                backup,
                key,
            },
        )
    };
    let (a, b, c) = tokio::join!(restore(0), restore(1), restore(2));
    for (i, answer) in [a, b, c].into_iter().enumerate() {
        let answer = answer.unwrap();
        assert!(answer.ok, "restore at node {i}: {:?}", answer.refusal);
        let report = answer.resync.unwrap();
        assert_eq!(report.scope, Scope::Delta, "node {i}");
        assert!(report.passed(), "node {i}: {:?}", report.audit);
        if i == lost {
            assert!(report.imported.blobs >= 3, "{:?}", report.imported);
        }
    }
    let view4 = l.request(VIEW, vec![shared("key", key)], payee);
    let (o, _, _) = l.run(&view4, "a view after the restore").await;
    assert_eq!(
        o,
        [0, ROUND_VIEW, 1, 1_037],
        "the restored node reads the pay since the backup"
    );
    eprintln!("keyed map rounds: {:.1}s", started.elapsed().as_secs_f64());
}
