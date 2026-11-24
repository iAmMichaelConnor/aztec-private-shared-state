//! What the lending secret-shared receipt intake suites share
//! (`lending_tip_shared.rs`, `lending_keeper_shared.rs`,
//! `lending_oblivious.rs`): examples/lending-tip's manifests as committed
//! with the price read pointed at a test oracle and the clock read at the
//! market, the oracle's epoch source, the market's clock, three real nodes
//! with every circuit registered and the book made by the non-secret-shared
//! init round, the secret-shared requests of the rounds under partial-note
//! delivery (each commits its requester's partial note; the round never
//! sees an owner), the relayer queueing and landing them, the user's
//! opening of the outcome `[code, position, mask, x, y, payout, aux]` with
//! the completed note's hash checked, the round's exit value (the exit tag
//! its write replaced, or a filler) and a clear book's leaves as the three
//! nodes hold them.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use serde_json::{Value, json};

use sidecar_core::bind::Elem;
use sidecar_core::field::{Fr, fr_from_hex, fr_to_hex};
use sidecar_core::hash::poseidon2_hash;
use sidecar_core::keys::label_field;
use sidecar_core::response::ExecuteResponse;
use sidecar_core::store::{StoreRead, VersionTree};
use sidecar_core::tree;
use sidecar_orchestrator::scheduler::Scheduler;
use sidecar_tip::testing::MemoryChain;

use crate::common::tip::*;
use crate::common::*;
use crate::shared_intake::*;

pub const SEED: &str = "pss_seed";
pub const INIT: &str = "lending_init";
pub const DEPOSIT: &str = "deposit_shared";
pub const WITHDRAW: &str = "withdraw_shared";
pub const SUPPLY: &str = "supply_shared";
pub const WITHDRAW_SUPPLY: &str = "withdraw_supply_shared";
pub const QUOTE: &str = "quote_shared";
pub const BORROW: &str = "borrow_shared";
pub const REPAY: &str = "repay_shared";
pub const LIQUIDATE: &str = "liquidate_shared";
pub const SCAN: &str = "scan_shared";
/// The book's tree (the lending manifests' `tree`): depth 16, leaves of
/// eight elements (a borrower's [1, collateral, debt, index_at_touch,
/// handle_partial, handle_key, exit_tag, blinding]; the header [total_debt,
/// liquidity, total_shares, borrow_index, last_accrual, next_index, 0,
/// blinding]), a scan's window of eight.
pub const DEPTH: u32 = 16;
pub const LEAF_LEN: usize = 8;
/// A borrower leaf's place of its delivery handle's partial commitment
/// (market.nr `P_HANDLE`).
pub const P_HANDLE: usize = 4;
/// A position leaf's place of its exit tag (market.nr `P_EXIT_TAG`).
pub const P_EXIT_TAG: usize = LEAF_LEN - 2;
/// The exit values a secret-shared round outputs first among its app values
/// (lending_tip shared.nr `EXIT_TAGS`).
pub const EXIT_TAGS: usize = 1;
/// INDEX_ONE (market.nr): a borrower leaf's index at touch and a borrower
/// note's mask, the borrower kind's marker.
pub const ONE: u64 = 1_000_000_000;
pub const WINDOW: u64 = 8;
/// The init round's liquidity.
pub const LIQUIDITY: u64 = 1_000_000;
/// lending_tip's `OUTCOME_SLOT`.
pub const OUTCOME_SLOT: u64 = 1;
/// The public parameters before the outputs (with the price, its epoch and
/// the clock), and the ciphertext's length (seven outcome fields and the
/// tag).
pub const PARAMS: usize = 7;
pub const CIPHERTEXT: usize = 8;
/// Below the borrow limit (market.nr `LTV_BPS`) after a borrow or a
/// withdrawal.
pub const CODE_LIMIT: u64 = 9;
pub const CODE_INPUTS_MISMATCH: u64 = 14;
/// The market's constants (lending_tip market.nr).
pub const CLOSE_BPS: u64 = 5000;
pub const BONUS_BPS: u64 = 500;
pub const BPS: u64 = 10_000;
pub const PRICE_SCALE: u64 = 100;
pub const LTV_BPS: u64 = 7500;
/// A payout's asset bit as [`Market::opened`] reports it: the circuits put
/// the collateral asset at 2^128 (market.nr `payout`); a test's amounts are
/// u64s, so the opened outcome carries it at 2^63.
pub const COLLATERAL_ASSET: u64 = 1 << 63;

fn two_128() -> Fr {
    Fr::from(1u128 << 64) * Fr::from(1u128 << 64)
}

/// The exit tag of the note completing `partial` in the round of chain
/// request `request_id`, naming position `entry` (pss_core exit.nr
/// `exit_tag`): `poseidon2([PSS_EXIT_TAG + 2^128 * entry, partial,
/// request_id])`, what the round stores in the position's leaf.
pub fn exit_tag(partial: Fr, request_id: Fr, entry: Fr) -> Fr {
    let domain = label_field(b"pss.exit_tag") + two_128() * entry;
    poseidon2_hash(&[domain, partial, request_id])
}

/// testvectors/exit_tag.json, which pss_core and pss-client check:
/// [`exit_tag`] agrees with it on every tag.
pub fn check_exit_tag_vectors() {
    let v = sidecar_test_fixtures::vectors::read("testvectors/exit_tag.json");
    let f = sidecar_test_fixtures::vectors::hex_value;
    assert_eq!(f(&v["pss_exit_tag"]), label_field(b"pss.exit_tag"));
    let tags = v["tags"].as_array().unwrap();
    assert!(!tags.is_empty());
    for t in tags {
        assert_eq!(
            exit_tag(f(&t["partial"]), f(&t["request_id"]), f(&t["entry"])),
            f(&t["tag"]),
            "{t}"
        );
    }
}

/// The exit tag of `req`'s own note naming `entry`: its partial note under
/// its chain request id.
pub fn tag_of(req: &SharedRequest, entry: u64) -> Fr {
    exit_tag(req.value("$partial_note"), req.chain, Fr::from(entry))
}

/// A liquidation of `debt` at `price`: half the debt repaid, the seize its
/// value at the price with the bonus. `(repay, seize)`.
pub fn liquidation(debt: u64, price: u64) -> (u64, u64) {
    let repay = debt * CLOSE_BPS / BPS;
    let seize = repay * PRICE_SCALE * (BPS + BONUS_BPS) / (price * BPS);
    (repay, seize)
}

/// A deposit's, withdrawal's, borrow's or repayment's inputs, in manifest
/// order: `amount` on `position`, `owner`'s next delivery handle (a partial
/// commitment from `owner` and a key, the handle a liquidation of the
/// position completes) and `owner`'s partial note under a fresh `rho` (the
/// contract's request function computes both commitments from the sender;
/// the round never sees `owner`).
pub fn owned_inputs(position: u64, amount: u64, owner: Fr) -> Vec<Input> {
    vec![
        clear("position", fr(position)),
        shared("amount", fr(amount)),
        shared("handle_partial", partial_commitment(owner, random())),
        shared("handle_key", random()),
        shared("$partial_note", partial_commitment(owner, random())),
    ]
}

/// A lender's supply inputs: `owned_inputs` without a delivery handle (a
/// lender position holds none).
pub fn supply_inputs(position: u64, amount: u64, owner: Fr) -> Vec<Input> {
    vec![
        clear("position", fr(position)),
        shared("amount", fr(amount)),
        shared("$partial_note", partial_commitment(owner, random())),
    ]
}

/// The public inputs of a lending result's one delivery, its last: a tag, a
/// note hash and the nine ciphertext fields (lending_tip shared.nr
/// `DELIVERIES`, `DELIVERY_LEN`).
pub const DELIVERY_FIELDS: usize = 2 + 9;

/// One suite's lending deployment: its namespace (the market contract, whose
/// `clock()` the clock reads call), its book's node-held key and the oracle
/// its price reads call.
#[derive(Clone, Copy)]
pub struct Market {
    pub tip: u64,
    pub book: &'static str,
    pub oracle: u64,
}

/// A started market: three real nodes and the orchestrator, every circuit
/// registered, the scheduler and the mock contract, the book made by the
/// init round.
pub struct Lending {
    pub mem: Arc<MemoryChain>,
    pub net: Net,
    pub started: Instant,
    pub clock: Clock,
    pub chain: Chain,
    pub s: Scheduler<Arc<MemoryChain>>,
    pub hidden: Hidden,
    /// The init round's public inputs.
    pub init: Vec<Fr>,
    pub tmp: TempDir,
}

impl Market {
    pub fn ns(&self) -> Fr {
        Fr::from(self.tip)
    }

    pub fn book(&self) -> Fr {
        fr_from_hex(self.book).unwrap()
    }

    /// A lending manifest as committed, its price read pointed at the
    /// oracle (its clock read is the market's own, `$self`).
    pub fn lending(&self, name: &str) -> Value {
        let mut m = manifest("lending-tip", name);
        for read in m["public_reads"].as_array_mut().unwrap() {
            if read["contract"] != "$self" {
                read["contract"] = json!(fr_to_hex(Fr::from(self.oracle)));
            }
        }
        m
    }

    /// The market's `clock()`: the block number the rounds accrue interest
    /// to. Every book starts with its last accrual at 0, so a clock of 0
    /// accrues nothing.
    pub fn set_clock(&self, mem: &MemoryChain, block: u64) {
        mem.set_call(self.ns(), "clock()", &[], Ok(vec![Fr::from(block)]));
    }

    /// The oracle's epoch source: [price, epoch, the previous epoch's
    /// price].
    pub fn set_price(&self, mem: &MemoryChain, price: u64, epoch: u64, previous: u64) {
        mem.set_call(
            Fr::from(self.oracle),
            "get_price_epoch()",
            &[],
            Ok(vec![Fr::from(price), Fr::from(epoch), Fr::from(previous)]),
        );
    }

    /// Every circuit after the seed writes the book; the init reads nothing.
    pub fn namespace(&self, circuits: &[&str]) -> TipEntry {
        self.namespace_with_init(circuits, INIT)
    }

    /// [`Self::namespace`] with `init` the init round (the oblivious
    /// deployment's `lending_init_oblivious`).
    pub fn namespace_with_init(&self, circuits: &[&str], init: &str) -> TipEntry {
        tip_namespace(self.ns(), self.book, &circuits[1..], &[init])
    }

    /// Start `circuits` (the seed first, then the init) under `label`, the
    /// price 2.50 at epoch 1 and the clock at 0, and run the init round under
    /// on-chain intake.
    pub async fn start(&self, label: &str, circuits: &[&str]) -> Lending {
        self.start_with_init(label, circuits, INIT).await
    }

    /// [`Self::start`] with `init` the init round (`circuits[1]`).
    pub async fn start_with_init(&self, label: &str, circuits: &[&str], init: &str) -> Lending {
        let packages: Vec<(&str, &str)> = circuits.iter().map(|c| (*c, *c)).collect();
        self.start_packages_with_init(label, &packages, false, init)
            .await
    }

    /// [`Self::start`] with each package `(name, compiled circuit)` (a
    /// second package of one compiled circuit under another manifest, as
    /// `deposit_shared_onchain` registers `deposit_shared`), and with
    /// `shared_onchain` the contract's `SharedOnchain` declared (the
    /// schedule's, the verifiers' and the mock contract's).
    pub async fn start_packages(
        &self,
        label: &str,
        packages: &[(&str, &str)],
        shared_onchain: bool,
    ) -> Lending {
        self.start_packages_with_init(label, packages, shared_onchain, INIT)
            .await
    }

    async fn start_packages_with_init(
        &self,
        label: &str,
        packages: &[(&str, &str)],
        shared_onchain: bool,
        init_round: &str,
    ) -> Lending {
        let names: Vec<&str> = packages.iter().map(|(n, _)| *n).collect();
        let mut circuits: Vec<&str> = packages.iter().map(|(_, c)| *c).collect();
        circuits.dedup();
        let namespace = {
            let ns = self.namespace_with_init(&names, init_round);
            if shared_onchain {
                with_shared_onchain(ns)
            } else {
                ns
            }
        };
        let tmp = TempDir::new(label);
        let mem = Arc::new(MemoryChain::new(100));
        let net = start(
            &tmp,
            mem.clone(),
            &circuits,
            std::slice::from_ref(&namespace),
        )
        .await;
        let started = Instant::now();
        let mut clock = Clock::new(100, mem.clone());
        let mut chain = Chain::new(&clock, self.ns(), self.book(), net.sig_pks);
        if shared_onchain {
            chain = chain.with_shared_onchain();
        }
        // pss_seed (packages[0]) and the lending packages, in one manifest
        let lending: Vec<(&str, &str, Value)> = packages[1..]
            .iter()
            .map(|(name, circuit)| (*name, *circuit, self.lending(name)))
            .collect();
        let registered = net.register_entry(&namespace, &lending).await;
        let vk: BTreeMap<&str, Fr> = packages
            .iter()
            .map(|(name, _)| (*name, registered[*name]))
            .collect();
        let mut s = scheduler(&net, &mem, &namespace);
        self.set_price(&mem, 250, 1, 250);
        self.set_clock(&mem, 0);

        let c0 = chain.intake_onchain(&clock, vk[init_round], &[fr(LIQUIDITY)], 0);
        let r = step(&mut s, clock.next(), "the init").await;
        assert_eq!(computed(&r), [0], "{r:?}");
        let init = net.latest(self.ns(), c0).await;
        let pi: Vec<Fr> = init.public_inputs.iter().map(|f| f.fr()).collect();
        net.apply(&clock, &mut chain, &init).unwrap();
        Lending {
            mem,
            net,
            started,
            clock,
            chain,
            s,
            hidden: Hidden::default(),
            init: pi,
            tmp,
        }
    }

    /// A secret-shared request of `circuit` with its inputs in manifest order.
    pub fn request(&self, net: &Net, circuit: &str, inputs: Vec<Input>) -> SharedRequest {
        self.skewed(net, circuit, inputs, None)
    }

    /// The same, its sharing of `skew.0` off by `skew.1`.
    pub fn skewed(
        &self,
        net: &Net,
        circuit: &str,
        inputs: Vec<Input>,
        skew: Option<(&str, u64)>,
    ) -> SharedRequest {
        SharedRequest::skewed(
            self.ns(),
            circuit,
            net.package(self.ns(), circuit).vk_hash,
            &net.enc_pks,
            inputs,
            skew,
        )
    }

    /// A deposit, withdrawal, borrow or repayment on `position` of
    /// `amount` (a lender's supply, with no delivery handle), its note
    /// `owner`'s.
    pub fn owned(
        &self,
        net: &Net,
        circuit: &str,
        position: u64,
        amount: u64,
        owner: Fr,
    ) -> SharedRequest {
        let inputs = if circuit == SUPPLY {
            supply_inputs(position, amount, owner)
        } else {
            owned_inputs(position, amount, owner)
        };
        self.request(net, circuit, inputs).owned_by(owner)
    }

    /// A lender's withdrawal of `shares` of `position`, its note `owner`'s.
    pub fn withdraw_supply(
        &self,
        net: &Net,
        position: u64,
        shares: u64,
        owner: Fr,
    ) -> SharedRequest {
        self.request(
            net,
            WITHDRAW_SUPPLY,
            vec![
                clear("position", fr(position)),
                shared("shares", fr(shares)),
                shared("$partial_note", partial_commitment(owner, random())),
            ],
        )
        .owned_by(owner)
    }

    /// A quote (no app input), its note `owner`'s.
    pub fn quote(&self, net: &Net, owner: Fr) -> SharedRequest {
        self.request(
            net,
            QUOTE,
            vec![shared("$partial_note", partial_commitment(owner, random()))],
        )
        .owned_by(owner)
    }

    /// A liquidation of position `p1` (one probe: K = 2), `count` of it
    /// used, repaying at most `budget`, its note `owner`'s (the
    /// liquidator's).
    pub fn liquidate(
        &self,
        net: &Net,
        p1: u64,
        count: u64,
        budget: u64,
        owner: Fr,
    ) -> SharedRequest {
        self.request(
            net,
            LIQUIDATE,
            vec![
                clear("p1", fr(p1)),
                clear("count", fr(count)),
                shared("budget", fr(budget)),
                shared("$partial_note", partial_commitment(owner, random())),
            ],
        )
        .owned_by(owner)
    }

    /// The outputs of a secret-shared round over `slots` tree slots, opened
    /// as the user opens them: the private outputs; `[code, position, mask,
    /// x, y, payout]` (the payout's asset bit at [`COLLATERAL_ASSET`]); the
    /// round's exit value (its first app value: the exit tag its write
    /// replaced on the position, or a filler); and the outcome's `aux` (a
    /// scan's occupied count, a quote's utilisation, else 0). The completed
    /// note's hash is checked against the request's partial note, and the
    /// inputs-opened bit (the last app value) is 0 exactly on code 14.
    pub fn opened(
        &self,
        req: &SharedRequest,
        result: &ExecuteResponse,
        slots: usize,
    ) -> (PrivateOutputs, [u64; 6], Fr, Fr) {
        // the round's app values follow the ciphertext: the exit value, the
        // book's append index when the round has a position slot (0 on the
        // clear deployment), then the inputs-opened bit; the round's delivery
        // after them; the rest is the library's private-outcome layout
        let mut outcome = result.clone();
        let delivered = outcome.public_inputs.len() - DELIVERY_FIELDS;
        outcome.public_inputs.truncate(delivered);
        let bit = outcome
            .public_inputs
            .pop()
            .expect("a lending result's last app value is its inputs-opened bit")
            .fr();
        let app = EXIT_TAGS + usize::from(slots > 1);
        let values = outcome.public_inputs.len() - app;
        let exit = outcome.public_inputs[values].fr();
        outcome.public_inputs.truncate(values);
        let out = private_outputs(&outcome, PARAMS, slots, CIPHERTEXT);
        let pinned: Vec<Fr> = result.public_inputs[4..PARAMS]
            .iter()
            .map(|f| f.fr())
            .collect();
        let plain = req.open(&out, fr(OUTCOME_SLOT), &pinned);
        let mut o = [0u64; 6];
        for (k, v) in plain.iter().take(5).enumerate() {
            o[k] = small(*v);
        }
        let digits = fr_to_hex(plain[5]);
        o[5] = if digits
            .trim_start_matches("0x")
            .trim_start_matches('0')
            .len()
            > 32
        {
            COLLATERAL_ASSET | small(plain[5] - two_128())
        } else {
            small(plain[5])
        };
        let opened = u64::from(o[0] != CODE_INPUTS_MISMATCH);
        assert_eq!(bit, fr(opened), "the inputs-opened bit, the last app value");
        (out, o, exit, plain[6])
    }

    /// Leaf `index` of the clear book's version under `commitment`, opened
    /// from the three nodes' pairs (a shared element summed, a public one
    /// the same at every node).
    pub fn leaf(&self, net: &Net, commitment: Fr, index: u64) -> [Fr; LEAF_LEN] {
        let z = tree::zeros(DEPTH);
        let parts: Vec<Vec<Elem>> = (0..3)
            .map(|i| {
                let store = &net.real.apps[i].node.store;
                let root = store
                    .tip_version(self.ns(), self.book, commitment)
                    .unwrap()
                    .unwrap_or_else(|| panic!("node {i}: no version {}", fr_to_hex(commitment)))
                    .tree
                    .and_then(VersionTree::clear)
                    .unwrap()
                    .root;
                let nodes = |h: Fr| {
                    Ok(store
                        .tip_node(self.ns(), self.book, h)
                        .unwrap()
                        .map(|n| n.node))
                };
                tree::leaves(&nodes, &z, root, LEAF_LEN, &[index]).unwrap()
            })
            .collect();
        std::array::from_fn(|k| match [&parts[0][k], &parts[1][k], &parts[2][k]] {
            [Elem::Shared(a), Elem::Shared(b), Elem::Shared(c)] => a.a + b.a + c.a,
            [Elem::Public(a), Elem::Public(b), Elem::Public(c)] if a == b && b == c => *a,
            _ => panic!("the nodes disagree on a leaf element"),
        })
    }

    /// Take the three receipts of `req` and queue it.
    pub async fn queue(
        &self,
        net: &Net,
        clock: &Clock,
        chain: &mut Chain,
        req: &SharedRequest,
        hidden: &mut Hidden,
    ) {
        hidden.add(req);
        let receipt = net.receipt(clock.block, req, hidden).await;
        let vk = net.package(self.ns(), &req.circuit).vk_hash;
        chain.intake_shared(clock, vk, req, &receipt, hidden);
    }

    /// The relayer lands `req`'s latest result: apply writes the new
    /// commitment whatever the outcome. Returns [`Self::opened`]'s.
    pub async fn land(
        &self,
        net: &Net,
        clock: &Clock,
        chain: &mut Chain,
        req: &SharedRequest,
        slots: usize,
        hidden: &Hidden,
    ) -> (PrivateOutputs, [u64; 6], Fr, Fr) {
        let result = net.latest(self.ns(), req.chain).await;
        let pi: Vec<Fr> = result.public_inputs.iter().map(|f| f.fr()).collect();
        hidden.assert_absent("the proof's public inputs", &pi);
        let (out, o, exit, aux) = self.opened(req, &result, slots);
        assert_ne!(
            out.new_c, out.old_c,
            "every secret-shared round re-blinds the book"
        );
        chain
            .apply(clock, &result, out.request_id, out.old_c, out.new_c, true)
            .unwrap_or_else(|e| panic!("apply: {e}"));
        (out, o, exit, aux)
    }
}
