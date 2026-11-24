//! A tip namespace as the scheduler, the chain verifier and the receipt chain
//! view read it: the facts about its contract that its registered contract
//! manifest states (docs/ARCHITECTURE.md section 7, "The contract
//! manifest"), resolved once into storage slots and request keys
//! ([`TipLayout::of`]).
//!
//! The operator's `[[tip.namespaces]]` lists which namespaces the machine
//! serves ([`crate::TipNamespace`], the allowlist); everything slot-shaped
//! comes from the namespace's own contract manifest, which the owner signed
//! and pss-client generated from the compiled contract. A namespace is driven
//! when it is both listed and registered with a queue. The machine reads the
//! declared slots only at the namespace's own address, the contract that
//! declared them, so a wrong declaration costs that namespace's liveness and
//! nothing else; and before a round each reader compares the instance's
//! current contract class with the manifest's `contract.class_id`
//! ([`TipLayout::class_differs`]), so a manifest is never applied to a
//! contract running other code.
//!
//! Under `upgrades` `circuits` or `contract` a namespace holds several
//! versions of its contract manifest, and every reader runs a round only
//! under the one whose hash the contract's circuit pins name in force at the
//! block it reads ([`TipLayout::version_differs`],
//! [`crate::chain::ChainReader::manifest_in_force`]); each version is its own
//! layout ([`TipLayout::of_version`]).

use std::collections::BTreeMap;

use sidecar_core::circuit_pins::{PinsSlots, constructor_manifest_hash_slot};
use sidecar_core::error::Refusal;
use sidecar_core::field::{Fr, fr_to_hex};
use sidecar_core::manifest::contract::{CheckedContractManifest, NodeKeysAxis, Upgrades};
use sidecar_core::request::StateKeys;
use sidecar_core::store::ManifestRow;

use crate::chain::QueueTarget;
use crate::chain::layout::QueueLayout;
use crate::init::InitLayout;
use crate::intake::IntakeLayout;
use crate::intake::shared_onchain::SharedOnchainLayout;
use crate::standing::ReceiptTarget;

/// One tip namespace's facts, from its registered contract manifest: the
/// app contract and where the tip's queue, stale period, state keys, plain
/// reads and init round live in its storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TipLayout {
    /// The namespace contract (the namespace itself).
    pub contract: Fr,
    /// The hash of the contract manifest this layout was read from.
    pub manifest_hash: Fr,
    /// The contract class the manifest was built for (`contract.class_id`).
    pub class_id: Fr,
    /// Whether the contract can change its node key set (`node_keys`).
    pub node_keys: NodeKeysAxis,
    /// What about the deployed app may change (`upgrades`).
    pub upgrades: Upgrades,
    /// Where an upgradable contract keeps its circuit pins
    /// (`storage.circuit_pins`); `None` under `fixed`.
    pub circuit_pins: Option<PinsLayout>,
    pub queue: QueueLayout,
    /// Where the contract keeps what its intakes read.
    pub intake: IntakeLayout,
    /// The slot of `TipConfig.stale_blocks.enabled`; `blocks` is the next.
    pub stale_blocks_slot: Fr,
    /// The request keys of each queued package, by package name, each key
    /// its commitment slot written as a field (`fr_to_hex`).
    pub circuits: BTreeMap<String, StateKeys>,
    /// Every state key's slot, with its request key.
    pub slots: BTreeMap<Fr, String>,
    /// Public-read params filled from a backing slot instead of simulated.
    pub plain_reads: BTreeMap<String, Fr>,
    /// The init round's package and where its pins live; a request of that
    /// package takes the init branch. `None`: the manifest has no init
    /// round.
    pub init: Option<InitLayout>,
}

/// Where an upgradable contract keeps the slots that say which contract
/// manifest version is in force (sidecar-core `circuit_pins`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinsLayout {
    /// The scheduled pins' metadata and the class id and manifest hash of
    /// each half.
    pub slots: PinsSlots,
    /// The constructor's manifest hash, in force while no upgrade was ever
    /// scheduled.
    pub constructor_manifest_hash: Fr,
}

/// A registered contract manifest that does not give what a tip namespace
/// needs: the machine checked it at REGISTER, so this is a store fault.
fn corrupt(contract: Fr, what: impl std::fmt::Display) -> Refusal {
    Refusal::mpc_failure(format!(
        "store: the contract manifest of namespace {}: {what}",
        fr_to_hex(contract)
    ))
}

impl TipLayout {
    /// The layout of namespace `contract` from its contract manifest
    /// `checked` (whose hash is `manifest_hash`). 400 for a manifest
    /// without a queue: the namespace is not a tip namespace.
    pub fn of(
        contract: Fr,
        manifest_hash: Fr,
        checked: &CheckedContractManifest,
    ) -> Result<TipLayout, Refusal> {
        let doc = &checked.document;
        let Some(queue) = &doc.queue else {
            return Err(Refusal::bad_request(format!(
                "namespace {}: its contract manifest `{}` has no queue, so it is not a tip \
                 namespace and the machine drives no round for it",
                fr_to_hex(contract),
                doc.name
            )));
        };
        let storage = doc
            .storage
            .as_ref()
            .ok_or_else(|| corrupt(contract, "a queue without `storage`"))?;
        let class_id = doc
            .contract
            .as_ref()
            .ok_or_else(|| corrupt(contract, "a queue without `contract`"))?
            .class_id
            .fr();
        let key = |name: &str| {
            doc.state_keys
                .get(name)
                .map(|slot| fr_to_hex(slot.fr()))
                .ok_or_else(|| corrupt(contract, format!("state key `{name}` has no slot")))
        };
        let mut circuits = BTreeMap::new();
        for package in &doc.packages {
            let Some(named) = &package.state_keys else {
                continue;
            };
            let state_keys = StateKeys {
                reads: named
                    .reads
                    .iter()
                    .map(|n| key(n))
                    .collect::<Result<_, _>>()?,
                writes: named
                    .writes
                    .iter()
                    .map(|n| key(n))
                    .collect::<Result<_, _>>()?,
            };
            circuits.insert(package.name.clone(), state_keys);
        }
        let init = doc.init.as_ref().map(|init| InitLayout {
            circuit: init.package.clone(),
            configured_slot: storage.configured.fr(),
            input_slots: init.input_slots.iter().map(|s| s.fr()).collect(),
        });
        let circuit_pins = match storage.circuit_pins {
            Some(slot) => {
                let capacity = doc
                    .contract
                    .as_ref()
                    .and_then(|c| c.package_capacity)
                    .ok_or_else(|| corrupt(contract, "a queue without a package capacity"))?;
                Some(PinsLayout {
                    slots: PinsSlots::new(slot.fr(), capacity),
                    constructor_manifest_hash: constructor_manifest_hash_slot(
                        queue.stale_blocks_slot.fr(),
                    ),
                })
            }
            None => None,
        };
        Ok(TipLayout {
            contract,
            manifest_hash,
            class_id,
            node_keys: doc.node_keys,
            upgrades: doc.upgrades,
            circuit_pins,
            queue: QueueLayout::new(queue.slot.fr()),
            intake: IntakeLayout {
                shared_onchain: storage
                    .shared_onchain
                    .map(|s| SharedOnchainLayout::new(s.fr())),
            },
            stale_blocks_slot: queue.stale_blocks_slot.fr(),
            circuits,
            slots: doc
                .state_keys
                .values()
                .map(|slot| (slot.fr(), fr_to_hex(slot.fr())))
                .collect(),
            plain_reads: doc
                .plain_reads
                .iter()
                .map(|(param, slot)| (param.clone(), slot.fr()))
                .collect(),
            init,
        })
    }

    /// The layout of namespace `contract` from its stored contract manifest
    /// row; `None` when the namespace has none (nothing registered yet).
    pub fn of_row(contract: Fr, row: Option<ManifestRow>) -> Result<Option<TipLayout>, Refusal> {
        match row {
            Some(row) => Self::of(contract, row.manifest_hash, &row.parse()?).map(Some),
            None => Ok(None),
        }
    }

    /// The layout of the version `manifest_hash` among a namespace's held
    /// versions `rows`; `None` when it holds no such version.
    pub fn of_version(
        contract: Fr,
        rows: Vec<ManifestRow>,
        manifest_hash: Fr,
    ) -> Result<Option<TipLayout>, Refusal> {
        Self::of_row(
            contract,
            rows.into_iter().find(|m| m.manifest_hash == manifest_hash),
        )
    }

    /// Why no round runs under this version at `block`: the contract's pins
    /// name another contract manifest, `in_force` ([`crate::chain::ChainReader::manifest_in_force`]);
    /// `None` when this is the version in force. Liveness only: a node that
    /// does not hold the version in force runs nothing until it does.
    pub fn version_differs(&self, in_force: Fr, block: u64) -> Option<String> {
        (in_force != self.manifest_hash).then(|| {
            format!(
                "the contract's circuit pins name contract manifest {} at block {block}, not {}: \
                 a round runs only under the version the pins name",
                fr_to_hex(in_force),
                fr_to_hex(self.manifest_hash)
            )
        })
    }

    /// Where the namespace's queue lives.
    pub fn target(&self) -> QueueTarget {
        QueueTarget {
            contract: self.contract,
            layout: self.queue,
        }
    }

    /// What a node's receipt chain view reads of this namespace: the queue
    /// and the intakes' layout.
    pub fn receipt_target(&self) -> ReceiptTarget {
        ReceiptTarget {
            queue: self.target(),
            intake: self.intake,
        }
    }

    /// Why no round runs at `block`: the instance's current contract class
    /// on the reader's chain view, `current` (`None`: no instance is
    /// published at the address), is not the manifest's `class_id`; `None`
    /// when they agree. Liveness only: a contract upgraded to other code,
    /// or a manifest built for another class, runs nothing until the two
    /// agree again.
    pub fn class_differs(&self, current: Option<Fr>, block: u64) -> Option<String> {
        match current {
            Some(class) if class == self.class_id => None,
            Some(class) => Some(format!(
                "the instance's current contract class is {} at block {block}, and its contract \
                 manifest {} was built for class {}: no round runs until the two agree",
                fr_to_hex(class),
                fr_to_hex(self.manifest_hash),
                fr_to_hex(self.class_id)
            )),
            None => Some(format!(
                "no contract instance is published at {} at block {block}: no round runs for it",
                fr_to_hex(self.contract)
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sidecar_core::ErrorClass;
    use sidecar_core::manifest::contract::{ContractManifest, manifest_hash};

    fn checked(document: &serde_json::Value) -> CheckedContractManifest {
        ContractManifest::parse(document)
            .and_then(ContractManifest::check)
            .unwrap()
    }

    /// The vector's contract manifest (examples/amm-tip's non-secret-shared
    /// deployment, with the receipt swap as an alias) resolves into the
    /// slots it states, every package, the alias included, with request
    /// keys as `fr_to_hex` writes the slots.
    #[test]
    fn the_vectors_manifest_gives_its_slots_and_request_keys() {
        let v = sidecar_test_fixtures::vectors::read("testvectors/contract_manifest.json");
        let document = &v["manifest"];
        let ns = Fr::from(0x7195u64);
        let hash = manifest_hash(document).unwrap();
        let layout = TipLayout::of(ns, hash, &checked(document)).unwrap();
        let pool = fr_to_hex(Fr::from(0x10u64));
        assert_eq!(
            (layout.contract, layout.manifest_hash, layout.class_id),
            (ns, hash, Fr::from(0xc1a55u64))
        );
        assert_eq!(layout.queue, QueueLayout::new(Fr::from(0x0cu64)));
        assert_eq!(layout.stale_blocks_slot, Fr::from(1u64));
        assert_eq!(layout.intake, IntakeLayout::default());
        assert_eq!(
            layout.circuits.keys().collect::<Vec<_>>(),
            ["amm_init_tip", "amm_swap_tip", "amm_swap_tip_receipt"]
        );
        assert!(layout.circuits["amm_init_tip"].reads.is_empty());
        assert_eq!(
            layout.circuits["amm_swap_tip_receipt"].reads,
            std::slice::from_ref(&pool)
        );
        assert_eq!(
            layout.slots,
            BTreeMap::from([(Fr::from(0x10u64), pool.clone())])
        );
        let init = layout.init.as_ref().unwrap();
        assert_eq!(
            (
                init.circuit.as_str(),
                init.configured_slot,
                init.input_slots.len()
            ),
            ("amm_init_tip", Fr::from(0x0bu64), 0)
        );
        assert_eq!(layout.receipt_target().queue, layout.target());
    }

    /// A contract manifest without a queue (the sidecar path) is no tip
    /// namespace (400); no stored row is none.
    #[test]
    fn a_manifest_without_a_queue_is_no_tip_namespace() {
        let document = sidecar_core::testing::contract_manifest(
            "seed",
            &[sidecar_core::testing::TestPackage::new(
                "pss_seed",
                sidecar_test_fixtures::vectors::read("examples/amm/manifests/pss_seed.json"),
            )],
            None,
            |_| Fr::from(0xabcdu64),
        );
        let err = TipLayout::of(Fr::from(1u64), Fr::from(2u64), &checked(&document)).unwrap_err();
        assert_eq!(err.class, ErrorClass::BadRequest);
        assert!(err.message.contains("is not a tip"), "{err}");
        assert_eq!(TipLayout::of_row(Fr::from(1u64), None).unwrap(), None);
    }

    /// Under upgrades the version in force is the one the pins name at the
    /// block's timestamp, the constructor's while none was ever scheduled;
    /// any other version runs nothing. Under `fixed` it is the layout's own,
    /// with nothing read.
    #[tokio::test]
    async fn the_version_in_force_is_the_one_the_pins_name() {
        use crate::chain::{ChainReader, Snapshot};
        use crate::testing::{MemoryChain, block_timestamp};
        use std::sync::Arc;
        let v = sidecar_test_fixtures::vectors::read("testvectors/contract_manifest.json");
        let mut document = v["manifest"].clone();
        document["upgrades"] = serde_json::json!("circuits");
        document["storage"]["circuit_pins"] = serde_json::json!("0x20");
        let ns = Fr::from(0x7195u64);
        let layout = TipLayout::of(ns, Fr::from(0xa1u64), &checked(&document)).unwrap();
        let pins = layout.circuit_pins.unwrap();
        let mem = Arc::new(MemoryChain::new(10));
        let reader = ChainReader::new(mem.clone());
        let at = Snapshot::at;
        // nothing scheduled: the constructor's manifest hash
        mem.set_storage(ns, pins.constructor_manifest_hash, Fr::from(0xa1u64));
        assert_eq!(
            reader.manifest_in_force(at(10), &layout).await.unwrap(),
            Fr::from(0xa1u64)
        );
        // an upgrade to 0xa2 at block 8's time
        mem.set_storage(ns, pins.slots.metadata, Fr::from(block_timestamp(8)));
        mem.set_storage(ns, pins.slots.after[1], Fr::from(0xa2u64));
        assert_eq!(
            reader.manifest_in_force(at(7), &layout).await.unwrap(),
            Fr::from(0xa1u64)
        );
        assert_eq!(
            reader.manifest_in_force(at(8), &layout).await.unwrap(),
            Fr::from(0xa2u64)
        );
        assert!(
            layout
                .version_differs(Fr::from(0xa2u64), 8)
                .unwrap()
                .contains("at block 8")
        );
        assert_eq!(layout.version_differs(Fr::from(0xa1u64), 7), None);
        let fixed = TipLayout::of(ns, Fr::from(0xa9u64), &checked(&v["manifest"])).unwrap();
        assert_eq!(fixed.circuit_pins, None);
        assert_eq!(
            reader.manifest_in_force(at(8), &fixed).await.unwrap(),
            Fr::from(0xa9u64)
        );
    }

    /// The class check: the manifest's class runs; another class, or no
    /// instance, does not, naming both. The in-memory chain's instances run
    /// the class the test contract manifests name.
    #[test]
    fn another_class_or_no_instance_runs_nothing() {
        let v = sidecar_test_fixtures::vectors::read("testvectors/contract_manifest.json");
        let layout =
            TipLayout::of(Fr::from(5u64), Fr::from(6u64), &checked(&v["manifest"])).unwrap();
        assert_eq!(layout.class_differs(Some(layout.class_id), 9), None);
        let other = layout.class_differs(Some(Fr::from(7u64)), 9).unwrap();
        assert!(
            other.contains("at block 9") && other.contains("was built for class"),
            "{other}"
        );
        assert!(
            layout
                .class_differs(None, 9)
                .unwrap()
                .contains("no contract instance")
        );
        let facts = sidecar_core::testing::TipFacts::new(Fr::from(1u64), 1, &[]);
        assert_eq!(facts.class_id, Fr::from(crate::testing::MEMORY_CLASS_ID));
    }
}
