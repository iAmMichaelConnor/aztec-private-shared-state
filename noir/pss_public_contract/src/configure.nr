//! The deployment of a tip app: a constructor that pins the circuits, then a
//! once-only `configure` (docs/ARCHITECTURE.md section 6, "Deployment,
//! configure and the init round").
//!
//! The namespace is the app contract's address, and REGISTER derives
//! `npk_app_hash` from it, so the pins come in two calls. The constructor
//! takes `TipPins`, what does not depend on the namespace: the stale period,
//! the three node `sig` keys and the circuit pins (`CircuitPins`: the
//! contract manifest's hash, the package list, each package's name hash in
//! the manifest's list order, and each listed package's vk hash). The
//! contract address therefore commits to the circuits and to the contract
//! manifest the nodes run them under: anyone checks them from the address
//! alone, and nothing later can pin another circuit or another manifest.
//! `configure` takes the namespace's `npk_app_hash` and the one REGISTER
//! answer of the contract manifest (its `seq` and the three node signatures),
//! rebuilds the manifest result message from this contract's address, its
//! pinned manifest hash, the packages hash of its own list and
//! `npk_app_hash`, checks the three signatures under the constructor's keys,
//! and stores `Configured` once: the constructor's pins with `npk_app_hash`
//! and `configured`. Every other function of the app reads `Configured`,
//! whose accessors assert `configured`, so nothing runs before `configure`
//! has landed.
//!
//! Why the vk hashes are the constructor's: invariant 0 (a leak of all
//! three nodes' secrets may cost privacy, never take funds). A `configure` that
//! pinned whatever vk hash the three nodes signed would let three nodes
//! compromised before a deployment pin a malicious circuit. Here the nodes'
//! signatures vouch for `npk_app_hash`, the network's key for this
//! namespace, and that they registered exactly the pinned contract manifest
//! and package list; three compromised nodes can sign another
//! `npk_app_hash`, but every result must still prove one of the
//! constructor's circuits.
//!
//! A namespace taken before the deployment (someone REGISTERs under the
//! address first, with an owner key of its own) can only be disabled, a
//! denial of service: the nodes sign the squatter's contract manifest, whose
//! hash and package list are not the constructor's, so the answer does not
//! verify here and the squatter cannot give the contract other circuits or
//! another manifest; the recovery is a new salt, which is a new namespace.
//!
//! An app declares the two immutables and writes three wrappers
//! (examples/amm-tip and examples/lending-tip, whose `Config` embeds
//! `TipPins` beside the app's own constants):
//!
//! ```noir
//! #[storage]
//! struct Storage<Context> {
//!     config: PublicImmutable<Config, Context>,              // the constructor's
//!     configured: PublicImmutable<Configured<P>, Context>,   // configure's
//!     ...
//! }
//!
//! #[external("public")]
//! #[initializer]
//! fn constructor(config: Config) {
//!     config.tip.assert_valid();
//!     self.storage.config.initialize(config);
//! }
//!
//! #[external("private")]
//! fn configure(npk_app_hash: Field, answer: RegistryAnswer) {
//!     let configured = configure::configure(self.context, self.storage.config.read().tip,
//!         npk_app_hash, answer);
//!     self.enqueue_self.set_configured(configured);
//! }
//!
//! #[external("public")]
//! #[only_self]
//! fn set_configured(configured: Configured<P>) {
//!     self.storage.configured.initialize(configured);
//! }
//! ```
//!
//! The round table is then built from `Configured` (`Configured::round`, a
//! `TipRound` per package name) in the private functions. The public ones
//! read no pin: an apply takes its row's keys from the slots alone, `skip()`
//! reads the stale period from `Configured`'s head (`stale_blocks_in_public`),
//! and each public entry point that reads nothing of it calls
//! `assert_configured_in_public` first.
//!
//! DEV DECISION (app developer): the form of `configure`. Default, built
//! here: the circuit pins in the constructor and a permissionless,
//! signature-checked `configure` of `npk_app_hash` alone, a private function
//! anyone may call, which accepts only what the three nodes signed for this
//! namespace over the constructor's contract manifest and package list.
//! Nobody is trusted for the values and anyone (the deployment script, the
//! relayer) can finish a deployment; the cost is three Schnorr verifications
//! and one hash per listed package, once (measured on `check_answer` below).
//! Alternatives, each one workable: the vk hashes from the signed answer
//! (no constructor pin): the same cost, but three nodes compromised before
//! the deployment pin any circuit, which breaks invariant 0. Or an app may
//! simply entrust its deployer to call a public `configure` with the data:
//! that is cheaper, and if the deployer passes the wrong data the contract
//! is effectively void, which users would catch, because anyone using the
//! contract validates its stored address, `npk_app_hash` and the other
//! up-front pins before relying on it; it keeps the deployer's address in
//! public state and needs that account to stay available. Choosing another
//! form replaces this module's `configure` and `check_answer` and the apps'
//! `configure` wrapper; `Configured` and everything that reads it stay.
use crate::app::{StateKeys, TipRound};
use crate::config::{NODES, StaleBlocks, TipConfig};
use crate::domains::MANIFEST_DOMAIN;
use crate::result::{ResultSignature, result_signature_verifies};
use aztec::context::{PrivateContext, PublicContext};
use aztec::protocol::hash::poseidon2_hash_bytes;
use aztec::protocol::traits::{Deserialize, Packable, Serialize, ToField};
use aztec::state_vars::{PublicImmutable, StateVariable};
use std::embedded_curve_ops::EmbeddedCurvePoint;
use total::hash::p2_hash;

/// The circuit pins: the contract manifest's hash, the package list and
/// each listed package's vk hash. The constructor fixes them (`TipPins`), so
/// the address commits to every circuit the deployment runs and to the
/// contract manifest the nodes run them under.
///
/// `manifest_hash` is `poseidon2_hash_bytes` of the contract manifest's
/// canonical JSON (pss-client `contractManifestHash`; it is a constructor
/// argument, never a constant of the class, because the manifest names the
/// class). `packages` is the deployment's package list: package `p`'s name
/// hash, `poseidon2_hash_bytes` of its name, at index `p` in the contract
/// manifest's list order, then zeros; `vk_hashes[p]` is package `p`'s vk
/// hash, 0 past the end of the list. P is the app's capacity, the number of
/// packages it has functions for; a list may be shorter. An alias of the
/// contract manifest (another intake of a listed package, on its circuit) is
/// not listed: the contract verifies its results under the listed package's
/// vk pin, and `manifest_hash` covers its circuit manifest.
///
/// DEV DECISION: the package list, default every package of the
/// deployment's intake family, the init first (the examples' README
/// "Deployment" lists theirs). A function whose package is not listed
/// refuses (its vk pin is 0), so one contract serves several deployments
/// with different lists (a secret-shared deployment and a non-secret-shared test deployment);
/// a package added later needs a new deployment. Design guide: "intake".
///
/// The vk hashes are computed on the developer's machine before any
/// REGISTER (pss-client `localVkHash`, bb `write_vk` over the nargo output)
/// and written into the contract manifest; REGISTER recomputes each one from
/// the circuit's bytes and refuses a manifest that states another, and
/// `configure` accepts only an answer the nodes signed over this manifest
/// hash and this list.
#[derive(Deserialize, Eq, Packable, Serialize)]
pub struct CircuitPins<let P: u32> {
    /// the contract manifest's hash
    pub manifest_hash: Field,
    /// the package list: name hashes in the contract manifest's list order,
    /// then zeros
    pub packages: [Field; P],
    /// each listed package's vk hash, in the list's order, then zeros
    pub vk_hashes: [Field; P],
}

/// A package's name hash, `poseidon2_hash_bytes` of its name (its
/// manifest's `circuit`): what the package list holds and REGISTER signs.
/// An app names each package once, in a global the compiler evaluates
/// (`pub global PAY_PACKAGE: Field = package_hash("pay");`), so no hash is
/// pasted and none can drift from its name.
pub fn package_hash<let N: u32>(name: str<N>) -> Field {
    poseidon2_hash_bytes(name.as_bytes())
}

impl<let P: u32> CircuitPins<P> {
    /// The constructor's check of the package list: at least one package,
    /// the listed name hashes first and then only zeros, no name twice, a
    /// vk hash for every listed package and none past the end of the list.
    /// A list that breaks it could never be configured (no contract manifest
    /// lists a name twice or leaves a gap, and no circuit has vk hash 0), so
    /// the deployment refuses it.
    pub fn assert_valid(self) {
        assert(self.packages[0] != 0, "empty package list");
        let mut ended = false;
        for p in 0..P {
            let name = self.packages[p];
            if name == 0 {
                ended = true;
                assert(self.vk_hashes[p] == 0, "a vk hash past the end of the list");
            } else {
                assert(!ended, "a package after the end of the list");
                assert(self.vk_hashes[p] != 0, "a listed package without a vk hash");
                for q in 0..p {
                    assert(self.packages[q] != name, "a package listed twice");
                }
            }
        }
    }

    /// The vk pin of the package named `name_hash`: its vk hash, or 0 when
    /// the list does not name it.
    pub fn vk_pin(self, name_hash: Field) -> Field {
        let mut pin = 0;
        for p in 0..P {
            if self.packages[p] == name_hash {
                pin = self.vk_hashes[p];
            }
        }
        pin
    }

    /// The packages hash the nodes sign: from `h = 0`, for each listed
    /// package in order, `h = poseidon2([h, name_hash, vk_hash])`, the
    /// machine's `packages_hash` (sidecar-core manifest::contract). A running
    /// hash over the listed entries only, so it needs no capacity.
    pub fn packages_hash(self) -> Field {
        let mut h = 0;
        for p in 0..P {
            let name = self.packages[p];
            if name != 0 {
                h = p2_hash([h, name, self.vk_hashes[p]]);
            }
        }
        h
    }
}

/// The constructor's part of a tip app's pins: none of it depends on the
/// namespace, so the address can be computed from it before any REGISTER,
/// and the address commits to all of it, the circuits and the contract
/// manifest included.
///
/// The members a public function reads come first (`ConfiguredHead` ends
/// with `stale_blocks`); the circuit pins, which only private functions
/// read, come last.
#[derive(Deserialize, Eq, Packable, Serialize)]
pub struct TipPins<let P: u32> {
    /// the contract manifest's `queue.stale_blocks`
    pub stale_blocks: StaleBlocks,
    /// node i's `sig` public key (Grumpkin), as GET /v1/nodes lists it,
    /// node 0 first
    pub node_sig_keys: [EmbeddedCurvePoint; NODES],
    /// the contract manifest's hash, the package list and the vk hashes
    pub circuits: CircuitPins<P>,
}

impl<let P: u32> TipPins<P> {
    /// The constructor's check (`CircuitPins::assert_valid`).
    pub fn assert_valid(self) {
        self.circuits.assert_valid();
    }
}

/// The REGISTER answer as `configure` takes it: the `ManifestResponse`'s
/// `seq` and node i's manifest signature in `signatures[i]` (`[s.lo, s.hi,
/// e.lo, e.hi]`, as a result signature). The answer's manifest hash and
/// packages hash are not arguments: the signatures are checked over the
/// constructor's.
#[derive(Deserialize, Eq, Serialize)]
pub struct RegistryAnswer {
    pub seq: Field,
    pub signatures: [ResultSignature; NODES],
}

/// The manifest result message node `i` signs for a REGISTER answer,
/// docs/ARCHITECTURE.md section 1: `poseidon2([MANIFEST_DOMAIN, namespace,
/// manifest_hash, packages_hash, npk_app_hash, seq, 0, i])`, sidecar-core's
/// `manifest_message`.
pub fn manifest_message(
    namespace: Field,
    manifest_hash: Field,
    packages_hash: Field,
    npk_app_hash: Field,
    seq: Field,
    i: u32,
) -> Field {
    p2_hash([MANIFEST_DOMAIN, namespace, manifest_hash, packages_hash, npk_app_hash, seq, 0, i as Field])
}

/// What `configure` stores once: the constructor's pins (the circuit pins
/// among them), the namespace's `npk_app_hash` and `configured = true`.
/// Every private function of the app reads this one immutable, so it makes
/// one historical read for all of its pins. A public function reads only its
/// head (`ConfiguredHead`: the flag, `npk_app_hash` and the stale period):
/// `skip()` (`stale_blocks_in_public`) and the state view.
///
/// The all-zero value (`configured = false`, every pin 0) is what the state
/// view returns before `configure` has landed (`view::TipState::read`, which
/// never reverts); every other reader refuses it.
#[derive(Deserialize, Eq, Packable, Serialize)]
pub struct Configured<let P: u32> {
    /// true once `configure` has landed; a read before then fails (the
    /// immutable is unset, and a zero value would fail this flag too)
    pub configured: bool,
    pub npk_app_hash: Field,
    /// the constructor's pins, last: the public functions read the members
    /// before it and the first of it alone (`ConfiguredHead`)
    pub pins: TipPins<P>,
}

impl<let P: u32> Configured<P> {
    /// Refuse before `configure` has landed.
    pub fn assert_configured(self) {
        assert(self.configured, "not configured");
    }

    /// The head public functions read (`ConfiguredHead`).
    pub fn head(self) -> ConfiguredHead {
        ConfiguredHead {
            configured: self.configured,
            npk_app_hash: self.npk_app_hash,
            stale_blocks: self.pins.stale_blocks,
        }
    }

    /// The library's pins (`TipConfig`), for the intake, result and init
    /// bodies; asserts configured.
    pub fn config(self) -> TipConfig {
        self.assert_configured();
        TipConfig {
            stale_blocks: self.pins.stale_blocks,
            node_sig_keys: self.pins.node_sig_keys,
            npk_app_hash: self.npk_app_hash,
        }
    }

    /// The same record under other circuit pins: the pins in force under the
    /// app's `upgrades` brick (`crate::upgrades::CircuitsInForce`), which
    /// leaves everything else as `configure` stored it.
    pub fn with_circuits(self, circuits: CircuitPins<P>) -> Self {
        let mut pins = self.pins;
        pins.circuits = circuits;
        Configured { configured: self.configured, npk_app_hash: self.npk_app_hash, pins }
    }

    /// The vk pin of the package named `name_hash`: the vk hash of it in the
    /// pins this record holds (the constructor's, or the upgraded pins in
    /// force), or 0 when the deployment's list does not name it (every
    /// entry point then refuses, `assert_deployed`); asserts configured.
    pub fn vk_pin(self, name_hash: Field) -> Field {
        self.assert_configured();
        self.pins.circuits.vk_pin(name_hash)
    }

    /// One row of the app's round table: the package named `name_hash`
    /// with the keys its circuit reads and writes; asserts configured. The
    /// row's `node_keys` brick `K` comes from the type the app gives the row.
    pub fn round<C, K, let R: u32, let W: u32>(
        self,
        name_hash: Field,
        state_keys: StateKeys<C, R, W>,
    ) -> TipRound<C, R, W, K> {
        TipRound { vk_hash: self.vk_pin(name_hash), tip: self.config(), state_keys }
    }
}

/// The head of `Configured`: its first packed fields, `configured`,
/// `npk_app_hash` and the stale period (`TipPins`' first member), all a
/// public function reads of it: `skip()` the stale period, the state view
/// the head (the pins are the Config's, which `configure` copied). Keep
/// these first, in this order: both read these four fields alone
/// (`read_head_in_public`).
#[derive(Deserialize, Eq, Packable, Serialize)]
pub struct ConfiguredHead {
    pub configured: bool,
    pub npk_app_hash: Field,
    pub stale_blocks: StaleBlocks,
}

/// Refuse a round whose package the deployment does not list (vk pin 0):
/// every intake, result and init body calls it on its vk pin, so a request
/// for an unlisted package is never queued and no result for one lands.
pub fn assert_deployed(vk_hash: Field) {
    assert(vk_hash != 0, "package not in this deployment");
}

/// The configured check of a public entry point that reads nothing of
/// `Configured` (the append wrappers, a sweep): `configured` is initialized.
/// One nullifier check, in the shared body every public read's set check
/// uses; `set_configured` is the only writer, and it writes
/// `configured = true`.
pub fn assert_configured_in_public<let P: u32>(
    context: PublicContext,
    configured: PublicImmutable<Configured<P>, PublicContext>,
) {
    // Safety: a public function is bytecode the AVM proves, so an
    // unconstrained body enforces what a constrained one would; it is only
    // out of line (`is_set_body`).
    unsafe {
        assert(is_set_body(context, configured.get_storage_slot()), "not configured");
    }
}

/// A public immutable's whole value as a public function reads it (the
/// state view's Config, a one-field record): `read_head_in_public` with the
/// record as its own head.
pub fn read_in_public<T, let N: u32>(context: PublicContext, value: PublicImmutable<T, PublicContext>) -> T
where
    T: Packable<N = N>,
{
    read_head_in_public(context, value)
}

/// The head of a stored record as a public function reads it: the first
/// `HN` packed fields of the `T` at `value`'s slot, read as an `H`
/// (`read_stored_head`), after the check that the record is set. Refuses
/// before the record is set, with a whole read's message. Public functions
/// only: a private function reads its pins with `PublicImmutable::read`
/// against its anchor block.
pub fn read_head_in_public<H, T, let HN: u32, let TN: u32>(
    context: PublicContext,
    value: PublicImmutable<T, PublicContext>,
) -> H
where
    H: Packable<N = HN>,
    T: Packable<N = TN>,
{
    let slot = value.get_storage_slot();
    // Safety: a public function is bytecode the AVM proves, so an
    // unconstrained body enforces what a constrained one would; it is only
    // out of line (`is_set_body`).
    unsafe {
        assert(is_set_body(context, slot), "Trying to read from uninitialized PublicImmutable");
    }
    read_stored_head::<H, T, HN, TN>(context, slot)
}

/// The head of a record stored with its hash at `slot` (aztec-nr's
/// `WithHash`, the layout a public immutable keeps its value in, and the
/// key epoch's at its own slot), unchecked: the first `HN` packed fields of
/// the `T` there, read as an `H`; an unset record reads as zeros. A record
/// whose readers differ lays out what its public functions use first, so
/// each of them makes `HN` storage reads, and its bytecode unpacks `HN`
/// fields, where a whole read makes and unpacks `TN`; the private functions
/// read the whole record with its hash. `H` may be `T` itself (a
/// record read whole). `T`'s packing must begin with `H`'s (the record's
/// first members, in `H`'s order): `is_head_of` is the check, and the
/// record's owner pins it in a test. Out of line: one body per head type
/// (`head_body`), since a read of a record is many storage reads, inlined at
/// each reader otherwise, and the class's public bytecode, which its first
/// deployment publishes, must stay under the network's per-transaction DA
/// limit. Public functions only.
pub fn read_stored_head<H, T, let HN: u32, let TN: u32>(context: PublicContext, slot: Field) -> H
where
    H: Packable<N = HN>,
    T: Packable<N = TN>,
{
    std::static_assert(HN <= TN, "a head longer than its record");
    // Safety: a public function is bytecode the AVM proves, so an
    // unconstrained body enforces what a constrained one would; it is only
    // out of line.
    unsafe {
        head_body(context, slot)
    }
}

/// Whether the public immutable at `slot` is set (its initialization
/// nullifier exists): one body for every record.
#[inline_never]
pub(crate) unconstrained fn is_set_body(context: PublicContext, slot: Field) -> bool {
    let record: PublicImmutable<Field, PublicContext> = PublicImmutable::new(context, slot);
    record.is_initialized()
}

/// The first `H`-many fields at `slot`, unchecked (`is_set_body` is the
/// check): one body per head type.
#[inline_never]
pub(crate) unconstrained fn head_body<H>(context: PublicContext, slot: Field) -> H
where
    H: Packable,
{
    let head: PublicImmutable<H, PublicContext> = PublicImmutable::new(context, slot);
    head.read_unsafe()
}

/// Whether `head`'s packing is the start of `value`'s, the layout
/// `read_head_in_public` reads by.
pub fn is_head_of<H, T, let HN: u32, let TN: u32>(head: H, value: T) -> bool
where
    H: Packable<N = HN>,
    T: Packable<N = TN>,
{
    let (h, v) = (head.pack(), value.pack());
    let mut same = HN <= TN;
    for i in 0..HN {
        if i < TN {
            same &= h[i] == v[i];
        }
    }
    same
}

/// The stale period as `skip()` reads it: `Configured`'s head alone
/// (`ConfiguredHead`, four storage reads). Refuses before `configure` has
/// landed: the immutable is unset, and the head's `configured` asserts it
/// as `Configured::config` does.
pub fn stale_blocks_in_public<let P: u32>(
    context: PublicContext,
    configured: PublicImmutable<Configured<P>, PublicContext>,
) -> StaleBlocks {
    let head: ConfiguredHead = read_head_in_public(context, configured);
    assert(head.configured, "not configured");
    head.stale_blocks
}

/// Check the REGISTER answer of the contract manifest for `namespace` and
/// return what `configure` stores: node i's signature verifies under
/// `pins.node_sig_keys[i]` over `manifest_message(namespace,
/// pins.circuits.manifest_hash, pins.circuits.packages_hash(), npk_app_hash,
/// answer.seq, i)` for every node. An answer the nodes signed for another
/// contract manifest or another package list (a circuit or a vk hash the
/// constructor did not pin, an alias listed or left out), a DISABLE answer,
/// an answer for another namespace or another `npk_app_hash`, and a
/// signature in another node's place all fail.
///
/// No rule on `seq`: the signatures vouch for `npk_app_hash` under the
/// constructor's manifest and list, and both are fixed for the namespace
/// (REGISTER derives `npk_app_hash` from it, the address commits to the
/// manifest hash and the list), so whichever registration of the manifest an
/// answer comes from (the first, a resend, a re-enable), a caller who
/// configures early or hostile can only write the same values. `seq` stays
/// an argument because the nodes sign it.
///
/// Measured with bb 6.0.0 `gates` on nargo 1.0.0-rc.3 output, as a private
/// function circuit (chonk): the AMM tip's `configure` (P = 2) is 12,095
/// gates, the credits tip's (P = 5) 12,297 and the lending tip's (P = 11)
/// 12,853, against 25,133 for the AMM tip's `process_result`; three Schnorr
/// verifications dominate and the list adds one hash per package.
pub fn check_answer<let P: u32>(
    namespace: Field,
    pins: TipPins<P>,
    npk_app_hash: Field,
    answer: RegistryAnswer,
) -> Configured<P> {
    let circuits = pins.circuits;
    let packages_hash = circuits.packages_hash();
    let mut verifies = [false; NODES];
    for i in 0..NODES {
        let message = manifest_message(
            namespace,
            circuits.manifest_hash,
            packages_hash,
            npk_app_hash,
            answer.seq,
            i,
        );
        verifies[i] = result_signature_verifies(pins.node_sig_keys[i], answer.signatures[i], message);
    }
    assert(verifies[0], "node 0's manifest signature does not verify");
    assert(verifies[1], "node 1's manifest signature does not verify");
    assert(verifies[2], "node 2's manifest signature does not verify");
    Configured { configured: true, pins, npk_app_hash }
}

/// The body of the app's private `configure`: `check_answer` for this
/// contract's own address. Open to anyone; the wrapper enqueues its
/// `#[only_self]` `set_configured` with the result, whose `initialize`
/// reverts on a second `configure`.
pub fn configure<let P: u32>(
    context: &mut PrivateContext,
    pins: TipPins<P>,
    npk_app_hash: Field,
    answer: RegistryAnswer,
) -> Configured<P> {
    check_answer(context.this_address().to_field(), pins, npk_app_hash, answer)
}

mod test {
    use super::{
        check_answer, CircuitPins, ConfiguredHead, is_head_of, manifest_message, package_hash, RegistryAnswer,
        TipPins,
    };
    use crate::config::StaleBlocks;
    use crate::result::result_signature_verifies;
    use std::embedded_curve_ops::EmbeddedCurvePoint;

    // BEGIN written by scripts/gen-noir-vectors.py from testvectors/registry.json
    // testvectors/registry.json: the three nodes' answers to the first
    // REGISTER (seq 0) of the contract manifest listing pss_seed alone, vk hash 0xabcd,
    // under namespace 0x1f2ea9c0, and to pss_seed's DISABLE (seq 1)
    global NAMESPACE: Field = 0x1f2ea9c0;
    global NPK_APP_HASH: Field = 0x1f21c078530872675c230b247bed26ffce80c76ab6eeb360895ca8cbd8b92e16;
    global VK_HASH: Field = 0xabcd;
    global MANIFEST_HASH: Field = 0x0989e76e314a901b423feb7dd8d7aa14de070c2440b21de9ac93ba41e68ee808;
    global PACKAGES_HASH: Field = 0x0300b5b7fbd7a38c00bb9a2bf6926b994f4e187d05b7a9cfe8a31eec96e2739a;
    // manifest.results[0].message: node 0's manifest answer
    global MESSAGE: Field = 0x0c01ef1673d155ef529c914bab8decee2fe46676e79a59256fa7a94315ebd137;
    // node i's sig key (results[i].sig_pubkey)
    global KEYS: [EmbeddedCurvePoint; 3] = [
        EmbeddedCurvePoint {
            x: 0x0f4c85396213d6133c1e636328d5e58c56d1a7d833ec673e56dae95b7ceda006,
            y: 0x23ece61f83ae1c9f10dbc8e23b44fc25cca667f26ba3ba219e23a121f881755a,
        },
        EmbeddedCurvePoint {
            x: 0x287140dfde14e2111974384a5588742f7d0f8dd841a1cfc9882b6726a0472a4f,
            y: 0x1b33dc1ba01c96a3b25779d16f9e12e8245f086d44c7f687b0dfd8761ac604d6,
        },
        EmbeddedCurvePoint {
            x: 0x1ac7171c368cc663eb54f1d036ad787b5feead48e4af9c094752939c866b4083,
            y: 0x09f1a194c810e23d5939cfadf2c00c7ef6b30a3bea2c6a943e88db3d207c8675,
        },
    ];
    global MANIFEST_SIGS: [[Field; 4]; 3] = [
        [
            0x4d201902b01c7e34b11c1dbf10557e5a,
            0x03f75380efb14157adc88743b7c4301b,
            0x579ea899da800f1b5283ac3b4bd5ae73,
            0x0a4d744feaaedd959df16e8661218e39,
        ],
        [
            0xd4fb781b51a04980c5c81b0dc5344c2b,
            0x28ada8b60604cc95df2b2e344273b787,
            0x8c7436b6eabdcdd8a522efd8d8ed9086,
            0x08e1ba3211e73e986df02350459054d4,
        ],
        [
            0x1d001ba570a164da54cd0cfd13e38147,
            0x17cc6d86da796832db94274f6b48076a,
            0x7e133b343010fc341a60e5d40b948a85,
            0x2238eaf73c22945736139f41023afff4,
        ],
    ];
    global DISABLE_SIGS: [[Field; 4]; 3] = [
        [
            0x12f9ccc929daf25776b281158bb00781,
            0x10dcf2a992af939fcf3f51073d086264,
            0x411408b2448fa679b7f8a236cf00f373,
            0x150a0d657169c144c92370c51372894e,
        ],
        [
            0x097d463fcb0edcdd3a382cc87ec42510,
            0x2210522bddbd85c5d1f11b9dffa9cb15,
            0xe731c8949b02fc9797d9728269e55f2b,
            0x1f1fdcee7d4dfb1dd735490814eed8a3,
        ],
        [
            0xd0bdbe22bcb0694a7047378d38c4c12e,
            0x03c010ac453c1f90b0f252d74f80532b,
            0xc7ca99e4b07fb9f645aef0609758e7be,
            0x1111c33dc7a296e3707e5d148de56246,
        ],
    ];
    // END written by scripts/gen-noir-vectors.py

    // the vectors' package list names pss_seed: the answers below verify
    // over its name hash as the machine and pss-client compute it
    fn name() -> Field {
        package_hash("pss_seed")
    }

    /// The vectors' contract manifest: its hash and the one-package list
    /// [pss_seed] with the vectors' vk hash, in a capacity of two, under the
    /// vectors' keys.
    fn pins() -> TipPins<2> {
        pins_with(MANIFEST_HASH, VK_HASH)
    }

    /// The same list with `manifest_hash` pinned and `vk_hash` for pss_seed.
    fn pins_with(manifest_hash: Field, vk_hash: Field) -> TipPins<2> {
        TipPins {
            stale_blocks: StaleBlocks::after(50),
            node_sig_keys: KEYS,
            circuits: CircuitPins { manifest_hash, packages: [name(), 0], vk_hashes: [vk_hash, 0] },
        }
    }

    /// A list of `packages` with vk hash `k + 0x100` for each listed name
    /// `k`.
    fn list<let P: u32>(packages: [Field; P]) -> CircuitPins<P> {
        let mut vk_hashes = [0; P];
        for p in 0..P {
            if packages[p] != 0 {
                vk_hashes[p] = packages[p] + 0x100;
            }
        }
        CircuitPins { manifest_hash: MANIFEST_HASH, packages, vk_hashes }
    }

    fn answer(seq: Field, signatures: [[Field; 4]; 3]) -> RegistryAnswer {
        RegistryAnswer { seq, signatures }
    }

    // The packages hash configure recomputes from its own list is the
    // machine's for the same list, and a capacity past the list changes
    // nothing.
    #[test]
    fn the_packages_hash_is_the_machines() {
        assert_eq(pins().circuits.packages_hash(), PACKAGES_HASH);
        let wider = CircuitPins { manifest_hash: MANIFEST_HASH, packages: [name(), 0, 0], vk_hashes: [VK_HASH, 0, 0] };
        assert_eq(wider.packages_hash(), PACKAGES_HASH);
        assert(list([1, 2]).packages_hash() != list([2, 1]).packages_hash());
    }

    // The message the machine signs is the one configure rebuilds, and the
    // machine's signature verifies over it; another seq, another manifest
    // hash, another packages hash, another namespace or another node index
    // is another message.
    #[test]
    fn the_manifest_message_is_the_machines() {
        let message = manifest_message(NAMESPACE, MANIFEST_HASH, PACKAGES_HASH, NPK_APP_HASH, 0, 0);
        assert_eq(message, MESSAGE);
        assert(result_signature_verifies(KEYS[0], MANIFEST_SIGS[0], message));
        let others = [
            manifest_message(NAMESPACE, MANIFEST_HASH, PACKAGES_HASH, NPK_APP_HASH, 1, 0),
            manifest_message(NAMESPACE, MANIFEST_HASH + 1, PACKAGES_HASH, NPK_APP_HASH, 0, 0),
            manifest_message(NAMESPACE, MANIFEST_HASH, PACKAGES_HASH + 1, NPK_APP_HASH, 0, 0),
            manifest_message(NAMESPACE + 1, MANIFEST_HASH, PACKAGES_HASH, NPK_APP_HASH, 0, 0),
            manifest_message(NAMESPACE, MANIFEST_HASH, PACKAGES_HASH, NPK_APP_HASH, 0, 1),
        ];
        for other in others {
            assert(!result_signature_verifies(KEYS[0], MANIFEST_SIGS[0], other));
        }
    }

    // The machine's REGISTER answer configures the constructor's manifest
    // and list; the place past the end of the list pins 0.
    #[test]
    fn the_machines_register_answer_configures() {
        let configured = check_answer(NAMESPACE, pins(), NPK_APP_HASH, answer(0, MANIFEST_SIGS));
        assert(configured.configured);
        assert_eq(configured.pins, pins());
        assert_eq(configured.vk_pin(name()), VK_HASH);
        assert_eq(configured.vk_pin(name() + 1), 0);
        assert_eq(configured.config().npk_app_hash, NPK_APP_HASH);
    }

    #[test(should_fail_with = "node 0's manifest signature does not verify")]
    fn another_namespace_is_refused() {
        let _ = check_answer(NAMESPACE + 1, pins(), NPK_APP_HASH, answer(0, MANIFEST_SIGS));
    }

    #[test(should_fail_with = "node 0's manifest signature does not verify")]
    fn another_npk_app_hash_is_refused() {
        let _ = check_answer(NAMESPACE, pins(), NPK_APP_HASH + 1, answer(0, MANIFEST_SIGS));
    }

    // The nodes signed the answer over another list than the constructor's
    // (here: another vk hash for the package): a circuit the constructor did
    // not pin cannot be configured around it.
    #[test(should_fail_with = "node 0's manifest signature does not verify")]
    fn an_answer_for_another_vk_hash_is_refused() {
        let _ = check_answer(
            NAMESPACE,
            pins_with(MANIFEST_HASH, VK_HASH + 1),
            NPK_APP_HASH,
            answer(0, MANIFEST_SIGS),
        );
    }

    // ... or over another contract manifest than the constructor's
    #[test(should_fail_with = "node 0's manifest signature does not verify")]
    fn an_answer_for_another_manifest_is_refused() {
        let _ = check_answer(
            NAMESPACE,
            pins_with(MANIFEST_HASH + 1, VK_HASH),
            NPK_APP_HASH,
            answer(0, MANIFEST_SIGS),
        );
    }

    // The REGISTER answer claimed at another seq than the one signed
    #[test(should_fail_with = "node 0's manifest signature does not verify")]
    fn an_answer_at_another_seq_is_refused() {
        let _ = check_answer(NAMESPACE, pins(), NPK_APP_HASH, answer(1, MANIFEST_SIGS));
    }

    // A DISABLE answer, at its own seq: signed under the registry message,
    // so its signatures do not verify over a manifest message
    #[test(should_fail_with = "node 0's manifest signature does not verify")]
    fn a_disable_answer_is_refused() {
        let _ = check_answer(NAMESPACE, pins(), NPK_APP_HASH, answer(1, DISABLE_SIGS));
    }

    // one node's signature in another's place
    #[test(should_fail_with = "node 1's manifest signature does not verify")]
    fn a_signature_in_another_place_is_refused() {
        let sigs = [MANIFEST_SIGS[0], MANIFEST_SIGS[2], MANIFEST_SIGS[1]];
        let _ = check_answer(NAMESPACE, pins(), NPK_APP_HASH, answer(0, sigs));
    }

    #[test]
    fn a_list_with_the_listed_names_first_is_valid() {
        pins().assert_valid();
        list([1, 2, 3]).assert_valid();
        list([1, 2, 0]).assert_valid();
    }

    #[test(should_fail_with = "empty package list")]
    fn an_empty_list_is_refused() {
        list([0, 0]).assert_valid();
    }

    #[test(should_fail_with = "a package after the end of the list")]
    fn a_gap_in_the_list_is_refused() {
        list([1, 0, 3]).assert_valid();
    }

    #[test(should_fail_with = "a package listed twice")]
    fn a_name_listed_twice_is_refused() {
        list([1, 2, 1]).assert_valid();
    }

    #[test(should_fail_with = "a listed package without a vk hash")]
    fn a_listed_package_without_a_vk_hash_is_refused() {
        let mut pins = list([1, 2, 0]);
        pins.vk_hashes[1] = 0;
        pins.assert_valid();
    }

    #[test(should_fail_with = "a vk hash past the end of the list")]
    fn a_vk_hash_past_the_end_of_the_list_is_refused() {
        let mut pins = list([1, 2, 0]);
        pins.vk_hashes[2] = 0x77;
        pins.assert_valid();
    }

    // `stale_blocks_in_public` and the state view read `Configured`'s first
    // four packed fields as its head.
    #[test]
    fn the_head_leads_configured() {
        let configured = check_answer(NAMESPACE, pins(), NPK_APP_HASH, answer(0, MANIFEST_SIGS));
        assert(is_head_of(configured.head(), configured));
        assert_eq(configured.head().npk_app_hash, NPK_APP_HASH);
        assert_eq(configured.head().stale_blocks, StaleBlocks::after(50));
        let other = ConfiguredHead { configured: true, npk_app_hash: NPK_APP_HASH + 1, stale_blocks: StaleBlocks::after(50) };
        assert(!is_head_of(other, configured));
    }

    #[test(should_fail_with = "not configured")]
    fn an_unset_configured_refuses() {
        let unset: super::Configured<2> = std::mem::zeroed();
        let _ = unset.vk_pin(name());
    }
}
