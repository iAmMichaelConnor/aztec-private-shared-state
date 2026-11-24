//! TXE tests for the LendingTip contract and its oracle: the deployment
//! (the Config with the oracle, the once-only `configure` and every refusal
//! before it, test_configure.nr), the init round outside the queue (once),
//! the non-secret-shared deployment's deposit under both non-secret-shared intakes (on-chain
//! intake's request log with the request's partial note and no address,
//! receipt intake's three node receipts; one request id for both), its
//! result transaction (ok = 1 and ok = 0 no-ops, the request's partial note
//! completed in public with the assigned position, no state log: the book
//! is node-held), the pinned epoch read of the price by every `apply` (a round
//! one epoch behind lands, two epochs behind reverts), the refusal of
//! `apply` from outside and `skip()` after `stale_blocks`; and every round
//! on the secret-shared deployment (test_shared.nr, test_cases.nr,
//! test_round_shape.nr, test_keeper.nr), with the credits they draw on
//! (test_tokens.nr): funding a credit note, the escrow and the usage
//! deposit drawn from it at request, the refund notes completed by
//! `skip()` and by a failed non-secret-shared deposit's apply, `redeem`'s
//! credits and `withdraw_funds`; ownership by note (test_ownership.nr); and
//! the escape hatch (test_hatch.nr).
//!
//! Ownership by note: a request on an open position needs one of the
//! sender's notes of it, so a test that borrows, repays or views first gives
//! the account a note (`hold`: an opening deposit landed and delivered).
//!
//! The tokens: two deployments of the vendored reference token
//! (examples/token), the collateral asset and the borrowed asset; the user
//! and the liquidator are account contracts (an authwit needs one), each
//! minted a private balance of both, and the market's public balance of the
//! borrowed asset is funded with the seeded liquidity. Each funds a credit
//! note of FUNDED of both assets at deployment (`fund`, under the authwits
//! of its two transfers), which its requests draw on.
//!
//! The proofs: recursive proof verification is a no-op during TXE witness
//! execution (as in the library's suite), so the staged capsule carries a
//! dummy vk whose hash the Config pins and a zero proof; the vk pin in front
//! of the verification runs for real, and so does everything after it. The
//! signatures are real: the nodes are testvectors/keys.json's, signing with
//! `nodes::sign_result`, so every result signature verifies in-circuit as a
//! node's would. The rounds' values are stand-ins (no circuit runs here):
//! commitments C1, C2, ... and the outputs of the circuits' fixtures
//! (examples/lending-tip/circuits, the race: seize 446, repay 850).
//!
//! Refusals: every check is an assertion, so a refused transaction reverts
//! as a whole and a TXE test that expects the failure ends at it. Each
//! refusal test therefore pins, right before the refused call, the exact
//! queue and slot state the call would have to change (`assert_state`).
mod test_configure;
mod test_followon;
mod test_init;
mod test_intake;
mod test_oracle;
mod test_result;
mod test_round_shape;
mod test_shared;
mod test_shared_onchain;
mod test_cases;
mod test_tokens;
mod test_lenders;
mod test_interest;
mod test_oblivious;

use aztec::oracle::random::random;
use aztec::protocol::abis::gas::Gas;
use aztec::protocol::address::AztecAddress;
use aztec::protocol::hash::{compute_siloed_private_log_first_field, poseidon2_hash};
use aztec::protocol::traits::{FromField, ToField};
use aztec::test::helpers::authwit::add_private_authwit_from_call;
use aztec::test::helpers::test_environment::TestEnvironment;
use aztec::test::helpers::txe_oracles;
use lending_oracle::LendingOracle;
use lending_market::app::{
    Config, DEPOSIT_PACKAGE, INDEX_ONE, LENDING_INIT_OBLIVIOUS_PACKAGE, LENDING_INIT_PACKAGE, Nonces,
    OBLIVIOUS_PACKAGES, OwnerResult, OUTCOME_SLOT, OutcomeNotes, PACKAGES, PLAIN_PACKAGES, PROBES, SHARED_PACKAGES,
    SharedDeliveries, SharedResult,
};
use lending_market::layouts::{
    BORROW_OBLIVIOUS_LAYOUT, DEPOSIT_OBLIVIOUS_LAYOUT, DEPOSIT_SHARED_LAYOUT, LIQUIDATE_OBLIVIOUS_LAYOUT,
    LIQUIDATE_SHARED_LAYOUT, QUOTE_SHARED_LAYOUT, SUPPLY_OBLIVIOUS_LAYOUT, SUPPLY_SHARED_LAYOUT, VIEW_OBLIVIOUS_LAYOUT,
    VIEW_SHARED_LAYOUT, WITHDRAW_SUPPLY_OBLIVIOUS_LAYOUT,
};
use lending_tip::{Keys, LendingTip};
use lending_tip_oblivious::LendingTipOblivious;
use aztec::context::UtilityContext;
use aztec::messages::processing::offchain::{MAX_OFFCHAIN_MESSAGES_PER_RECEIVE_CALL, OffchainMessage};
use aztec::state_vars::{PublicImmutable, StateVariable};
use pss_core::tip::exit::{exit_filler, exit_tag};
use pss_core::tip::handle::{deliver, filler, filler_seed, Handle, handle_tag};
use pss_core::tip::outcome::{encrypt_mismatch, encrypt_outcome, EncryptedOutcome};
use pss_public_contract::handle::Delivery;
use pss_public_contract::partial_note::partial_commitment;
use pss_public_contract::{
    chain_request_id, Configured, inputs_hash, Layout, Queue, Receipt, receipt_message,
    FixedCircuits, RegistryAnswer, Sharing, StaleBlocks, UsageDeposit,
};
use pss_public_contract::init::init_request_id;
use pss_public_contract::outcome::{OutcomeApply, OutcomeResult, OutcomeTx};
use pss_public_contract::result::{NodeHeld, PartialResult, ResultSignature, Sealing, TipResult};
use pss_probe::PssProbe;
pub use pss_tip_test::last_tx;
use pss_tip_test::{configure_answer, result_signatures, tip_pins};
use pss_tip_test::nodes::receipts;
use pss_tip_test::queue::QueueReader;
use pss_tip_test::shape::kind_options;
use pss_tip_test::sharing::{shared_receipts, sharing_of};
use pss_tip_test::outcome::open_outcome_log;
use token::Token;

/// The stale period the tests deploy with: short, so they mine few blocks;
/// the rule is the same at the manifests' 50.
pub global STALE: u32 = 4;
/// The escape hatch's period the tests deploy with (`Config::t_live`):
/// short, so they mine few blocks; the rule is the same at the default
/// 20,000.
pub global T_LIVE: u32 = 12;
/// The rounds' code for shares that do not open C: such a round seals this
/// code alone.
pub use lending_market::app::CODE_INPUTS_MISMATCH;
/// The network identity `configure` pins (a stand-in: no round runs here).
pub global NPK_APP_HASH: Field = 0x9b9b;
/// The seeded liquidity the Config pins and the init proof states.
pub global LIQUIDITY: Field = 1000000;
/// The oracle's first price, 2.50 at scale 100 (the fixtures' borrow
/// price), and the price at which the fixtures' position is liquidatable.
pub global PRICE: u64 = 250;
pub global LOW_PRICE: u64 = 200;
/// The oracle's first epoch, the constructor's.
pub global EPOCH: u64 = 1;
/// The oracle's least epoch length in the tests' deployment: none, so a
/// test opens epochs in consecutive blocks (test_oracle.nr deploys one
/// with a minimum).
pub global EPOCH_BLOCKS: u32 = 0;
/// How long after a new price the tests' oracle still offers the previous
/// one: the market's stale period, the deployments' rule.
pub global PREVIOUS_BLOCKS: u32 = STALE;

// the market commitments the stand-in rounds produce
pub global C_INIT: Field = 0xc0;
/// The book header's new leaf hash the stand-in init outputs, the init
/// layout's tail (`init_market`'s `new_hashes`).
pub global INIT_HASHES: [Field; 1] = [0x4a];
pub global C1: Field = 0xc1;
pub global C2: Field = 0xc2;
pub global C3: Field = 0xc3;

// the fixtures' story: Alice opens a position with 1,000 (the scheduler
// assigns position 1) and borrows 1,700; Bob opens position 2; a
// liquidation of both at 2.00 liquidates Alice's (mask 1), seizes 446 and
// repays 850 (the non-secret-shared deployment runs the deposits, the secret-shared one every
// round)
pub global POSITION: Field = 1;
pub global OTHER_POSITION: Field = 2;
pub global DEPOSIT: Field = 1000;
pub global BORROW: Field = 1700;
pub global REPAY: Field = 400;
pub global SEIZE_OUT: Field = 446;
pub global REPAY_OUT: Field = 850;
pub global NONCE_A: Field = 0xa1;
pub global NONCE_B: Field = 0xb2;
pub global NONCE_C: Field = 0xc3;
/// The usage deposit every request pays, in the borrowed asset, which the
/// tests' market keeps on every round that runs (lending's DEV DECISION).
pub global USAGE_DEPOSIT: Field = 5;
/// The liquidator's budget in the tests' liquidations (the fixtures'): 150
/// of it unused by the race's liquidation.
pub global BUDGET: Field = 1000;
/// What the deployer mints each user, privately, of each token.
pub global MINTED: Field = 100000;
/// What each user funds its credit with at deployment, of each token.
pub global FUNDED: Field = 50000;
/// The request number of the opening deposit that gives the user its note
/// in `held_setup` (one no test uses for another request of the user).
pub global HELD_N: Field = 0x40;

// one dummy vk per circuit, so each pin is tested against the others' proofs
pub unconstrained fn init_vk() -> [Field; 115] {
    [5; 115]
}

pub unconstrained fn deposit_vk() -> [Field; 115] {
    [6; 115]
}

/// The oblivious deployment's init's dummy vk.
pub unconstrained fn oblivious_init_vk() -> [Field; 115] {
    [4; 115]
}

/// The init's dummy vk of the oblivious deployment (`oblivious`) or of the
/// clear ones.
pub unconstrained fn init_vk_of(oblivious: bool) -> [Field; 115] {
    if oblivious {
        oblivious_init_vk()
    } else {
        init_vk()
    }
}

/// The vk hashes of the non-secret-shared list's circuits, which the
/// constructor pins and the test network's REGISTER answer signs over (the
/// secret-shared ones: `shared_vk_hash`).
pub struct Vks {
    pub init_vk_hash: Field,
    pub deposit_vk_hash: Field,
}

pub unconstrained fn vks() -> Vks {
    vks_of(false)
}

/// `vks()` with the oblivious init's vk hash in place of the init's on the
/// oblivious deployment (`oblivious`).
pub unconstrained fn vks_of(oblivious: bool) -> Vks {
    Vks { init_vk_hash: poseidon2_hash(init_vk_of(oblivious)), deposit_vk_hash: poseidon2_hash(deposit_vk()) }
}

/// The vk hash of the package named `name`: its circuit's (0 for 0, the
/// end of a list, and for a name that is no package of the contract).
pub unconstrained fn vk_hash_of(name: Field) -> Field {
    let v = vks();
    let mut hash = 0;
    if name == LENDING_INIT_PACKAGE {
        hash = v.init_vk_hash;
    } else if name == LENDING_INIT_OBLIVIOUS_PACKAGE {
        hash = poseidon2_hash(oblivious_init_vk());
    } else if name == DEPOSIT_PACKAGE {
        hash = v.deposit_vk_hash;
    } else if name != 0 {
        for round in 1..PACKAGES {
            if name == SHARED_PACKAGES[round] {
                hash = shared_vk_hash(round);
            }
            if name == OBLIVIOUS_PACKAGES[round] {
                hash = poseidon2_hash(oblivious_vk(round));
            }
        }
    }
    hash
}

/// The vk hash of each place of `packages`, as the constructor pins them.
pub unconstrained fn vk_hashes_of(packages: [Field; PACKAGES]) -> [Field; PACKAGES] {
    packages.map(|name| vk_hash_of(name))
}

pub struct Setup {
    pub env: TestEnvironment,
    pub deployer: AztecAddress,
    /// the depositor and borrower, owner of POSITION
    pub user: AztecAddress,
    /// anyone else: the liquidator
    pub other: AztecAddress,
    pub relayer: AztecAddress,
    pub oracle: AztecAddress,
    /// the collateral asset's token
    pub collateral: AztecAddress,
    /// the borrowed asset's token (the liquidity, the usage deposit)
    pub borrowed: AztecAddress,
    pub app: AztecAddress,
    pub config: Config,
    pub vks: Vks,
    /// whether the deployment is the oblivious one (its list starts with the
    /// oblivious init): its rounds' dummy vks, its opening request
    /// functions and its results' outputs are the oblivious family's
    pub oblivious: bool,
    /// whether the users hold private balances of both tokens, from which
    /// `init` funds each one's credit once the market is initialised
    /// (`fund` refuses before)
    pub funded: bool,
}

/// The non-secret-shared test deployment's Config: the seeded liquidity, the oracle, the
/// test network's keys, the short stale period, the non-secret-shared package list,
/// the two tokens and the usage deposit.
pub unconstrained fn config(oracle: AztecAddress, collateral: AztecAddress, borrowed: AztecAddress) -> Config {
    config_of(oracle, collateral, borrowed, PLAIN_PACKAGES, vk_hashes_of(PLAIN_PACKAGES))
}

/// A Config of the package list `packages` with the vk hashes `vk_hashes`.
pub unconstrained fn config_of(
    oracle: AztecAddress,
    collateral: AztecAddress,
    borrowed: AztecAddress,
    packages: [Field; PACKAGES],
    vk_hashes: [Field; PACKAGES],
) -> Config {
    Config {
        init_liquidity: LIQUIDITY,
        oracle,
        tip: tip_pins(StaleBlocks::after(STALE), packages, vk_hashes),
        collateral,
        borrowed,
        deposit: UsageDeposit { token: borrowed, amount: USAGE_DEPOSIT as u128, kept: true },
        treasury: AztecAddress::from_field(TREASURY),
        t_live: T_LIVE,
    }
}

/// Deploy the oracle (owner: the deployer, price PRICE), then the non-secret-shared
/// test deployment, and configure it; the market is not initialised.
pub unconstrained fn deploy() -> Setup {
    let s = deploy_unconfigured(PLAIN_PACKAGES);
    configure(s);
    s
}

/// The test network's REGISTER answer for the deployment's contract
/// manifest, at seq 0, signed over the constructor's manifest hash and list.
pub unconstrained fn answer_for(s: Setup) -> RegistryAnswer {
    configure_answer(s.app, s.config.tip, NPK_APP_HASH)
}

/// Configure the deployment with the network's answer, sent by the relayer
/// (anyone may).
pub unconstrained fn configure(s: Setup) {
    configure_with(s, answer_for(s));
}

pub unconstrained fn configure_with(s: Setup, answer: RegistryAnswer) {
    s.env.call_private(s.relayer, LendingTip::at(s.app).configure(NPK_APP_HASH, answer));
}

/// Deploy the oracle and the two tokens, then the market with the
/// package list `packages`, each package's circuit's vk hash pinned
/// (`vk_hashes_of`), without configuring it; mint the users their balances
/// and fund the market's liquidity. The users fund their credits when the
/// init lands (`init`).
pub unconstrained fn deploy_unconfigured(packages: [Field; PACKAGES]) -> Setup {
    deploy_unconfigured_with(packages, vk_hashes_of(packages))
}

/// `deploy_unconfigured(packages)` with the vk hashes `vk_hashes` pinned
/// (a round whose circuit the suite stages under a vk of its own).
pub unconstrained fn deploy_unconfigured_with(
    packages: [Field; PACKAGES],
    vk_hashes: [Field; PACKAGES],
) -> Setup {
    deploy_with(packages, vk_hashes, true)
}

/// `deploy_unconfigured_with`, the usage deposit kept by `apply` (`kept`)
/// or refunded.
pub unconstrained fn deploy_with(
    packages: [Field; PACKAGES],
    vk_hashes: [Field; PACKAGES],
    kept: bool,
) -> Setup {
    let mut env = TestEnvironment::new();
    let deployer = env.create_light_account();
    let user = env.create_contract_account();
    let other = env.create_contract_account();
    let relayer = env.create_light_account();
    let oracle = env
        .deploy("../lending_oracle@lending_oracle/LendingOracle")
        .with_public_initializer(
            deployer,
            LendingOracle::interface().constructor(deployer, PRICE, EPOCH_BLOCKS, PREVIOUS_BLOCKS),
        );
    let collateral = deploy_token(env, deployer, "Collateral000000000000000000000", "COL0000000000000000000000000000");
    let borrowed = deploy_token(env, deployer, "Borrowed00000000000000000000000", "BOR0000000000000000000000000000");
    let mut config = config_of(oracle, collateral, borrowed, packages, vk_hashes);
    config.deposit.kept = kept;
    let app = deploy_app(env, deployer, config);
    for t in [collateral, borrowed] {
        for who in [user, other] {
            env.call_private(deployer, Token::at(t).mint_to_private(who, MINTED as u128));
        }
    }
    env.call_public(deployer, Token::at(borrowed).mint_to_public(app, LIQUIDITY as u128));
    let oblivious = packages[0] == LENDING_INIT_OBLIVIOUS_PACKAGE;
    Setup { env, deployer, user, other, relayer, oracle, collateral, borrowed, app, config, vks: vks_of(oblivious), oblivious, funded: true }
}

/// Deploy the market under `config`: `lending_tip_oblivious` when its
/// package list is the oblivious one (it starts with the oblivious init),
/// else `lending_tip`. The functions both contracts have are declared alike,
/// so their selectors are equal and the helpers call them through
/// `LendingTip`'s interface on either deployment; the oblivious deployment's
/// own request functions go through `LendingTipOblivious`'s.
pub unconstrained fn deploy_app(mut env: TestEnvironment, deployer: AztecAddress, config: Config) -> AztecAddress {
    if config.tip.circuits.packages[0] == LENDING_INIT_OBLIVIOUS_PACKAGE {
        env.deploy("../lending_tip_oblivious@lending_tip_oblivious/LendingTipOblivious").with_public_initializer(
            deployer,
            LendingTipOblivious::interface().constructor(config),
        )
    } else {
        env.deploy("../lending_tip@lending_tip/LendingTip").with_public_initializer(
            deployer,
            LendingTip::interface().constructor(config),
        )
    }
}

/// A reference token, the deployer its admin and minter.
pub unconstrained fn deploy_token(
    mut env: TestEnvironment,
    deployer: AztecAddress,
    name: str<31>,
    symbol: str<31>,
) -> AztecAddress {
    env.deploy("../../../token/contract/token@token/Token").with_public_initializer(
        deployer,
        Token::interface().constructor(deployer, name, symbol, 18),
    )
}

/// `deploy_unconfigured(packages)` without the users' private balances: for
/// a test that moves no user's token (configure, the init, a refusal before
/// any transfer), so it skips their mints; the market's liquidity is minted,
/// which the init checks.
pub unconstrained fn deploy_unfunded(packages: [Field; PACKAGES]) -> Setup {
    deploy_bare(packages, LIQUIDITY)
}

/// `deploy_unfunded` with `liquidity` minted to the market's public balance
/// of the borrowed asset.
pub unconstrained fn deploy_bare(packages: [Field; PACKAGES], liquidity: Field) -> Setup {
    let mut env = TestEnvironment::new();
    let deployer = env.create_light_account();
    let user = env.create_contract_account();
    let other = env.create_contract_account();
    let relayer = env.create_light_account();
    let oracle = env
        .deploy("../lending_oracle@lending_oracle/LendingOracle")
        .with_public_initializer(
            deployer,
            LendingOracle::interface().constructor(deployer, PRICE, EPOCH_BLOCKS, PREVIOUS_BLOCKS),
        );
    let collateral = deploy_token(env, deployer, "Collateral000000000000000000000", "COL0000000000000000000000000000");
    let borrowed = deploy_token(env, deployer, "Borrowed00000000000000000000000", "BOR0000000000000000000000000000");
    let config = config_of(oracle, collateral, borrowed, packages, vk_hashes_of(packages));
    let app = deploy_app(env, deployer, config);
    env.call_public(deployer, Token::at(borrowed).mint_to_public(app, liquidity as u128));
    let oblivious = packages[0] == LENDING_INIT_OBLIVIOUS_PACKAGE;
    Setup { env, deployer, user, other, relayer, oracle, collateral, borrowed, app, config, vks: vks_of(oblivious), oblivious, funded: false }
}

/// `deploy()` without the mints (`deploy_unfunded`): the non-secret-shared
/// deployment, configured, the market not initialised.
pub unconstrained fn deploy_configured_unfunded() -> Setup {
    let s = deploy_unfunded(PLAIN_PACKAGES);
    configure(s);
    s
}

// ---- tokens ------------------------------------------------------------------

/// `who`'s authwit for the market to move `amount` of `token` from its
/// private balance to the market's public one under `nonce` (the call the
/// market's request function makes, pss_public_contract `token::take`).
pub unconstrained fn authorize(s: Setup, who: AztecAddress, token: AztecAddress, amount: Field, nonce: Field) {
    add_private_authwit_from_call(
        s.env,
        who,
        s.app,
        Token::at(token).transfer_to_public(who, s.app, amount as u128, nonce),
    );
}

/// `who` funds its credit with `collateral` of the collateral asset and
/// `borrowed` of the borrowed asset (the market's `fund`, under the authwits
/// of its two transfers).
pub unconstrained fn fund(s: Setup, who: AztecAddress, collateral: Field, borrowed: Field) {
    let nonces = Nonces { collateral: random(), borrowed: random() };
    if collateral != 0 {
        authorize(s, who, s.collateral, collateral, nonces.collateral);
    }
    if borrowed != 0 {
        authorize(s, who, s.borrowed, borrowed, nonces.borrowed);
    }
    s.env.call_private(
        who,
        LendingTip::at(s.app).fund(collateral as u128, borrowed as u128, nonces),
    );
}

/// The sum of `who`'s credit notes, `[collateral, borrowed]` (the market's
/// `credit_balance`).
pub unconstrained fn credit(s: Setup, who: AztecAddress) -> [Field; 2] {
    let app = LendingTip::at(s.app);
    [
        s.env.execute_utility(app.credit_balance(who, 1)) as Field,
        s.env.execute_utility(app.credit_balance(who, 0)) as Field,
    ]
}

/// `who`'s private balance of `token`.
pub unconstrained fn private_balance(s: Setup, token: AztecAddress, who: AztecAddress) -> Field {
    s.env.execute_utility(Token::at(token).balance_of_private(who)) as Field
}

/// `who`'s public balance of `token` (the market's custody).
pub unconstrained fn public_balance(s: Setup, token: AztecAddress, who: AztecAddress) -> Field {
    s.env.view_public(Token::at(token).balance_of_public(who)) as Field
}

/// Deploy and land the init round (market = C_INIT).
pub unconstrained fn setup() -> Setup {
    let s = deploy();
    init(s, C_INIT);
    s
}

// ---- state readers ---------------------------------------------------------

impl Setup {
    /// The app's queue and market as the suite reads them (pss_tip_test
    /// `queue`): the state view, the head and the tail, each entry's request
    /// id, done code and outcome, and the post-condition of a refused call.
    /// (No outcome is stored by queue index: the reader's outcome type is
    /// unused.)
    pub unconstrained fn queue(self) -> QueueReader<Config, 1, Field, Keys, FixedCircuits> {
        QueueReader::at(self.env, self.app)
    }
}

pub unconstrained fn market(s: Setup) -> Field {
    s.queue().commitment(0)
}

pub unconstrained fn market_key(s: Setup) -> Field {
    s.queue().state().state_keys[0]
}

/// The stored `Configured`, whole, read from the app's storage in a utility
/// context (the state view returns its head).
pub unconstrained fn stored_configured(s: Setup) -> Configured<PACKAGES> {
    s.env.utility_context_at(s.app, |context| {
        let configured: PublicImmutable<Configured<PACKAGES>, UtilityContext> =
            PublicImmutable::new(context, LendingTip::storage_layout().configured.slot);
        configured.read()
    })
}

/// The queue's `seen[request_id]`, read from the app's storage (no view
/// reads it) in a utility context, which leaves the last transaction as it
/// was.
pub unconstrained fn is_seen(s: Setup, request_id: Field) -> bool {
    s.env.utility_context_at(s.app, |context| {
        let queue: Queue<UtilityContext> =
            Queue::new(context, LendingTip::storage_layout().queue.slot);
        queue.is_seen(request_id)
    })
}

/// The owner opens a new epoch at `price`.
pub unconstrained fn set_price(s: Setup, price: u64) {
    s.env.call_public(s.deployer, LendingOracle::at(s.oracle).set_price(price));
}

/// The queue and slot state a refused call must leave: head index, tail and
/// market commitment.
pub unconstrained fn assert_state(s: Setup, head_index: u64, tail_: u64, market_: Field) {
    let state = s.queue().state();
    assert_eq(state.head.index, head_index);
    assert_eq(state.tail, tail_);
    assert_eq(state.commitments[0], market_);
}

/// The fields after the tag of the public log the app emitted under `tag` in
/// the last transaction (its `log_in_tx` utility); fails if there is none or
/// it has another length.
pub unconstrained fn last_tx_log<let N: u32>(s: Setup, tag: Field) -> [Field; N] {
    let tx_hash = txe_oracles::get_last_tx_effects().tx_hash;
    let fields = s.env.execute_utility(LendingTip::at(s.app).log_in_tx(tx_hash, tag));
    assert(fields.len() != 0, "no log with this tag from the app");
    assert_eq(fields.len(), N, "the log has another length");
    let mut out = [0; N];
    for k in 0..N {
        out[k] = fields.get(k);
    }
    out
}

/// Whether the app emitted no public log under `tag` in the last
/// transaction.
pub unconstrained fn no_tx_log(s: Setup, tag: Field) -> bool {
    let tx_hash = txe_oracles::get_last_tx_effects().tx_hash;
    s.env.execute_utility(LendingTip::at(s.app).log_in_tx(tx_hash, tag)).len() == 0
}

/// Deploy the tip suites' probe (`PssProbe`, uninitialised; a transaction
/// of its own), whose utilities read an earlier transaction's effects.
pub unconstrained fn deploy_probe(mut s: Setup) -> AztecAddress {
    s.env.deploy("../../../../noir/pss_probe@pss_probe/PssProbe").without_initializer()
}

/// How many public logs the last transaction emitted, read through the
/// probe's `tx_summary`. The probe's deployment is a transaction of its
/// own, so a test calls this last.
pub unconstrained fn public_logs(s: Setup) -> u32 {
    let tx_hash = txe_oracles::get_last_tx_effects().tx_hash;
    let probe = deploy_probe(s);
    s.env.execute_utility(PssProbe::at(probe).tx_summary(tx_hash)).public_logs
}

// ---- the network's side ----------------------------------------------------

/// Stage the (vk, proof) capsule the result functions and `init_market`
/// load, under the relayer as scope.
pub unconstrained fn stage_proof(s: Setup, vk: [Field; 115]) {
    pss_tip_test::stage_proof(s.env, s.app, s.relayer, vk);
}

/// The three nodes' signatures over a result for `request_id` read at
/// `old_c` with the pinned values `reads` (the price and its epoch; none for
/// the init) and leaving `new_c`: node i signs poseidon2(RESULT_DOMAIN,
/// namespace, machine request id, new_c, i, 0), the machine request id over
/// the old commitment and the pinned values, and 0 for node-held state's
/// sealed-third hash.
pub unconstrained fn signatures_at<let Q: u32>(
    s: Setup,
    request_id: Field,
    old_c: Field,
    reads: [Field; Q],
    new_c: Field,
) -> [ResultSignature; 3] {
    result_signatures(s.app.to_field(), request_id, [old_c], reads, [new_c], NodeHeld {}.sealed_hashes())
}

// ---- init ------------------------------------------------------------------

pub unconstrained fn init_id(s: Setup) -> Field {
    init_request_id(s.app, s.vks.init_vk_hash, [LIQUIDITY])
}

/// The init's signatures: over `new_c` for the empty slot, no pinned value.
pub unconstrained fn init_signatures(s: Setup, request_id: Field, new_c: Field) -> [ResultSignature; 3] {
    signatures_at(s, request_id, 0, [], new_c)
}

/// Land an init result leaving `new_c`, signed for the empty slot; then,
/// on a funded deployment, each user funds its credit (`fund_users`).
pub unconstrained fn init(s: Setup, new_c: Field) {
    init_with(s, init_vk_of(s.oblivious), new_c, init_signatures(s, init_id(s), new_c));
    fund_users(s);
}

/// On a funded deployment, the user and the other account each fund a
/// credit note of FUNDED of both assets, which their requests draw on.
pub unconstrained fn fund_users(s: Setup) {
    if s.funded {
        for who in [s.user, s.other] {
            fund(s, who, FUNDED, FUNDED);
        }
    }
}

pub unconstrained fn init_with(s: Setup, vk: [Field; 115], new_c: Field, sigs: [ResultSignature; 3]) {
    stage_proof(s, vk);
    s.env.call_private(s.relayer, LendingTip::at(s.app).init_market(new_c, INIT_HASHES, sigs));
}

// ---- partial notes ------------------------------------------------------------

/// The randomness the client derives for the request numbered `n` (a
/// stand-in for pss-client's `SecretStore` derivation): every request of an
/// account in a test takes its own `n`, so no partial note is used twice.
pub fn rho_of(n: Field) -> Field {
    0x9a00 + n
}

/// The partial note a request function commits for `owner` under `rho`.
pub fn partial_of(owner: AztecAddress, rho: Field) -> Field {
    partial_commitment(owner, rho)
}

/// The delivery handle's randomness and key the client derives for the
/// request numbered `n` (stand-ins for pss-client's `SecretStore.handle`).
pub fn handle_secrets(n: Field) -> (Field, Field) {
    (0xaa00 + n, 0x6c00 + n)
}

/// Hand the last call's offchain messages to the app's `offchain_receive`,
/// as a client hands its PXE the send result's `offchainMessages`. Returns
/// how many there were.
pub unconstrained fn receive_offchain(s: Setup) -> u32 {
    let messages = s.env.offchain_messages();
    let mut batch: BoundedVec<OffchainMessage, MAX_OFFCHAIN_MESSAGES_PER_RECEIVE_CALL> = BoundedVec::new();
    for i in 0..messages.len() {
        batch.push(messages.get(i));
    }
    s.env.execute_utility(LendingTip::at(s.app).offchain_receive(batch));
    messages.len()
}

// ---- intake ----------------------------------------------------------------

/// The chain request id of a non-secret-shared deposit, under either
/// non-secret-shared intake (one circuit, one vk hash): inputs `[position,
/// amount, partial_note]`.
pub unconstrained fn plain_id(s: Setup, position: Field, amount: Field, partial: Field, nonce: Field) -> Field {
    chain_request_id(s.app, s.vks.deposit_vk_hash, inputs_hash([position, amount, partial]), nonce)
}

/// The user's partial note of the non-secret-shared deposit with nonce
/// `nonce` (its randomness `rho_of(nonce)`).
pub unconstrained fn user_partial(s: Setup, nonce: Field) -> Field {
    partial_of(s.user, rho_of(nonce))
}

/// Queue the user's opening deposit (position 0, the scheduler assigns
/// the index) under on-chain intake, its randomness `rho_of(nonce)`;
/// returns its chain request id.
pub unconstrained fn deposit(s: Setup, amount: Field, nonce: Field) -> Field {
    deposit_from(s, s.user, 0, amount, rho_of(nonce), nonce);
    plain_id(s, 0, amount, user_partial(s, nonce), nonce)
}

/// `who` queues an on-chain intake deposit, its escrow and usage deposit
/// drawn from its credit, and hands its partial note's offchain message to
/// its PXE.
pub unconstrained fn deposit_from(
    s: Setup,
    who: AztecAddress,
    position: Field,
    amount: Field,
    rho: Field,
    nonce: Field,
) {
    s.env.call_private(who, LendingTip::at(s.app).deposit(position, amount, rho, nonce));
    let _ = receive_offchain(s);
}

/// The three nodes' receipts over a receipt intake deposit of `amount` into
/// `position` with the partial note `partial`, expiring at `expiry`.
pub unconstrained fn node_receipts(
    s: Setup,
    position: Field,
    amount: Field,
    partial: Field,
    nonce: Field,
    expiry: u32,
) -> [Receipt; 3] {
    receipts(receipt_message(
        plain_id(s, position, amount, partial, nonce),
        inputs_hash([position, amount, partial]),
        expiry,
    ))
}

/// `requester` queues a receipt intake deposit with the given receipts and
/// hands its partial note's offchain message to its PXE.
pub unconstrained fn deposit_with(
    s: Setup,
    requester: AztecAddress,
    position: Field,
    amount: Field,
    rho: Field,
    nonce: Field,
    expiry: u32,
    r: [Receipt; 3],
) {
    s.env.call_private(
        requester,
        LendingTip::at(s.app).deposit_with_receipts(position, amount, rho, nonce, expiry, r),
    );
    let _ = receive_offchain(s);
}

/// Queue the user's receipt intake opening deposit of `amount` with three
/// valid receipts expiring ten blocks on, its randomness `rho_of(nonce)`;
/// returns its chain request id, the one on-chain intake gives the same
/// inputs.
pub unconstrained fn deposit_with_receipts(s: Setup, amount: Field, nonce: Field) -> Field {
    let expiry = s.env.next_block_number() + 10;
    let partial = user_partial(s, nonce);
    let r = node_receipts(s, 0, amount, partial, nonce, expiry);
    deposit_with(s, s.user, 0, amount, rho_of(nonce), nonce, expiry, r);
    plain_id(s, 0, amount, partial, nonce)
}

/// The probes of the tests' liquidations: Alice's position and Bob's.
pub global PROBED: [Field; PROBES - 1] = [POSITION];

pub unconstrained fn mine_until_next_block_is(s: Setup, block: u32) {
    pss_tip_test::mine_until_next_block_is(s.env, block);
}

// ---- results ----------------------------------------------------------------
//
// A deposit round as the tests build it: the fields of its result by name.
// The new leaf hashes are stand-ins: the proof binds them and the contract
// passes them through.

/// The new leaf hashes an owner-bound round's stand-in result carries.
pub global OWNER_HASHES: [Field; 2] = [0x4a0, 0x4a1];
/// The new leaf hashes a liquidation's stand-in result carries.
pub global PROBE_HASHES: [Field; PROBES] = [0x4b0, 0x4b1];

/// A non-secret-shared deposit round (`OwnerResult`): the request's
/// partial note, the price, its epoch and the clock as the pinned values,
/// then the code and the position (the mask the borrower kind's when ok,
/// the payout 0).
pub struct DepositRound {
    pub request_id: Field,
    pub partial: Field,
    pub old_c: Field,
    pub new_c: Field,
    pub ok: bool,
    pub price: Field,
    pub epoch: Field,
    /// the pinned clock; CLOCK_NOW (the default) is the block the result
    /// lands in, which `submit_deposit` fills in
    pub clock: Field,
    pub code: Field,
    pub position: Field,
}

/// A round's clock left to `submit_deposit` and `submit_shared`: the block
/// the result lands in (the next block), the clock an honest scheduler
/// reads within CLOCK_BAND of.
pub global CLOCK_NOW: Field = 0;

/// The clock `clock` if a test set one, else the block the next
/// transaction lands in.
pub unconstrained fn clock_or_now(s: Setup, clock: Field) -> Field {
    if clock == CLOCK_NOW {
        s.env.next_block_number() as Field
    } else {
        clock
    }
}

impl DepositRound {
    pub fn pinned(self) -> [Field; 3] {
        [self.price, self.epoch, self.clock]
    }

    /// The round at the pinned clock `clock` (a block number).
    pub fn at_clock(self, clock: Field) -> Self {
        let mut r = self;
        r.clock = clock;
        r
    }

    /// The borrower kind's marker when the deposit applied, else 0.
    pub fn mask(self) -> Field {
        if self.ok {
            BORROWER
        } else {
            0
        }
    }

    pub fn result(self) -> OwnerResult {
        PartialResult {
            partial_note: self.partial,
            result: TipResult::new(
                self.request_id,
                [self.old_c],
                [self.new_c],
                self.ok,
                self.pinned(),
                [self.code, self.position, self.mask(), 0, OWNER_HASHES[0], OWNER_HASHES[1]],
            ),
        }
    }

    /// The round for the request whose partial note is `partial` (a stand-in
    /// round carries 0 unless a test reads the completed note).
    pub fn with_partial(self, partial: Field) -> Self {
        let mut r = self;
        r.partial = partial;
        r
    }

    /// The fields the completed note packs: `[code, position, mask, 0, 0,
    /// payout, 0, request_id]` (the contract's `owner_note_fields`).
    pub fn note(self) -> [Field; 8] {
        [self.code, self.position, self.mask(), 0, 0, 0, 0, self.request_id]
    }
}

/// A deposit at `price` of the oracle's `epoch`, ok on POSITION, leaving
/// `new_c`.
pub unconstrained fn deposit_round(
    request_id: Field,
    old_c: Field,
    new_c: Field,
    price: u64,
    epoch: u64,
) -> DepositRound {
    DepositRound {
        request_id,
        partial: 0,
        old_c,
        new_c,
        ok: true,
        price: price as Field,
        epoch: epoch as Field,
        clock: CLOCK_NOW,
        code: 0,
        position: POSITION,
    }
}

/// An ok deposit at the oracle's first price and epoch.
pub unconstrained fn ok_round(request_id: Field, old_c: Field, new_c: Field) -> DepositRound {
    deposit_round(request_id, old_c, new_c, PRICE, EPOCH)
}

/// A no-op deposit with `code` at the first price and epoch.
pub unconstrained fn failed_round(request_id: Field, old_c: Field, code: Field) -> DepositRound {
    DepositRound {
        request_id,
        partial: 0,
        old_c,
        new_c: old_c,
        ok: false,
        price: PRICE as Field,
        epoch: EPOCH as Field,
        clock: CLOCK_NOW,
        code,
        position: 0,
    }
}

/// The nodes' signatures over a deposit round.
pub unconstrained fn deposit_signatures(s: Setup, r: DepositRound) -> [ResultSignature; 3] {
    signatures_at(s, r.request_id, r.old_c, r.pinned(), r.new_c)
}

/// Submit a deposit result as the relayer, correctly signed; returns the
/// block it landed in.
pub unconstrained fn submit_deposit(s: Setup, r: DepositRound) -> u32 {
    let r = r.at_clock(clock_or_now(s, r.clock));
    stage_proof(s, deposit_vk());
    s.env.call_private(s.relayer, LendingTip::at(s.app).process_result(r.result(), deposit_signatures(s, r)));
    s.env.last_block_number()
}

/// An opening deposit applied: the market at C1, the head at 1, the user's
/// note of POSITION in its PXE.
pub unconstrained fn deposited(s: Setup) {
    let d = deposit(s, DEPOSIT, NONCE_A);
    let _ = submit_deposit(s, ok_round(d, C_INIT, C1).with_partial(user_partial(s, NONCE_A)));
    assert_state(s, 1, 1, C1);
}

// ---- secret-shared receipt intake ---------------------------------------------------
//
// The secret-shared deployment (`SHARED_PACKAGES`: the init, then the secret-shared entries
// of deposit, borrow, repay, view, liquidate and scan, each at its round
// type's place, `ROUND_*`). A request goes in as the user's client
// sends it (its partial note from its own address and `rho_of(n)`, three node
// receipts over C), a result as the relayer lands it (the outcome encrypted
// under the request's outcome key and the partial note completed with it,
// with the round's own `encrypt_outcome`, as the MPC does), each under its
// transaction kind's one gas setting. The outcomes are stand-ins (no circuit
// runs here); the proofs are dummy capsules, the round type's dummy vk
// [11 + round; 115].

/// The round types, the round table's indices (`app::ROUND_*`).
pub use lending_market::app::{
    ROUND_BORROW, ROUND_DEPOSIT, ROUND_LIQUIDATE, ROUND_QUOTE, ROUND_REPAY, ROUND_SCAN, ROUND_SUPPLY,
    ROUND_VIEW, ROUND_WITHDRAW, ROUND_WITHDRAW_SUPPLY,
};

/// The treasury the test deployments pin: an address that is no account,
/// whose public balance of the borrowed asset the sweep pays.
pub global TREASURY: Field = 0x7ea5;

/// The amount a lender supplies in the tests, and the shares it holds after
/// (a stand-in: the pool's value per share is 1 until interest).
pub global SUPPLY: Field = 5000;

/// 2^128: a payout's asset bit (lending_tip market.nr `payout`): `amount +
/// COLLATERAL_ASSET` is an amount of the collateral asset.
pub use lending_market::app::ASSET_BIT as COLLATERAL_ASSET;

/// A borrower note's mask: its position's index at touch, INDEX_ONE until
/// interest (the borrower kind's marker; a lender note's mask is 0).
pub global BORROWER: Field = INDEX_ONE;

// The stand-in outcomes the suites land, `[code, position, mask, x, y,
// payout, aux]`, the fixtures' numbers.
/// Alice's opening deposit, position 1 assigned.
pub global OPENED: [Field; 7] = [0, POSITION, BORROWER, DEPOSIT, 0, 0, 0];
/// The liquidator's outcome of a liquidation that wrote its probe: the
/// seize in x, the unused budget its payout.
pub global LIQUIDATED: [Field; 7] = [0, 0, 1, SEIZE_OUT, REPAY_OUT, BUDGET - REPAY_OUT, 0];
/// The liquidator's outcome of a liquidation that found its probe healthy:
/// the whole budget back, nothing written.
pub global HEALTHY: [Field; 7] = [0, 0, 0, 0, 0, BUDGET, 0];
/// A round whose shares did not open C: the code alone.
pub global MISMATCH: [Field; 7] = [CODE_INPUTS_MISMATCH, 0, 0, 0, 0, 0, 0];

/// The notice of a liquidation of `position`: the position after it, an
/// owner note that pays nothing.
pub fn notice_of(position: Field) -> [Field; 7] {
    [0, position, BORROWER, DEPOSIT - SEIZE_OUT, REPAY_OUT, 0, 0]
}

/// The amount the tests withdraw from POSITION's collateral.
pub global WITHDRAW: Field = 100;

/// The gas limits of each transaction kind, the app's one fee setting
/// (pss-client `LENDING_TIP_FEE_SETTING`): never estimated per transaction,
/// so they are the same for every round type; the gas the kind's
/// transactions used in the tip e2e, metered (test_round_shape.nr) plus
/// their AVM execution, with 25% headroom.
pub global REQUEST_GAS: Gas = Gas { da_gas: 7500, l2_gas: 2050000 };
pub global RESULT_GAS: Gas = Gas { da_gas: 3500, l2_gas: 1650000 };
pub global REDEEM_GAS: Gas = Gas { da_gas: 3500, l2_gas: 1350000 };

/// The new leaf hash a scan's stand-in result carries: the header only.
pub global SCAN_HASHES: [Field; 1] = [0x4c0];

/// The header's append index after the round, the app value after the exit
/// tag of every stand-in two-slot result on the oblivious deployment (the
/// circuits' `next_index`, 0 on a clear deployment; a stand-in no other value
/// of the suite takes, so a test can look for it in what a transaction
/// shows).
pub global NEXT_INDEX: Field = 0x5a5b;

/// A secret-shared round type's dummy vk (`round` a `ROUND_*` index).
pub unconstrained fn shared_vk(round: u32) -> [Field; 115] {
    [11 + round as Field; 115]
}

pub unconstrained fn shared_vk_hash(round: u32) -> Field {
    poseidon2_hash(shared_vk(round))
}

/// The oblivious deployment's round type's dummy vk.
pub unconstrained fn oblivious_vk(round: u32) -> [Field; 115] {
    [29 + round as Field; 115]
}

/// The dummy vk of round type `kind` in the deployment of `s`: the
/// oblivious one's or the secret-shared one's.
pub unconstrained fn round_vk(s: Setup, kind: u32) -> [Field; 115] {
    if s.oblivious {
        oblivious_vk(kind)
    } else {
        shared_vk(kind)
    }
}

/// Deploy the secret-shared list, configure it with the network's answers and land
/// the init (market = C_INIT).
pub unconstrained fn shared_setup() -> Setup {
    let s = deploy_unconfigured(SHARED_PACKAGES);
    configure(s);
    init(s, C_INIT);
    s
}

/// Deploy the oblivious list (`OBLIVIOUS_PACKAGES`), configure it and land
/// its init (market = C_INIT): every helper below then takes the oblivious
/// family's dummy vks, its opening request functions and its results'
/// outputs (`Setup::oblivious`).
pub unconstrained fn oblivious_setup() -> Setup {
    let s = deploy_unconfigured(OBLIVIOUS_PACKAGES);
    configure(s);
    init(s, C_INIT);
    s
}

/// `shared_setup`, then the user holds a note of POSITION (`hold`): queue
/// index 0 applied, the head at 1, the market still C_INIT (the stand-in
/// opening keeps the commitment), the user's opening escrow (DEPOSIT of the
/// collateral asset) and usage deposit drawn from its credit, the deposit
/// kept.
pub unconstrained fn held_setup() -> Setup {
    let s = shared_setup();
    let _ = hold(s, s.user, POSITION, HELD_N);
    s
}

/// A queued secret-shared request: its round type, chain request id and expiry
/// block, the outcome key and tag C commits to, and the partial note's owner
/// and randomness (the completed note's owner and the `rho` its client
/// delivers it with).
pub struct Request {
    pub kind: u32,
    pub id: Field,
    pub expiry: u32,
    pub key: Field,
    pub tag: Field,
    pub owner: AztecAddress,
    pub rho: Field,
    /// the delivery handle the request leaves in its position (an owner
    /// round on a borrower position; 0s otherwise): its randomness and key
    pub handle_rho: Field,
    pub handle_key: Field,
}

impl Request {
    /// The request's partial note.
    pub fn partial(self) -> Field {
        partial_of(self.owner, self.rho)
    }
}

/// The outcome key, tag and blinding of the request numbered `n`.
pub fn request_keys(n: Field) -> (Field, Field, Field) {
    (0x6b00 + n, 0x7a00 + n, 0xb100 + n)
}

/// The id, expiry and receipts of a request of `kind` over `values` (C's
/// order) under `blinding`, its sharing `sharing` under the round's
/// `layout`, expiring ten blocks on: the receipts are over C and the
/// sharing's digest over the clear values of `signed`, the values the nodes
/// stored (`values` for an honest request).
pub unconstrained fn receipted<let M: u32, let Q: u32, let X: u32, let L: u32>(
    s: Setup,
    kind: u32,
    values: [Field; M],
    signed: [Field; M],
    blinding: Field,
    layout: Layout<M, Q, X>,
    sharing: Sharing<L>,
) -> (Field, u32, [Receipt; 3]) {
    let c = poseidon2_hash(values.concat([blinding]));
    let id = poseidon2_hash([s.app.to_field(), poseidon2_hash(round_vk(s, kind)), c]);
    let expiry = s.env.next_block_number() + 10;
    (id, expiry, shared_receipts(id, c, expiry, layout, signed, sharing))
}

/// What request number `n` of `kind` by `who` over the app inputs `inputs`
/// sends: the outcome key, tag and blinding (`request_keys`), its `rho`
/// (`rho_of`), its sharing under the round's layout (`sharing_of` over C's
/// values: `inputs`, then the partial note, the key and the tag), and the
/// id, expiry and receipts (`receipted`).
pub struct Intake<let L: u32> {
    pub key: Field,
    pub tag: Field,
    pub blinding: Field,
    pub rho: Field,
    pub sharing: Sharing<L>,
    pub id: Field,
    pub expiry: u32,
    pub receipts: [Receipt; 3],
    pub handle_rho: Field,
    pub handle_key: Field,
}

pub unconstrained fn intake<let N: u32, let Q: u32, let X: u32, let L: u32>(
    s: Setup,
    who: AztecAddress,
    kind: u32,
    inputs: [Field; N],
    n: Field,
    layout: Layout<N + 3, Q, X>,
) -> Intake<L> {
    let (key, tag, blinding) = request_keys(n);
    let rho = rho_of(n);
    let values = inputs.concat([partial_of(who, rho), key, tag]);
    let sharing = sharing_of(layout, values, blinding);
    let (id, expiry, receipts) = receipted(s, kind, values, values, blinding, layout, sharing);
    Intake { key, tag, blinding, rho, sharing, id, expiry, receipts, handle_rho: 0, handle_key: 0 }
}

/// `intake` of a request that carries `who`'s delivery handle number `n`
/// after the app inputs (`handle_secrets`; the request function commits its
/// partial commitment from `who`'s address); `layout` covers the handle.
pub unconstrained fn handled_intake<let N: u32, let Q: u32, let X: u32, let L: u32>(
    s: Setup,
    who: AztecAddress,
    kind: u32,
    inputs: [Field; N],
    n: Field,
    layout: Layout<N + 2 + 3, Q, X>,
) -> Intake<L> {
    let (handle_rho, handle_key) = handle_secrets(n);
    let mut i = intake(s, who, kind, inputs.concat([partial_of(who, handle_rho), handle_key]), n, layout);
    i.handle_rho = handle_rho;
    i.handle_key = handle_key;
    i
}

impl<let L: u32> Intake<L> {
    /// The queued request: `kind` by `who`.
    pub fn request(self, kind: u32, who: AztecAddress) -> Request {
        Request {
            kind,
            id: self.id,
            expiry: self.expiry,
            key: self.key,
            tag: self.tag,
            owner: who,
            rho: self.rho,
            handle_rho: self.handle_rho,
            handle_key: self.handle_key,
        }
    }
}

/// `requester` queues a secret-shared deposit, withdrawal, borrow, repay,
/// supply or withdrawal of supply of `amount` on `position`, its partial
/// note its own under `rho_of(n)`; `n` also picks the outcome key, tag and
/// blinding. On the oblivious deployment it goes through
/// `lending_tip_oblivious`'s request function (`request_opening` with the
/// opening flag for a deposit or a supply, `request_oblivious_owner`
/// otherwise).
pub unconstrained fn request_owner(
    s: Setup,
    requester: AztecAddress,
    kind: u32,
    position: Field,
    amount: Field,
    n: Field,
) -> Request {
    if !s.oblivious {
        request_clear_owner(s, requester, kind, position, amount, n)
    } else if (kind == ROUND_DEPOSIT) | (kind == ROUND_SUPPLY) {
        request_opening(s, requester, kind, position, (position == 0) as Field, amount, n)
    } else {
        request_oblivious_owner(s, requester, kind, position, amount, n)
    }
}

/// Whether `kind` is a lender round, whose request carries no delivery
/// handle (the borrower rounds carry the owner's).
fn is_lender(kind: u32) -> bool {
    (kind == ROUND_SUPPLY) | (kind == ROUND_WITHDRAW_SUPPLY)
}

/// `request_owner` through `lending_tip`'s request functions, the
/// position clear (one layout per kind, equal across its rounds:
/// `SUPPLY_SHARED_LAYOUT` for a lender's, `DEPOSIT_SHARED_LAYOUT` for a
/// borrower's).
pub unconstrained fn request_clear_owner(
    s: Setup,
    requester: AztecAddress,
    kind: u32,
    position: Field,
    amount: Field,
    n: Field,
) -> Request {
    let app = LendingTip::at(s.app);
    let opts = kind_options(REQUEST_GAS);
    if is_lender(kind) {
        let i: Intake<5> = intake(s, requester, kind, [position, amount], n, SUPPLY_SHARED_LAYOUT);
        let (rho, key, tag, sh, expiry, r) = (i.rho, i.key, i.tag, i.sharing, i.expiry, i.receipts);
        if kind == ROUND_SUPPLY {
            s.env.call_private_opts(requester, opts, app.supply_shared(position, amount, rho, key, tag, sh, expiry, r));
        } else {
            s.env.call_private_opts(
                requester,
                opts,
                app.withdraw_supply_shared(position, amount, rho, key, tag, sh, expiry, r),
            );
        }
        i.request(kind, requester)
    } else {
        let i: Intake<7> = handled_intake(s, requester, kind, [position, amount], n, DEPOSIT_SHARED_LAYOUT);
        let (rho, key, tag, sh, expiry, r) = (i.rho, i.key, i.tag, i.sharing, i.expiry, i.receipts);
        let (hr, hk) = (i.handle_rho, i.handle_key);
        if kind == ROUND_DEPOSIT {
            s.env.call_private_opts(
                requester,
                opts,
                app.deposit_shared(position, amount, hr, hk, rho, key, tag, sh, expiry, r),
            );
        } else if kind == ROUND_BORROW {
            s.env.call_private_opts(
                requester,
                opts,
                app.borrow_shared(position, amount, hr, hk, rho, key, tag, sh, expiry, r),
            );
        } else if kind == ROUND_WITHDRAW {
            s.env.call_private_opts(
                requester,
                opts,
                app.withdraw_shared(position, amount, hr, hk, rho, key, tag, sh, expiry, r),
            );
        } else {
            assert_eq(kind, ROUND_REPAY, "not an owner-bound round type");
            s.env.call_private_opts(
                requester,
                opts,
                app.repay_shared(position, amount, hr, hk, rho, key, tag, sh, expiry, r),
            );
        }
        i.request(kind, requester)
    }
}

/// `request_owner` of a round on an open position (a borrow, withdrawal,
/// repay or withdrawal of supply) through `lending_tip_oblivious`'s
/// request functions, the position shared (`BORROW_OBLIVIOUS_LAYOUT`, equal
/// for the withdrawal and the repay, and `WITHDRAW_SUPPLY_OBLIVIOUS_LAYOUT`).
pub unconstrained fn request_oblivious_owner(
    s: Setup,
    requester: AztecAddress,
    kind: u32,
    position: Field,
    amount: Field,
    n: Field,
) -> Request {
    let app = LendingTipOblivious::at(s.app);
    let opts = kind_options(REQUEST_GAS);
    if is_lender(kind) {
        assert_eq(kind, ROUND_WITHDRAW_SUPPLY, "an opening goes through request_opening");
        let i: Intake<6> = intake(s, requester, kind, [position, amount], n, WITHDRAW_SUPPLY_OBLIVIOUS_LAYOUT);
        s.env.call_private_opts(
            requester,
            opts,
            app.withdraw_supply_shared(position, amount, i.rho, i.key, i.tag, i.sharing, i.expiry, i.receipts),
        );
        i.request(kind, requester)
    } else {
        let i: Intake<8> = handled_intake(s, requester, kind, [position, amount], n, BORROW_OBLIVIOUS_LAYOUT);
        let (rho, key, tag, sh, expiry, r) = (i.rho, i.key, i.tag, i.sharing, i.expiry, i.receipts);
        let (hr, hk) = (i.handle_rho, i.handle_key);
        if kind == ROUND_BORROW {
            s.env.call_private_opts(
                requester,
                opts,
                app.borrow_shared(position, amount, hr, hk, rho, key, tag, sh, expiry, r),
            );
        } else if kind == ROUND_WITHDRAW {
            s.env.call_private_opts(
                requester,
                opts,
                app.withdraw_shared(position, amount, hr, hk, rho, key, tag, sh, expiry, r),
            );
        } else {
            assert_eq(kind, ROUND_REPAY, "not an owner-bound round type");
            s.env.call_private_opts(
                requester,
                opts,
                app.repay_shared(position, amount, hr, hk, rho, key, tag, sh, expiry, r),
            );
        }
        i.request(kind, requester)
    }
}

/// `requester` queues a deposit or a supply (`kind`) of `amount` into
/// `position` through `lending_tip_oblivious`'s request function
/// (`deposit_shared`, `supply_shared`), naming the public opening flag
/// `opens` beside the shared position: C's values are `[position, opens,
/// amount, P, key, tag]` (`DEPOSIT_OBLIVIOUS_LAYOUT`,
/// `SUPPLY_OBLIVIOUS_LAYOUT`).
pub unconstrained fn request_opening(
    s: Setup,
    requester: AztecAddress,
    kind: u32,
    position: Field,
    opens: Field,
    amount: Field,
    n: Field,
) -> Request {
    let app = LendingTipOblivious::at(s.app);
    let opts = kind_options(REQUEST_GAS);
    if kind == ROUND_DEPOSIT {
        let i: Intake<8> = handled_intake(s, requester, kind, [position, opens, amount], n, DEPOSIT_OBLIVIOUS_LAYOUT);
        s.env.call_private_opts(
            requester,
            opts,
            app.deposit_shared(
                position,
                opens,
                amount,
                i.handle_rho,
                i.handle_key,
                i.rho,
                i.key,
                i.tag,
                i.sharing,
                i.expiry,
                i.receipts,
            ),
        );
        i.request(kind, requester)
    } else {
        assert_eq(kind, ROUND_SUPPLY, "not an opening round type");
        let i: Intake<6> = intake(s, requester, kind, [position, opens, amount], n, SUPPLY_OBLIVIOUS_LAYOUT);
        s.env.call_private_opts(
            requester,
            opts,
            app.supply_shared(position, opens, amount, i.rho, i.key, i.tag, i.sharing, i.expiry, i.receipts),
        );
        i.request(kind, requester)
    }
}

/// `who` queues a secret-shared view of `position`: `view_shared`, the
/// position clear (`VIEW_SHARED_LAYOUT`), or on the oblivious deployment
/// shared (`VIEW_OBLIVIOUS_LAYOUT`, `lending_tip_oblivious`).
pub unconstrained fn request_view_by(s: Setup, who: AztecAddress, position: Field, n: Field) -> Request {
    let opts = kind_options(REQUEST_GAS);
    if s.oblivious {
        let i: Intake<7> = handled_intake(s, who, ROUND_VIEW, [position], n, VIEW_OBLIVIOUS_LAYOUT);
        s.env.call_private_opts(
            who,
            opts,
            LendingTipOblivious::at(s.app).view_shared(
                position,
                i.handle_rho,
                i.handle_key,
                i.rho,
                i.key,
                i.tag,
                i.sharing,
                i.expiry,
                i.receipts,
            ),
        );
        i.request(ROUND_VIEW, who)
    } else {
        let i: Intake<6> = handled_intake(s, who, ROUND_VIEW, [position], n, VIEW_SHARED_LAYOUT);
        s.env.call_private_opts(
            who,
            opts,
            LendingTip::at(s.app).view_shared(
                position,
                i.handle_rho,
                i.handle_key,
                i.rho,
                i.key,
                i.tag,
                i.sharing,
                i.expiry,
                i.receipts,
            ),
        );
        i.request(ROUND_VIEW, who)
    }
}

/// The user queues a secret-shared view of `position`.
pub unconstrained fn request_view(s: Setup, position: Field, n: Field) -> Request {
    request_view_by(s, s.user, position, n)
}

/// `who` queues a secret-shared quote (no app input, `QUOTE_SHARED_LAYOUT`,
/// equal to `QUOTE_OBLIVIOUS_LAYOUT`, on either deployment).
pub unconstrained fn request_quote(s: Setup, who: AztecAddress, n: Field) -> Request {
    let i: Intake<4> = intake(s, who, ROUND_QUOTE, [], n, QUOTE_SHARED_LAYOUT);
    s.env.call_private_opts(
        who,
        kind_options(REQUEST_GAS),
        LendingTip::at(s.app).quote_shared(i.rho, i.key, i.tag, i.sharing, i.expiry, i.receipts),
    );
    i.request(ROUND_QUOTE, who)
}

/// `who` gets a note of a lender position `position`: its opening supply
/// of SUPPLY (request number `n`) lands at the head, its outcome reporting
/// `position`, mask 0, SUPPLY shares worth SUPPLY, and its client delivers
/// the note. Returns the request.
pub unconstrained fn lend(s: Setup, who: AztecAddress, position: Field, n: Field) -> Request {
    let d = request_owner(s, who, ROUND_SUPPLY, 0, SUPPLY, n);
    let c = market(s);
    let tx = submit_shared(s, d, c, c, PRICE, EPOCH, [0, position, 0, SUPPLY, SUPPLY, 0, 0]);
    let _ = open_and_deliver(s, d, tx);
    d
}

/// The liquidator (`other`) queues a secret-shared liquidation of POSITION
/// with the budget BUDGET (one probe: K = 2).
pub unconstrained fn request_liquidation(s: Setup, n: Field) -> Request {
    request_liquidation_of(s, PROBED, 1, n)
}

/// The liquidator queues a secret-shared liquidation of the first `count` of
/// `positions` with the budget BUDGET: `liquidate_shared`, the probes clear
/// (`LIQUIDATE_SHARED_LAYOUT`), or on the oblivious deployment shared
/// (`LIQUIDATE_OBLIVIOUS_LAYOUT`, `lending_tip_oblivious`).
pub unconstrained fn request_liquidation_of(
    s: Setup,
    positions: [Field; PROBES - 1],
    count: Field,
    n: Field,
) -> Request {
    let opts = kind_options(REQUEST_GAS);
    let inputs = positions.concat([count, BUDGET]);
    if s.oblivious {
        let i: Intake<6> = intake(s, s.other, ROUND_LIQUIDATE, inputs, n, LIQUIDATE_OBLIVIOUS_LAYOUT);
        s.env.call_private_opts(
            s.other,
            opts,
            LendingTipOblivious::at(s.app).liquidate_shared(
                positions,
                count,
                BUDGET,
                i.rho,
                i.key,
                i.tag,
                i.sharing,
                i.expiry,
                i.receipts,
            ),
        );
        i.request(ROUND_LIQUIDATE, s.other)
    } else {
        let i: Intake<5> = intake(s, s.other, ROUND_LIQUIDATE, inputs, n, LIQUIDATE_SHARED_LAYOUT);
        s.env.call_private_opts(
            s.other,
            opts,
            LendingTip::at(s.app).liquidate_shared(
                positions,
                count,
                BUDGET,
                i.rho,
                i.key,
                i.tag,
                i.sharing,
                i.expiry,
                i.receipts,
            ),
        );
        i.request(ROUND_LIQUIDATE, s.other)
    }
}

/// The apply of `req` read at `old_c` and leaving `new_c`, with the price
/// `price` of the oracle's `epoch` and the clock `clock` as its pinned reads.
pub unconstrained fn shared_apply(
    req: Request,
    old_c: Field,
    new_c: Field,
    price: u64,
    epoch: u64,
    clock: Field,
) -> OutcomeApply<1, 1, 3> {
    OutcomeApply::new(req.id, [old_c], [new_c], [price as Field, epoch as Field, clock])
}

/// The relayer lands the result of `req` read at `old_c` with the pinned
/// price `price` of the oracle's `epoch` and the clock of the block it
/// lands in, leaving `new_c`, with `outcome`
/// (`[code, position, mask, x, y, payout, aux]`) encrypted under the
/// request's outcome key and the request's partial note completed with it
/// and the request id, as the MPC does, and the inputs-opened bit the round
/// outputs with it (0 exactly when the code is 14), its exit tag a stand-in
/// (`filler_tag`); returns what the requester's client reads from the
/// transaction's effect.
pub unconstrained fn submit_shared(
    s: Setup,
    req: Request,
    old_c: Field,
    new_c: Field,
    price: u64,
    epoch: u64,
    outcome: [Field; 7],
) -> OutcomeTx {
    submit_landing(s, req, old_c, new_c, price, epoch, outcome, Landing::now())
}

/// How `submit_landing` lands a stand-in result beyond `submit_shared`'s
/// defaults: the pinned clock (CLOCK_NOW: the block it lands in), the
/// round's delivery (a notice: the delivery handle request `notice.0` left
/// completed with the outcome fields `notice.1`, as a liquidation completes
/// the liquidated owner's; else a filler, `filled`) and the exit tag among
/// the round's app values, which the landing emits as a nullifier of the
/// app (`Chain`'s for a test of the exit; else `filler_tag`).
pub struct Landing {
    clock: Field,
    notice: Option<(Request, [Field; 7])>,
    tag: Option<Field>,
}

impl Landing {
    /// The defaults: at the block it lands in, a filler delivery, `filler_tag`.
    pub fn now() -> Self {
        Landing { clock: CLOCK_NOW, notice: Option::none(), tag: Option::none() }
    }

    /// The defaults at the pinned clock `clock`.
    pub fn at(clock: Field) -> Self {
        Landing { clock, notice: Option::none(), tag: Option::none() }
    }

    pub fn noticing(self, notice: Option<(Request, [Field; 7])>) -> Self {
        Landing { clock: self.clock, notice, tag: self.tag }
    }

    pub fn tagged(self, tag: Field) -> Self {
        Landing { clock: self.clock, notice: self.notice, tag: Option::some(tag) }
    }
}

/// The stand-in exit tag of a landing of `req` in a test that follows no
/// chain of tags (`Chain` follows one): the round's first filler (pss_core
/// `exit::exit_filler`, what a round that writes no entry outputs), nonzero
/// and its own for every request, so no two landings of a test emit one
/// nullifier.
pub fn filler_tag(req: Request) -> Field {
    exit_filler(req.partial(), req.id, 0)
}

/// `submit_shared` as `landing` says.
pub unconstrained fn submit_landing(
    s: Setup,
    req: Request,
    old_c: Field,
    new_c: Field,
    price: u64,
    epoch: u64,
    outcome: [Field; 7],
    landing: Landing,
) -> OutcomeTx {
    let notice = landing.notice;
    let tag = landing.tag.unwrap_or(filler_tag(req));
    let apply = shared_apply(req, old_c, new_c, price, epoch, clock_or_now(s, landing.clock));
    let encrypted = sealed(req, outcome);
    let r: SharedResult = OutcomeResult {
        apply,
        outcome_tag: req.tag,
        note_hashes: [encrypted.note_hash],
        ciphertext: encrypted.ciphertext,
    };
    // on the oblivious deployment no leaf hash
    let hashes = if s.oblivious {
        [0; 2]
    } else if req.kind == ROUND_LIQUIDATE {
        PROBE_HASHES
    } else {
        OWNER_HASHES
    };
    let deliveries = if notice.is_some() {
        let (owner_req, fields) = notice.unwrap();
        noticed(owner_req, fields, req)
    } else {
        filled(req)
    };
    land_shared(s, req, r, new_c, hashes, tag, outcome[0] != CODE_INPUTS_MISMATCH, deliveries)
}

/// The outcome `outcome` of `req` as the round seals it (pss_core's own
/// functions, as the MPC does): the request's partial note completed with
/// it and its encryption under that note hash's nonce
/// (`encrypt_outcome`), or, for code CODE_INPUTS_MISMATCH (shares that did
/// not open C), the code alone in the mismatch domain (`encrypt_mismatch`),
/// whatever else `outcome` holds.
pub fn sealed(req: Request, outcome: [Field; 7]) -> EncryptedOutcome<8> {
    if outcome[0] == CODE_INPUTS_MISMATCH {
        encrypt_mismatch::<7>(CODE_INPUTS_MISMATCH, req.key, req.partial(), OUTCOME_SLOT, req.id)
    } else {
        encrypt_outcome(outcome, req.key, req.partial(), OUTCOME_SLOT, req.id)
    }
}

/// The deliveries of a round that notifies the owner who sent `owner_req`:
/// that request's delivery handle completed with `fields` and the request
/// id of `req` (pss_core `handle::deliver`, as the MPC completes it).
pub fn noticed(owner_req: Request, fields: [Field; 7], req: Request) -> SharedDeliveries {
    let handle = Handle { partial: partial_of(owner_req.owner, owner_req.handle_rho), key: owner_req.handle_key };
    let d = deliver(handle, true, fields, OUTCOME_SLOT, req.id, filler_seed(req.key));
    [Delivery { tag: d.tag, note_hash: d.note_hash, ciphertext: d.ciphertext }]
}

/// What the owner's client does with the last transaction's delivery log
/// (the second private log), the result of round `by`: find it under the
/// siloed tag of the handle request `owner_req` left and `by`'s request id
/// (`handle_tag`), read the delivery's note hash, open the 9-field
/// ciphertext with the handle's key under its nonce to the note's packed
/// fields (the outcome and the request id of the round that completed it),
/// and deliver the note `as_owner`'s PXE rebuilds from them under the
/// handle's randomness. Returns the packed fields.
pub unconstrained fn open_notice_as(
    s: Setup,
    owner_req: Request,
    by: Request,
    as_owner: AztecAddress,
    tx: OutcomeTx,
) -> [Field; 8] {
    let effects = txe_oracles::get_last_tx_effects();
    assert_eq(effects.private_logs.len(), 2);
    let log = effects.private_logs.get(1);
    assert_eq(log.len(), 16);
    assert_eq(log.get(0), compute_siloed_private_log_first_field(s.app, handle_tag(owner_req.handle_key, by.id)));
    let packed: [Field; 8] = open_outcome_log(log, owner_req.handle_key);
    s.env.execute_utility(LendingTip::at(s.app).deliver_outcome(as_owner, owner_req.handle_rho, packed, tx));
    packed
}

/// The deliveries of a round that notifies nobody (every round of these
/// tests but a liquidation's notice): one filler, seeded as the MPC seeds
/// it from a secret of the request's (here its outcome key: any value the
/// proof binds does).
pub fn filled(req: Request) -> SharedDeliveries {
    let f = filler::<7>(filler_seed(req.key), req.id);
    [Delivery { tag: f.tag, note_hash: f.note_hash, ciphertext: f.ciphertext }]
}

/// The relayer lands the prepared result `r` of `req`, leaving `new_c`,
/// with the new leaf hashes `hashes` (an owner round's or a liquidation's
/// two; a quote's and a scan's one is SCAN_HASHES, zero on the oblivious
/// deployment), its app values (the exit tag `tag`, then for a two-slot
/// round the header's append index, NEXT_INDEX on the oblivious deployment
/// and 0 on a clear one, and last the inputs-opened bit `opened`) and the
/// round's `deliveries`; returns what the requester's client reads.
pub unconstrained fn land_shared(
    s: Setup,
    req: Request,
    r: SharedResult,
    new_c: Field,
    hashes: [Field; 2],
    tag: Field,
    opened: bool,
    deliveries: SharedDeliveries,
) -> OutcomeTx {
    let old_c = r.apply.old_commitments[0];
    stage_proof(s, round_vk(s, req.kind));
    let sigs = signatures_at(s, req.id, old_c, r.apply.reads(), new_c);
    let app = LendingTip::at(s.app);
    let opts = kind_options(RESULT_GAS);
    let next_index = if s.oblivious { NEXT_INDEX } else { 0 };
    let values = [tag, next_index, opened as Field];
    let header_values = [tag, opened as Field];
    let round = req.kind;
    if (round == ROUND_QUOTE) | (round == ROUND_SCAN) {
        let header = if s.oblivious { [0] } else { SCAN_HASHES };
        s.env.call_private_opts(s.relayer, opts, app.process_header_shared(round, r, header, header_values, deliveries, sigs));
    } else {
        s.env.call_private_opts(s.relayer, opts, app.process_shared(round, r, hashes, values, deliveries, sigs));
    }
    last_tx()
}

/// What the requester's client does with the last transaction's outcome
/// log: find it under its siloed tag, read the note hash it carries, open
/// the 8-field ciphertext with its outcome key under that note hash's
/// nonce (the opened domain, else the mismatch one), and deliver the
/// completed note it rebuilds (the outcome and the request id, under the
/// request's `rho`) to its PXE. Returns the opened outcome.
pub unconstrained fn open_and_deliver(s: Setup, req: Request, tx: OutcomeTx) -> [Field; 7] {
    let effects = txe_oracles::get_last_tx_effects();
    // the outcome log, then the delivery's
    assert_eq(effects.private_logs.len(), 2);
    let log = effects.private_logs.get(0);
    assert_eq(log.len(), 16);
    assert_eq(log.get(0), compute_siloed_private_log_first_field(s.app, req.tag));
    let outcome: [Field; 7] = open_outcome_log(log, req.key);
    s.env.execute_utility(LendingTip::at(s.app).deliver_outcome(
        req.owner,
        req.rho,
        outcome.concat([req.id]),
        tx,
    ));
    outcome
}

/// An owner-bound round's outcome on `position` that applied: `[0,
/// position, BORROWER, x, y, payout, 0]`, the mask a borrower note's (its
/// position's index at touch).
pub fn applied_on(position: Field, x: Field, y: Field, payout: Field) -> [Field; 7] {
    [0, position, BORROWER, x, y, payout, 0]
}

/// `who` gets a note of `position`: its opening deposit of DEPOSIT (request
/// number `n`) lands at the head, its outcome reporting `position` (the
/// stand-in opening keeps the market's commitment), and its client delivers
/// the note. Returns the request.
pub unconstrained fn hold(s: Setup, who: AztecAddress, position: Field, n: Field) -> Request {
    let d = request_owner(s, who, ROUND_DEPOSIT, 0, DEPOSIT, n);
    let c = market(s);
    let tx = submit_shared(s, d, c, c, PRICE, EPOCH, applied_on(position, DEPOSIT, 0, 0));
    let _ = open_and_deliver(s, d, tx);
    d
}

/// The lending notes `owner`'s PXE holds.
pub unconstrained fn outcome_notes(s: Setup, owner: AztecAddress) -> OutcomeNotes {
    s.env.execute_utility(LendingTip::at(s.app).outcome_notes(owner))
}

/// `who` redeems its note of request `request_id`, under the redeem gas
/// setting.
pub unconstrained fn redeem(s: Setup, who: AztecAddress, request_id: Field) {
    s.env.call_private_opts(who, kind_options(REDEEM_GAS), LendingTip::at(s.app).redeem(request_id));
}

// ---- the exit tags --------------------------------------------------------
//
// The chain of exit tags (pss_core `tip::exit`) as the rounds keep it: a
// round that writes a position's leaf stores in it the exit tag of the note
// it issues for the position and outputs the tag the leaf held, which its
// landing emits as a nullifier of the app. An owner round on position i of
// chain request r issues the requester's note, `exit_tag(P, r, i)` with P
// its partial note; a liquidation of i issues the owner's notice, the note
// of the owner's delivery handle H (the partial commitment of its last
// request's handle), `exit_tag(H, r, i)`. A position's one unspent tag is
// its newest note's, the one its exit pushes.

/// The tag each position's leaf holds in a test of the exit (by index, below
/// 8; 0 for a leaf that holds none), which the test's landings follow.
pub struct Chain {
    held: [Field; 8],
}

impl Chain {
    pub fn new() -> Self {
        Chain { held: [0; 8] }
    }

    /// The tag `position`'s leaf holds: its newest note's exit tag.
    pub fn held(self, position: Field) -> Field {
        self.held[position as u32]
    }

    /// Round `req` writes `position` and issues for it the note of the
    /// partial commitment `issued`: the leaf takes that note's tag, and the
    /// round outputs the tag the leaf held, or its stand-in filler
    /// (`filler_tag`) for a leaf that held none (an opening, whose circuit
    /// outputs a value nobody recomputes).
    fn writes(&mut self, req: Request, position: Field, issued: Field) -> Field {
        let i = position as u32;
        let spent = if self.held[i] == 0 { filler_tag(req) } else { self.held[i] };
        self.held[i] = exit_tag(issued, req.id, position);
        spent
    }

    /// The relayer lands owner round `req`, whose outcome `outcome` names
    /// the position it writes, at the market's commitment and the first
    /// price, following the chain; the requester's client delivers its note.
    /// Returns the result transaction.
    pub unconstrained fn owner_round(&mut self, s: Setup, req: Request, outcome: [Field; 7]) -> OutcomeTx {
        let tag = self.writes(req, outcome[1], req.partial());
        land_on_chain(s, req, outcome, Option::none(), tag)
    }

    /// `who` opens `position` with DEPOSIT (request number `n`) and borrows
    /// `amount` on it (`n + 1`), each landed on the chain. Returns the two
    /// requests.
    pub unconstrained fn open_and_borrow(
        &mut self,
        s: Setup,
        who: AztecAddress,
        position: Field,
        amount: Field,
        n: Field,
    ) -> (Request, Request) {
        let opened = request_owner(s, who, ROUND_DEPOSIT, 0, DEPOSIT, n);
        let _ = self.owner_round(s, opened, applied_on(position, DEPOSIT, 0, 0));
        let borrowed = request_owner(s, who, ROUND_BORROW, position, amount, n + 1);
        let _ = self.owner_round(s, borrowed, applied_on(position, DEPOSIT, amount, amount));
        (opened, borrowed)
    }

    /// The relayer lands liquidation `req` with `outcome`, following the
    /// chain: with a `notice` (the last request of the owner whose handle
    /// the probe's leaf holds, and the notice's fields, which name the
    /// position) it writes the position and issues the notice; without, it
    /// found its probe healthy and writes nothing. The liquidator's client
    /// delivers its note. Returns the result transaction.
    pub unconstrained fn liquidation(
        &mut self,
        s: Setup,
        req: Request,
        outcome: [Field; 7],
        notice: Option<(Request, [Field; 7])>,
    ) -> OutcomeTx {
        let tag = if notice.is_some() {
            let (owner_req, fields) = notice.unwrap();
            self.writes(req, fields[1], partial_of(owner_req.owner, owner_req.handle_rho))
        } else {
            filler_tag(req)
        };
        land_on_chain(s, req, outcome, notice, tag)
    }
}

/// `Chain`'s landing: `req`'s result with exit tag `tag` at the market's
/// commitment (the stand-in keeps it), the first price and the block it
/// lands in, its note delivered to the requester.
unconstrained fn land_on_chain(
    s: Setup,
    req: Request,
    outcome: [Field; 7],
    notice: Option<(Request, [Field; 7])>,
    tag: Field,
) -> OutcomeTx {
    let c = market(s);
    let tx = submit_landing(s, req, c, c, PRICE, EPOCH, outcome, Landing::now().noticing(notice).tagged(tag));
    let _ = open_and_deliver(s, req, tx);
    tx
}

mod test_keeper;
mod test_notice;
mod test_ownership;
mod test_hatch;
