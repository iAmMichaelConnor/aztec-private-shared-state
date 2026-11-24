use aztec::macros::aztec;

/// A minimal price oracle for the lending example: one public price of the
/// collateral in units of the borrowed token, a u64 at scale 100 (`250` is
/// 2.50), that its owner publishes in epochs and anyone reads. Each new
/// price opens an epoch: the epoch counter goes up by one and the price
/// before it is kept as `previous`.
///
/// Every lending round takes the price as a pinned epoch read of
/// `get_price_epoch()` (the borrow, the withdrawal, the liquidation and the
/// scan use it; the others read it too, so the round type stays hidden): the scheduler simulates it, the
/// circuit takes the price and its epoch, each node's chain verifier
/// repeats the read, and `apply` calls it again first and accepts the
/// round's epoch at its price or the epoch before it at the previous price.
/// So a round lands as long as at most one new epoch opens between the
/// scheduler's read and `apply`, and lands within `previous_blocks` blocks
/// of that opening.
///
/// The previous price is offered for `previous_blocks` blocks after an
/// epoch opens, then no longer: from then on `get_price_epoch()` reports
/// the current price as the previous one too, so a round computed at the
/// old price no longer lands (pss_public_contract `Freshness`, "the epoch
/// source's window"). Without the bound, a round's prover could choose the
/// older of two prices for as long as the oracle stays quiet: borrow
/// against a price that has since fallen, or liquidate at one that has
/// since risen.
///
/// Functions:
/// - `constructor(owner, price, epoch_blocks, previous_blocks)`: the owner,
///   the first price (epoch 1, its previous price the same), the least epoch
///   length and the previous price's window;
/// - `set_price(price)`: the owner opens a new epoch at `price`, once the
///   current one has lasted `epoch_blocks` blocks;
/// - `get_price_epoch()`: `[price, epoch, previous]`, three fields (the
///   pinned read's target), `previous` the price itself once the current
///   epoch is older than `previous_blocks` blocks;
/// - `get_price()`: the price alone;
/// - `get_owner()`.
///
/// Not an oracle design: no feed, no staleness, no bounds. It stands in for
/// whatever price source a deployment pins.
#[aztec]
pub contract LendingOracle {
    use aztec::macros::{functions::{external, initializer, view}, storage::storage};
    use aztec::protocol::address::AztecAddress;
    use aztec::protocol::traits::{Deserialize, Serialize};
    use aztec::state_vars::{PublicImmutable, PublicMutable};

    /// What `get_price_epoch()` returns, three fields in this order: the
    /// current price, its epoch and the price of the epoch before.
    #[derive(Deserialize, Eq, Serialize)]
    pub struct PriceEpoch {
        pub price: u64,
        pub epoch: u64,
        pub previous: u64,
    }

    #[storage]
    struct Storage<Context> {
        // DEV DECISION: who may move the price, default one owner address
        // fixed at deployment (a PublicImmutable), checked against
        // msg_sender in `set_price`. The lending market trusts this
        // address completely: whoever sets the price decides which
        // positions are liquidatable and how much a borrow may take. A
        // real deployment pins a real price source here (a feed contract,
        // a medianiser, a TWAP) and the lending Config pins that source's
        // address; nothing in the lending contract changes as long as the
        // getter keeps its signature `get_price_epoch()` returning the
        // three fields [price, epoch, previous] and offers `previous` only
        // for a bounded window after each new epoch (`previous_blocks`;
        // a source that keeps it for ever lets the nodes choose a stale
        // price for ever). The owner-set price is
        // this example's. Design guide: "pinned-read freshness".
        owner: PublicImmutable<AztecAddress, Context>,
        // The price's type and scale: a u64 at
        // scale 100 (two decimals), the circuits' PRICE_SCALE, read as one
        // field. The circuits treat 0 and anything wider than a u64 as no
        // price (code 6, a no-op), so the oracle does not refuse them
        // itself: a zero price stops borrows and liquidations without a
        // revert. The scale is the circuits' PRICE_SCALE and the width
        // their u64 check.
        price: PublicMutable<u64, Context>,
        // the current epoch, 1 from the constructor, one more per new price
        epoch: PublicMutable<u64, Context>,
        // the price of the epoch before the current one (the constructor's
        // price in epoch 1)
        previous: PublicMutable<u64, Context>,
        // the block the current epoch opened in
        opened: PublicMutable<u32, Context>,
        // the least number of blocks an epoch lasts before `set_price` may
        // open the next, set at deployment; 0 means no minimum. The example
        // deployment's parameter: the longer the epochs, the longer a round
        // may take and still land, and the slower the price follows the
        // market.
        epoch_blocks: PublicImmutable<u32, Context>,
        // DEV DECISION: how long after an epoch opens the previous price is
        // still offered (`get_price_epoch()`'s third field), set at
        // deployment, default the lending market's stale period (50
        // blocks). Why: a round computed just before a new price may still
        // land, but the nodes can then choose between two prices, so the
        // choice must expire; a live network lands a waiting request's
        // round within the stale period, and a head that waits longer is
        // anyone's to skip. Consequences: a round that lands later than
        // this after a new price is refused ("pinned read changed") and
        // recomputed at the current price, a liveness cost only; within
        // the window the nodes may still pick the price before, a gap of
        // one price move. The market trusts this value as it trusts the
        // price. Alternative: 0 (every round at the current price only, so
        // each new price fails the round in flight), or a longer window
        // (fewer recomputes, a longer choice).
        previous_blocks: PublicImmutable<u32, Context>,
    }

    #[external("public")]
    #[initializer]
    fn constructor(owner: AztecAddress, price: u64, epoch_blocks: u32, previous_blocks: u32) {
        self.storage.owner.initialize(owner);
        self.storage.price.write(price);
        self.storage.epoch.write(1);
        self.storage.previous.write(price);
        self.storage.opened.write(self.context.block_number());
        self.storage.epoch_blocks.initialize(epoch_blocks);
        self.storage.previous_blocks.initialize(previous_blocks);
    }

    /// Open a new epoch at `price`; only the owner may, and only once the
    /// current epoch has lasted `epoch_blocks` blocks.
    #[external("public")]
    fn set_price(price: u64) {
        assert(self.msg_sender() == self.storage.owner.read(), "only the owner sets the price");
        let now = self.context.block_number();
        let opened = self.storage.opened.read();
        assert(
            now - opened >= self.storage.epoch_blocks.read(),
            "the price epoch is younger than epoch_blocks",
        );
        self.storage.previous.write(self.storage.price.read());
        self.storage.price.write(price);
        self.storage.epoch.write(self.storage.epoch.read() + 1);
        self.storage.opened.write(now);
    }

    /// The price at scale 100, its epoch and the previous epoch's price
    /// while the current epoch is at most `previous_blocks` blocks old (the
    /// price itself after that): the value the lending rounds' pinned epoch
    /// read returns. A view, so the lending contract's static call may make
    /// it.
    #[external("public")]
    #[view]
    fn get_price_epoch() -> PriceEpoch {
        let price = self.storage.price.read();
        let age = self.context.block_number() - self.storage.opened.read();
        let previous = if age <= self.storage.previous_blocks.read() {
            self.storage.previous.read()
        } else {
            price
        };
        PriceEpoch { price, epoch: self.storage.epoch.read(), previous }
    }

    /// The price at scale 100.
    #[external("public")]
    #[view]
    fn get_price() -> u64 {
        self.storage.price.read()
    }

    #[external("public")]
    #[view]
    fn get_owner() -> AztecAddress {
        self.storage.owner.read()
    }
}
