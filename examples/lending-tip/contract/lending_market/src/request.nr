//! What a secret-shared request function hands its shared body
//! (`LendingStorage::request`, through each contract's `shared_request`):
//! whose note the request needs (`Holds`), what it escrows (`Escrow`) and,
//! on a borrower position, the delivery handle after its app inputs
//! (`with_handle`). Each request function is one call naming these, its
//! round, layout and validity check.
use crate::app::{Config, Draw};
use aztec::protocol::address::AztecAddress;
use aztec::protocol::traits::{Deserialize, Serialize};
use pss_public_contract::handle;

/// The app inputs of a request on a borrower position: `inputs`, then the
/// sender's next delivery handle, `[handle_partial, handle_key]`, the
/// partial note of `sender`'s `handle_rho` (pss_public_contract `handle`),
/// which the round writes into the position's leaf and a liquidation of the
/// position completes.
pub fn with_handle<let P: u32>(
    sender: AztecAddress,
    inputs: [Field; P],
    handle_rho: Field,
    handle_key: Field,
) -> [Field; P + 2] {
    // BRICK delivery-handle (pss_public_contract::handle::commit), in every request function on a
    // borrower position. No alternative; an app whose rounds notify nobody but the requester leaves
    // it out. docs/design-guide/BRICKS.md#other-bricks
    inputs.concat([handle::commit(sender, handle_rho), handle_key])
}

/// Whose note a request needs before it is queued: the sender's note of a
/// position of a kind (`KIND_BORROWER`, `KIND_LENDER`, or 0 for either),
/// checked by the contract's `assert_holds`, or none.
#[derive(Deserialize, Serialize)]
pub struct Holds {
    pub required: bool,
    pub position: Field,
    pub kind: Field,
}

impl Holds {
    /// The sender's note of `position`, of `kind`.
    pub fn note(position: Field, kind: Field) -> Self {
        Holds { required: true, position, kind }
    }

    /// As `note`, unless `position` is 0, which opens a new position and
    /// needs no note.
    pub fn note_or_open(position: Field, kind: Field) -> Self {
        Holds { required: position != 0, position, kind }
    }

    /// No note: a round anyone may ask for.
    pub fn anyone() -> Self {
        Holds { required: false, position: 0, kind: 0 }
    }
}

/// What a request escrows from the sender's credit beside the usage deposit
/// (`Draw`): nothing, or an amount of the collateral asset (a deposit) or of
/// the borrowed asset (a repayment, a supply, a liquidation budget).
pub struct Escrow {
    in_collateral: bool,
    amount: Field,
}

impl Escrow {
    pub fn none() -> Self {
        Escrow { in_collateral: false, amount: 0 }
    }

    pub fn collateral(amount: Field) -> Self {
        Escrow { in_collateral: true, amount }
    }

    pub fn borrowed(amount: Field) -> Self {
        Escrow { in_collateral: false, amount }
    }

    /// The escrow (its amount a u128: the request's static validity has
    /// passed) and the Config's usage deposit.
    pub fn draw(self, config: Config) -> Draw {
        let a = self.amount as u128;
        let (collateral, borrowed) = if self.in_collateral { (a, 0) } else { (0, a) };
        Draw { collateral, borrowed, deposit: config.deposit.amount }
    }
}
