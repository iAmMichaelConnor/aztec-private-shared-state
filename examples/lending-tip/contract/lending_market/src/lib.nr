//! The lending market's contract library: everything the market's two
//! contracts share, `lending_tip` (the clear tree: the secret-shared and
//! the non-secret-shared deployments) and `lending_tip_oblivious` (the
//! oblivious tree). The two are one market over two tree accesses
//! (docs/ARCHITECTURE.md section 6, "The oblivious tree"; docs/DECISIONS.md,
//! "Lending's two tree accesses: two contracts over one library"): the access
//! is chosen once per contract, by its round table (`app::RoundTable::clear` or
//! `oblivious`), and each contract declares only its own entry points, each a
//! call into this library. What differs between them is what a request
//! function's ABI shows: on the clear tree a request's position is clear, on
//! the oblivious tree it is shared and an opening also names the public opening
//! flag, so each round's layout (`layouts`) and sharing differ.
//!
//! Lending at the tip of the chain: a book of borrower positions
//! {collateral, debt, index at touch} and lender positions {shares} and its
//! header of aggregates, held by the network as private shared state,
//! node-held (docs/ARCHITECTURE.md section 6; examples/lending-tip/README.md).
//! The book is one tree-valued machine key, a depth-16 Merkle tree whose
//! root's commitment lives in the public slot `market`; deposits,
//! withdrawals, borrows, repayments, lenders' supplies and withdrawals of
//! supply, views, quotes, liquidations and the keeper's scans are queued
//! requests that the network serves in queue order, each proved by a total
//! circuit, so a request that cannot apply still lands, with `ok = 0` and a
//! code, and a liquidation that finds its probes healthy lands with mask 0.
//! Every round takes the oracle's price and its epoch as a pinned epoch
//! read, which `apply` re-reads first: the round lands at the oracle's
//! current epoch or the one before it; and the contract's `clock()` (the
//! block number) as a pinned read under a tolerance of CLOCK_BAND blocks, to
//! which the round accrues interest (the book's borrow index;
//! examples/lending-tip/README.md, "Interest").
//!
//! Ownership by note (docs/ARCHITECTURE.md section 6, "Ownership by note"): the
//! book records no owner. A position's owner is whoever holds a completed note
//! of it: every request function on an open position first reads one of the
//! sender's notes that reports success on the position
//! (`LendingStorage::assert_holds`, with its inclusion check; never nullified),
//! then commits the request's partial note to the sender
//! (`partial_note::commit`: `P = partial_commitment(msg_sender, rho)`, never an
//! argument, with its use nullifier), so the round's note is the sender's
//! again. The nodes never see an owner, in shares or otherwise: with every node
//! secret, nobody can request a round on a position without its owner's note
//! and keys (invariant 0).
//!
//! The liquidated owner's notice (pss_public_contract `handle`, the standing
//! delivery handle; docs/ARCHITECTURE.md section 6, "The standing delivery
//! handle"): every request on a borrower position also commits the sender's
//! next delivery handle (`request::with_handle`: `handle::commit(msg_sender,
//! handle_rho)` and the client's `handle_key`, in C after the app inputs),
//! which the round writes into the position's leaf; a liquidation that writes
//! the position completes it, so its result carries the owner's note of the
//! position after the liquidation, encrypted to the handle's key (the owner's
//! client opens it and hands it to `deliver_outcome` under `handle_rho`). Every
//! result carries one such delivery, a filler when nobody is notified.
//!
//! Tokens and credits (pss_public_contract `token`; docs/ARCHITECTURE.md
//! section 6, "Tokens and escrow"; examples/lending-tip/README.md, "Tokens"):
//! two tokens, the collateral asset and the borrowed asset (`Config`), held
//! in the contract's public balances; each user's claim on them is a private
//! balance of this market, its credit notes (`app::Credit`), funded in a
//! transaction of its own (`fund`: tokens in, amounts public, unlinked to
//! any request) and withdrawn as tokens (`withdraw_funds`). Every request
//! pays the usage deposit (`Config::deposit`, in the borrowed asset), and a
//! deposit, a repayment, a supply and a liquidation escrow their amount (a
//! liquidation its budget, the most it repays), all from one of the
//! sender's credit notes, spent in its private function with the change
//! returned as a new one, and commit two refund notes of the sender's, the
//! escrow's and the deposit's, partial notes of the credit type whose
//! commitments bind their amounts. No request calls a token or shows an
//! amount: the public wrapper records two commitments for every round type,
//! so a request shows neither its class nor its amount, to the world or to a
//! node. Skip completes both refund notes in public (the request id the only
//! public field); a round that serves the request keeps the deposit
//! (lending's choice) and settles the escrow in its outcome, which `redeem`
//! credits: a borrow's amount, a withdrawal's, a repayment's excess over the
//! debt, a liquidation's seize and unused budget, a failed deposit's,
//! repayment's or supply's escrow; a round whose shares do not open C served
//! nobody, so `apply_shared` completes both its refund notes, the escrow's
//! and the deposit's.
//!
//! Modules: `app` (the package names, the Config pins, the round table, the
//! validity checks, the price and clock reads, the lending note
//! `LendingOutcome` with what it confers and its settlement, the credit),
//! `request` (what a request function hands the shared body), `storage`
//! (the bodies over the storage both contracts declare) and `layouts` (each
//! secret-shared round's layout, generated).
//!
//! Trust model: semi-honest MPC; the chain trusts the proofs, the three node
//! signatures and the pinned oracle, never the operator or the relayer, who
//! can only delay.

pub mod app;
pub mod layouts;
pub mod request;
pub mod storage;
