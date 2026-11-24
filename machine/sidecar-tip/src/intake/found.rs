//! The found values of the built intakes ([`FoundInputs`]): the
//! non-secret-shared intakes' clear inputs with `user_nonce`, and the
//! secret-shared intakes' clear inputs with the inputs commitment `C` and
//! the source of the shares the synthesised request carries.

use crate::receipt::inputs_hash;
use sidecar_core::field::Fr;
use sidecar_core::manifest::ReservedOperand;
use sidecar_core::request::{Full, Request};

use super::FoundInputs;

/// The non-secret-shared intakes' inputs (on-chain intake's request log,
/// receipt intake's stored receipt, and the init round's inputs): the clear
/// app inputs and `user_nonce`, committed as `inputs_hash(inputs),
/// user_nonce` (crate::ids, `chain_request_id`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlainFound {
    pub inputs: Vec<Fr>,
    pub user_nonce: Fr,
}

impl PlainFound {
    pub fn new(inputs: Vec<Fr>, user_nonce: Fr) -> Self {
        PlainFound { inputs, user_nonce }
    }
}

impl FoundInputs for PlainFound {
    fn commitment_parts(&self) -> Vec<Fr> {
        vec![inputs_hash(&self.inputs), self.user_nonce]
    }

    fn clear_inputs(&self) -> &[Fr] {
        &self.inputs
    }

    /// `$user_nonce` only, never `$vk_hash`.
    fn reserved(&self, operand: ReservedOperand) -> Option<Fr> {
        (operand == ReservedOperand::UserNonce).then_some(self.user_nonce)
    }
}

/// Where a secret-shared request's shares come from, as the synthesised
/// request carries it: each secret-shared intake's own.
pub trait CarriedShares: Clone + std::fmt::Debug + PartialEq + Send + Sync + 'static {
    /// Put the shares' source in `request`.
    fn carry(&self, request: &mut Request<Full>);
}

/// The secret-shared intakes' inputs: the clear app inputs, the inputs
/// commitment `C` (the chain request id commits to it alone, and it fills
/// `$inputs_hash`) and the source of the shares, `S`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedFound<S> {
    pub inputs: Vec<Fr>,
    pub c: Fr,
    pub shares: S,
}

impl<S> SharedFound<S> {
    pub fn new(inputs: Vec<Fr>, c: Fr, shares: S) -> Self {
        SharedFound { inputs, c, shares }
    }
}

impl<S: CarriedShares> FoundInputs for SharedFound<S> {
    fn commitment_parts(&self) -> Vec<Fr> {
        vec![self.c]
    }

    fn clear_inputs(&self) -> &[Fr] {
        &self.inputs
    }

    fn reserved(&self, operand: ReservedOperand) -> Option<Fr> {
        (operand == ReservedOperand::InputsHash).then_some(self.c)
    }

    fn fill(&self, request: &mut Request<Full>) {
        self.shares.carry(request);
    }
}

/// Secret-shared receipt intake's inputs: the shares are the envelopes of
/// every shared input, as the synthesised request's `shared_inputs` carries
/// them.
pub type SharedReceiptFound = SharedFound<Vec<sidecar_core::request::SharedInput>>;

/// Secret-shared on-chain intake's inputs: the shares derive from the
/// request log, which the synthesised request carries as `shared_log`.
pub type SharedOnchainFound = SharedFound<sidecar_core::derived::SharedLog>;
