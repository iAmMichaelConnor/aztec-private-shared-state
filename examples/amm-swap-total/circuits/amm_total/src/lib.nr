//! The total constant-product swap as a library: `swap::swap_total`,
//! its `SwapResult` and the failure codes `CODE_*`. This repository's
//! total swap round circuits call it by path and never copy it:
//! `amm_swap_total` beside this package (which examples/amm registers as
//! its total swap) and examples/amm-tip.
pub mod swap;
