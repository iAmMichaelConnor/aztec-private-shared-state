//! The one difference between this contract's two classes: the build
//! number `get_class_version` returns. The e2e's class upgrade compiles the
//! second class from these very sources, staged with `CLASS_VERSION = 2`
//! (e2e/engine/contracts.ts `buildStagedContract`, from the `classUpgrade`
//! spec of e2e/harness/tip.ts), so the instance moves to a class
//! whose new code answers visibly, and nothing is copied in the tree.

/// This build of the AMM tip contract.
pub global CLASS_VERSION: Field = 1;
