//! The check of a queued (tip) circuit's public parameters against the contract
//! library's public-input layout of a tip round.

use super::*;
use crate::manifest::QueuedIntake;

/// What fills one element of a tip circuit's public parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
enum TipPublic {
    Namespace,
    VkHash,
    Key(KeyRef),
    /// an element of an app input (a request public name)
    AppInput,
    /// the value of `public_reads[k]`
    Read(usize),
    /// the epoch of `public_reads[k]` (an epoch read)
    Epoch(usize),
    /// anything else, described
    Other(String),
}

impl TipPublic {
    fn describe(&self) -> String {
        match self {
            TipPublic::Namespace => "`$namespace`".into(),
            TipPublic::VkHash => "`$vk_hash`".into(),
            TipPublic::Key(k) => format!("`{k}`"),
            TipPublic::AppInput => "an app input".into(),
            TipPublic::Read(k) => format!("the value of `public_reads[{k}]`"),
            TipPublic::Epoch(k) => format!("the epoch of `public_reads[{k}]`"),
            TipPublic::Other(what) => what.clone(),
        }
    }
}

/// What one PUBLIC operand fills.
fn tip_element(op: &PublicOperand) -> TipPublic {
    match op {
        PublicOperand::Namespace => TipPublic::Namespace,
        PublicOperand::Reserved(ReservedOperand::VkHash) => TipPublic::VkHash,
        PublicOperand::Reserved(r) => TipPublic::Other(format!("`{r}`")),
        PublicOperand::Key(k) => TipPublic::Key(*k),
        PublicOperand::Name(_) => TipPublic::AppInput,
        PublicOperand::Const(_) => TipPublic::Other("a constant".into()),
    }
}

/// The check of a circuit's public parameters against its intake's
/// public-input layout ([`crate::intake::IntakeRules::check_public_prefix`]:
/// under a queued intake [`check_queued_public_prefix`]; a `direct` manifest
/// passes).
pub fn check_tip_public_prefix(manifest: &Manifest, shape: &CircuitShape) -> Result<(), Refusal> {
    manifest.intake.rules().check_public_prefix(manifest, shape)
}

/// The check of a queued (tip) circuit's public parameters under the queued
/// intake `intake` against the public-input layout the contract library
/// rebuilds for every tip round, whatever its intake
/// (`pss_public_contract::result::proved_public_inputs`,
/// and `init::init_public_inputs` for the init round): exactly `[$namespace,
/// $vk_hash, $state_keys.reads[0..R], $state_keys.writes[0..W], the pinned values]`,
/// every app input private. The pinned values follow `public_reads` order:
/// each read's value, then an epoch read's epoch. A reserved operand other
/// than `$vk_hash` is never public. The round's proof outputs the chain
/// request id over its private inputs, so one compiled circuit serves both
/// non-secret-shared intakes. A circuit that breaks the
/// order registers fine, but no proof of it verifies at a contract built on
/// the library and every request of it is skipped; REGISTER runs this check
/// after [`check_manifest`] and refuses it (400, naming the first element
/// out of place). The return value's order is the circuit's to keep (the
/// commitment-slot and note-hash checks name its fields).
pub(crate) fn check_queued_public_prefix(
    intake: QueuedIntake,
    manifest: &Manifest,
    shape: &CircuitShape,
) -> Result<(), Refusal> {
    let reads = &manifest.public_reads;
    let read_element = |name: &str| {
        reads.iter().enumerate().find_map(|(k, r)| {
            if r.param == name {
                Some(TipPublic::Read(k))
            } else if r.epoch_param.as_deref() == Some(name) {
                Some(TipPublic::Epoch(k))
            } else {
                None
            }
        })
    };
    // the public elements in ABI order
    let mut actual = Vec::new();
    let tree_params: BTreeSet<&str> = manifest.tree_params().collect();
    for param in &shape.params {
        if param.visibility != Visibility::Public || tree_params.contains(param.name.as_str()) {
            // a tree's parameters are filled from the nodes' trees, private
            // ([`check_manifest`])
            continue;
        }
        if let Some(element) = read_element(&param.name) {
            actual.extend(std::iter::repeat_n(element, param.width));
            continue;
        }
        match &param.source {
            Source::Public(PublicSource::One(op)) => {
                actual.extend(std::iter::repeat_n(tip_element(op), param.width));
            }
            Source::Public(PublicSource::List(ops)) => actual.extend(ops.iter().map(tip_element)),
            other => actual.extend(std::iter::repeat_n(
                TipPublic::Other(format!("a {} value", other.opcode())),
                param.width,
            )),
        }
    }

    let mut expected = vec![TipPublic::Namespace, TipPublic::VkHash];
    expected.extend((0..manifest.state_keys.reads).map(|i| TipPublic::Key(KeyRef::Read(i))));
    expected.extend((0..manifest.state_keys.writes).map(|j| TipPublic::Key(KeyRef::Write(j))));
    for (k, read) in reads.iter().enumerate() {
        let width = shape.param(&read.param).map_or(1, |p| p.width);
        expected.extend(std::iter::repeat_n(TipPublic::Read(k), width));
        if read.epoch_param.is_some() {
            expected.push(TipPublic::Epoch(k));
        }
    }
    if actual == expected {
        return Ok(());
    }

    let at = actual
        .iter()
        .zip(&expected)
        .position(|(a, e)| a != e)
        .unwrap_or(actual.len().min(expected.len()));
    let found = actual
        .get(at)
        .map_or("nothing".to_string(), TipPublic::describe);
    let wanted = expected
        .get(at)
        .map_or("nothing".to_string(), TipPublic::describe);
    Err(Refusal::bad_request(format!(
        "field `witness`: under `{}` intake the circuit's public parameters must be \
         [$namespace, $vk_hash, $state_keys.reads[0..R], $state_keys.writes[0..W], the pinned values in \
         `public_reads` order (each value, then an epoch read's epoch)], the app inputs \
         private, the contract library's public-input layout; public element {at} is {found} \
         where the layout has {wanted}",
        intake.as_str()
    )))
}
