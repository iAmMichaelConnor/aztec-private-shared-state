use aztec::protocol::traits::{Deserialize, Serialize};

/// What every PSS circuit returns, field for field: the circuit's return
/// value is flattened into its public inputs in exactly this order, so the
/// field order is part of the interface with the circuits and the machine.
/// The one definition is `pss_core`'s, which the circuits return.
pub use pss_core::effects::PssEffects;

/// The network identity a contract pins.
///
/// Both fields are fixed at deployment. `owner` is the
/// constant the circuits bake into every note hash (the manifests'
/// `owner` const); it must equal it, or every proof fails. `npk_app_hash`
/// is the value the namespace's first REGISTER returned; pinning it means
/// only that network, holding that namespace's nsk_app, can nullify the
/// contract's PSS notes. Changing either means a new deployment.
#[derive(Deserialize, Eq, Serialize)]
pub struct PssConfig {
    pub owner: Field,
    pub npk_app_hash: Field,
}
