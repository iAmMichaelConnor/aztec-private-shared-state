//! The checks that need only the manifest: [`Manifest::validate`] and the
//! rules of the round, the shared inputs and the partial note.

use super::tree::validate_trees;
use super::*;
use crate::schnorr::check_name;

impl Manifest {
    /// The checks that need only the manifest. Every refusal is `bad_request` and
    /// names the field.
    pub fn validate(&self) -> Result<(), Refusal> {
        let in_range = |key: KeyRef| in_range(self.state_keys, key);
        let UsedKeys { used, loaded } = validate_round(self)?;
        let intake = self.intake.as_str();

        // The fields of the other path.
        let other_path = if self.queued() {
            [("consume", self.consume.is_some())]
                .into_iter()
                .find(|(_, given)| *given)
                .map(|(field, _)| (field, "intake direct"))
        } else {
            [
                ("binding", self.binding.is_some()),
                ("commitment_slot", self.commitment_slot.is_some()),
                ("tree", self.tree.is_some()),
            ]
            .into_iter()
            .find(|(_, given)| *given)
            .map(|(field, _)| (field, "a queued intake"))
        };
        if let Some((field, path)) = other_path {
            return bad(
                field.into(),
                format!("only with {path}; this manifest has intake {intake}"),
            );
        }

        // State: keys loaded or stored, never a fixed key, in a mode the
        // path allows; the rest are node.
        for (key, mode) in &self.state {
            let at = format!("state.{key}");
            if key.is_fixed() {
                return bad(
                    at,
                    format!("the fixed key {key} has no state mode; the nodes hold it"),
                );
            }
            in_range(*key).or_else(|e| bad(at.clone(), e))?;
            if !used.contains(key) {
                return bad(at, format!("{key} is neither loaded nor stored"));
            }
            if !mode.allowed(self.queued()) {
                let needs = if self.queued() {
                    "intake direct (a queued round has no owner to sign for a client-held record)"
                } else {
                    "a queued intake"
                };
                return bad(
                    at,
                    format!(
                        "the state mode `{}` needs {needs}; this manifest has intake {intake}",
                        mode.as_str()
                    ),
                );
            }
        }

        // Commitment slots (queued intakes): one per loaded key, each naming
        // its own output that is not a new commitment.
        let mut olds = BTreeSet::new();
        for (key, slot) in self.commitment_slots() {
            let at = format!("commitment_slot.{key}");
            if key.is_fixed() {
                return bad(at, format!("the fixed key {key} has no commitment slot"));
            }
            in_range(*key).or_else(|e| bad(at.clone(), e))?;
            if !loaded.contains(key) {
                return bad(
                    at,
                    format!(
                        "{key} is not loaded; a commitment slot names the old commitment of a key the round reads"
                    ),
                );
            }
            let at = format!("{at}.old");
            if slot.old.is_empty() {
                return bad(at, "empty output name".into());
            }
            if !olds.insert(slot.old.as_str()) {
                return bad(at, format!("`{}` is named by two keys", slot.old));
            }
            if let Some(k) = self.outputs.iter().position(|o| o.note_hash == slot.old) {
                return bad(
                    at,
                    format!("`{}` is the new commitment of outputs[{k}]", slot.old),
                );
            }
        }
        if let Some(key) = loaded
            .iter()
            .find(|k| self.queued() && !self.commitment_slots().any(|(slot, _)| slot == *k))
        {
            return bad(
                "commitment_slot".into(),
                format!(
                    "the {}-held key {key} is loaded but has no commitment slot (the public output carrying its old commitment)",
                    self.state_mode(*key).unwrap_or_default().as_str()
                ),
            );
        }

        // Public reads: each fills a distinct witness parameter (and an epoch
        // read a second one), by a request public name, never the namespace;
        // the fields of its freshness policy and no other policy's.
        let mut read_params = BTreeSet::new();
        for (k, read) in self.public_reads.iter().enumerate() {
            let at = format!("public_reads[{k}]");
            let identifier = {
                let mut chars = read.function.chars();
                matches!(chars.next(), Some('a'..='z' | 'A'..='Z' | '_'))
                    && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
            };
            if !identifier {
                return bad(
                    format!("{at}.function"),
                    format!("`{}` is not a function name", read.function),
                );
            }
            let policy = read.freshness.as_str();
            match (read.freshness, &read.epoch_param, &read.band) {
                (Freshness::Epoch, None, _) => {
                    return bad(
                        format!("{at}.epoch_param"),
                        "missing: an epoch read names the parameter its epoch fills".into(),
                    );
                }
                (Freshness::Tolerance, _, None) => {
                    return bad(
                        format!("{at}.band"),
                        "missing: a tolerance read needs a band (`absolute` or `relative_bps`)"
                            .into(),
                    );
                }
                (Freshness::Exact | Freshness::Tolerance, Some(_), _) => {
                    return bad(
                        format!("{at}.epoch_param"),
                        format!("only under freshness epoch, not {policy}"),
                    );
                }
                (Freshness::Exact | Freshness::Epoch, _, Some(_)) => {
                    return bad(
                        format!("{at}.band"),
                        format!("only under freshness tolerance, not {policy}"),
                    );
                }
                _ => {}
            }
            match read.band {
                Some(Band::Absolute(0)) => {
                    return bad(
                        format!("{at}.band.absolute"),
                        "0 is no band; use freshness exact".into(),
                    );
                }
                Some(Band::RelativeBps(bps)) if bps == 0 || bps > MAX_RELATIVE_BPS => {
                    return bad(
                        format!("{at}.band.relative_bps"),
                        format!("{bps} is outside 1 ..= {MAX_RELATIVE_BPS} basis points"),
                    );
                }
                _ => {}
            }
            for (field, param) in [
                ("param", Some(&read.param)),
                ("epoch_param", read.epoch_param.as_ref()),
            ] {
                let Some(param) = param else { continue };
                let at = format!("{at}.{field}");
                let Some((w, entry)) = self.witness_entry(param) else {
                    return bad(at, format!("`{param}` is not a witness parameter"));
                };
                if *param == self.namespace_param {
                    return bad(at, format!("`{param}` is the namespace parameter"));
                }
                if !read_params.insert(param.as_str()) {
                    return bad(at, format!("`{param}` is filled by two reads"));
                }
                if !matches!(
                    entry.from,
                    Source::Public(PublicSource::One(PublicOperand::Name(_)))
                ) {
                    return bad(
                        at,
                        format!(
                            "`{param}` (witness[{w}]) must be filled by PUBLIC with a request public name, which the scheduler fills from the call"
                        ),
                    );
                }
            }
        }

        // Reserved operands (the comment on [`ReservedOperand`]): queued
        // intakes only; each fills one whole parameter, at most once, under a
        // parameter name no request public name shares (the synthesised
        // `public` map holds the value under that name).
        let names: BTreeSet<&str> = self
            .witness
            .iter()
            .filter_map(|w| match &w.from {
                Source::Public(p) => Some(p.operands().iter().filter_map(|op| match op {
                    PublicOperand::Name(n) => Some(n.as_str()),
                    _ => None,
                })),
                _ => None,
            })
            .flatten()
            .collect();
        let mut reserved = BTreeSet::new();
        for (k, entry, operand, in_list) in reserved_uses(&self.witness) {
            let at = format!("witness[{k}].from.PUBLIC");
            if !self.queued() {
                return bad(
                    at,
                    format!(
                        "the reserved operand `{operand}` needs a queued intake (a direct request has no chain request id); this manifest has intake {intake}"
                    ),
                );
            }
            if in_list {
                return bad(
                    at,
                    format!(
                        "the reserved operand `{operand}` fills a whole parameter (`\"PUBLIC\": \"{operand}\"`), not an element of a list"
                    ),
                );
            }
            if !reserved.insert(operand) {
                return bad(at, format!("`{operand}` fills two parameters"));
            }
            let shared = self.queued_intake().is_some_and(QueuedIntake::shared);
            match operand {
                ReservedOperand::UserNonce if shared => {
                    return bad(
                        at,
                        format!(
                            "`{operand}` is refused under intake {intake}: a secret-shared intake's chain request id commits to the inputs commitment (`$inputs_hash`) and holds no nonce"
                        ),
                    );
                }
                ReservedOperand::InputsHash if !shared => {
                    return bad(
                        at,
                        format!(
                            "`$inputs_hash` needs a secret-shared intake (shared_receipt or shared_onchain); this manifest has intake {intake}"
                        ),
                    );
                }
                ReservedOperand::PartialNote if shared => {
                    return bad(
                        at,
                        format!(
                            "`{operand}` is INPUT_SHARED under intake {intake}: a clear partial note would show the nodes a commitment they could link to the completed note"
                        ),
                    );
                }
                _ => {}
            }
            if names.contains(entry.param.as_str()) {
                return bad(
                    at,
                    format!(
                        "parameter `{}` is filled by `{operand}`, and `{}` is also a request public name of this manifest",
                        entry.param, entry.param
                    ),
                );
            }
        }

        validate_shared(self, &reserved)?;
        validate_trees(self, &used, &loaded, &names, &reserved)?;
        validate_partial(self)?;

        // Consume: loaded keys only, once each, with a policy their mode
        // allows; every loaded client-held key is listed.
        let mut consumed = BTreeSet::new();
        for (k, entry) in self.consume().iter().enumerate() {
            let at = format!("consume[{k}]");
            if entry.key.is_fixed() {
                return bad(
                    format!("{at}.key"),
                    format!("the fixed key {} is never consumed", entry.key),
                );
            }
            if !loaded.contains(&entry.key) {
                return bad(format!("{at}.key"), format!("{} is not loaded", entry.key));
            }
            if !consumed.insert(entry.key) {
                return bad(
                    format!("{at}.key"),
                    format!("{} is listed twice", entry.key),
                );
            }
            let mode = self.state_mode(entry.key).unwrap_or_default();
            if let Some(policy) = entry.policy
                && !policy.allowed_for(mode)
            {
                return bad(
                    format!("{at}.policy"),
                    format!(
                        "{} applies to client-held keys only; {} is node-held",
                        policy.as_str(),
                        entry.key
                    ),
                );
            }
        }
        for key in &loaded {
            if self.state_mode(*key) == Some(StateMode::Client) && !consumed.contains(key) {
                return bad(
                    "consume".into(),
                    format!(
                        "the client-held key {key} is loaded but not listed (list it, with policy never to leave it untracked)"
                    ),
                );
            }
        }
        Ok(())
    }
}

/// The keys a manifest's witness and outputs use, other than the fixed keys:
/// every key loaded or stored, and every key loaded.
struct UsedKeys {
    used: BTreeSet<KeyRef>,
    loaded: BTreeSet<KeyRef>,
}

/// The INPUT_SHARED rules of the manifest's intake; `reserved` holds the
/// reserved operands its PUBLIC sources use. Intake direct takes INPUT_SHARED
/// app inputs (the sidecar path); the non-secret-shared queued intakes (`onchain`,
/// `receipt`) take none, since a request log carries and a node signs clear
/// inputs only; a secret-shared intake (`shared_receipt`, `shared_onchain`) takes at
/// least one INPUT_SHARED app input or a shared `$partial_note`, exactly one parameter each for
/// `$blinding`, `$outcome_key` and `$outcome_tag` (and, under `outcome:
/// partial`, `$partial_note`), and PUBLIC
/// `$inputs_hash`. A `$` name under INPUT_SHARED is a reserved shared name
/// or refused, under every intake. The inputs commitment `C` covers every
/// app input and every reserved value but `$blinding`, and ends in `$blinding`
/// (docs/ARCHITECTURE.md section 6, "The inputs commitment and the request
/// id"), so a secret-shared-intake round needs all four, and a manifest without a
/// shared value of its own gains nothing from a secret-shared intake. A shared
/// partial note is one: a round whose app inputs are all clear (e.g. lending's
/// view and keeper scan) still hides whose note it completes, and its outcome, behind
/// the secret-shared intake.
fn validate_shared(m: &Manifest, reserved: &BTreeSet<ReservedOperand>) -> Result<(), Refusal> {
    let intake = m.intake.as_str();
    let queued = m.queued_intake();
    let shared = queued.is_some_and(QueuedIntake::shared);
    let mut found = BTreeSet::new();
    let mut app_inputs = 0;
    for (k, entry) in m.witness.iter().enumerate() {
        let Source::InputShared(name) = &entry.from else {
            continue;
        };
        let at = format!("witness[{k}].from.INPUT_SHARED");
        if name.starts_with('$') {
            let Some(r) = SharedReserved::from_name(name) else {
                return bad(
                    at,
                    format!(
                        "`{name}` is not a reserved shared name ($blinding, $outcome_key, $outcome_tag, $partial_note); an app input's name does not start with `$`"
                    ),
                );
            };
            if !shared {
                return bad(
                    at,
                    format!(
                        "`{r}` needs a secret-shared intake (shared_receipt or shared_onchain); this manifest has intake {intake}"
                    ),
                );
            }
            if !found.insert(r) {
                return bad(at, format!("`{r}` fills two parameters"));
            }
        } else if let Some(plain) = queued.filter(|q| !q.shared()) {
            return bad(
                at,
                format!(
                    "{} takes no INPUT_SHARED source; shared inputs take secret-shared receipt intake or secret-shared on-chain intake",
                    plain.name()
                ),
            );
        } else {
            app_inputs += 1;
        }
    }
    if !shared {
        return Ok(());
    }
    if app_inputs == 0 && !found.contains(&SharedReserved::PartialNote) {
        return bad(
            "witness".into(),
            format!(
                "intake {intake} needs at least one INPUT_SHARED app input or a shared `$partial_note`; a manifest whose inputs are all clear and that completes no partial note takes a non-secret-shared intake"
            ),
        );
    }
    let required =
        |r: &SharedReserved| m.outcome() == Outcome::Partial || *r != SharedReserved::PartialNote;
    if let Some(missing) = SharedReserved::ALL
        .into_iter()
        .filter(required)
        .find(|r| !found.contains(r))
    {
        return bad(
            "witness".into(),
            format!("intake {intake}: no parameter takes INPUT_SHARED `{missing}`"),
        );
    }
    if !reserved.contains(&ReservedOperand::InputsHash) {
        return bad(
            "witness".into(),
            format!(
                "intake {intake}: no parameter takes PUBLIC `$inputs_hash` (the inputs commitment C)"
            ),
        );
    }
    Ok(())
}

/// The partial note's rules that need only the manifest: under `outcome:
/// partial`, a non-secret-shared intake fills exactly one parameter with
/// PUBLIC `$partial_note` (the secret-shared intakes' INPUT_SHARED one is
/// [`validate_shared`]'s), and no parameter takes an app input named
/// `recipient` (the partial note names the owner, behind its randomness);
/// under any other outcome no parameter takes a partial note, shared or
/// clear.
fn validate_partial(m: &Manifest) -> Result<(), Refusal> {
    let partial = m.outcome() == Outcome::Partial;
    let form = m.outcome().as_str();
    let shared = m.queued_intake().is_some_and(QueuedIntake::shared);
    let mut clear_partial = 0;
    for (k, entry) in m.witness.iter().enumerate() {
        let (name, at) = match &entry.from {
            Source::InputShared(name) => (name.as_str(), format!("witness[{k}].from.INPUT_SHARED")),
            Source::Public(PublicSource::One(PublicOperand::Name(name))) => {
                (name.as_str(), format!("witness[{k}].from.PUBLIC"))
            }
            Source::Public(PublicSource::One(PublicOperand::Reserved(r))) if r.app_input() => {
                if *r == ReservedOperand::PartialNote {
                    clear_partial += 1;
                }
                (r.as_str(), format!("witness[{k}].from.PUBLIC"))
            }
            _ => continue,
        };
        if name == "$partial_note" && !partial {
            return bad(
                at,
                format!(
                    "`{name}` belongs to `outcome: partial`; this manifest takes `outcome: {form}`"
                ),
            );
        }
        if partial && name == "recipient" {
            return bad(
                at,
                "`recipient` is refused under `outcome: partial`: the request's `$partial_note` names the completed note's owner, behind its randomness".into(),
            );
        }
    }
    if partial && m.queued() && !shared && clear_partial == 0 {
        return bad(
            "witness".into(),
            format!(
                "intake {}: no parameter takes PUBLIC `$partial_note` (`outcome: partial` completes the request's partial note)",
                m.intake.as_str()
            ),
        );
    }
    Ok(())
}

/// Every reserved operand of a witness, in witness order: the entry's index,
/// the entry, the operand, and whether it sits in a PUBLIC list.
pub(super) fn reserved_uses(
    witness: &[WitnessEntry],
) -> impl Iterator<Item = (usize, &WitnessEntry, ReservedOperand, bool)> {
    witness.iter().enumerate().flat_map(|(k, w)| {
        let (operands, in_list): (&[PublicOperand], bool) = match &w.from {
            Source::Public(PublicSource::One(op)) => (std::slice::from_ref(op), false),
            Source::Public(PublicSource::List(ops)) => (ops.as_slice(), true),
            _ => (&[], false),
        };
        operands.iter().filter_map(move |op| match op {
            PublicOperand::Reserved(r) => Some((k, w, *r, in_list)),
            _ => None,
        })
    })
}

pub(super) fn bad<T>(field: String, why: String) -> Result<T, Refusal> {
    Err(Refusal::bad_request(format!("field `{field}`: {why}")))
}

/// Whether a request key reference lies within the declared key counts.
pub(super) fn in_range(state_keys: KeyCounts, key: KeyRef) -> Result<(), String> {
    match key {
        KeyRef::Read(i) if i >= state_keys.reads => Err(format!(
            "{key} is out of range: the manifest declares {} read key(s)",
            state_keys.reads
        )),
        KeyRef::Write(j) if j >= state_keys.writes => Err(format!(
            "{key} is out of range: the manifest declares {} write key(s)",
            state_keys.writes
        )),
        _ => Ok(()),
    }
}

/// The checks of the fields every manifest has for one round, whatever its
/// intake: the circuit name, the witness entries and their sources, the
/// namespace parameter and the outputs. Returns the keys they use.
fn validate_round(m: &Manifest) -> Result<UsedKeys, Refusal> {
    let (circuit, namespace_param, state_keys) =
        (&m.circuit, m.namespace_param.as_str(), m.state_keys);
    let (witness, outputs) = (&m.witness, &m.outputs);
    // The circuit and every INPUT_SHARED name reach an envelope's
    // associated data through poseidon2_hash_bytes.
    check_name("circuit", "circuit name", circuit)?;

    // Witness entries: one per parameter, each source well formed.
    let mut params = BTreeSet::new();
    let mut shared_names = BTreeSet::new();
    let mut load_lens: BTreeMap<KeyRef, usize> = BTreeMap::new();
    let mut used_keys: BTreeSet<KeyRef> = BTreeSet::new();
    let mut loaded_keys: BTreeSet<KeyRef> = BTreeSet::new();
    let mut namespace_bound = false;
    for (k, entry) in witness.iter().enumerate() {
        let at = format!("witness[{k}]");
        if entry.param.is_empty() {
            return bad(format!("{at}.param"), "empty parameter name".into());
        }
        if !params.insert(entry.param.as_str()) {
            return bad(
                format!("{at}.param"),
                format!("`{}` is listed twice", entry.param),
            );
        }
        match &entry.from {
            Source::Public(p) => {
                for op in p.operands() {
                    if let PublicOperand::Key(key) = op {
                        in_range(state_keys, *key)
                            .or_else(|e| bad(format!("{at}.from.PUBLIC"), e))?;
                    }
                }
                if entry.param == namespace_param {
                    namespace_bound = matches!(p, PublicSource::One(PublicOperand::Namespace));
                }
            }
            Source::Sample(n) => {
                if *n == 0 {
                    return bad(
                        format!("{at}.from.SAMPLE"),
                        "SAMPLE draws at least 1 element".into(),
                    );
                }
            }
            Source::Load(load) => {
                let field = format!("{at}.from");
                in_range(state_keys, load.key).or_else(|e| bad(format!("{field}.LOAD"), e))?;
                if let KeyRef::Write(_) = load.key {
                    return bad(
                        format!("{field}.LOAD"),
                        "LOAD reads a $state_keys.reads[i] key; $state_keys.writes[j] names a key to store"
                            .into(),
                    );
                }
                if load.len == 0 {
                    return bad(
                        format!("{field}.len"),
                        "a stored length is at least 1".into(),
                    );
                }
                let [a, b] = load.slice;
                if a >= b || b > load.len {
                    return bad(
                        format!("{field}.slice"),
                        format!(
                            "[{a}, {b}] is not a non-empty slice of a length-{} value",
                            load.len
                        ),
                    );
                }
                if let KeyRef::Fixed(fixed) = load.key
                    && load.len != fixed.stored_len()
                {
                    return bad(
                        format!("{field}.len"),
                        format!(
                            "the fixed key {} has length {}",
                            fixed.name(),
                            fixed.stored_len()
                        ),
                    );
                }
                // Slices of one key share one read, so they must agree on its length.
                if let Some(len) = load_lens.insert(load.key, load.len)
                    && len != load.len
                {
                    return bad(
                        format!("{field}.len"),
                        format!("{} is loaded with lengths {len} and {}", load.key, load.len),
                    );
                }
                if !load.key.is_fixed() {
                    used_keys.insert(load.key);
                    loaded_keys.insert(load.key);
                }
            }
            Source::InputShared(name) => {
                check_name(&format!("{at}.from.INPUT_SHARED"), "input name", name)?;
                if !shared_names.insert(name.as_str()) {
                    return bad(
                        format!("{at}.from.INPUT_SHARED"),
                        format!("`{name}` fills two parameters"),
                    );
                }
            }
        }
    }
    if namespace_param.is_empty() || !params.contains(namespace_param) {
        return bad(
            "namespace_param".into(),
            format!("`{}` is not a witness parameter", namespace_param),
        );
    }
    if !namespace_bound {
        return bad(
            "namespace_param".into(),
            format!(
                "`{}` must be filled by PUBLIC \"$namespace\"",
                namespace_param
            ),
        );
    }

    // Outputs: each stored once, under a write key.
    let mut taceo_names = BTreeSet::new();
    let mut stored = BTreeSet::new();
    for (k, out) in outputs.iter().enumerate() {
        let at = format!("outputs[{k}]");
        if out.taceo_store.is_empty() || !taceo_names.insert(out.taceo_store.as_str()) {
            return bad(
                format!("{at}.TACEO_store"),
                format!("`{}` is empty or listed twice", out.taceo_store),
            );
        }
        if !matches!(out.store, KeyRef::Write(_)) {
            return bad(
                format!("{at}.STORE"),
                format!("{} is not a $state_keys.writes[j] key", out.store),
            );
        }
        in_range(state_keys, out.store).or_else(|e| bad(format!("{at}.STORE"), e))?;
        if !stored.insert(out.store) {
            return bad(
                format!("{at}.STORE"),
                format!("{} is stored twice", out.store),
            );
        }
        if out.len == 0 {
            return bad(format!("{at}.len"), "a stored length is at least 1".into());
        }
        if out.note_hash.is_empty() {
            return bad(format!("{at}.note_hash"), "empty output name".into());
        }
        used_keys.insert(out.store);
    }
    Ok(UsedKeys {
        used: used_keys,
        loaded: loaded_keys,
    })
}
