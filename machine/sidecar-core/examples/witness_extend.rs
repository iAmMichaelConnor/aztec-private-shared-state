//! A co-noir three-party (REP3) witness extension of one fixture of a
//! compiled circuit, checked against the witness nargo solved for it: the
//! inputs come from the fixture's Prover.toml, the parameters named
//! `--shared` are secret-shared by a dealer in this process and the rest
//! are public, and three parties on mpc_net's in-process network run
//! `co_noir::execute_circuit_rep3`, the call the nodes' executor makes
//! before it proves. The opened witness must equal nargo's, element by
//! element. No proving key and no proof: it checks only that co-noir's MPC
//! solver (its Brillig VM included) runs the circuit and gets nargo's values.
//!
//! ```text
//! witness_extend <circuit.json> <Prover.toml> <nargo witness.gz> [--shared a,b,c]
//! ```
//!
//! scripts/witness-extend.sh runs it on every fixture of an example's round
//! circuits, with `--shared` the parameters the round's manifest fills from
//! the nodes (LOAD, SAMPLE, INPUT_SHARED): the split the network makes. The
//! dealer stands in for the nodes' LOAD and SAMPLE; it is a test harness,
//! never a way to run a round on secret data.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use co_noir_types::{PubPrivate, Rep3Type};
use eyre::{Context, ensure, eyre};
use mpc_net::local::LocalNetwork;
use noirc_abi::MAIN_RETURN_NAME;
use noirc_abi::input_parser::Format;
use sidecar_core::crs::Artifact;
use sidecar_core::field::{Fr, fr_to_hex};

/// The fixture's inputs under co-noir's witness keys (`name`, or `name[i]`
/// for a parameter wider than one field), public or private.
fn inputs(
    artifact: &Artifact,
    toml: &str,
    shared: &BTreeSet<String>,
) -> eyre::Result<BTreeMap<String, PubPrivate<Fr>>> {
    let abi = &artifact.program.abi;
    let mut parsed = Format::Toml
        .parse(toml, abi)
        .map_err(|e| eyre!("parsing the fixture: {e}"))?;
    parsed.remove(MAIN_RETURN_NAME);
    let encoded = abi
        .encode(&parsed, None)
        .map_err(|e| eyre!("encoding the fixture: {e}"))?;
    let mut values = encoded.into_iter().map(|(_, v)| v.into_repr());
    let mut out = BTreeMap::new();
    for param in &abi.parameters {
        let n = param.typ.field_count();
        let private = shared.contains(&param.name);
        for i in 0..n {
            let key = if n == 1 {
                param.name.clone()
            } else {
                format!("{}[{i}]", param.name)
            };
            let v = values
                .next()
                .ok_or_else(|| eyre!("the encoded fixture ends before `{key}`"))?;
            out.insert(
                key,
                if private {
                    PubPrivate::Private(v)
                } else {
                    PubPrivate::Public(v)
                },
            );
        }
    }
    ensure!(
        values.next().is_none(),
        "the encoded fixture has more fields than the ABI's parameters"
    );
    Ok(out)
}

/// One witness element opened from the three parties' copies.
fn open(i: usize, parts: [&Rep3Type<Fr>; 3]) -> eyre::Result<Fr> {
    match parts {
        [
            Rep3Type::Public(a),
            Rep3Type::Public(b),
            Rep3Type::Public(c),
        ] => {
            ensure!(
                a == b && b == c,
                "witness {i}: a public value differs between parties"
            );
            Ok(*a)
        }
        [
            Rep3Type::Shared(s0),
            Rep3Type::Shared(s1),
            Rep3Type::Shared(s2),
        ] => {
            ensure!(
                s1.b == s0.a && s2.b == s1.a && s0.b == s2.a,
                "witness {i}: inconsistent replicated shares"
            );
            Ok(s0.a + s1.a + s2.a)
        }
        _ => Err(eyre!(
            "witness {i}: the parties disagree on whether it is shared"
        )),
    }
}

fn main() -> eyre::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: witness_extend <circuit.json> <Prover.toml> <witness.gz> [--shared a,b,c]";
    let shared: BTreeSet<String> = match args.len() {
        3 => BTreeSet::new(),
        5 if args[3] == "--shared" => args[4]
            .split(',')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
        _ => return Err(eyre!("{usage}")),
    };
    let artifact = Artifact::read(Path::new(&args[0]))?;
    for name in &shared {
        ensure!(
            artifact
                .program
                .abi
                .parameters
                .iter()
                .any(|p| &p.name == name),
            "`--shared {name}`: `{}` has no such parameter",
            artifact.name
        );
    }
    let toml = std::fs::read_to_string(&args[1]).with_context(|| format!("reading {}", args[1]))?;
    let plain = co_noir::witness_from_reader(
        std::fs::File::open(&args[2]).with_context(|| format!("reading {}", args[2]))?,
    )
    .with_context(|| format!("decoding nargo's witness {}", args[2]))?;
    let shares = co_noir::split_input_rep3(inputs(&artifact, &toml, &shared)?);

    let results: Vec<eyre::Result<Vec<Rep3Type<Fr>>>> = std::thread::scope(|s| {
        let handles: Vec<_> = LocalNetwork::new_3_parties()
            .into_iter()
            .zip(shares)
            .map(|(net, input)| {
                let program = artifact.program.clone();
                s.spawn(move || {
                    co_noir::execute_circuit_rep3(input, program, &net).map(|(witness, _)| witness)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("a party thread panicked"))
            .collect()
    });
    let parties: Vec<Vec<Rep3Type<Fr>>> = results
        .into_iter()
        .enumerate()
        .map(|(i, r)| r.map_err(|e| eyre!("party {i}: witness extension failed: {e:#}")))
        .collect::<eyre::Result<_>>()?;
    ensure!(
        parties[0].len() == parties[1].len() && parties[1].len() == parties[2].len(),
        "the parties' witnesses differ in length"
    );
    ensure!(
        parties[0].len() == plain.len(),
        "the extended witness has {} elements, nargo's {}",
        parties[0].len(),
        plain.len()
    );
    let mut shared_out = 0;
    for (i, want) in plain.iter().enumerate() {
        let parts = [&parties[0][i], &parties[1][i], &parties[2][i]];
        shared_out += usize::from(matches!(parts[0], Rep3Type::Shared(_)));
        let got = open(i, parts)?;
        ensure!(
            got == *want,
            "witness {i}: the parties' value opens to {}, nargo's is {}",
            fr_to_hex(got),
            fr_to_hex(*want)
        );
    }
    println!(
        "{}: the three parties' witness opens to nargo's ({} elements, {} of them shared; {} parameters dealt as shares)",
        artifact.name,
        plain.len(),
        shared_out,
        shared.len()
    );
    Ok(())
}
