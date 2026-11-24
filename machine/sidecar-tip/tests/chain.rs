//! The chain reader against a local Aztec 6.0.0 network, behind
//! `PSS_TIP_NODE_URL` (skipped, with a SKIPPED line, when it is unset).
//! tests/chain/run.sh starts a network, runs this test and stops it:
//!
//! ```sh
//! machine/sidecar-tip/tests/chain/run.sh
//! # or, against a network already up:
//! PSS_TIP_NODE_URL=http://127.0.0.1:10280 cargo test --release -p sidecar-tip --test chain -- --nocapture
//! ```
//!
//! The test runs tests/chain/setup.ts, which compiles and deploys
//! `noir/pss_public_contract_test` and enqueues seven requests
//! through it (three through its on-chain intake, which emits the request
//! log), then reads the queue, the commitment slot, two pinned reads and the
//! logs through the node's RPC and compares them with what the contract's
//! own view functions and setup.ts report. setup.ts calls no apply, so no
//! sealed-thirds log exists on this network: the test checks that the read
//! answers none, and the sealed-thirds log and the emitter filter are
//! covered by the recorded fixtures (the tests of src/chain/mod.rs);
//! `tests/chain/run.sh --record` re-records tests/fixtures/logs.json.

use std::process::Command;

use serde_json::Value;
use sidecar_core::Fr;
use sidecar_core::field::{fr_from_hex, fr_to_hex};
use sidecar_core::manifest::{KeyRef, PublicRead};
use sidecar_tip::intake::onchain::request_log;
use sidecar_tip::{ChainAt, ChainReader, HttpTransport, QueueLayout, QueueTarget};

fn f(v: &Value) -> Fr {
    fr_from_hex(v.as_str().unwrap()).unwrap()
}

#[tokio::test]
async fn reads_the_queue_a_local_network_holds() {
    let Ok(url) = std::env::var("PSS_TIP_NODE_URL") else {
        println!(
            "SKIPPED: PSS_TIP_NODE_URL is not set (tests/chain/run.sh starts a local network and sets it)"
        );
        return;
    };
    let repo = sidecar_test_fixtures::dirs::repo();
    let setup = Command::new("bash")
        .arg("-c")
        .arg("source scripts/toolchain.sh && exec node --import ./ts/hooks/register.mjs machine/sidecar-tip/tests/chain/setup.ts")
        .current_dir(&repo)
        .env("AZTEC_NODE_URL", &url)
        .output()
        .expect("running tests/chain/setup.ts");
    assert!(
        setup.status.success(),
        "setup.ts failed: {}",
        String::from_utf8_lossy(&setup.stderr)
    );
    let stdout = String::from_utf8(setup.stdout).unwrap();
    let wrote: Value = serde_json::from_str(stdout.lines().last().unwrap()).unwrap();
    println!("WROTE: {wrote}");

    let contract = f(&wrote["contract"]);
    let ids: Vec<Fr> = wrote["request_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(f)
        .collect();
    let reader = ChainReader::new(HttpTransport::new(&url).unwrap());
    let snap = reader.snapshot().await.unwrap();
    assert!(snap.block >= wrote["tip"].as_u64().unwrap());

    // PssPublicTest's queue and pool slots, from its compiled storage layout
    let (queue_slot, pool_slot) = (f(&wrote["slots"]["queue"]), f(&wrote["slots"]["pool"]));
    let target = QueueTarget {
        contract,
        layout: QueueLayout::new(queue_slot),
    };
    let queue = reader.queue(snap, &target).await.unwrap();
    assert_eq!(queue.head, wrote["head"]["index"].as_u64().unwrap());
    assert_eq!(queue.head_since, wrote["head"]["since"].as_u64().unwrap());
    assert_eq!(queue.tail, wrote["tail"].as_u64().unwrap());
    assert_eq!(
        queue.head_since,
        wrote["blocks"][0].as_u64().unwrap(),
        "the first append restarted the clock"
    );
    let window: Vec<Fr> = queue.window.iter().map(|e| e.chain_request_id).collect();
    assert_eq!(window, ids[..5], "the head and four entries after it");
    assert_eq!(reader.done(snap, &target, 0).await.unwrap(), 0);

    let slots = reader
        .slots(snap, contract, &[(KeyRef::Read(0), pool_slot)])
        .await
        .unwrap();
    assert_eq!(slots[0].commitment, f(&wrote["pool"]));

    // a pinned read by simulation, and the same getter from its backing slot
    let tail_read = PublicRead {
        contract: contract.into(),
        function: "get_tail".into(),
        args: vec![],
        param: "tail".into(),
        freshness: sidecar_core::manifest::Freshness::Exact,
        epoch_param: None,
        band: None,
    };
    let mut simulated = reader.simulate(snap, contract, &tail_read).await;
    if let Err(sidecar_tip::ReadError::SnapshotMoved { .. }) = simulated {
        // a block landed between the snapshot and the call; once more
        let snap = reader.snapshot().await.unwrap();
        simulated = reader.simulate(snap, contract, &tail_read).await;
    }
    let simulated = simulated.unwrap();
    assert_eq!(simulated.values, [Fr::from(queue.tail)]);
    let stored = reader
        .pinned_storage(snap, contract, &tail_read, target.layout.tail())
        .await
        .unwrap();
    assert_eq!(stored.values, simulated.values);
    let second = PublicRead {
        contract: contract.into(),
        function: "request_at(u64)".into(),
        args: vec![Fr::from(1u64).into()],
        param: "second".into(),
        freshness: sidecar_core::manifest::Freshness::Exact,
        epoch_param: None,
        band: None,
    };
    let snap2 = reader.snapshot().await.unwrap();
    let second = reader.simulate(snap2, contract, &second).await.unwrap();
    assert_eq!(second.values, [ids[1]]);

    // the on-chain request logs, whose content recomputes the queued ids
    let at = ChainAt {
        reader: &reader,
        snap,
        namespace: contract,
        layout: Default::default(),
    };
    let vk_hash = f(&wrote["vk_hash"]);
    let mut logged = Vec::new();
    for (i, onchain) in wrote["onchain"].as_array().unwrap().iter().enumerate() {
        let log = request_log(&at, ids[i])
            .await
            .unwrap()
            .expect("a request log");
        let plain = log.plain().unwrap();
        let inputs: Vec<Fr> = onchain["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(f)
            .collect();
        assert_eq!(plain.inputs, inputs);
        assert_eq!(plain.user_nonce, f(&onchain["user_nonce"]));
        assert_eq!(log.log.block, wrote["blocks"][i].as_u64().unwrap());
        assert_eq!(
            sidecar_tip::chain_request_id(contract, vk_hash, plain.inputs, plain.user_nonce),
            ids[i]
        );
        logged.push(format!(
            "{} = inputs {:?}, nonce {} (block {})",
            fr_to_hex(ids[i]),
            inputs.iter().map(|v| fr_to_hex(*v)).collect::<Vec<_>>(),
            fr_to_hex(plain.user_nonce),
            log.log.block
        ));
    }
    // an id appended without intake has no log; setup.ts calls no apply, so
    // no sealed thirds
    assert_eq!(request_log(&at, ids[3]).await.unwrap(), None);
    let sealed_tag = sidecar_tip::state::chain::sealed_log_tag(ids[0]);
    let sealed = reader.logs(snap, contract, sealed_tag).await.unwrap();
    assert_eq!(sidecar_tip::SealedState::latest(ids[0], sealed), None);

    println!(
        "READ at block {}: head {} since {} tail {}; window {:?}; pool slot {}; get_tail() simulated {} (block {}), tail slot {}; request_at(1) simulated {}; request logs {:?}; sealed-thirds log none",
        snap.block,
        queue.head,
        queue.head_since,
        queue.tail,
        window.iter().map(|v| fr_to_hex(*v)).collect::<Vec<_>>(),
        fr_to_hex(slots[0].commitment),
        fr_to_hex(simulated.values[0]),
        simulated.block,
        fr_to_hex(stored.values[0]),
        fr_to_hex(second.values[0]),
        logged,
    );
}
