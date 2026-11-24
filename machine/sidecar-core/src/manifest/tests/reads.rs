//! Pinned read tests: freshness policies, bands and what each admits.

use crate::field::Fr;

use super::*;

// A pinned read of amm_swap_tip's `amount_in` under `policy`'s fields.
fn read_with(policy: Value) -> Value {
    let one = format!("0x{:064x}", 1);
    let mut read = json!({"contract": one, "function": "get_price", "args": [],
                          "param": "amount_in"});
    for (k, v) in policy.as_object().unwrap() {
        read[k] = v.clone();
    }
    read
}

#[test]
fn a_pinned_read_names_its_freshness_policy() {
    // exact by default, and left out when re-serialised
    let mut v = amm_swap_tip();
    v["public_reads"] = json!([read_with(json!({}))]);
    let m = parse(&v).unwrap();
    assert_eq!(m.public_reads[0].freshness, Freshness::Exact);
    assert_eq!(
        m.public_reads[0].params().collect::<Vec<_>>(),
        ["amount_in"]
    );
    assert!(
        serde_json::to_value(&m).unwrap()["public_reads"][0]
            .get("freshness")
            .is_none()
    );
    v["public_reads"] = json!([read_with(json!({"freshness": "exact"}))]);
    assert_eq!(parse(&v).unwrap(), m);

    // epoch: the value and its epoch fill two public names
    let epoch = read_with(json!({"freshness": "epoch", "epoch_param": "direction"}));
    v["public_reads"] = json!([epoch]);
    let m = parse(&v).unwrap();
    let read = &m.public_reads[0];
    assert_eq!(read.freshness, Freshness::Epoch);
    assert_eq!(
        read.params().collect::<Vec<_>>(),
        ["amount_in", "direction"]
    );
    assert_eq!(read.returns(1), 3);
    let again = serde_json::to_value(&m).unwrap();
    assert_eq!(again["public_reads"][0], epoch);
    assert_eq!(Manifest::parse(&again).unwrap(), m);

    // tolerance, absolute (a decimal u128) or relative
    for band in [
        json!({"absolute": "340282366920938463463374607431768211455"}),
        json!({"relative_bps": 50}),
    ] {
        let read = read_with(json!({"freshness": "tolerance", "band": band}));
        v["public_reads"] = json!([read]);
        let m = parse(&v).unwrap();
        assert_eq!(m.public_reads[0].freshness, Freshness::Tolerance);
        assert_eq!(serde_json::to_value(&m).unwrap()["public_reads"][0], read);
    }
}

#[test]
fn a_pinned_read_refuses_an_unknown_policy_and_a_missing_or_stray_field() {
    let cases: Vec<(Value, &str)> = vec![
        (
            json!({"freshness": "fresh"}),
            "field `public_reads[0].freshness`: unknown variant `fresh`",
        ),
        (
            json!({"freshness": "tolerance"}),
            "field `public_reads[0].band`: missing: a tolerance read needs a band",
        ),
        (
            json!({"freshness": "epoch"}),
            "field `public_reads[0].epoch_param`: missing: an epoch read names",
        ),
        (
            json!({"epoch_param": "direction"}),
            "field `public_reads[0].epoch_param`: only under freshness epoch, not exact",
        ),
        (
            json!({"freshness": "tolerance", "band": {"relative_bps": 5}, "epoch_param": "direction"}),
            "field `public_reads[0].epoch_param`: only under freshness epoch, not tolerance",
        ),
        (
            json!({"band": {"absolute": "1"}}),
            "field `public_reads[0].band`: only under freshness tolerance, not exact",
        ),
        (
            json!({"freshness": "epoch", "epoch_param": "direction", "band": {"absolute": "1"}}),
            "field `public_reads[0].band`: only under freshness tolerance, not epoch",
        ),
        (
            json!({"freshness": "tolerance", "band": {}}),
            "field `public_reads[0].band`",
        ),
        (
            json!({"freshness": "tolerance", "band": {"absolute": "1", "relative_bps": 1}}),
            "field `public_reads[0].band`",
        ),
        (
            json!({"freshness": "tolerance", "band": {"percent": 1}}),
            "field `public_reads[0].band`: unknown variant `percent`",
        ),
        (
            json!({"freshness": "tolerance", "band": {"absolute": 100}}),
            "field `public_reads[0].band.absolute`",
        ),
        (
            json!({"freshness": "tolerance", "band": {"absolute": "0x64"}}),
            "`0x64` is not a decimal integer",
        ),
        (
            json!({"freshness": "tolerance", "band": {"absolute": "340282366920938463463374607431768211456"}}),
            "does not fit 128 bits",
        ),
        (
            json!({"freshness": "tolerance", "band": {"absolute": "0"}}),
            "field `public_reads[0].band.absolute`: 0 is no band; use freshness exact",
        ),
        (
            json!({"freshness": "tolerance", "band": {"relative_bps": 0}}),
            "field `public_reads[0].band.relative_bps`: 0 is outside 1 ..= 10000 basis points",
        ),
        (
            json!({"freshness": "tolerance", "band": {"relative_bps": 10001}}),
            "field `public_reads[0].band.relative_bps`: 10001 is outside 1 ..= 10000",
        ),
        (
            json!({"freshness": "epoch", "epoch_param": "epoch"}),
            "field `public_reads[0].epoch_param`: `epoch` is not a witness parameter",
        ),
        (
            json!({"freshness": "epoch", "epoch_param": "namespace"}),
            "field `public_reads[0].epoch_param`: `namespace` is the namespace parameter",
        ),
        (
            json!({"freshness": "epoch", "epoch_param": "amount_in"}),
            "field `public_reads[0].epoch_param`: `amount_in` is filled by two reads",
        ),
        (
            json!({"freshness": "epoch", "epoch_param": "pool"}),
            "field `public_reads[0].epoch_param`: `pool` (witness[9]) must be filled by PUBLIC",
        ),
    ];
    for (policy, needle) in cases {
        let mut v = amm_swap_tip();
        v["public_reads"] = json!([read_with(policy)]);
        refused(v, needle);
    }
    // two reads may not share an epoch parameter
    let mut v = amm_swap_tip();
    let a = read_with(json!({"freshness": "epoch", "epoch_param": "direction"}));
    let mut b = read_with(json!({"freshness": "epoch", "epoch_param": "direction"}));
    b["param"] = json!("min_out");
    v["public_reads"] = json!([a, b]);
    refused(
        v,
        "field `public_reads[1].epoch_param`: `direction` is filled by two reads",
    );
}

#[test]
fn each_freshness_policy_admits_what_apply_accepts() {
    let f = |n: u64| Fr::from(n);
    let read = |policy: Value| -> PublicRead { serde_json::from_value(read_with(policy)).unwrap() };
    // exact: the value itself only
    let exact = read(json!({}));
    assert!(exact.admits(&[f(7)], None, &[f(7)]));
    assert!(!exact.admits(&[f(7)], None, &[f(8)]));

    // epoch: the current epoch with its value, or the one before with
    // the previous value; never two behind, never a wrong value
    let epoch = read(json!({"freshness": "epoch", "epoch_param": "direction"}));
    let now = [f(9), f(5)];
    assert!(epoch.admits(&now, Some(f(7)), &[f(9), f(5)]));
    assert!(epoch.admits(&now, Some(f(7)), &[f(7), f(4)]));
    assert!(!epoch.admits(&now, Some(f(7)), &[f(7), f(3)]), "two behind");
    assert!(
        !epoch.admits(&now, Some(f(7)), &[f(8), f(4)]),
        "not the previous value"
    );
    assert!(
        !epoch.admits(&now, Some(f(7)), &[f(7), f(5)]),
        "not the current value"
    );
    assert!(
        !epoch.admits(&now, Some(f(7)), &[f(9), f(6)]),
        "an epoch ahead"
    );
    // both epochs below 2^64, compared as integers: an epoch of p - 1 is not
    // the one before 0, and the current values at an epoch past 2^64 do not
    // land either
    let p_minus_1 = -f(1);
    assert!(!epoch.admits(&[f(9), f(0)], Some(f(7)), &[f(7), p_minus_1]));
    let wide = f(u64::MAX) + f(1);
    assert!(!epoch.admits(&[f(9), wide], Some(f(7)), &[f(9), wide]));
    assert!(!epoch.admits(&[f(9), wide], Some(f(7)), &[f(7), f(u64::MAX)]));
    assert!(epoch.admits(&[f(9), f(u64::MAX)], Some(f(7)), &[f(7), f(u64::MAX - 1)]));

    // tolerance: within the band of the current value, both below 2^128
    let absolute = read(json!({"freshness": "tolerance", "band": {"absolute": "10"}}));
    assert!(absolute.admits(&[f(100)], None, &[f(90)]));
    assert!(absolute.admits(&[f(100)], None, &[f(110)]));
    assert!(!absolute.admits(&[f(100)], None, &[f(111)]));
    assert!(!absolute.admits(&[f(100)], None, &[f(89)]));
    let relative = read(json!({"freshness": "tolerance", "band": {"relative_bps": 50}}));
    // 0.5% of 10,000 is 50
    assert!(relative.admits(&[f(10_000)], None, &[f(10_050)]));
    assert!(relative.admits(&[f(10_000)], None, &[f(9_950)]));
    assert!(!relative.admits(&[f(10_000)], None, &[f(10_051)]));
    assert!(!relative.admits(&[f(0)], None, &[f(1)]));
    // near 2^128, where diff * 10000 needs more than 128 bits
    let top = Fr::from(u128::MAX);
    let off = Fr::from(u128::MAX - u128::MAX / 200);
    assert!(relative.admits(&[top], None, &[off]));
    assert!(!relative.admits(&[top], None, &[off - Fr::from(1u64 << 40)]));
    // a value of 2^128 or more is no number for a band, even unmoved
    // (apply reverts on it)
    let wide = Fr::from(u128::MAX) + Fr::from(1u64);
    assert!(!absolute.admits(&[wide], None, &[wide - f(1)]));
    assert!(!absolute.admits(&[wide], None, &[wide]));
    assert!(absolute.admits(&[top], None, &[top]));
}

// A read of the namespace's own contract is `$self`: the machine reads it at
// the namespace, and the address written out is refused.
#[test]
fn a_read_of_the_namespace_itself_is_written_self() {
    let mut v = amm_swap_tip();
    v["public_reads"] = json!([read_with(json!({}))]);
    v["public_reads"][0]["contract"] = json!("$self");
    let m = parse(&v).unwrap();
    assert_eq!(m.public_reads[0].contract, ReadContract::Own);
    assert_eq!(
        m.public_reads[0].contract.address(Fr::from(7u64)),
        Fr::from(7u64)
    );
    assert_eq!(
        serde_json::to_value(&m).unwrap()["public_reads"][0]["contract"],
        "$self"
    );
    refuse_own_address(&m, Fr::from(7u64)).unwrap();

    v["public_reads"][0]["contract"] = json!("0x7");
    let m = parse(&v).unwrap();
    assert_eq!(
        m.public_reads[0].contract.address(Fr::from(9u64)),
        Fr::from(7u64)
    );
    let err = refuse_own_address(&m, Fr::from(7u64)).unwrap_err();
    assert_eq!(
        err.message,
        "field `public_reads[0].contract`: the namespace's own address; a read of the \
         namespace's own contract is written `$self`"
    );
    v["public_reads"][0]["contract"] = json!("self");
    let err = parse(&v).unwrap_err();
    assert!(
        err.message.contains("field `public_reads[0].contract`"),
        "{err}"
    );
}
