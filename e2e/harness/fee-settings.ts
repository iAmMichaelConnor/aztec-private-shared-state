// The tip examples' fee settings: what a tip run's transactions of each
// example pay under (pss-client fee.ts is the mechanism: FeeSetting,
// feeOptions, wFJ).
//
// One setting per app and transaction kind, fixed from the gas the kind's
// transactions used in the tip e2e (e2e/scenarios/README.md, "Gas per
// transaction kind": every deployment of the app, every round type and
// outcome; Aztec 6.0.0, whose AVM gas schedule the numbers depend on). Each
// limit is the kind's largest measurement plus 25%, rounded up to the next
// 50,000 L2 gas and 500 DA gas. The headroom covers the gas that follows
// chain state rather than the round type (a request queued behind another
// writes to slots already set and uses about 66,000 L2 gas less; a contract's
// first deployment publishes its class; a token transfer spends more or
// fewer of the sender's notes), never a hidden round type: under
// secret-shared receipt intake every round type's request and result used
// the same gas (lending draws a request's escrow and usage deposit from the
// sender's credit note). What it costs: wFJ charges the limit at the declared max fee per gas
// in full, so a transaction pays at most 25% over its gas used beyond the
// max fee's own padding. A kind's limit must cover its largest case, so a
// kind whose cases differ (a non-secret-shared result that fails writes less) declares
// one limit for all of them. An app with other contracts or circuits
// measures its own (e2e/engine/gas.ts records every transaction's gas).

import { DEFAULT_FEE_SETTING, type FeeSetting } from "@aztec-pss/pss-client";

const gas = (daGas: number, l2Gas: number) => ({ gasLimits: { daGas, l2Gas } });

/** examples/amm-tip (AmmTip). Measured maxima, DA / L2: deploy 33,376 /
 * 1,539,937 (AmmTip's first deployment, which publishes its class; a later
 * one 2,496 / 1,436,137), configure 2,144 / 1,476,933 (a key-set rotation,
 * `rotate_keys`, which writes the whole key epoch; a deployment's configure
 * 1,792 / 1,238,639), request 1,696 / 949,311 (a secret-shared on-chain swap;
 * a secret-shared swap or a swap under receipt intake 1,088 / 926,801; a
 * non-secret-shared on-chain request 1,344 / 897,027), result 1,568 / 886,201
 * (L2: a non-secret-shared filled swap, DA 1,248; DA: a secret-shared swap,
 * 884,054 L2, filled or failed; the init round 800 / 752,050), skip 928 /
 * 766,186. No redeem kind: the trader's completed note
 * lands with the result, and the example's `redeem` moves no token. */
// The key epochs (pss_public_contract `key_epoch`) add one enqueued public
// call (`assert_key_epoch`) to every transaction that verifies node
// signatures (a result, a request under receipt intake), and the class guard
// one (`assert_upgrade_class`) to every round transaction; the figures above
// include both.
export const AMM_TIP_FEE_SETTING: FeeSetting = {
  method: "wfj",
  gas: {
    deploy: gas(42_000, 1_950_000),
    configure: gas(3_000, 1_850_000),
    request: gas(2_500, 1_250_000),
    result: gas(2_000, 1_200_000),
    skip: gas(1_500, 1_000_000),
  },
};

/** examples/lending-tip (LendingTip, LendingTipOblivious, their two tokens and
 * LendingOracle), measured under ownership by note, partial-note delivery and
 * the standing delivery handle. Maxima, DA / L2: deploy 42,400 / 2,431,205
 * (LendingTip's first deployment, which publishes its class; a later one
 * 4,000 / 2,308,625; LendingTipOblivious's first 34,912 / 2,431,124; a
 * token's first 17,792 / 1,393,008, the oracle's first 7,296 / 1,295,791, the
 * harness's mints under this kind 3,168 / 1,081,562), configure 2,944 /
 * 1,886,312, request 4,480 / 1,131,835 (L2: a deposit under secret-shared
 * on-chain intake, DA 3,648; DA: a credit funding, `fund`, 1,074,407 L2; every
 * secret-shared round type and a deposit under receipt intake 3,040 /
 * 1,107,582, each drawing its escrow and usage deposit from the sender's
 * credit note; on the oblivious tree 3,040 / 1,106,829; a non-secret-shared
 * on-chain deposit 3,264 / 1,079,452), result 2,304 / 1,041,973 (every
 * secret-shared round type, the delivery handle's note hash and log
 * included; a non-secret-shared deposit, its note completed in public, 1,536
 * / 993,903; on the oblivious tree 2,304 / 1,038,352; the init round 800 /
 * 746,630), redeem 1,408 / 511,400 (every round type's note, credited
 * privately), exit 1,440 / 527,400 (a borrower's note, which also spends the
 * credit note its repayment draws on: one nullifier more, 16,000 L2 and 32 DA
 * gas) and 1,408 / 511,400 (a lender's): a private-only transaction with a
 * redeem's effects (its note read and its historical read of the hatch's slot
 * are proving work, which costs no gas). Skip: not measured (the lending e2e
 * skips no head): the AMM's library `skip()` used 928 / 766,186, and a
 * lending skip adds two token payouts (a payout measured about 78,000 L2 of
 * AVM each) and the holdings write, so its limit is an estimate. The
 * transactions the e2e sends under the request kind outside a round:
 * `withdraw_funds` 2,176 / 849,219, `open_hatch` 800 / 701,643, the
 * treasury's `sweep_deposits` 928 / 814,387, a node's `rotate_enc_key` 928 /
 * 782,127, the oblivious deployment's `poke` 800 / 686,568 and the oracle's
 * `set_price` 992 / 791,862. */
export const LENDING_TIP_FEE_SETTING: FeeSetting = {
  method: "wfj",
  gas: {
    // DA: 42,400 plus 25% is 53,000, under the network's per-transaction
    // maximum (55,836 DA gas, which the wallet refuses to exceed)
    deploy: gas(55_000, 3_050_000),
    configure: gas(4_000, 2_500_000),
    request: gas(6_000, 1_500_000),
    result: gas(3_500, 1_400_000),
    redeem: gas(2_000, 650_000),
    exit: gas(2_000, 700_000),
    skip: gas(3_000, 1_300_000),
  },
};

/** The apps' fee settings, by the name a deployment file's `fee` gives
 * (e2e/tip/<deployment>.json). */
export const TIP_FEE_SETTINGS: Readonly<Record<string, FeeSetting>> = { "amm-tip": AMM_TIP_FEE_SETTING, "lending-tip": LENDING_TIP_FEE_SETTING };

/** The fee setting named `name` (a deployment's `fee`: the app's fixed gas
 * per transaction kind), or with no name pss-client's DEFAULT_FEE_SETTING
 * (wFJ, each transaction declaring the wallet's estimate). */
export function tipFeeSetting(name: string | undefined): FeeSetting {
  if (name === undefined) return DEFAULT_FEE_SETTING;
  const setting = TIP_FEE_SETTINGS[name];
  if (setting === undefined) throw new Error(`no fee setting ${name} in harness/fee-settings.ts`);
  return setting;
}

