// The proof capsule: the bb verification key and the proof as field elements,
// staged for the contract's pss_contract::apply, which loads
// ProofData { vk: [Field; 115], proof: [Field; 458] } from capsule slot 0x10.

import { AztecAddress } from "@aztec-labs/aztec.js/addresses";
import { Fr } from "@aztec-labs/aztec.js/fields";
import { Capsule } from "@aztec-labs/aztec.js/tx";
import { poseidon2Hash } from "@aztec-labs/foundation/crypto/poseidon";

import { fieldAddress, fieldHex, hexBytes, type FieldLike } from "./field.ts";

// The capsule layout: slot 0x10, then 115 vk fields and 458 proof fields,
// matching the ProofData type and CAPSULE_SLOT_PROOF of
// noir/pss_contract (src/proof_data.nr). 115 and 458 are the bb
// 6.0.0 UltraHonk (ZK, poseidon2 oracle) verification key and proof sizes the
// contract's verify_proof_with_type expects; another bb version or proof type
// changes both, and the contract's ProofData with them. Another slot must be
// changed in the contract at the same time, or apply fails with "proof
// capsule missing".
export const CAPSULE_SLOT_PROOF = 0x10;
export const VK_FIELDS = 115;
export const PROOF_FIELDS = 458;

/** Split a bb-format proof (`0x` + 458 big-endian 32-byte fields, no length
 * prefix) into its field elements. */
export function proofToFields(proofHex: string, fields = PROOF_FIELDS): Fr[] {
  const digits = hexBytes(proofHex, "proof").slice(2);
  if (digits.length !== fields * 64) {
    throw new RangeError(`proof: ${digits.length / 2} bytes, expected ${fields} fields of 32 bytes`);
  }
  const out: Fr[] = [];
  for (let i = 0; i < digits.length; i += 64) {
    out.push(Fr.fromString(fieldHex("0x" + digits.slice(i, i + 64), `proof field ${i / 64}`)));
  }
  return out;
}

/** The vk fields of a `vk.json` that `bb write_vk --output_format json` wrote
 * (`{ vk: [hex × 115], hash, ... }`), given as text or parsed JSON. When the
 * file carries bb's own `hash`, check it with vkHashFromFields. */
export function vkFieldsFromBbJson(vkJson: string | { vk: unknown }): Fr[] {
  const json = (typeof vkJson === "string" ? JSON.parse(vkJson) : vkJson) as { vk?: unknown };
  if (!Array.isArray(json.vk)) throw new RangeError("vk.json: no `vk` array");
  if (json.vk.length !== VK_FIELDS) throw new RangeError(`vk.json: ${json.vk.length} fields, expected ${VK_FIELDS}`);
  return json.vk.map((f, i) => Fr.fromString(fieldHex(f as FieldLike, `vk[${i}]`)));
}

/** The vk hash a contract pins and the sidecar returns: Poseidon2 of the vk
 * fields (the sponge bb, Noir and sidecar-core's hash::vk_hash compute). */
export async function vkHashFromFields(fields: FieldLike[]): Promise<Fr> {
  return poseidon2Hash(fields.map((f, i) => Fr.fromString(fieldHex(f, `vk[${i}]`))));
}

/** The capsule the contract loads with scope = msg_sender: `scope` must be
 * the account that sends the transaction. Pass it to
 * `contract.methods.f(...).with({ capsules: [capsule] })`. */
export function stageCapsule(contract: FieldLike | AztecAddress, scope: FieldLike | AztecAddress, vkFields: FieldLike[], proof: string | FieldLike[]): Capsule {
  if (vkFields.length !== VK_FIELDS) throw new RangeError(`vk: ${vkFields.length} fields, expected ${VK_FIELDS}`);
  const proofFields = typeof proof === "string" ? proofToFields(proof) : proof.map((f, i) => Fr.fromString(fieldHex(f, `proof[${i}]`)));
  if (proofFields.length !== PROOF_FIELDS) throw new RangeError(`proof: ${proofFields.length} fields, expected ${PROOF_FIELDS}`);
  return new Capsule(
    fieldAddress(contract, "contract"),
    new Fr(CAPSULE_SLOT_PROOF),
    [...vkFields.map((f, i) => Fr.fromString(fieldHex(f, `vk[${i}]`))), ...proofFields],
    fieldAddress(scope, "scope"),
  );
}
