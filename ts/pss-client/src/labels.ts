// Domain labels: an ASCII string read big-endian as one field element, the
// rule every Noir and Rust side applies to the same strings (at most 31
// bytes, so the value is below r).

/** `s`'s ASCII bytes read big-endian as one field element. */
export function asciiLabel(s: string): bigint {
  if (!/^[\x20-\x7e]{1,31}$/.test(s)) throw new RangeError(`label ${JSON.stringify(s)}: 1 to 31 printable ASCII characters`);
  return BigInt("0x" + Buffer.from(s, "ascii").toString("hex"));
}
