// Node >= 20.10 requires `with { type: 'json' }` on JSON imports. Published
// @aztec-labs 6.0.0 packages perform DYNAMIC json imports without the
// attribute (e.g. @aztec-labs/accounts/dest/schnorr/initializerless/lazy.js
// and the kernel artifacts in @aztec-labs/noir-protocol-circuits-types),
// which throws ERR_IMPORT_ATTRIBUTE_MISSING under plain node. This load
// hook supplies the attribute for any .json module, upstream code
// unchanged. Registered via register.mjs (node --import <repo>/ts/hooks/register.mjs).
export async function load(url, context, nextLoad) {
  if (url.endsWith(".json") && context.importAttributes?.type !== "json") {
    return nextLoad(url, {
      ...context,
      importAttributes: { ...(context.importAttributes ?? {}), type: "json" },
    });
  }
  return nextLoad(url, context);
}
