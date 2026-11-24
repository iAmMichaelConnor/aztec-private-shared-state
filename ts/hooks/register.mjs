// Needed by every process that loads @aztec-labs/accounts or the kernel
// artifacts (wallets, PXE): they import JSON without `with { type: "json" }`.
import { register } from "node:module";

register("./json-import-hooks.mjs", import.meta.url);
