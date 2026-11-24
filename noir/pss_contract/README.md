# pss_contract

The contract side of private shared state on the sidecar path: `apply` verifies a network
co-SNARK in a private function and forwards its effects (read requests, nullifiers, note
hashes); `anchor_leaf`, `assert_anchored` and `once_nullifier` are the anchoring helpers.
The two examples on it are `examples/amm/contract` and `examples/monty-hall/contract`.

## Where state lives

The rule (`docs/DECISIONS.md` section 6, "Where state lives on Aztec"), by who reads a value:

- **One reader, the user who owns it:** an ordinary aztec-nr note owned by that reader
  and held in its PXE (`PrivateImmutable` for a value written once, `PrivateMutable`
  for one it replaces). The reader's own call reads it with a note read request; no
  argument carries its preimage or nonce, and nobody mines that nonce. Monty Hall's
  Config (the operator's), Game and choices (the player's) are of this kind.
- **Many readers, preimage not secret:** a hash anchor (`anchor.nr`): a raw note hash
  that no PXE discovers, presented by every caller as an argument with the protocol
  nonce mined from the anchoring transaction's effects, and checked with
  `assert_anchored`. The AMM's pool Config is of this kind.
- **No single party may see it:** the sidecar holds it as secret shares, and the chain
  holds only the raw note hashes the round circuits output, which `apply` pushes and
  spends. Clients mine those nonces from the tx's effects (`pss-client`'s `mineNonces`).

Choose by the readers, not by convenience: an anchor publishes its preimage to every
caller, and a note is invisible to anyone without the owner's keys. A note read with
aztec-nr's getter fails the call when the note is missing, which is right when only the
owner's own call reads it; where another party's call reads state that someone else can
make missing, use total-noir's flagged reads (`total_aztec`, `get_note_or`).
