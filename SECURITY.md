# Security

This repository is a research prototype. It has not been audited. Do not use it with
real funds, or with data whose exposure would harm anyone.

## Reporting a vulnerability

Report it privately through GitHub's private vulnerability reporting on this repository
(the Security tab, "Report a vulnerability"). Please do not open a public issue for it.

Say what you found, how to reproduce it, and what it affects: privacy, funds or liveness.

## What counts

The claims are in [README.md](README.md) ("Trust") and [docs/DESIGN.md](docs/DESIGN.md)
("The trust boundary", "Who sees what", "Limits"). A way to break one is in scope, for
example:

- a result that lands without a proof under the contract's pinned verification key, or
  (at the tip) without the three nodes' signatures;
- value taken or lost by anyone holding every node secret (invariant 0,
  [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) section 5). Value frozen by nodes that
  refuse service is a known limit, stated there;
- a secret-shared input, or a state value it touched, reaching a single node or the chain;
- a requester's address reaching the chain or the nodes.

The limits those documents already state, such as what a participant learns from its own
outcomes or what the user's Aztec node can link, are known and not vulnerabilities.
