# PSS demo: the examples, step by step

A self-contained visualisation of this repository's example apps: who holds what, what each
contract function and co-SNARK circuit checks and emits, what moves between them in each
step, and which bricks are at work. It lives entirely in `demo/`; nothing outside `demo/`
depends on it, refers to it or is changed by it. It only reads
`docs/design-guide/design-space.json` (the brick panel).

Plain HTML, CSS and JavaScript, no framework, no package install, no network.

The scenarios transcribe the counter-tip and monty-hall examples as the code stands (each
lists its source files in `source.files`). Every step is hand-written: the values are
illustrative and consistent across steps.

## Viewing it

During development, serve the repository root (the page reads
`../docs/design-guide/design-space.json`):

```sh
python3 -m http.server 8000          # from the repository root
# open http://localhost:8000/demo/#counter-tip-16
```

One self-contained file, which opens from `file://` and publishes as one page:

```sh
python3 -I demo/build.py             # checks every scenario, writes demo/dist/index.html
python3 -I demo/build.py --check     # checks only
```

`demo/dist/` is ignored by git.

Deep links: `#<tab>-<step>`, e.g. `#counter-tip-16`, `#monty-hall-12`. Keys: ← and →
step, Home and End jump. `?theme=dark` or `?theme=light` forces a theme (the page follows
the system otherwise).

## What the page shows

- **Left, who holds what**: the orchestrator, one parametric block for the three nodes
  ("Node i ×3"), the relayer and the users, each with three stacked sections that open and
  close: contract code, long-lived state, this interaction. The co-SNARK circuits are rows
  in Node i's contract code: parameters with their manifest sources, numbered logic (a
  **flag** sets an error code, an **assert** fails the proof), public outputs.
- **Right, smart-contract land**: each contract top to bottom: public state, public
  functions, the public/private divide, private state, private functions. A function is a
  full-width row with its kind, its summary, the step it last ran, what it verifies and its
  `enqueues →` / `enqueued by ←` links; it opens to the call it received in this step (a
  struct with every argument), the proof's public inputs and its logic. A transaction is a
  struct drawn directly above the entry function it calls.
- **Middle, the flow lane**: the active step's reads, sends, pushes, submits, calls,
  writes and emits as arrows, numbered at the base and near the tip; hovering one says what
  it carries and thickens it. Below 1280px wide the lane hides and the numbered list shows.
- **Colour = who can read it**: green circle public, red diamond one user, blue triangle
  secret-shared among the nodes, amber square the operator's side only; a hollow mark is a
  hash, commitment or ciphertext of such a value. Violet marks what acts in this step.
- **State is replayed**: the picture at step k is steps 1..k applied in order. Each item
  shows the step that made it; this step's items are ringed; a spent item stays, struck
  through. Clicking an item picks it: its copies (same `same` id) are outlined and the card
  says what it is, who reads it, where it is held.
- **Names are links**: every state item, function, circuit and entity named in any text
  (the step banner, flow lines, logic lines, panels, tooltips) links to its home in the
  picture: a click opens the closed sections and rows around it, scrolls to it and flashes
  it for about two seconds (a static outline when reduced motion is on).
- **Brick panel**: every axis of `design-space.json`, the example's option lit, the
  options this step uses in violet, the others with their status (not built yet, not
  offered, experimental) and the rule that rules each out for this example; the add-on
  bricks `data/addons.json` names, with their names and statuses from `design-space.json`.
  Picking a play is not built yet.

## Files

| Path | What |
| --- | --- |
| `index.html` | the page skeleton; loads `src/` and, when served, fetches the data |
| `src/demo.css` | the look: colour tokens (light and dark), marks, structs, rows, the stage |
| `src/model.js` | loading, the reference registry, text markup, the replay of steps into state |
| `src/view.js` | renders a scenario at a step: entities, contracts, panels, timeline, bricks |
| `src/arrows.js` | draws the active step's flows over the stage, hover tooltips |
| `src/app.js` | tabs, Prev / Next / Play, keys, deep links, picking, reference clicks |
| `scenarios/*.json` | one scenario per built example (the schema below) |
| `data/tabs.json` | the example tabs: which have a scenario, which are coming next |
| `data/addons.json` | the add-on bricks the panel lists, by `design-space.json` brick id |
| `build.py` | checks every scenario, writes `dist/index.html` |

## Adding a scenario

1. Write `scenarios/<tab>.json` (schema below). Transcribe every function's and circuit's
   logic from the code, in code order, library calls expanded; give the source files in
   `source.files`. Keep values illustrative but consistent across steps: one value per
   thing, the same string wherever it appears.
2. Add or update its tab in `data/tabs.json` (`scenario` names the file's `id`).
3. `python3 -I demo/build.py --check` until it passes; then look at it.

## The scenario schema

Every text field may use two bits of markup: `` `code` `` and references `[[id]]` or
`[[id|shown text]]`. A reference names any id below (an item, a function, a circuit, an
entity, an entity section `alice.interaction`, a contract, a logic line); the page renders
it as a link to that thing. A reference to an item not yet made at the shown step renders
as plain text. Function and circuit names are also linked wherever they appear in text as
whole words with an underscore (`process_result`); write `[[add]]` for names without one.

### Top level

```json
{
  "id": "counter-tip", "label": "counter-tip", "path": "tip", "example": "counter_tip",
  "title": "Alice adds 5 to a private counter",
  "summary": "one paragraph",
  "basis": "hand-written",
  "source": { "files": ["examples/counter-tip/contract/counter_tip/src/main.nr"] },
  "phases": [ { "id": "setup", "label": "Setup · once" } ],
  "interactions": { "add5": "Alice adds 5" },
  "addons": [ "add-on brick ids from data/addons.json that the example uses" ],
  "entities": [ ... ], "contracts": [ ... ],
  "initial": [ create effects, made before step 1: shown as step 0 ],
  "steps": [ ... ]
}
```

`example` is the `design-space.json` example id whose `asBuilt` options the brick panel
lights. `basis` is `hand-written`: no step is recorded from a run.

### Items: every value, note, call and struct

```json
{ "id": "k-ctr", "label": "counter", "value": "c0 0x19c4…03ab",
  "reader": "shared", "form": "sealed", "note": "aside, muted",
  "fields": [ { "k": "total", "v": "parts i, i−1 of 5", "reader": "shared", "form": "part",
               "src": "LOAD", "note": "...", "fields": [ ...nested... ] } ],
  "open": "{", "close": "}", "to": "→ note hash `0x0b3d…c6f4`", "to_reader": "user", "to_form": "sealed",
  "same": "c1", "per_node": { "0": "...", "1": "...", "2": "..." },
  "about": "what it is, one sentence (the picked-item card)" }
```

- `reader`: `public` (green), `user` (red), `shared` (blue), `operator` (amber).
- `form`: `clear`; `part` (one node's parts of a shared value); `sealed` (a hash,
  commitment or ciphertext of a value of that colour: hollow mark).
- An item with `fields` is drawn as a struct (`label` is its type line, then `open`, one line
  per field, `close` and `to`); without, as one row. A field with `fields` nests.
- `src`: a circuit parameter's manifest source (`PUBLIC`, `INPUT_SHARED`, `LOAD`, `SAMPLE`).
- `same`: one id for the same thing in several places; picking one outlines them all.
- `per_node`: a value that differs per node (keys, parts, signatures); drawn once, written
  with i, listed per node under it.

### Entities (left)

```json
{ "id": "node", "kind": "node", "label": "Node i", "copies": 3, "role": "watches the chain",
  "meta": "one line under the name", "idle": "why it does nothing here (then drawn as one line)",
  "empty": { "interaction": "what an empty section says" },
  "circuits": [ circuit... ] }
```

`kind`: `orchestrator`, `node`, `relayer`, `user`, `developer`. Each entity has three
places, `code`, `long_lived` and `interaction`; its items arrive by effects. Entities are
drawn in list order (orchestrator, nodes, relayer, users; consecutive users share a band).

### Contracts (right)

```json
{ "id": "ct", "label": "CounterTip contract", "address": "0x2c1a…9f04",
  "groups": { "public":  [ { "id": "set_once", "label": "long-lived · set once, by the constructor and configure" } ],
              "private": [ { "id": "notes", "label": "long-lived · outcome_notes" } ] },
  "empty": { "public": "none: no public state" },
  "functions": [ function... ] }
```

A contract place is `{ "in": "ct", "sec": "public" | "private", "group": "<group id>" }`.

### Functions and circuits

```json
{ "id": "process_result", "kind": "private", "badges": ["only_self"],
  "summary": "one line", "runs_in": "runs in the sender's wallet",
  "verifies": { "circuit": "counter_add", "vk_source": "pinned in configured", "signatures": "3 node signatures" },
  "check": "for a function that verifies no proof: what it checks instead, e.g. `3 node receipts`",
  "enqueues": ["assert_key_epoch", "apply_result"], "called": "called directly, at deploy",
  "logic": [ { "kind": "assert", "text": "…", "msg": "failure message", "item": "k-ctr", "id": "pr-enq-ar" } ] }
```

`kind`: `public`, `private`, `utility` (dotted row, no transaction), `view`. `enqueued by`
is computed from every `enqueues`. Logic `kind`: `assert` (fails the transaction, or the
proof in a circuit), `flag` (a total circuit's check: sets a `code`), `read`, `load`,
`compute`, and the effects `write`, `push`, `emit`, `enqueue`, `seal`, `complete`, `store`.
A logic line with an `id` can be an arrow's end (an enqueue arrow starts at its line).

A circuit sits in its node entity's `circuits`, with `vk_hash`, `verified_by`, `total`
(true: no check can fail the proof), `total_note`, `params` (an item: every parameter of
`main` as a field with its `src`), `logic` and `outputs` (an item: the public outputs).

### Steps

```json
{ "n": 16, "phase": "land", "interaction": "add5", "title": "…", "text": "…",
  "basis": "hand-written",
  "acts": ["relayer", "process_result", "assert_key_epoch", "apply_result"],
  "open": ["counter_add"],
  "tx": { "id": "0x5e2d…a019", "by": "relayer", "entry": "process_result",
          "item": { Tx struct }, "args": { the entry call's arguments, a struct } },
  "calls": [ { "caller": "process_result", "callee": "apply_result",
               "kind": "private_to_public_enqueue", "args": { struct } } ],
  "verifies": [ { "function": "process_result", "circuit": "counter_add",
                  "public_inputs": { struct } } ],
  "runs": [ { "circuit": "counter_add" } ],
  "flows": [ { "from": "relayer-tx", "to": ["tx"], "kind": "submit", "reader": "public",
               "payload": "tx 0x5e2d…a019", "text": "[[relayer]] → the transaction …" } ],
  "effects": [ { "op": "create", "at": { place }, "item": { item } },
               { "op": "update", "ref": "k-ctr", "set": { "value": "c1 0x0e5f…b872" } },
               { "op": "spend", "ref": "node-c0", "note": "replaced at 16" },
               { "op": "move", "ref": "node-c1", "to": { place } },
               { "op": "remove", "ref": "..." } ],
  "learns": [ { "party": "Everyone", "text": "…" } ],
  "bricks": ["path", "intake", "outputs"],
  "pick": "k-ctr" }
```

- `acts`: entities, functions and circuits that act; their blocks and rows are lit, the
  rows open. Running functions come first in their group, in this order.
- `tx`: the transaction this step sends; a transaction is one step, its whole call chain
  lit. `tx.item` is drawn above `tx.entry`'s row; `tx.args` and each call's `args` show in
  the callee's open row, `verifies[].public_inputs` beside them.
- `flows`: the arrows. `from` and `to` are ids: items, functions, circuits, entities,
  sections (`alice.interaction`), contracts, logic lines, or `tx` (this step's transaction object).
  `kind`: `read` (dashed), `send`, `push` (dotted), `submit`, `call` (thick), `write`,
  `emit`. `reader` colours it. `text` is the numbered list's line and the hover.
- `effects`: what the step makes, changes, spends, moves or removes. An update shows
  old → new for this step.
- `learns`: the "who learns what" panel; `pick`: the item the card shows first.

### Not built yet

Recorded steps (`basis` other than `hand-written`), fragments, app cards and the assembler
that composes a play from bricks: the brick panel shows the options and the rules but does
not play a combination.

## How build.py works

1. Loads every `scenarios/*.json` and checks it: required fields, enums, every place,
   every id unique, every effect's `ref` made by an earlier step, every flow endpoint an id
   (an item one that exists at that step), every `[[reference]]` an id, every function
   named by `enqueues`, `verifies`, `verified_by` and `calls`, and each step's `bricks`,
   the scenario's `example` and `addons` and every add-on in `data/addons.json` against
   `design-space.json`.
2. Reads `../docs/design-guide/design-space.json` and keeps what the brick panel uses:
   the statuses, the axes with their values and statuses, the constraints, the examples'
   `asBuilt` and each brick's name and status.
3. Writes `dist/index.html`: `index.html` with the stylesheet and scripts inlined and the
   data as one inline `window.PSS_DEMO` object, so the page needs no fetch.

Served from the repository, the page fetches the same JSON files itself, so editing a
scenario needs only a reload.
