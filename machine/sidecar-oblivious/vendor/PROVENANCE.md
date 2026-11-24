# Vendored: gigadoram-rs

The four crates here (`primitives`, `circuits`, `data-structures`, `doram`) are
TACEO's Rust port of GigaDORAM, copied from
https://github.com/TaceoLabs/gigadoram-rs at commit
`09bea241410bb554b143957bd7b34b30626d7be2` (2026-08-13), under its dual licence
(`LICENSE-APACHE`, `LICENSE-MIT`). The crates here, changes included, stay under
MIT OR Apache-2.0, as their `Cargo.toml` files say. The
package names carry a `gigadoram-` prefix; the library crate names are the
originals, so the code's `use primitives::` paths are untouched.

Changes against the upstream commit (`docs/ARCHITECTURE.md` section 6, "The DORAM and its measurements"):

- The port to the machine's pinned co-snarks (`iAmMichaelConnor/co-snarks`
  `8ec1568e`, 140 commits past gigadoram-rs's `114408b1`), which carries its own
  mod-2 garbling in `mpc_core::protocols::rep3::yao::fancy` in place of the
  external `fancy-garbling` and `scuttlebutt` crates: in
  `circuits/src/cht_lookup.rs` the import line, `GcError` for `G::Error`,
  `constant(0)` for `constant(0, 2)`, `WireMod2::from_block(block)` for
  `from_block(block, 2)`, `wires()` for `extract().wires()`, and a balanced AND
  tree in `tags_equal` for the removed `and_many`; the two swanky dependencies
  dropped from `circuits/Cargo.toml`.
- The crate manifests: workspace dependencies of this workspace (`mpc_core`,
  `mpc_net`; its `local` feature, which `primitives::run_parties` needs, behind
  `primitives`' `testing` feature, which the crates' tests enable),
  `num-traits` and `rand_chacha` named directly, no `publish`/`homepage`/
  `authors` workspace keys; `rust-version` is the workspace's 1.90 (upstream says
  1.92; nothing in the crates needs it).
- The benchmark binaries (`doram/src/bin`) and their dependencies (`clap`,
  `indicatif`, `toml`, `tracing-subscriber`) are not vendored; the benchmark
  numbers of the design document were taken with them on the ported copy.
- Persistence: `doram/src/state.rs` (new) encodes and decodes a
  `GigaDoram<FieldValue<F>>` level by level: a head (the configuration, the level
  counters, each live level's stamp and query bookkeeping, the speed cache) and one part
  per live level (what its build made), each as public bytes, the party's two XOR share
  components as byte streams and the copies two parties hold alike (the receivers'
  shuffle), with `GigaDoram::from_parts`, `had_initial_bottom_level()`, `level_stamp`
  and `next_stamp` and the per-level build stamps in `doram/src/lib.rs` (stamped where a
  level's table is made, reset where the levels are); `OhTable::cht_rep3` in
  `data-structures/src/ohtable.rs`, the CHT's Rep3 sharing kept beside the receivers'
  two-party resharing that `build_cht` makes of it. Not persisted: the builder-order
  arrays (unread after a build), the bit-sliced round keys (recomputed from the key with
  `precompute_round_keys`) and the shuffle's inverse.
- The sparse map (docs/ARCHITECTURE.md section 6, "The storage: one DORAM addressed by (height, prefix)", "The port changes"): the address
  type `primitives::X` is `u128` (upstream `u32`), so an address space can be a
  label space far wider than any level's capacity; the oblivious sort's row packs
  the dummy flag below the address (`flag | x << 1`, addresses below 2^127);
  `GigaDoramConfig.log_capacity` sizes the bottom level beside
  `log_address_space_size` (equal for a dense DORAM, `GigaDoramConfig::new`;
  smaller for a sparse one, `GigaDoramConfig::sparse`, built lazily with
  `GigaDoram::new`, an address never written reading as zero); a sparse bottom
  rebuild opens the sorted dummy flags, refuses a fill over the capacity instead
  of truncating real records, and records the fill (`GigaDoram::fill_count`);
  the dummy labels are computed in `u128`; `grow_*` grow the capacity by one bit
  (the address space with it for a dense DORAM); the speed cache's fused zero
  check folds `X::BITS / 8` bytes instead of four.
- Framing: `primitives/src/chunked.rs` (new), a network adapter that sends every
  message in frames of at most half mpc-net's default frame limit (a length header,
  then the message in chunks), and `GigaDoram`'s entry points that reach the network
  (`new_with_initial_bottom_level`, `batch_access`, `grow_naturally`, `grow_on_demand`
  and the single access `read_and_maybe_write`) wrap their network in it: a dense
  bottom level of depth 16 reshares about 190 MiB in one message, over the 64 MiB that
  mpc-net's blocking TCP and TLS transports accept in one frame. Its test runs
  on mpc-net's local network, a dev-dependency of `primitives`.
- The address type's follow-ups: `primitives/src/cast.rs` widens an address
  to a block with `as Block`, `data-structures/src/cht.rs` receives the CHT
  index as `RingElement<X>` and narrows addresses with `as u64`.
- `primitives/src/timed_network.rs`: the communication timer counts `recv`
  calls (`CommunicationTimer::recvs`, an upper bound on a protocol's sequential
  steps), which the benchmark binaries report; nothing in this tree reads it.
- Bounds on what a party reads from a peer or from its store, and the
  configuration's bounds as a check: `GigaDoramConfig::check` (every bound
  `validate` asserted, as a `Result`; `validate` panics on its error) and
  `try_with_capacity` (the general constructor without the panic), so an owner
  can refuse a shape before building it; `doram/src/state.rs` checks a stored
  configuration with `check`, bounds a level's slots in the head by the
  configuration (`2^(log_capacity + 1)`) before allocating them, and reads a
  head's configuration alone (`head_config`) so the owner compares it with the
  shape it expects before the rest is decoded; `primitives/src/chunked.rs`
  refuses a message length over `MAX_MESSAGE` (2 GiB) before reserving it.
- `circuits/src/oblivious_sort.rs`: the row packing's debug assertion on each
  share component's top bit is dropped (a reshared component's top bit is
  random; the address the components open to is below `2^127` by the
  configuration), so the sparse bottom rebuild that follows a level's resharing
  passes in debug builds.

Nothing else is changed. Upstream's tests are kept and run as this workspace's,
with these edits: the address literals and types of
`circuits/tests/{cht_lookup,oblivious_sort,replace_if_dummy,xy_if_xs_equal}.rs`,
`data-structures/tests/{cht,speed_cache}.rs` and `doram/tests/gigadoram.rs`
follow the address type (`u128`, `as u64`), and `doram/tests/gigadoram.rs`
gains the sparse DORAM's test (`test_sparse_address_space_with_bounded_capacity`).
