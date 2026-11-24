-- A node's tables (docs/ARCHITECTURE.md section 1, "The store trait"), as
-- sidecar-node's PostgresStore reads and writes them. Every table but
-- `values`, `tip_versions`, `tip_nodes` and `tip_blobs` is identical on the
-- three nodes; those hold this node's own shares. Field elements
-- (namespaces, note hashes, request ids, vk hashes, commitments) are their
-- 32-byte big-endian integers, the digits of their 0x hex.

-- Written by a namespace's first REGISTER; `seq` by every later registry body.
CREATE TABLE namespaces (
    namespace BYTEA PRIMARY KEY,
    -- the owner's Grumpkin key, ark's uncompressed serialisation
    owner_pubkey BYTEA NOT NULL,
    -- this node's replicated share of nsk_app, ark's uncompressed serialisation
    nsk_app BYTEA NOT NULL,
    npk_app_hash BYTEA NOT NULL,
    seq BIGINT NOT NULL CHECK (seq >= 0)
);

-- Each namespace's contract manifests with their packages: one version, or under
-- `upgrades` `circuits` or `contract` up to MAX_HELD_VERSIONS (3), the newest kept.
CREATE TABLE manifests (
    namespace BYTEA NOT NULL,
    manifest_hash BYTEA NOT NULL,
    -- the contract manifest as JSON text
    document TEXT NOT NULL,
    -- the seq of the REGISTER that last wrote it
    seq BIGINT NOT NULL CHECK (seq >= 0),
    PRIMARY KEY (namespace, manifest_hash)
);

-- The registered packages of a contract manifest; REGISTER upserts a row,
-- DISABLE sets `disabled`.
CREATE TABLE packages (
    namespace BYTEA NOT NULL,
    manifest_hash BYTEA NOT NULL,
    name TEXT NOT NULL,
    -- nargo's output as the client sent it
    circuit_json BYTEA NOT NULL,
    -- the manifest as JSON text
    manifest TEXT NOT NULL,
    vk BYTEA NOT NULL,
    vk_hash BYTEA NOT NULL,
    disabled BOOLEAN NOT NULL,
    seq BIGINT NOT NULL CHECK (seq >= 0),
    PRIMARY KEY (namespace, manifest_hash, name)
);

-- The consumed set: written by a round's commit, never pruned; only the
-- operator rollback deletes the entries of the request it rolls back.
CREATE TABLE consumed (
    namespace BYTEA NOT NULL,
    note_hash BYTEA NOT NULL,
    -- the vk_hash of the consuming circuit
    circuit BYTEA NOT NULL,
    request_id BYTEA NOT NULL,
    PRIMARY KEY (namespace, note_hash)
);
CREATE INDEX consumed_by_request ON consumed (namespace, request_id);

-- One row per committed round, for FETCH and for the rollback; pruned by age.
CREATE TABLE requests (
    namespace BYTEA NOT NULL,
    request_id BYTEA NOT NULL,
    body_hash BYTEA NOT NULL,
    vk_hash BYTEA NOT NULL,
    proof BYTEA NOT NULL,
    -- the public inputs, 32 bytes each, concatenated
    public_inputs BYTEA NOT NULL,
    -- the node-held keys the round stored, and those it created
    stored_keys TEXT[] NOT NULL,
    created_keys TEXT[] NOT NULL,
    -- this node's thirds of the new records (key, note hash, c_i) and the
    -- sealed node-held vectors the round replaced (key, prior request id,
    -- note hash, sealed vector), in the order the round sealed them; the
    -- encoding is sidecar-node's codec (`Writer::sealed`)
    sealed BYTEA NOT NULL,
    -- this node's result signature: s.lo, s.hi, e.lo, e.hi, 32 bytes each
    signature BYTEA,
    status TEXT NOT NULL CHECK (status IN ('committed', 'rolled_back')),
    -- unix seconds; what the pruning job compares
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    -- at the tip: the chain request id the round answers; NULL for a round
    -- off the tip
    chain_request_id BYTEA,
    PRIMARY KEY (namespace, request_id)
);
CREATE INDEX requests_by_age ON requests (created_at);
-- FETCH by chain request id (the tip): the latest `requests` row carrying a
-- chain request id under a namespace, by created_at then request_id
-- (sidecar-node's PostgresStore, `q_chain_request`). Rows off the tip carry
-- none and stay out of the index.
CREATE INDEX requests_by_chain_request_id
    ON requests (namespace, chain_request_id, created_at DESC, request_id DESC)
    WHERE chain_request_id IS NOT NULL;

-- Node-held state: one row per key, rewritten in place by the commit.
CREATE TABLE "values" (
    namespace BYTEA NOT NULL,
    key TEXT NOT NULL,
    -- this node's third of the vector, the core's tag-prefixed encoding
    vec BYTEA NOT NULL,
    note_hash BYTEA NOT NULL,
    -- the request that wrote the row
    request_id BYTEA NOT NULL,
    PRIMARY KEY (namespace, key)
);

-- The tip's receipts (docs/ARCHITECTURE.md section 1, "The store trait";
-- section 6, the receipts row): the inputs a node checked and signed a
-- receipt for, keyed by (namespace, chain request id). Written by the
-- receipt route (`POST /v1/receipt`), read by `GET /v1/receipt/...` for the
-- scheduler and the chain verifier, deleted by the pruning job once
-- `expiry_block + stale_blocks` is below the block it is told; a row whose
-- stale period is NULL (skipping disabled) is never pruned. A row names no
-- requester (the hidden requester, section 6): a receipt-intake row keeps
-- the requester's nonce and holds no shares; a secret-shared receipt
-- intake row (section 6, "Secret-shared receipt intake, end to end", step 3) holds
-- no nonce and, per shared input, this node's own envelope and the three
-- share hashes.
CREATE TABLE receipts (
    namespace BYTEA NOT NULL,
    request_id BYTEA NOT NULL,
    -- the registered circuit name and its vk_hash when the node signed
    circuit TEXT NOT NULL,
    vk_hash BYTEA NOT NULL,
    -- the app inputs in ABI order, 32 bytes each, concatenated
    inputs BYTEA NOT NULL,
    inputs_hash BYTEA NOT NULL,
    -- the requester's nonce under receipt intake; NULL under secret-shared
    -- receipt intake
    user_nonce BYTEA,
    -- the codec's layout: a u32 count, then per shared input its name, its
    -- envelope (eph.x, eph.y, ct0, ct1, tag) and the three share hashes;
    -- the count 0 under receipt intake
    shares BYTEA NOT NULL,
    expiry_block BIGINT NOT NULL CHECK (expiry_block >= 0),
    -- the manifest's stale period at signing time; NULL keeps the row
    stale_blocks BIGINT CHECK (stale_blocks >= 0),
    -- expiry_block + stale_blocks (saturating at the BIGINT maximum), the
    -- last block the row is kept through; NULL when stale_blocks is
    keep_until BIGINT CHECK (keep_until >= 0),
    -- this node's receipt signature: s.lo, s.hi, e.lo, e.hi, 32 bytes each
    signature BYTEA NOT NULL,
    PRIMARY KEY (namespace, request_id)
);
-- The pruning job's scan.
CREATE INDEX receipts_by_keep_until ON receipts (keep_until)
    WHERE keep_until IS NOT NULL;

-- Node-held tip state (docs/ARCHITECTURE.md section 1, "The store trait";
-- section 6, "Node-held state"): every version of a node-held tip key, named
-- by its commitment. A round's commit inserts the version it created (never
-- over an existing one) and updates the status and block of the key's other
-- versions; the pruning marks orphans and deletes those first marked orphan
-- below the settled block. A version of a tree-valued key (section 6,
-- "Tree-valued keys") names the root of its clear tree and its append index
-- (one past the highest leaf ever written); its nodes are in `tip_nodes`.
CREATE TABLE tip_versions (
    namespace BYTEA NOT NULL,
    key TEXT NOT NULL,
    -- the round's new commitment for the key (never 0)
    commitment BYTEA NOT NULL,
    -- the commitment of the version the round loaded; 0 for a created key
    parent BYTEA NOT NULL,
    -- the queue index of the entry the round was computed for
    queue_index BIGINT NOT NULL CHECK (queue_index >= 0),
    -- the round (one attempt of that entry) that created it
    request_id BYTEA NOT NULL,
    -- this node's pairs of the vector, the core's tag-prefixed encoding
    vec BYTEA NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('canonical', 'live', 'orphan')),
    -- the last block at which it was canonical or live
    block BIGINT NOT NULL CHECK (block >= 0),
    -- the hash of `block` as the chain view that set it read it (32 zero
    -- bytes: a mark with no hash). An orphan mark whose block the chain has
    -- since replaced is ignored (sidecar-core `rules::stage_versions`).
    block_hash BYTEA NOT NULL,
    -- a tree-valued key's root and append index; both NULL otherwise
    tree_root BYTEA,
    tree_next BIGINT CHECK (tree_next >= 0),
    PRIMARY KEY (namespace, key, commitment),
    CONSTRAINT tip_versions_tree CHECK ((tree_root IS NULL) = (tree_next IS NULL))
);

-- The nodes of tree-valued tip keys, content-addressed by hash: an internal
-- node's two children in the clear, or a leaf's index with this node's pairs
-- of it. `refs` counts the stored nodes and versions that point to the
-- node; a version's delete removes the nodes no kept version reaches.
CREATE TABLE tip_nodes (
    namespace BYTEA NOT NULL,
    key TEXT NOT NULL,
    hash BYTEA NOT NULL,
    -- an internal node's children
    left_child BYTEA,
    right_child BYTEA,
    -- a leaf's index and this node's pairs of it, the core's tag-prefixed encoding
    leaf_index BIGINT CHECK (leaf_index >= 0),
    leaf_vec BYTEA,
    refs BIGINT NOT NULL CHECK (refs >= 0),
    PRIMARY KEY (namespace, key, hash),
    CHECK ((left_child IS NOT NULL AND right_child IS NOT NULL
            AND leaf_index IS NULL AND leaf_vec IS NULL)
        OR (left_child IS NULL AND right_child IS NULL
            AND leaf_index IS NOT NULL AND leaf_vec IS NOT NULL))
);

-- Opaque per-key state of a node-held tip key's holder
-- (docs/ARCHITECTURE.md section 6, "Versions, rollback and pipelining" and
-- "Persistence, resync, share refresh, audit": the oblivious tree brick's DORAM
-- state and its journal entries), one row per (key, name), written and read
-- whole by the holder and never interpreted by the store.
CREATE TABLE tip_blobs (
    namespace BYTEA NOT NULL,
    key TEXT NOT NULL,
    name TEXT NOT NULL,
    bytes BYTEA NOT NULL,
    PRIMARY KEY (namespace, key, name)
);

-- The dead records (docs/ARCHITECTURE.md section 3, step 7 and the rollback
-- path): the note hash of every client-held record a rolled-back request
-- created, under that request. Written by the operator rollback; a later
-- round that creates a record with the same note hash deletes its row; never
-- pruned otherwise.
CREATE TABLE dead_records (
    namespace BYTEA NOT NULL,
    note_hash BYTEA NOT NULL,
    -- the rolled-back request that created the record
    request_id BYTEA NOT NULL,
    PRIMARY KEY (namespace, note_hash)
);
