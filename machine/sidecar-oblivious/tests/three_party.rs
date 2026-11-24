//! The two layouts' DORAMs over an in-process three-party network, every
//! value checked against sidecar-core's clear tree: the dense tree built
//! from the empty tree, a slot written and read back at shared and public
//! addresses, the journal's undo (the path nodes included), the persisted
//! state's round trip through a store (a head and one blob per level, each
//! public part equal at the three parties and each party's share
//! components the ones its neighbours hold, so XORing them opens the
//! values) and the share conversions; then a keyed map of depth 64 built
//! lazily, a key inserted, looked up, a neighbour's path meeting it, an
//! absent key, the undo and the fill bound; then the lending book's depth
//! 16, whose commit without a rebuild writes the head alone.

use std::collections::BTreeMap;
use std::time::Duration;

use ark_ff::PrimeField;
use mpc_core::protocols::rep3::arithmetic::{open_vec, promote_to_trivial_share};
use mpc_core::protocols::rep3::conversion::A2BType;
use mpc_core::protocols::rep3::{Rep3State, id::PartyID};

use mpc_net::Network;
use mpc_net::config::{Address, NetworkConfig, NetworkParty};
use mpc_net::tcp::TcpNetwork;
use primitives::{X, open_many, open_many_y, promote_public, promote_public_y, run_parties};
use sidecar_core::field::Fr;
use sidecar_core::request::{next, prev};
use sidecar_core::store::blob::Blob;
use sidecar_core::store::{MemoryStore, Store, StoreRead};
use sidecar_core::tree::{leaf_hash, node, zeros};
use sidecar_oblivious::oram::{field_to_values, indices_to_xor, values_to_field, xor_public};
use sidecar_oblivious::{Addressing, Doram, Journal, Layout, MapAddressing, SlotJournal};

const DEPTH: u32 = 4;
const W: usize = 2;
const NS: u64 = 0x7196;
const KEY: u64 = 0xa003;

/// The clear tree of depth 4 with `leaves` set: level `l` as a map position
/// -> hash (empty positions absent, their hash `Z_l`).
fn clear_tree(leaves: &[(u32, [u64; W])]) -> Vec<Vec<Fr>> {
    let mut levels: Vec<Vec<Fr>> = Vec::new();
    let mut level: Vec<Fr> = vec![Fr::from(0u64); 1 << DEPTH];
    for (i, leaf) in leaves {
        let leaf: Vec<Fr> = leaf.iter().map(|x| Fr::from(*x)).collect();
        level[*i as usize] = leaf_hash(Fr::from(NS), Fr::from(KEY), *i as u64, &leaf);
    }
    levels.push(level.clone());
    for _ in 0..DEPTH {
        level = (0..level.len() / 2)
            .map(|p| node(level[2 * p], level[2 * p + 1]))
            .collect();
        levels.push(level.clone());
    }
    levels
}

/// What a slot read of leaf `i` returns in the clear tree `levels` with
/// `leaves`: siblings bottom up, the leaf hash, the elements.
#[allow(clippy::needless_range_loop)]
fn expected_read(levels: &[Vec<Fr>], leaves: &[(u32, [u64; W])], i: u32) -> Vec<Fr> {
    let mut out = Vec::new();
    for h in 0..DEPTH as usize {
        out.push(levels[h][((i >> h) ^ 1) as usize]);
    }
    out.push(levels[0][i as usize]);
    let leaf = leaves
        .iter()
        .find(|(j, _)| *j == i)
        .map_or([0; W], |(_, l)| *l);
    out.extend(leaf.iter().map(|x| Fr::from(*x)));
    out
}

/// What a slot write of leaf `i` stores: the elements, the hash, the path
/// nodes of heights 1 to D.
#[allow(clippy::needless_range_loop)]
fn write_values(levels: &[Vec<Fr>], leaves: &[(u32, [u64; W])], i: u32) -> Vec<Fr> {
    let leaf = leaves
        .iter()
        .find(|(j, _)| *j == i)
        .map_or([0; W], |(_, l)| *l);
    let mut out: Vec<Fr> = leaf.iter().map(|x| Fr::from(*x)).collect();
    out.push(levels[0][i as usize]);
    for h in 1..=DEPTH as usize {
        out.push(levels[h][(i >> h) as usize]);
    }
    out
}

const KEY_NAME: &str = "0xa003";

/// Commit `d`'s blob writes to `store` (bytes written), as a holder's
/// commit does.
fn persist<L: Layout>(d: &mut Doram<L>, store: &MemoryStore) -> usize {
    let mut txn = store.begin(Fr::from(NS));
    let mut written = 0;
    for (name, bytes) in d.writes().unwrap() {
        written += bytes.as_ref().map_or(0, Vec::len);
        txn.blob(KEY_NAME, &name, bytes);
    }
    store.commit(txn).unwrap();
    d.persisted();
    written
}

/// Every blob of the key in `store`, by name.
fn blobs(store: &MemoryStore) -> Vec<(String, Blob)> {
    store
        .blob_names(Fr::from(NS), KEY_NAME)
        .unwrap()
        .into_iter()
        .map(|n| {
            let b = store.blob(Fr::from(NS), KEY_NAME, &n).unwrap().unwrap();
            (n, Blob::from_bytes(&b).unwrap())
        })
        .collect()
}

/// The three parties' blobs are one sharing: the same names and public
/// bytes, and party j's `a` components (shares and copies) are party j+1's
/// `b`.
fn assert_one_sharing(parties: &[Vec<(String, Blob)>]) {
    for j in 0..3 {
        let (mine, theirs) = (&parties[j], &parties[next(j)]);
        assert_eq!(mine.len(), theirs.len());
        for ((n, b), (m, c)) in mine.iter().zip(theirs) {
            assert_eq!(n, m);
            assert_eq!(b.public, c.public, "blob {n}");
            assert_eq!(b.shares.a, c.shares.b, "blob {n}: party {j}'s a");
            assert_eq!(b.copies.a, c.copies.b, "blob {n}: party {j}'s copies");
            assert_eq!(
                b.shares.a.len(),
                parties[prev(j)]
                    .iter()
                    .find(|x| x.0 == *n)
                    .unwrap()
                    .1
                    .shares
                    .a
                    .len()
            );
        }
    }
}

fn frs(values: &[Fr]) -> Vec<<Fr as PrimeField>::BigInt> {
    values.iter().map(|v| v.into_bigint()).collect()
}

#[test]
fn the_dense_doram_holds_the_clear_tree() {
    let a = Addressing::new(DEPTH, W);
    let empty = clear_tree(&[]);
    let book = [(3u32, [30u64, 7u64])];
    let with_3 = clear_tree(&book);
    let results = run_parties(|net| {
        let mut state = Rep3State::new(&net, A2BType::Direct).unwrap();
        let id = PartyID::try_from(net.id()).unwrap();
        let mut d = Doram::build_empty(a, &net, &mut state).unwrap();

        // the empty tree: leaf 3's path is the zero subtrees, hash 0, zeros
        let index3 = a.mask_path(&promote_public(id, 3 as X));
        let read = d.read_slot(&index3, &net, &mut state).unwrap();
        let opened_empty = open_many_y(&read.values, &net);
        assert_eq!(opened_empty, frs(&expected_read(&empty, &[], 3)));
        assert_eq!(
            read.raw, read.values,
            "a dense DORAM stores the values as they are"
        );

        // write leaf 3's new path (trivial sharings of the clear values)
        let writes3 = a.slot_writes(id, &index3);
        let values: Vec<_> = write_values(&with_3, &book, 3)
            .iter()
            .map(|v| promote_public_y(id, v.into_bigint()))
            .collect();
        let before = d.write_slot(&writes3, &values, &net, &mut state).unwrap();
        // what the write addresses held: the empty tree's values in write order
        assert_eq!(
            open_many_y(&before, &net),
            frs(&write_values(&empty, &[], 3))
        );

        // read leaf 3 at a shared index (the index arrives as an arithmetic
        // share and is converted)
        let shared3 = indices_to_xor(
            &a,
            &[promote_to_trivial_share(id, Fr::from(3u64))],
            &net,
            &mut state,
        )
        .unwrap();
        assert_eq!(open_many(&shared3, &net), vec![3 as X]);
        let got3 = d.read_slot(&shared3[0], &net, &mut state).unwrap();
        assert_eq!(
            open_many_y(&got3.values, &net),
            frs(&expected_read(&with_3, &book, 3))
        );
        // and leaf 2, whose height-0 sibling is leaf 3's new hash
        let index2 = a.mask_path(&promote_public(id, 2 as X));
        let got2 = d.read_slot(&index2, &net, &mut state).unwrap();
        assert_eq!(
            open_many_y(&got2.values, &net),
            frs(&expected_read(&with_3, &book, 2))
        );
        // the values back as arithmetic shares open the same
        let fields = values_to_field(&got2.values, &net, &mut state).unwrap();
        assert_eq!(
            open_vec(&fields, &net).unwrap(),
            expected_read(&with_3, &book, 2)
        );

        // the journal of the write undoes it, the path nodes included: leaf 2's
        // siblings are the empty tree's again
        let journal = Journal {
            slots: vec![SlotJournal {
                reads: read.reads.clone(),
                old: read.raw.clone(),
                writes: writes3.clone(),
                old_writes: before.clone(),
            }],
        };
        let journal = Journal::from_bytes(&journal.to_bytes()).unwrap();
        assert!(journal.applied());
        d.undo(&journal, &net, &mut state).unwrap();
        let back = d.read_slot(&index3, &net, &mut state).unwrap();
        assert_eq!(open_many_y(&back.values, &net), opened_empty);
        let back2 = d.read_slot(&index2, &net, &mut state).unwrap();
        assert_eq!(
            open_many_y(&back2.values, &net),
            frs(&expected_read(&empty, &[], 2))
        );
        // a journal never applied cannot be undone
        let unapplied = Journal {
            slots: vec![SlotJournal {
                reads: read.reads.clone(),
                old: read.raw.clone(),
                writes: writes3.clone(),
                old_writes: vec![],
            }],
        };
        assert!(!unapplied.applied());
        assert!(d.undo(&unapplied, &net, &mut state).is_err());

        // the state survives a round trip through a store, and a write of
        // arithmetic shares converted lands too
        let store = MemoryStore::default();
        persist(&mut d, &store);
        let mut d2 = Doram::load(a, id, &store, Fr::from(NS), KEY_NAME)
            .unwrap()
            .unwrap();
        let shares: Vec<_> = write_values(&with_3, &book, 3)
            .iter()
            .map(|v| promote_to_trivial_share(id, *v))
            .collect();
        let values = field_to_values(&shares, &net, &mut state).unwrap();
        d2.write_slot(&writes3, &values, &net, &mut state).unwrap();
        let again = d2.read_slot(&index3, &net, &mut state).unwrap();
        assert_eq!(
            open_many_y(&again.values, &net),
            frs(&expected_read(&with_3, &book, 3))
        );
        blobs(&store)
    })
    .unwrap();
    // a head and the live levels, one sharing across the three parties: a
    // level's receiver shuffle is a copy at the builder's two neighbours
    assert!(results[0].iter().any(|(n, _)| n == "oram"));
    assert!(results[0].iter().any(|(n, _)| n.starts_with("oram.level.")));
    assert_one_sharing(&results);
    assert!(
        results
            .iter()
            .flatten()
            .any(|(n, b)| n.starts_with("oram.level.") && !b.copies.a.is_empty())
    );
}

/// A clear sparse tree of depth `D` over 64-bit paths: the leaves set, every
/// other node the empty subtree of its height.
struct ClearMap {
    depth: u32,
    leaf_len: usize,
    leaves: BTreeMap<u64, Vec<Fr>>,
    z: Vec<Fr>,
}

impl ClearMap {
    fn new(depth: u32, leaf_len: usize) -> Self {
        ClearMap {
            depth,
            leaf_len,
            leaves: BTreeMap::new(),
            z: zeros(depth),
        }
    }

    fn set(&mut self, path: u64, leaf: Vec<Fr>) {
        self.leaves.insert(path, leaf);
    }

    /// The node at `height` with `prefix` (the paths below it shifted).
    fn node_at(&self, height: u32, prefix: u64) -> Fr {
        let below = self.leaves.keys().any(|p| shr(*p, height) == prefix);
        if !below {
            return self.z[height as usize];
        }
        if height == 0 {
            return leaf_hash(Fr::from(NS), Fr::from(KEY), prefix, &self.leaves[&prefix]);
        }
        node(
            self.node_at(height - 1, prefix << 1),
            self.node_at(height - 1, (prefix << 1) | 1),
        )
    }

    fn root(&self) -> Fr {
        self.node_at(self.depth, 0)
    }

    /// A slot read of `path`: the siblings bottom up, the leaf hash, the leaf.
    fn read(&self, path: u64) -> Vec<Fr> {
        let mut out: Vec<Fr> = (0..self.depth)
            .map(|l| self.node_at(l, shr(path, l) ^ 1))
            .collect();
        out.push(self.node_at(0, path));
        match self.leaves.get(&path) {
            Some(leaf) => out.extend(leaf.iter().copied()),
            None => out.extend(vec![Fr::from(0u64); self.leaf_len]),
        }
        out
    }

    /// A slot write of `path`: the leaf, the leaf hash, the path nodes of
    /// heights 1 to D.
    fn write(&self, path: u64) -> Vec<Fr> {
        let mut out = match self.leaves.get(&path) {
            Some(leaf) => leaf.clone(),
            None => vec![Fr::from(0u64); self.leaf_len],
        };
        out.push(self.node_at(0, path));
        out.extend((1..=self.depth).map(|l| self.node_at(l, shr(path, l))));
        out
    }
}

/// `x >> l` with `x >> 64 = 0`.
fn shr(x: u64, l: u32) -> u64 {
    if l >= 64 { 0 } else { x >> l }
}

#[test]
fn the_keyed_map_holds_a_sparse_tree_of_depth_64() {
    let m = MapAddressing {
        depth: 64,
        leaf_len: 3,
        log_capacity: 8,
    };
    assert_eq!(m.reads_per_slot(), 68);
    // two keys of 254 bits whose paths (their low 64 bits) meet at height 10
    let k1 = Fr::from_be_bytes_mod_order(&[0x5a; 32]);
    let path1 = fr_low64(k1);
    let path2 = path1 ^ (1 << 10);
    let k2 = Fr::from(path2) + Fr::from(7u64) * Fr::from(1u128 << 64);
    assert_eq!(fr_low64(k2), path2);
    let path3 = path1 ^ 1; // the leaf next to k1: its height-0 sibling is k1's hash
    let leaf1 = vec![k1, Fr::from(42u64), Fr::from(1001u64)];
    let empty = ClearMap::new(64, 3);
    let mut with_1 = ClearMap::new(64, 3);
    with_1.set(path1, leaf1.clone());
    assert_ne!(with_1.root(), empty.root());

    let results = run_parties(|net| {
        let mut state = Rep3State::new(&net, A2BType::Direct).unwrap();
        let id = PartyID::try_from(net.id()).unwrap();
        let mut d = Doram::build_empty(m, &net, &mut state).unwrap();
        assert_eq!(d.capacity(), 256);
        assert_eq!(d.fill_count(), None);

        // the key arrives as an arithmetic share; its path is its low 64 bits
        let paths = indices_to_xor(
            &m,
            &[
                promote_to_trivial_share(id, k1),
                promote_to_trivial_share(id, k2),
            ],
            &net,
            &mut state,
        )
        .unwrap();
        assert_eq!(open_many(&paths, &net), vec![path1 as X, path2 as X]);

        // the empty map: an untouched path decodes to the empty tree (Z_l
        // siblings, hash 0, a zero leaf), while the DORAM returned zeros
        let read1 = d.read_slot(&paths[0], &net, &mut state).unwrap();
        assert_eq!(open_many_y(&read1.values, &net), frs(&empty.read(path1)));
        assert!(
            open_many_y(&read1.raw, &net)
                .iter()
                .all(|v| *v == <Fr as PrimeField>::BigInt::default()),
            "an address never written is 0 in the DORAM"
        );

        // insert k1: its leaf, hash and 64 path nodes
        let writes1 = m.slot_writes(id, &paths[0]);
        let values: Vec<_> = with_1
            .write(path1)
            .iter()
            .map(|v| promote_public_y(id, v.into_bigint()))
            .collect();
        let before = d.write_slot(&writes1, &values, &net, &mut state).unwrap();
        // the raw old values decode to the empty tree's write values
        let offsets = m.write_offsets();
        let decoded: Vec<_> = before
            .iter()
            .zip(&offsets)
            .map(|(v, k)| xor_public(id, v, &k.into_bigint()))
            .collect();
        assert_eq!(open_many_y(&decoded, &net), frs(&empty.write(path1)));

        // k1 is present: its leaf and a path to the new root
        let got1 = d.read_slot(&paths[0], &net, &mut state).unwrap();
        assert_eq!(open_many_y(&got1.values, &net), frs(&with_1.read(path1)));
        // k2 is absent, and its path meets k1's at height 10
        let got2 = d.read_slot(&paths[1], &net, &mut state).unwrap();
        let expected2 = with_1.read(path2);
        assert_eq!(open_many_y(&got2.values, &net), frs(&expected2));
        assert_eq!(expected2[10], with_1.node_at(10, path1 >> 10));
        assert_eq!(expected2[64], Fr::from(0u64), "an empty leaf's hash");
        assert_eq!(&expected2[65..], &[Fr::from(0u64); 3]);
        // the neighbour's height-0 sibling is k1's leaf hash
        let path3x = m.mask_path(&promote_public(id, path3 as X));
        let got3 = d.read_slot(&path3x, &net, &mut state).unwrap();
        let opened3 = open_many_y(&got3.values, &net);
        assert_eq!(opened3, frs(&with_1.read(path3)));
        assert_eq!(opened3[0], with_1.node_at(0, path1).into_bigint());
        // the values back as arithmetic shares open the same
        let fields = values_to_field(&got1.values, &net, &mut state).unwrap();
        assert_eq!(open_vec(&fields, &net).unwrap(), with_1.read(path1));

        // update k1 in place, then undo both writes newest first: the empty
        // map again, k2's path all Z
        let mut with_1b = ClearMap::new(64, 3);
        with_1b.set(path1, vec![k1, Fr::from(43u64), Fr::from(1002u64)]);
        let values_b: Vec<_> = with_1b
            .write(path1)
            .iter()
            .map(|v| promote_public_y(id, v.into_bigint()))
            .collect();
        let before_b = d.write_slot(&writes1, &values_b, &net, &mut state).unwrap();
        let got1b = d.read_slot(&paths[0], &net, &mut state).unwrap();
        assert_eq!(open_many_y(&got1b.values, &net), frs(&with_1b.read(path1)));
        let second = Journal {
            slots: vec![SlotJournal {
                reads: got1.reads.clone(),
                old: got1.raw.clone(),
                writes: writes1.clone(),
                old_writes: before_b,
            }],
        };
        let first = Journal {
            slots: vec![SlotJournal {
                reads: read1.reads.clone(),
                old: read1.raw.clone(),
                writes: writes1.clone(),
                old_writes: before,
            }],
        };
        d.undo(
            &Journal::from_bytes(&second.to_bytes()).unwrap(),
            &net,
            &mut state,
        )
        .unwrap();
        let back1 = d.read_slot(&paths[0], &net, &mut state).unwrap();
        assert_eq!(open_many_y(&back1.values, &net), frs(&with_1.read(path1)));
        d.undo(&first, &net, &mut state).unwrap();
        let back = d.read_slot(&paths[0], &net, &mut state).unwrap();
        assert_eq!(open_many_y(&back.values, &net), frs(&empty.read(path1)));
        let back2 = d.read_slot(&paths[1], &net, &mut state).unwrap();
        assert_eq!(open_many_y(&back2.values, &net), frs(&empty.read(path2)));

        // the state survives a round trip through bytes; the bottom rebuild
        // (every 248 accesses with a 256-entry cache and one level) has
        // opened the fill: the distinct addresses written so far
        let store = MemoryStore::default();
        persist(&mut d, &store);
        let mut d2 = Doram::load(m, id, &store, Fr::from(NS), KEY_NAME)
            .unwrap()
            .unwrap();
        assert_eq!(d2.fill_count(), d.fill_count());
        d2.write_slot(&writes1, &values, &net, &mut state).unwrap();
        let again = d2.read_slot(&paths[0], &net, &mut state).unwrap();
        assert_eq!(open_many_y(&again.values, &net), frs(&with_1.read(path1)));
        d2.fill_count()
    })
    .unwrap();
    for fill in results {
        // every access leaves a record (a read writes the value back), so the
        // fill counts k1's siblings, path nodes, hash and elements (132), the
        // addresses of k2's path below the meeting height and the neighbour's
        // own: about 150 distinct addresses, within the capacity of 256
        let fill = fill.expect("a bottom rebuild ran");
        assert!((132..=256).contains(&fill), "fill {fill}");
    }
}

/// The low 64 bits of a field element's canonical integer.
fn fr_low64(v: Fr) -> u64 {
    let big = v.into_bigint();
    let limbs: &[u64] = big.as_ref();
    limbs[0]
}

/// Three parties over a TCP mesh on loopback, as the nodes' TLS mesh frames
/// its messages (mpc-net's blocking transport and its default frame limit),
/// each running `f` on its own thread.
fn run_on_tcp_mesh<R, F>(f: F) -> [R; 3]
where
    R: Send,
    F: Fn(TcpNetwork) -> R + Sync,
{
    let ports: Vec<u16> = (0..3)
        .map(|_| {
            std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port()
        })
        .collect();
    let parties: Vec<NetworkParty> = ports
        .iter()
        .enumerate()
        .map(|(id, port)| NetworkParty::new(id, Address::new("127.0.0.1".into(), *port)))
        .collect();
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..3)
            .map(|id| {
                let config = NetworkConfig::builder(
                    id,
                    format!("127.0.0.1:{}", ports[id]).parse().unwrap(),
                    parties.clone(),
                )
                .connect_timeout(Duration::from_secs(30))
                .timeout(Duration::from_secs(600))
                .build();
                let f = &f;
                scope.spawn(move || f(TcpNetwork::new(config).unwrap()))
            })
            .collect();
        let mut out = handles.into_iter().map(|h| h.join().unwrap());
        [
            out.next().unwrap(),
            out.next().unwrap(),
            out.next().unwrap(),
        ]
    })
}

/// The dense DORAM at the depth the lending book runs at (16, leaves of 8)
/// over the framed mesh: its bottom level is built from every address in
/// messages larger than one frame may be, and the DORAM sends them below the
/// limit; the empty tree reads back, and a leaf's written path is the
/// sibling its neighbour reads. Persisted: the first commit writes the head
/// and every level; a later commit of one slot's read and write writes the
/// head (and only a level a rebuild replaced); the store's state reads back
/// to the same DORAM.
#[test]
fn the_dense_doram_builds_at_depth_16_over_the_tcp_mesh() {
    const D: u32 = 16;
    const LEAF: usize = 8;
    let a = Addressing::new(D, LEAF);
    let z = zeros(D);
    let leaf: Vec<Fr> = (1..=LEAF as u64).map(Fr::from).collect();
    let h5 = leaf_hash(Fr::from(NS), Fr::from(KEY), 5, &leaf);
    let sent = run_on_tcp_mesh(|net| {
        let mut state = Rep3State::new(&net, A2BType::Direct).unwrap();
        let id = PartyID::try_from(net.id()).unwrap();
        let mut d = Doram::build_empty(a, &net, &mut state).unwrap();
        let built = net
            .get_connection_stats()
            .iter()
            .map(|(_, (sent, _))| sent)
            .max()
            .unwrap();

        // leaf 5 of the empty tree: the zero subtrees, hash 0, zeros
        let index5 = a.mask_path(&promote_public(id, 5 as X));
        let read = d.read_slot(&index5, &net, &mut state).unwrap();
        let mut empty: Vec<Fr> = z[..D as usize].to_vec();
        empty.push(Fr::from(0u64));
        empty.extend(std::iter::repeat_n(Fr::from(0u64), LEAF));
        assert_eq!(open_many_y(&read.values, &net), frs(&empty));

        // write leaf 5's path; leaf 4 reads its hash as the height-0 sibling
        let mut path = leaf.clone();
        path.push(h5);
        let mut up = h5;
        for (h, zh) in z.iter().take(D as usize).enumerate() {
            up = if (5u32 >> h) & 1 == 1 {
                node(*zh, up)
            } else {
                node(up, *zh)
            };
            path.push(up);
        }
        let values: Vec<_> = path
            .iter()
            .map(|v| promote_public_y(id, v.into_bigint()))
            .collect();
        d.write_slot(&a.slot_writes(id, &index5), &values, &net, &mut state)
            .unwrap();
        let index4 = a.mask_path(&promote_public(id, 4 as X));
        let got4 = d.read_slot(&index4, &net, &mut state).unwrap();
        let opened = open_many_y(&got4.values, &net);
        assert_eq!(opened[0], h5.into_bigint());
        assert_eq!(opened[1..D as usize], frs(&z[1..D as usize])[..]);

        // the persisted state at this depth: the first commit writes every
        // level, the next (a round of one slot, no bottom rebuild) the head
        // and at most the small levels a rebuild replaced
        let store = MemoryStore::default();
        let first = persist(&mut d, &store);
        let sizes: Vec<(String, usize)> = blobs(&store)
            .into_iter()
            .map(|(n, b)| (n, b.len()))
            .collect();
        let index6 = a.mask_path(&promote_public(id, 6 as X));
        // a round's slot: its path read (every access writes its value back)
        d.read_slot(&index6, &net, &mut state).unwrap();
        let names_before: Vec<String> = sizes.iter().map(|(n, _)| n.clone()).collect();
        let next_writes: Vec<(String, usize)> = d
            .writes()
            .unwrap()
            .into_iter()
            .map(|(n, b)| (n, b.map_or(0, |b| b.len())))
            .collect();
        let later = persist(&mut d, &store);
        let mut back = Doram::load(a, id, &store, Fr::from(NS), KEY_NAME)
            .unwrap()
            .unwrap();
        let again = back.read_slot(&index4, &net, &mut state).unwrap();
        assert_eq!(open_many_y(&again.values, &net), opened);
        assert!(names_before.iter().any(|n| n == "oram"));
        let bottom = format!("oram.level.{}", a.config().num_levels - 1);
        assert!(names_before.contains(&bottom));
        assert!(
            next_writes.iter().all(|(n, _)| *n != bottom),
            "no bottom rebuild in one slot: {next_writes:?}"
        );
        (built, first, sizes, later, next_writes)
    });
    for (built, first, sizes, later, next_writes) in &sent {
        eprintln!(
            "depth 16: sent {built} bytes to the largest peer; first commit {first} bytes \
             {sizes:?}; a one-slot commit {later} bytes {next_writes:?}"
        );
        assert!(
            *later * 20 < *first,
            "a commit without a bottom rebuild writes the head"
        );
    }
    assert!(
        sent.iter()
            .all(|(s, ..)| *s > mpc_net::DEFAULT_MAX_FRAME_LENGTH),
        "the build sends more than one frame's worth to a peer: {sent:?}"
    );
}
