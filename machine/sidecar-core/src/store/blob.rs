//! The format of a `tip_blobs` row, which the recovery paths carry without
//! knowing whose state it is (docs/ARCHITECTURE.md section 6, "Node-held
//! state"; the oblivious tree's DORAM, docs/ARCHITECTURE.md section
//! 6, "Persistence, resync, share refresh, audit"):
//!
//! ```text
//! public   bytes equal at the three nodes (shapes, counters, lists)
//! shares   two byte streams a and b of equal length: node j's components x_j and x_{j-1}
//!          of Rep3 XOR shares, element after element in the same order and widths at
//!          the three nodes, so node j's a is node j+1's b, and the three nodes' a
//!          streams XOR to the values
//! copies   two byte streams a and b, placed by the same rule, of values two nodes hold
//!          alike and the third does not (not XOR shares: a refresh leaves them)
//! ```
//!
//! So a node replacement's refresh XORs fresh masks into `shares` (crate::replace),
//! a resync rebuilds a node's blob from the component each neighbour shares with
//! it (`a` from node `i + 1`'s `b`, `b` from node `i - 1`'s `a`, the public bytes
//! equal at both), and a backup carries the bytes as they are. A holder writes
//! every blob in this format and reads its own bytes back; the store never
//! interprets them.

use crate::error::Refusal;
use crate::request::next;

/// The format's version byte, first in every blob.
const VERSION: u8 = 1;

/// One node's two components of a blob section (module documentation).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pair {
    pub a: Vec<u8>,
    pub b: Vec<u8>,
}

impl Pair {
    /// The component node `from` shares with node `to`: its `b` (`x_to`)
    /// when it is the node after `to`, else its `a` (`x_{to-1}`).
    pub fn component(&self, from: usize, to: usize) -> &[u8] {
        if from == next(to) { &self.b } else { &self.a }
    }
}

/// One `tip_blobs` row as its holder wrote it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Blob {
    pub public: Vec<u8>,
    pub shares: Pair,
    pub copies: Pair,
}

/// What node `from` sends node `to` of one blob: the public bytes and the
/// component of each section it shares with `to`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Part {
    pub public: Vec<u8>,
    pub shares: Vec<u8>,
    pub copies: Vec<u8>,
}

fn malformed(why: &str) -> Refusal {
    Refusal::mpc_failure(format!("store: a holder blob is malformed ({why})"))
}

impl Blob {
    /// A blob of public bytes only.
    pub fn public(public: Vec<u8>) -> Blob {
        Blob {
            public,
            ..Blob::default()
        }
    }

    /// The blob's size in bytes, as stored less the framing.
    pub fn len(&self) -> usize {
        self.public.len()
            + self.shares.a.len()
            + self.shares.b.len()
            + self.copies.a.len()
            + self.copies.b.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 5 * 8 + self.len());
        out.push(VERSION);
        for part in [
            &self.public,
            &self.shares.a,
            &self.shares.b,
            &self.copies.a,
            &self.copies.b,
        ] {
            out.extend_from_slice(&(part.len() as u64).to_le_bytes());
            out.extend_from_slice(part);
        }
        out
    }

    /// The blob `to_bytes` wrote; 500 for bytes of another shape (a store
    /// that holds something else under the name), or share streams of
    /// different lengths.
    pub fn from_bytes(bytes: &[u8]) -> Result<Blob, Refusal> {
        let (version, mut rest) = bytes.split_first().ok_or_else(|| malformed("empty"))?;
        if *version != VERSION {
            return Err(malformed(&format!("format version {version}")));
        }
        let mut take = || -> Result<Vec<u8>, Refusal> {
            if rest.len() < 8 {
                return Err(malformed("truncated"));
            }
            let (len, tail) = rest.split_at(8);
            let len = u64::from_le_bytes(len.try_into().expect("8 bytes"));
            let len = usize::try_from(len)
                .ok()
                .filter(|n| *n <= tail.len())
                .ok_or_else(|| malformed("truncated"))?;
            let (part, tail) = tail.split_at(len);
            rest = tail;
            Ok(part.to_vec())
        };
        let blob = Blob {
            public: take()?,
            shares: Pair {
                a: take()?,
                b: take()?,
            },
            copies: Pair {
                a: take()?,
                b: take()?,
            },
        };
        if !rest.is_empty() {
            return Err(malformed("trailing bytes"));
        }
        if blob.shares.a.len() != blob.shares.b.len() {
            return Err(malformed("share streams of different lengths"));
        }
        Ok(blob)
    }

    /// What node `from` sends node `to` ([`Part`]).
    pub fn part(&self, from: usize, to: usize) -> Part {
        Part {
            public: self.public.clone(),
            shares: self.shares.component(from, to).to_vec(),
            copies: self.copies.component(from, to).to_vec(),
        }
    }

    /// A node's blob from what its neighbours sent: `from_next` (node
    /// `i + 1`, its `b` components, `x_i`) and `from_prev` (node `i - 1`,
    /// its `a` components, `x_{i-1}`). 400 when the public bytes differ or
    /// the share components have different lengths.
    pub fn rebuild(from_next: Part, from_prev: Part) -> Result<Blob, Refusal> {
        if from_next.public != from_prev.public {
            return Err(Refusal::bad_request(
                "the two neighbours' public parts of a holder blob differ",
            ));
        }
        if from_next.shares.len() != from_prev.shares.len() {
            return Err(Refusal::bad_request(
                "the two neighbours' share components of a holder blob have different lengths",
            ));
        }
        Ok(Blob {
            public: from_next.public,
            shares: Pair {
                a: from_next.shares,
                b: from_prev.shares,
            },
            copies: Pair {
                a: from_next.copies,
                b: from_prev.copies,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::{NODES, prev};

    /// Node j's blob of the values `x = x_0 ^ x_1 ^ x_2` (bytewise), with a
    /// copy held by nodes 1 and 2 (component 1).
    fn dealt(x: [&[u8]; 3], copy: &[u8]) -> [Blob; NODES] {
        [0, 1, 2].map(|j| Blob {
            public: b"shape".to_vec(),
            shares: Pair {
                a: x[j].to_vec(),
                b: x[prev(j)].to_vec(),
            },
            copies: Pair {
                a: if j == 1 { copy.to_vec() } else { vec![] },
                b: if j == 2 { copy.to_vec() } else { vec![] },
            },
        })
    }

    #[test]
    fn a_blob_round_trips_and_is_rebuilt_from_its_neighbours() {
        let blobs = dealt([&[1, 2], &[3, 4], &[5, 6]], &[9, 9, 9]);
        for (j, blob) in blobs.iter().enumerate() {
            assert_eq!(Blob::from_bytes(&blob.to_bytes()).unwrap(), *blob);
            let rebuilt = Blob::rebuild(
                blobs[next(j)].part(next(j), j),
                blobs[prev(j)].part(prev(j), j),
            )
            .unwrap();
            assert_eq!(rebuilt, *blob, "node {j}");
        }
        let bytes = blobs[0].to_bytes();
        assert!(Blob::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        assert!(Blob::from_bytes(&[2]).is_err());
        let mut other = blobs[2].part(2, 0);
        other.public = b"other".to_vec();
        assert!(Blob::rebuild(blobs[1].part(1, 0), other).is_err());
    }
}
