//! A layout's public bound on its DORAM's fill (docs/ARCHITECTURE.md section 6,
//! "The storage: one DORAM addressed by (height, prefix)", "Capacity and the fill
//! bound"): none for the dense tree, whose DORAM holds every address
//! from its first build ([`Unbounded`]); the keyed map's [`Fill`], checked
//! before a session's first DORAM access.
//!
//! A sparse DORAM keeps a record of every address it was ever asked for, read
//! or write (a read writes its value back into the speed cache), and its
//! bottom rebuild refuses a fill over the capacity. A refused rebuild fails
//! the round and the failed session is not persisted, so every later round
//! that reaches the same rebuild fails the same way. The bound keeps the
//! rebuild from ever being reached over the capacity: it counts the DORAM's
//! fill as opened at the last bottom rebuild plus every access since (each
//! may be a new address), and a session that would run the next bottom
//! rebuild while that count, with the session's accesses before it, could
//! pass the capacity is refused before it touches the DORAM.

use sidecar_core::error::Refusal;
use sidecar_core::field::Fr;
use sidecar_core::store::StoreRead;
use sidecar_core::store::blob::Blob;

use crate::oram::BlobWrite;

/// The blob of a keyed map's fill bound.
pub const FILL: &str = "fill";

/// When a DORAM's next bottom rebuild runs, in accesses: all public, and
/// equal at the three nodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schedule {
    /// The accesses before the next bottom rebuild: the access after them
    /// runs it, with every record the accesses up to it left.
    pub before_bottom: u64,
    /// The accesses from one bottom rebuild to the next.
    pub cycle: u64,
    /// The bottom level's capacity in records.
    pub capacity: u64,
}

/// A layout's bound on its DORAM's fill, kept beside the DORAM.
pub trait Bound: Copy + Send + Sync + 'static {
    /// The bound `store` holds for `key` (the start when none is held).
    fn load(store: &dyn StoreRead, ns: Fr, key: &str) -> Result<Self, Refusal>;
    /// Its public bytes, which the sync's handshake compares (empty when
    /// the layout keeps none).
    fn public(&self) -> Vec<u8>;
    /// Refuse a session of `accesses` DORAM accesses on a DORAM at
    /// `schedule` that the bound cannot admit; run before its first access.
    fn admit(&self, schedule: Schedule, accesses: u64, key: &str) -> Result<(), Refusal>;
    /// The bound after a session of `accesses`; `rebuilt` when it ran a
    /// bottom rebuild, which opened `fill_count`.
    fn after(self, rebuilt: bool, fill_count: Option<usize>, accesses: u64) -> Self;
    /// The blob write that persists it, if the layout keeps one.
    fn write(&self) -> Option<BlobWrite>;
}

/// The dense tree's bound: none, every address exists.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Unbounded;

impl Bound for Unbounded {
    fn load(_: &dyn StoreRead, _: Fr, _: &str) -> Result<Self, Refusal> {
        Ok(Unbounded)
    }

    fn public(&self) -> Vec<u8> {
        vec![]
    }

    fn admit(&self, _: Schedule, _: u64, _: &str) -> Result<(), Refusal> {
        Ok(())
    }

    fn after(self, _: bool, _: Option<usize>, _: u64) -> Self {
        self
    }

    fn write(&self) -> Option<BlobWrite> {
        None
    }
}

/// A keyed map's public fill bound (the `fill` blob): the distinct
/// addresses its DORAM may hold.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fill {
    /// The DORAM's fill count at the bottom rebuild this bound counts from
    /// (0 before the first).
    pub at_rebuild: u64,
    /// The DORAM accesses since, reads and writes, every one counted as a new
    /// address.
    pub accesses_since: u64,
}

impl Fill {
    fn bytes(self) -> Vec<u8> {
        let mut out = self.at_rebuild.to_le_bytes().to_vec();
        out.extend_from_slice(&self.accesses_since.to_le_bytes());
        out
    }

    pub fn to_bytes(self) -> Vec<u8> {
        Blob::public(self.bytes()).to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Refusal> {
        let blob = Blob::from_bytes(bytes)?;
        let bytes = blob.public.as_slice();
        if bytes.len() != 16 || blob.len() != 16 {
            return Err(Refusal::mpc_failure(
                "oblivious tree: the fill bound is malformed",
            ));
        }
        Ok(Fill {
            at_rebuild: u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            accesses_since: u64::from_le_bytes(bytes[8..].try_into().unwrap()),
        })
    }

    /// The most distinct addresses the DORAM can hold now.
    pub fn bound(self) -> u64 {
        self.at_rebuild.saturating_add(self.accesses_since)
    }
}

/// Why a session is refused: it would run a bottom rebuild that could hold
/// more than the capacity, or two bottom rebuilds (the second's count
/// cannot be bounded before the first opens its own).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// The next bottom rebuild could hold this many distinct addresses.
    Full(u64),
    TwoRebuilds,
}

/// Whether a session of `accesses` on a DORAM whose fill is at most `bound`
/// now keeps every bottom rebuild it runs within the capacity: a session
/// that ends before the next bottom rebuild runs none; one that runs it
/// brings `schedule.before_bottom` more accesses into it, each possibly a
/// new address.
pub fn admit(bound: u64, schedule: Schedule, accesses: u64) -> Result<(), Refused> {
    if accesses <= schedule.before_bottom {
        return Ok(());
    }
    if accesses - schedule.before_bottom > schedule.cycle {
        return Err(Refused::TwoRebuilds);
    }
    let at_rebuild = bound.saturating_add(schedule.before_bottom);
    if at_rebuild > schedule.capacity {
        return Err(Refused::Full(at_rebuild));
    }
    Ok(())
}

impl Bound for Fill {
    fn load(store: &dyn StoreRead, ns: Fr, key: &str) -> Result<Self, Refusal> {
        match store.blob(ns, key, FILL)? {
            Some(bytes) => Fill::from_bytes(&bytes),
            None => Ok(Fill::default()),
        }
    }

    fn public(&self) -> Vec<u8> {
        self.bytes()
    }

    fn admit(&self, schedule: Schedule, accesses: u64, key: &str) -> Result<(), Refusal> {
        admit(self.bound(), schedule, accesses).map_err(|refused| match refused {
            Refused::Full(at_rebuild) => Refusal::conflict(format!(
                "key `{key}`: the keyed map is full: its DORAM's next bottom rebuild could hold \
                 {at_rebuild} distinct addresses (every access since the last one counted as \
                 new), over its capacity of {}; the round is refused before it touches the \
                 DORAM. The map takes no new keys (a keyed map has no grow path)",
                schedule.capacity
            )),
            Refused::TwoRebuilds => Refusal::conflict(format!(
                "key `{key}`: the round's {accesses} DORAM accesses span two bottom rebuilds of \
                 the keyed map (one every {} accesses): its capacity is too small for the round",
                schedule.cycle
            )),
        })
    }

    /// Restarted from the opened count when the session ran a bottom
    /// rebuild (all its accesses counted after it, a bound on those that
    /// were), else grown by the session's accesses.
    fn after(self, rebuilt: bool, fill_count: Option<usize>, accesses: u64) -> Self {
        if rebuilt {
            Fill {
                at_rebuild: fill_count.unwrap_or(0) as u64,
                accesses_since: accesses,
            }
        } else {
            Fill {
                accesses_since: self.accesses_since.saturating_add(accesses),
                ..self
            }
        }
    }

    fn write(&self) -> Option<BlobWrite> {
        Some((FILL.to_string(), Some(self.to_bytes())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::MapAddressing;
    use crate::oram::Doram;
    use mpc_core::protocols::rep3::Rep3State;
    use mpc_core::protocols::rep3::conversion::A2BType;
    use primitives::{X, XShare, promote_public, run_parties};
    use sidecar_core::error::ErrorClass;

    #[test]
    fn the_fill_bound_restarts_at_a_rebuild_and_round_trips() {
        let f = Fill {
            at_rebuild: 0,
            accesses_since: 200,
        };
        assert_eq!(f.after(false, None, 50).bound(), 250, "no rebuild");
        let after = f.after(true, Some(150), 30);
        assert_eq!((after.at_rebuild, after.accesses_since), (150, 30));
        assert_eq!(Fill::from_bytes(&after.to_bytes()).unwrap(), after);
        assert!(Fill::from_bytes(&[0; 15]).is_err());
    }

    /// The guard's arithmetic: a session that ends before the bottom rebuild
    /// is admitted whatever the bound; one that runs it is admitted while the
    /// bound and its accesses before the rebuild fit the capacity.
    #[test]
    fn a_session_that_runs_the_bottom_rebuild_is_bounded() {
        let s = Schedule {
            before_bottom: 100,
            cycle: 248,
            capacity: 256,
        };
        assert_eq!(admit(250, s, 100), Ok(()), "the rebuild is not reached");
        assert_eq!(admit(156, s, 101), Ok(()), "156 + 100 = 256 fits");
        assert_eq!(admit(157, s, 101), Err(Refused::Full(257)));
        assert_eq!(admit(0, s, 100 + 248), Ok(()));
        assert_eq!(admit(0, s, 100 + 249), Err(Refused::TwoRebuilds));
    }

    /// The guard over a real keyed map's DORAM of capacity 2^8 (one level:
    /// a speed cache of 256 entries, 8 of them the stash, so a bottom rebuild
    /// every 248 accesses), in rounds of 40 accesses to addresses never
    /// asked for (reads: each leaves a record as a write does). The schedule
    /// names the access that runs each bottom rebuild. Seven rounds reach
    /// the first bottom rebuild with 248 addresses, within the capacity, and
    /// are admitted; five more fit before the next one; the round that would
    /// run it is refused (the map is full), and run anyway, its bottom
    /// rebuild overflows the capacity.
    #[test]
    fn the_guard_refuses_the_round_before_a_bottom_rebuild_overflows() {
        let m = MapAddressing::new(32, 3, 8);
        const ROUND: u64 = 40;
        let results = run_parties(|net| {
            let mut state = Rep3State::new(&net, A2BType::Direct).unwrap();
            let id = state.id;
            let mut doram = Doram::build_empty(m, &net, &mut state).unwrap();
            assert_eq!(
                doram.schedule(),
                Schedule {
                    before_bottom: 248,
                    cycle: 248,
                    capacity: 256
                }
            );
            let mut fill = Fill::default();
            let mut rounds = vec![];
            for r in 0..20u64 {
                let schedule = doram.schedule();
                let addrs: Vec<XShare> = (r * ROUND..(r + 1) * ROUND)
                    .map(|a| promote_public(id, a as X))
                    .collect();
                if let Err(refused) = fill.admit(schedule, ROUND, "k") {
                    let overflow = doram.read_raw(&addrs, &net, &mut state).err().unwrap();
                    return (rounds, refused, overflow);
                }
                let bottom = doram.bottom_stamp();
                doram.read_raw(&addrs, &net, &mut state).unwrap();
                let rebuilt = doram.bottom_stamp() != bottom;
                assert_eq!(rebuilt, ROUND > schedule.before_bottom, "round {r}");
                fill = fill.after(rebuilt, doram.fill_count(), ROUND);
                rounds.push((rebuilt, doram.fill_count()));
            }
            panic!("the guard never refused");
        })
        .unwrap();
        for (rounds, refused, overflow) in results {
            assert_eq!(rounds.len(), 12, "{rounds:?}");
            assert_eq!(
                rounds.iter().filter(|(rebuilt, _)| *rebuilt).count(),
                1,
                "one bottom rebuild"
            );
            assert_eq!(rounds[6], (true, Some(248)));
            assert_eq!(refused.class, ErrorClass::Conflict, "{refused}");
            assert!(
                refused.message.contains("the keyed map is full"),
                "{refused}"
            );
            assert!(overflow.message.contains("over its capacity"), "{overflow}");
        }
    }
}
