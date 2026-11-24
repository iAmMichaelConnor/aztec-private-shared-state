//! The tip follower: a Rust port of the block-hash comparison in aztec's
//! `L2BlockStream` (stdlib `block/l2_block_stream/l2_block_stream.js`,
//! `work` and `areBlockHashesEqualAt`). It keeps `(number, hash)` for the
//! followed blocks from the settled block up to the followed tip. Each poll
//! reads the node's four tips, walks back from the top of what it keeps to
//! the highest block on which both sides agree, and reports a [`Prune`]
//! when that block is below the top; after a walk-back it reads the tips
//! again and follows from the fresh ones, as `L2BlockStream` does; after
//! reading the blocks below a new tip one call each, it reads the tip
//! block's hash again and fails the poll, keeping none of them, when it is
//! no longer the tips' (`L2BlockStream`'s check of the delivered tip). The
//! settled block is the node's finalized tip (the block whose proof's L1
//! transaction is final, below which nothing is ever replaced), the floor
//! `L2BlockStream` walks back to, once the follower has seen it move. A
//! replacement that reaches below what it keeps is reported with
//! `below_kept`, and its consumer reloads from the chain.
//!
//! RPC methods (Aztec node 6.0.0, `@aztec-labs/stdlib`
//! `interfaces/aztec-node.d.ts`; sidecar-tip's `tests/fixtures/logs.json`
//! records a local network's answers):
//! - `node_getChainTips([])` → `{proposed: {number, hash}, checkpointed:
//!   {block: {number, hash}, checkpoint: {number, hash}}, proven: {block,
//!   checkpoint}, finalized: {block, checkpoint}}`. The node keeps
//!   finalized ≤ proven ≤ checkpointed ≤ proposed; an answer out of that
//!   order is refused ([`ReadError::Malformed`]).
//! - `node_getBlockData([n])` → `{header, archive, blockHash,
//!   checkpointNumber, indexWithinCheckpoint}`, or null for a block the node
//!   does not have.

use std::collections::BTreeMap;

use serde_json::{Value, json};
use sidecar_core::Fr;
use sidecar_core::field::fr_to_hex;

use super::ReadError;
use super::rpc::{Transport, call, field, malformed, number};

/// A block on the followed chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockId {
    pub number: u64,
    pub hash: Fr,
}

impl std::fmt::Display for BlockId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.number, fr_to_hex(self.hash))
    }
}

/// The node's four chain tips, each a block (`node_getChainTips`):
/// `proposed` the latest block it has, `checkpointed` the latest whose
/// checkpoint is on L1, `proven` the latest whose checkpoint has a proof on
/// L1, `finalized` the latest whose proof's L1 transaction is final.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tips {
    pub proposed: BlockId,
    pub checkpointed: BlockId,
    pub proven: BlockId,
    pub finalized: BlockId,
}

/// Blocks the follower held were replaced: every block above `to` up to
/// `from`, and everything read from them, is void.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prune {
    /// The highest block the follower held before.
    pub from: u64,
    /// The highest block both sides agree on; with `below_kept`, the block
    /// below the lowest one the follower kept, which it never compared.
    pub to: u64,
    /// The replacement reached below every block the follower kept (the
    /// settled block's, or the first block it followed): blocks at or
    /// below `to` may be replaced too, so a consumer reloads from the
    /// chain.
    pub below_kept: bool,
}

impl Prune {
    /// Whether a read made at `block` read a replaced block (or the chain
    /// below one: a log query up to `block` saw every block under it): any
    /// block above `to`, and with `below_kept` every block, since the
    /// replacement may reach below what the follower kept. A consumer that kept what it
    /// built on reads at `block` drops it.
    pub fn voids(&self, block: u64) -> bool {
        self.below_kept || block > self.to
    }

    /// One prune covering `self` and the later `next`: from the higher
    /// top, to the lower agreement.
    fn merge(self, next: Prune) -> Prune {
        Prune {
            from: self.from.max(next.from),
            to: self.to.min(next.to),
            below_kept: self.below_kept || next.below_kept,
        }
    }
}

impl std::fmt::Display for Prune {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.below_kept {
            write!(
                f,
                "the followed chain went back from block {} below every block hash kept (to {} or below)",
                self.from, self.to
            )
        } else {
            write!(
                f,
                "the followed chain went back from block {} to {}: the blocks after {} were replaced",
                self.from, self.to, self.to
            )
        }
    }
}

/// One poll's outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Poll {
    /// The followed tip after the poll.
    pub tip: BlockId,
    /// The node's four tips, as the poll last read them.
    pub tips: Tips,
    /// Blocks the follower held that the node replaced since the last poll
    /// that reported one.
    pub prune: Option<Prune>,
}

/// The tip follower over one node.
///
/// It keeps `(number, hash)` for every block it followed from the settled
/// block up to the followed tip, so a replacement anywhere above the
/// settled block is placed exactly: the prune voids the reads made above
/// the last block both chains share. Only one that reaches the settled
/// block or below is `below_kept`, and none can there but an answer that
/// contradicts the node's own finality. The settled block is the node's
/// finalized tip once the follower has seen it move above the one its
/// first poll read; until then it is 0 and the follower keeps every block
/// since its first poll, so a fresh follower deletes nothing on the word
/// of a single answer. Between two polls it reads the hash of every block
/// in between, except the blocks below the current proven tip after a long
/// gap (an idle reader): no read was made at them, a replacement there is
/// placed at the highest block it kept below them, deeper than the true
/// point and never shallower, and the fill stays bounded by the unproven
/// blocks. A prune a poll found before it failed is reported by the next
/// poll that succeeds. Its memory is bounded by the blocks between the
/// finalized tip and the tip, and grows, with nothing dropped, while
/// finality stalls ([`Self::retained`]; the chain reader logs and reports
/// it).
#[derive(Clone, Debug, Default)]
pub struct Follower {
    /// The blocks kept, by number: from the floor up, contiguous except
    /// across a stretch at or below the proven tip that no poll read.
    blocks: BTreeMap<u64, Fr>,
    /// The tips the last poll read.
    tips: Option<Tips>,
    /// The finalized tip the first poll read.
    first_finalized: Option<u64>,
    /// A prune found by a poll that then failed, not reported yet.
    pending: Option<Prune>,
}

impl Follower {
    pub fn new() -> Self {
        Follower::default()
    }

    /// The highest block followed.
    pub fn tip(&self) -> Option<BlockId> {
        self.blocks
            .last_key_value()
            .map(|(&number, &hash)| BlockId { number, hash })
    }

    /// The lowest block kept.
    pub fn lowest(&self) -> Option<u64> {
        self.blocks.first_key_value().map(|(&n, _)| n)
    }

    /// The node's four tips at the last poll; `None` before the first.
    pub fn tips(&self) -> Option<Tips> {
        self.tips
    }

    /// The node's proven tip at the last poll; 0 before the first.
    pub fn proven(&self) -> u64 {
        self.tips.map_or(0, |t| t.proven.number)
    }

    /// The settled block: the node's finalized tip at the last poll, once
    /// it is above the finalized tip of the first poll; else 0. The floor
    /// of the blocks kept, of node-held version retention and of what a
    /// node deletes by its chain view. A finalized tip that goes back
    /// lowers it with it.
    pub fn settled(&self) -> u64 {
        match (self.first_finalized, self.tips) {
            (Some(first), Some(t)) if t.finalized.number > first => t.finalized.number,
            _ => 0,
        }
    }

    /// How many block hashes the follower keeps.
    pub fn retained(&self) -> usize {
        self.blocks.len()
    }

    /// The hash kept for block `number`.
    pub fn hash_at(&self, number: u64) -> Option<Fr> {
        self.blocks.get(&number).copied()
    }

    /// Note the tips a poll read.
    fn observe(&mut self, tips: Tips) {
        self.first_finalized.get_or_insert(tips.finalized.number);
        self.tips = Some(tips);
    }

    /// Read the node's tips, report a replacement of blocks the follower
    /// keeps, extend what it keeps to the tip and drop the blocks below the
    /// settled block. A prune found before a later read of the poll fails
    /// is kept and reported by the next poll that succeeds.
    pub async fn poll<T: Transport + ?Sized>(&mut self, node: &T) -> Result<Poll, ReadError> {
        let mut tips = chain_tips(node).await?;
        self.observe(tips);
        let Some(top) = self.tip() else {
            self.blocks.insert(tips.proposed.number, tips.proposed.hash);
            return Ok(Poll {
                tip: tips.proposed,
                tips,
                prune: self.pending.take(),
            });
        };
        let source = tips.proposed;
        // the node's hashes read in this poll, seeded with its tip only (as
        // L2BlockStream seeds its cache)
        let mut theirs = BTreeMap::from([(source.number, source.hash)]);
        let mut below = Some(top.number);
        let mut lowest = top.number;
        let mut agreed = None;
        while let Some(upto) = below {
            let Some((&at, &ours)) = self.blocks.range(..=upto).next_back() else {
                break;
            };
            lowest = at;
            let hash = match theirs.get(&at) {
                Some(h) => Some(*h),
                None => block_hash(node, at).await?,
            };
            match hash {
                Some(h) => {
                    theirs.insert(at, h);
                    if h == ours {
                        agreed = Some(at);
                        break;
                    }
                }
                // no block above the node's tip compares unequal; none at or
                // below it means the node contradicts itself
                None if at <= source.number => {
                    return Err(ReadError::Unsettled {
                        block: at,
                        tip: source.number,
                    });
                }
                None => {}
            }
            below = at.checked_sub(1);
        }
        let prune = match agreed {
            Some(n) if n == top.number => None,
            Some(n) => Some(Prune {
                from: top.number,
                to: n,
                below_kept: false,
            }),
            None => Some(Prune {
                from: top.number,
                to: lowest.saturating_sub(1).min(source.number),
                below_kept: true,
            }),
        };
        if let Some(p) = prune {
            if p.below_kept {
                self.blocks.clear();
            } else {
                self.blocks.split_off(&(p.to + 1));
            }
            self.pending = Some(self.pending.map_or(p, |q| q.merge(p)));
            // the node's tips may have moved on during the walk: follow
            // from fresh ones (L2BlockStream reads them again too)
            tips = chain_tips(node).await?;
            self.observe(tips);
            theirs = BTreeMap::from([(tips.proposed.number, tips.proposed.hash)]);
        }
        self.extend(node, tips, &theirs).await?;
        Ok(Poll {
            tip: tips.proposed,
            tips,
            prune: self.pending.take(),
        })
    }

    /// Add the blocks after the top kept up to the proposed tip, each with
    /// its hash, from no lower than the proven tip (the blocks below it that
    /// no poll read are skipped), then drop the blocks below the settled
    /// block, keeping the top.
    async fn extend<T: Transport + ?Sized>(
        &mut self,
        node: &T,
        tips: Tips,
        theirs: &BTreeMap<u64, Fr>,
    ) -> Result<(), ReadError> {
        let source = tips.proposed;
        match self.tip() {
            Some(top) if top.number > source.number => {
                // agreement at a block above the node's tip: the node moved on
                // between its two answers
                return Err(ReadError::Unsettled {
                    block: top.number,
                    tip: source.number,
                });
            }
            Some(top) => {
                let from = (top.number + 1).max(tips.proven.number.min(source.number));
                let mut filled = BTreeMap::new();
                let mut read = false;
                for n in from..source.number {
                    let hash = match theirs.get(&n) {
                        Some(h) => *h,
                        None => {
                            read = true;
                            block_hash(node, n).await?.ok_or(ReadError::Unsettled {
                                block: n,
                                tip: source.number,
                            })?
                        }
                    };
                    filled.insert(n, hash);
                }
                // The blocks were read one call each after the tips: a node
                // that switched fork in between gave some from the old fork.
                // The tip block's hash read again after them must still be
                // the tips' (L2BlockStream checks the same), or the poll
                // fails and keeps none of them.
                if read && block_hash(node, source.number).await? != Some(source.hash) {
                    return Err(ReadError::Unsettled {
                        block: source.number,
                        tip: source.number,
                    });
                }
                self.blocks.append(&mut filled);
                self.blocks.insert(source.number, source.hash);
            }
            None => {
                self.blocks.insert(source.number, source.hash);
            }
        }
        let floor = self.settled().min(source.number);
        self.blocks = self.blocks.split_off(&floor);
        Ok(())
    }
}

/// The node's four tips, refused unless finalized ≤ proven ≤ checkpointed ≤
/// proposed (the order the node keeps them in). The follower follows
/// proposed blocks: about one block every 6 s, the latency the tip is built
/// for (docs/DECISIONS.md, "The chain reader follows proposed blocks"), at
/// the price of replaced blocks; the chain reader's pinned reads simulate on
/// the latest proposed block.
pub async fn chain_tips<T: Transport + ?Sized>(node: &T) -> Result<Tips, ReadError> {
    const METHOD: &str = "node_getChainTips";
    let answer = call(node, METHOD, json!([])).await?;
    let block = |pointer: &str| -> Result<BlockId, ReadError> {
        let tip = answer
            .pointer(pointer)
            .ok_or_else(|| malformed(METHOD, format!("no {pointer} in {answer}")))?;
        Ok(BlockId {
            number: number(METHOD, tip, "number")?,
            hash: field(METHOD, tip.get("hash").unwrap_or(&Value::Null))?,
        })
    };
    let tips = Tips {
        proposed: block("/proposed")?,
        checkpointed: block("/checkpointed/block")?,
        proven: block("/proven/block")?,
        finalized: block("/finalized/block")?,
    };
    let ordered = tips.finalized.number <= tips.proven.number
        && tips.proven.number <= tips.checkpointed.number
        && tips.checkpointed.number <= tips.proposed.number;
    if !ordered {
        return Err(malformed(
            METHOD,
            format!(
                "the tips are out of order: proposed {}, checkpointed {}, proven {}, finalized {} \
                 (the node keeps finalized <= proven <= checkpointed <= proposed)",
                tips.proposed.number,
                tips.checkpointed.number,
                tips.proven.number,
                tips.finalized.number
            ),
        ));
    }
    Ok(tips)
}

/// The hash of block `number` on the node's chain; `None` when the node has
/// no such block.
pub async fn block_hash<T: Transport + ?Sized>(
    node: &T,
    number: u64,
) -> Result<Option<Fr>, ReadError> {
    const METHOD: &str = "node_getBlockData";
    let answer = call(node, METHOD, json!([number])).await?;
    if answer.is_null() {
        return Ok(None);
    }
    field(METHOD, answer.get("blockHash").unwrap_or(&Value::Null)).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::rpc::RpcError;
    use crate::testing::{FixtureTransport, MemoryNode};
    use std::sync::Mutex;

    fn kept(f: &Follower) -> Vec<u64> {
        f.blocks.keys().copied().collect()
    }

    #[tokio::test]
    async fn a_follower_keeps_every_block_back_to_the_settled_block() {
        let node = MemoryNode::new(10);
        let mut f = Follower::new();
        let poll = f.poll(&node).await.unwrap();
        assert_eq!((poll.tip.number, poll.prune), (10, None));
        assert_eq!(poll.tip.hash, node.hash(10));
        node.set_tip(13);
        let poll = f.poll(&node).await.unwrap();
        assert_eq!((poll.tip.number, poll.prune), (13, None));
        assert_eq!(kept(&f), [10, 11, 12, 13]);
        assert_eq!(f.hash_at(12), Some(node.hash(12)));
        // a proof lands; the finalized tip has not moved: nothing is dropped
        node.set_proven(12);
        node.set_tip(14);
        f.poll(&node).await.unwrap();
        assert_eq!((f.proven(), f.settled()), (12, 0));
        assert_eq!(kept(&f), [10, 11, 12, 13, 14]);
        // the next proof finalizes block 12: the blocks below it go
        node.set_proven(13);
        node.set_tip(15);
        f.poll(&node).await.unwrap();
        assert_eq!((f.proven(), f.settled()), (13, 12));
        assert_eq!(kept(&f), [12, 13, 14, 15]);
        assert_eq!(f.retained(), 4);
        // an unchanged tip costs one call
        let before = node.calls("node_getBlockData");
        f.poll(&node).await.unwrap();
        assert_eq!(node.calls("node_getBlockData"), before);
        // a long gap (an idle reader) is filled from the proven tip up; the
        // unread blocks at or below it are skipped
        node.set_proven(35);
        node.set_tip(40);
        let before = node.calls("node_getBlockData");
        f.poll(&node).await.unwrap();
        assert_eq!(
            node.calls("node_getBlockData") - before,
            7,
            "block 15 checked, 35 to 39 filled, 40 read again"
        );
        assert_eq!(kept(&f), [13, 14, 15, 35, 36, 37, 38, 39, 40]);
        assert_eq!(f.hash_at(20), None);
        // a replacement in the skipped stretch is placed at the highest block
        // kept below it, deeper than the true point and never shallower: no
        // read was made in between
        node.replace_from(20);
        let prune = f.poll(&node).await.unwrap().prune.unwrap();
        assert_eq!(
            prune,
            Prune {
                from: 40,
                to: 15,
                below_kept: false
            }
        );
        assert_eq!(kept(&f), [13, 14, 15, 35, 36, 37, 38, 39, 40]);
        assert_eq!(f.hash_at(36), Some(node.hash(36)));
    }

    #[tokio::test]
    async fn a_finality_stall_grows_what_the_follower_keeps_and_drops_nothing() {
        let node = MemoryNode::new(100);
        node.set_proven(90);
        let mut f = Follower::new();
        f.poll(&node).await.unwrap();
        node.set_proven(95);
        node.set_tip(101);
        f.poll(&node).await.unwrap();
        assert_eq!(f.settled(), 90);
        // the finalized tip stays at 90 for 400 blocks
        for tip in (110..=500).step_by(10) {
            node.set_tip(tip);
            assert_eq!(f.poll(&node).await.unwrap().prune, None);
        }
        assert_eq!(f.retained(), 401, "blocks 100 to 500");
        assert_eq!(f.lowest(), Some(100));
        // a replacement deep in the stall is still placed exactly
        node.replace_from(150);
        let prune = f.poll(&node).await.unwrap().prune.unwrap();
        assert_eq!((prune.to, prune.below_kept), (149, false));
        // finality resumes: two proofs bring the floor up
        node.set_proven(400);
        f.poll(&node).await.unwrap();
        assert_eq!(f.lowest(), Some(100), "the floor is the settled block, 95");
        node.set_proven(480);
        node.set_tip(501);
        f.poll(&node).await.unwrap();
        assert_eq!(f.lowest(), Some(400));
        assert_eq!(f.retained(), 102);
    }

    /// A follower that followed from block 85 while the proven tip moved
    /// 80, 90, 95 (finalizing 80, then 90): it keeps blocks 90 (the settled
    /// block) to 110.
    async fn following_two_finalized_tips(node: &MemoryNode) -> Follower {
        node.set_tip(85);
        node.set_proven(80);
        let mut f = Follower::new();
        f.poll(node).await.unwrap();
        node.set_tip(100);
        node.set_proven(90);
        f.poll(node).await.unwrap();
        node.set_tip(110);
        node.set_proven(95);
        f.poll(node).await.unwrap();
        assert_eq!((f.proven(), f.settled()), (95, 90));
        assert_eq!(kept(&f), (90..=110).collect::<Vec<_>>());
        f
    }

    #[tokio::test]
    async fn a_replacement_at_the_proven_tip_is_placed_exactly() {
        let node = MemoryNode::new(0);
        let mut f = following_two_finalized_tips(&node).await;
        // an L1 reorg replaces the proven tip's block and everything after it
        node.replace_from(95);
        let prune = f.poll(&node).await.unwrap().prune.unwrap();
        assert_eq!(
            prune,
            Prune {
                from: 110,
                to: 94,
                below_kept: false
            }
        );
        assert!(prune.voids(95) && !prune.voids(94));
        assert_eq!(kept(&f), (90..=110).collect::<Vec<_>>());
        assert_eq!(f.hash_at(95), Some(node.hash(95)));
    }

    #[tokio::test]
    async fn a_replacement_above_the_finalized_tip_is_placed_exactly() {
        let node = MemoryNode::new(0);
        let mut f = following_two_finalized_tips(&node).await;
        node.replace_from(92);
        let prune = f.poll(&node).await.unwrap().prune.unwrap();
        assert_eq!(
            prune,
            Prune {
                from: 110,
                to: 91,
                below_kept: false
            }
        );
        assert!(prune.voids(92) && !prune.voids(91) && !prune.voids(12));
    }

    // L2BlockStream refuses to walk below its finalized tip, which no
    // replacement reaches. A node that answers one anyway contradicts its
    // own finality: the follower voids everything rather than trust the
    // blocks below.
    #[tokio::test]
    async fn a_replacement_reaching_the_settled_block_is_past_the_ring() {
        // the settled block's own block
        let node = MemoryNode::new(0);
        let mut f = following_two_finalized_tips(&node).await;
        node.replace_from(90);
        let prune = f.poll(&node).await.unwrap().prune.unwrap();
        assert_eq!(
            prune,
            Prune {
                from: 110,
                to: 89,
                below_kept: true
            }
        );
        assert_eq!(kept(&f), [110]);
        assert!(prune.to_string().contains("went back"), "{prune}");
        // nothing read before stands
        assert!(prune.voids(1));

        // deeper still
        let node = MemoryNode::new(0);
        let mut f = following_two_finalized_tips(&node).await;
        node.replace_from(50);
        let prune = f.poll(&node).await.unwrap().prune.unwrap();
        assert_eq!((prune.to, prune.below_kept), (89, true));
    }

    #[tokio::test]
    async fn a_replaced_block_is_a_prune_to_the_last_shared_block() {
        let node = MemoryNode::new(30);
        let mut f = Follower::new();
        f.poll(&node).await.unwrap();
        node.set_tip(32);
        f.poll(&node).await.unwrap();
        // block 31 and its child are replaced at the same height
        node.replace_from(31);
        let poll = f.poll(&node).await.unwrap();
        assert_eq!(
            poll.prune,
            Some(Prune {
                from: 32,
                to: 30,
                below_kept: false
            })
        );
        assert_eq!(
            poll.tip,
            BlockId {
                number: 32,
                hash: node.hash(32)
            }
        );
        assert_eq!(f.hash_at(31), Some(node.hash(31)));
        // reads at a replaced block are void, reads below it stand
        let prune = poll.prune.unwrap();
        assert!(prune.voids(31) && prune.voids(32));
        assert!(!prune.voids(30) && !prune.voids(12));
        // the replaced chain is followed from then on
        node.set_tip(33);
        assert_eq!(f.poll(&node).await.unwrap().prune, None);

        // a shorter chain: the tip goes back below the follower's, to
        // heights both sides have (L2BlockStream's "source tip dropped
        // below local tip")
        node.replace_from(33);
        node.set_tip(32);
        let poll = f.poll(&node).await.unwrap();
        assert_eq!(
            poll.prune,
            Some(Prune {
                from: 33,
                to: 32,
                below_kept: false
            })
        );
        assert_eq!(poll.tip.number, 32);
    }

    #[tokio::test]
    async fn the_settled_block_is_the_finalized_tip_once_it_moves() {
        let node = MemoryNode::new(50);
        node.set_proven(20);
        let mut f = Follower::new();
        let poll = f.poll(&node).await.unwrap();
        assert_eq!((poll.tip.number, poll.tips.proven.number), (50, 20));
        assert_eq!(poll.tips.checkpointed.number, 50);
        // the first answer's finalized tip is not trusted to delete by
        assert_eq!((f.proven(), f.settled()), (20, 0));
        node.set_proven(30);
        f.poll(&node).await.unwrap();
        assert_eq!((f.proven(), f.settled()), (30, 20));
        // finality moves on its own
        node.set_finalized(25);
        f.poll(&node).await.unwrap();
        assert_eq!((f.proven(), f.settled()), (30, 25));
        // an L1 reorg takes a proof away: the tips are clamped together, and
        // the settled block never stands above the finalized tip
        node.set_proven(22);
        let poll = f.poll(&node).await.unwrap();
        assert_eq!(
            (poll.tips.proven.number, poll.tips.finalized.number),
            (22, 22)
        );
        assert_eq!(f.settled(), 22);
        // the checkpointed tip held back below the proposed one
        node.set_checkpointed(Some(45));
        let poll = f.poll(&node).await.unwrap();
        assert_eq!(poll.tips.checkpointed.number, 45);
        assert_eq!(poll.tips.checkpointed.hash, node.hash(45));
        // a fresh follower of a node whose finality is already past 0
        // deletes nothing until it sees the finalized tip move
        let mut fresh = Follower::new();
        fresh.poll(&node).await.unwrap();
        assert_eq!(fresh.settled(), 0);
        node.set_proven(40);
        node.set_proven(44);
        fresh.poll(&node).await.unwrap();
        assert_eq!(fresh.settled(), 40);
    }

    #[tokio::test]
    async fn tips_out_of_order_are_refused() {
        let tips = |proposed: u64, checkpointed: u64, proven: u64, finalized: u64| {
            let id = |n: u64| json!({"number": n, "hash": fr_to_hex(Fr::from(n))});
            let tier = |n: u64| json!({"block": id(n), "checkpoint": id(n)});
            json!({"calls": [{
                "method": "node_getChainTips",
                "params": [],
                "response": {"result": {
                    "proposed": id(proposed),
                    "checkpointed": tier(checkpointed),
                    "proven": tier(proven),
                    "finalized": tier(finalized),
                }},
            }]})
        };
        let ok = FixtureTransport::new(&tips(10, 9, 8, 7));
        let read = chain_tips(&ok).await.unwrap();
        assert_eq!(
            [
                read.proposed.number,
                read.checkpointed.number,
                read.proven.number,
                read.finalized.number
            ],
            [10, 9, 8, 7]
        );
        for (p, c, v, f) in [(10, 11, 8, 7), (10, 9, 10, 7), (10, 9, 8, 9)] {
            let node = FixtureTransport::new(&tips(p, c, v, f));
            let err = chain_tips(&node).await.unwrap_err();
            assert!(
                matches!(&err, ReadError::Malformed { detail, .. } if detail.contains("out of order")),
                "{err}"
            );
            let mut f = Follower::new();
            assert!(f.poll(&node).await.is_err());
            assert_eq!(f.tip(), None, "nothing kept from a refused answer");
        }
    }

    /// The node answers no block below its own tip once, for `missing`.
    struct Gap {
        node: MemoryNode,
        missing: Mutex<Option<u64>>,
    }

    impl Transport for Gap {
        async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
            if method == "node_getBlockData" {
                let mut missing = self.missing.lock().unwrap();
                if params[0].as_u64() == *missing {
                    *missing = None;
                    return Ok(Value::Null);
                }
            }
            self.node.call(method, params).await
        }
    }

    // L2BlockStream: a source with no block below its own tip skips the
    // pass and recovers on the next one. A prune found before the failure
    // is reported by the next poll that succeeds.
    #[tokio::test]
    async fn a_node_missing_a_block_below_its_tip_fails_the_poll_and_the_next_recovers() {
        let gap = Gap {
            node: MemoryNode::new(28),
            missing: Mutex::new(None),
        };
        let mut f = Follower::new();
        f.poll(&gap).await.unwrap();
        gap.node.set_tip(30);
        f.poll(&gap).await.unwrap();
        assert_eq!(kept(&f), [28, 29, 30]);
        // in the walk
        gap.node.replace_from(30);
        gap.node.set_tip(32);
        *gap.missing.lock().unwrap() = Some(30);
        assert_eq!(
            f.poll(&gap).await,
            Err(ReadError::Unsettled { block: 30, tip: 32 })
        );
        let poll = f.poll(&gap).await.unwrap();
        assert_eq!(
            poll.prune,
            Some(Prune {
                from: 30,
                to: 29,
                below_kept: false
            })
        );
        assert_eq!(poll.tip.number, 32);
        // in the fill after the walk found a prune
        gap.node.replace_from(31);
        gap.node.set_tip(34);
        *gap.missing.lock().unwrap() = Some(33);
        assert_eq!(
            f.poll(&gap).await,
            Err(ReadError::Unsettled { block: 33, tip: 34 })
        );
        let poll = f.poll(&gap).await.unwrap();
        assert_eq!(
            poll.prune,
            Some(Prune {
                from: 32,
                to: 30,
                below_kept: false
            }),
            "the prune the failed poll found"
        );
        assert_eq!(poll.tip.number, 34);
        assert_eq!(f.poll(&gap).await.unwrap().prune, None, "reported once");
        assert_eq!(f.hash_at(31), Some(gap.node.hash(31)));
    }

    // L2BlockStream: with nothing finalized, a replacement of every block
    // is a real prune to genesis.
    #[tokio::test]
    async fn a_replacement_of_every_block_is_a_prune_to_genesis() {
        let node = MemoryNode::new(1);
        let mut f = Follower::new();
        f.poll(&node).await.unwrap();
        node.set_tip(5);
        f.poll(&node).await.unwrap();
        assert_eq!(kept(&f), [1, 2, 3, 4, 5]);
        node.replace_from(1);
        let prune = f.poll(&node).await.unwrap().prune.unwrap();
        assert_eq!(
            prune,
            Prune {
                from: 5,
                to: 0,
                below_kept: true
            }
        );
        assert!(prune.voids(1));
    }

    // L2BlockStream: after a walk-back it reads the tips again and follows
    // the fresh ones, not the ones read before the walk.
    #[tokio::test]
    async fn after_a_walk_back_the_follower_reads_the_tips_again() {
        let node = MemoryNode::new(18);
        let mut f = Follower::new();
        f.poll(&node).await.unwrap();
        node.set_tip(20);
        f.poll(&node).await.unwrap();
        node.replace_from(20);
        // the tips read before the walk say 20; the node is at 21 after it
        node.script_tips(&[20, 21]);
        let poll = f.poll(&node).await.unwrap();
        assert_eq!(
            poll.prune,
            Some(Prune {
                from: 20,
                to: 19,
                below_kept: false
            })
        );
        assert_eq!(poll.tip.number, 21);
        assert_eq!(poll.tips.proposed.number, 21);
        assert_eq!(kept(&f), [18, 19, 20, 21]);
        assert_eq!(f.hash_at(20), Some(node.hash(20)));
        assert_eq!(f.hash_at(21), Some(node.hash(21)));
    }

    // L2BlockStream: a node that switches fork right after answering its
    // tips. The stale tip agrees with what the follower holds, so the pass
    // reports nothing; the next poll places the replacement exactly, and a
    // read pinned to the stale tip's hash is refused by the node in between
    // (crate::chain's tests).
    #[tokio::test]
    async fn a_fork_switch_after_the_tips_read_is_placed_by_the_next_poll() {
        let node = MemoryNode::new(20);
        let mut f = Follower::new();
        f.poll(&node).await.unwrap();
        node.set_tip(22);
        f.poll(&node).await.unwrap();
        let held = node.hash(22);
        node.replace_after_next_tips(21);
        let poll = f.poll(&node).await.unwrap();
        assert_eq!((poll.tip.hash, poll.prune), (held, None));
        assert_ne!(node.hash(22), held, "the node switched after answering");
        let poll = f.poll(&node).await.unwrap();
        assert_eq!(
            poll.prune,
            Some(Prune {
                from: 22,
                to: 20,
                below_kept: false
            })
        );
        assert_eq!(poll.tip.hash, node.hash(22));
    }

    // L2BlockStream: a node that switches fork while the follower fills in
    // the blocks below its tip. The blocks read after the switch are the new
    // fork's and the tips' hash the old fork's; the tip block's hash, read
    // again after the fill, differs, so the poll fails and keeps none of
    // them. The next poll fills them from the new fork alone.
    #[tokio::test]
    async fn a_fork_switch_during_the_fill_fails_the_poll() {
        let node = MemoryNode::new(20);
        let mut f = Follower::new();
        f.poll(&node).await.unwrap();
        node.set_tip(25);
        node.replace_after_next_tips(22);
        let err = f.poll(&node).await.unwrap_err();
        assert!(
            matches!(err, ReadError::Unsettled { block: 25, tip: 25 }),
            "{err}"
        );
        assert_eq!(kept(&f), [20]);
        let poll = f.poll(&node).await.unwrap();
        assert_eq!(poll.prune, None, "no replaced block was kept");
        assert_eq!(kept(&f), [20, 21, 22, 23, 24, 25]);
        for n in 20..=25 {
            assert_eq!(f.hash_at(n), Some(node.hash(n)), "block {n}");
        }
    }
}
