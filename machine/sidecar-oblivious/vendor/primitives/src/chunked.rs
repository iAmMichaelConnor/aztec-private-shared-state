//! A network adapter that sends every message in frames of at most
//! [`MAX_CHUNK`] bytes, so a DORAM message of any size passes a transport
//! with a frame limit (mpc-net's blocking TCP and TLS transports refuse a
//! frame over `max_frame_length`, by default
//! [`mpc_net::DEFAULT_MAX_FRAME_LENGTH`]). A bottom level built from every
//! address of a dense DORAM of depth 16 reshares about 190 MiB in one
//! message.
//!
//! Framing: a message's first frame starts with its length (8 bytes, little
//! endian) and carries up to `MAX_CHUNK - 8` bytes of it; the rest follows
//! in frames of `MAX_CHUNK` bytes. Both ends of every channel use the
//! adapter for the same messages (the DORAM wraps its network at each entry
//! point), so the frames are read back in the order they were sent.

use bytes::{Bytes, BytesMut};
use mpc_net::{ConnectionStats, Network};

/// The largest frame the adapter sends: half of mpc-net's default frame
/// limit, so a transport configured below the default still passes it. A
/// message is at most 64 frames ahead of its receiver before the sender
/// blocks (mpc-net's send and receive queues hold 32 frames each), about
/// 2 GiB.
pub const MAX_CHUNK: usize = mpc_net::DEFAULT_MAX_FRAME_LENGTH / 2;

const HEADER: usize = 8;

/// The longest message a receiver accepts, 2 GiB: a peer's length header is
/// refused past it before anything is allocated, so a peer cannot make its
/// neighbour reserve memory it never sends. The largest message the machine's
/// shapes send is a dense bottom level's resharing, about 190 MiB per 2^20
/// addresses (about 760 MiB at the 2^22 the oblivious tree allows).
pub const MAX_MESSAGE: usize = 1 << 31;

/// `N` with every message sent in frames of at most `max` bytes.
pub struct Chunked<'a, N: Network> {
    net: &'a N,
    max: usize,
}

impl<'a, N: Network> Chunked<'a, N> {
    /// `net` in frames of at most [`MAX_CHUNK`] bytes.
    pub fn new(net: &'a N) -> Self {
        Self::with_max(net, MAX_CHUNK)
    }

    /// `net` in frames of at most `max` bytes (more than the 8-byte header).
    pub fn with_max(net: &'a N, max: usize) -> Self {
        assert!(max > HEADER, "a frame holds the 8-byte header and data");
        Self { net, max }
    }
}

impl<N: Network> Network for Chunked<'_, N> {
    fn id(&self) -> usize {
        self.net.id()
    }

    fn send(&self, to: usize, data: Bytes) -> eyre::Result<()> {
        let first = data.len().min(self.max - HEADER);
        let mut head = BytesMut::with_capacity(HEADER + first);
        head.extend_from_slice(&(data.len() as u64).to_le_bytes());
        head.extend_from_slice(&data[..first]);
        self.net.send(to, head.freeze())?;
        let mut at = first;
        while at < data.len() {
            let end = data.len().min(at + self.max);
            self.net.send(to, data.slice(at..end))?;
            at = end;
        }
        Ok(())
    }

    fn recv(&self, from: usize) -> eyre::Result<Bytes> {
        let head = self.net.recv(from)?;
        eyre::ensure!(
            head.len() >= HEADER,
            "a chunked message from party {from} starts with {} bytes, short of its header",
            head.len()
        );
        let len = u64::from_le_bytes(head[..HEADER].try_into().expect("8 bytes"));
        eyre::ensure!(
            len <= MAX_MESSAGE as u64,
            "a chunked message from party {from} claims {len} bytes, over the {MAX_MESSAGE} accepted"
        );
        let len = len as usize;
        let first = head.slice(HEADER..);
        eyre::ensure!(
            first.len() <= len,
            "a chunked message from party {from} of {len} bytes starts with {} bytes",
            first.len()
        );
        if first.len() == len {
            return Ok(first);
        }
        let mut out = BytesMut::with_capacity(len);
        out.extend_from_slice(&first);
        while out.len() < len {
            let frame = self.net.recv(from)?;
            eyre::ensure!(
                out.len() + frame.len() <= len,
                "a chunked message from party {from} runs past its {len} bytes"
            );
            out.extend_from_slice(&frame);
        }
        Ok(out.freeze())
    }

    fn flush(&self) -> eyre::Result<()> {
        self.net.flush()
    }

    fn get_connection_stats(&self) -> ConnectionStats {
        self.net.get_connection_stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpc_net::local::LocalNetwork;

    /// `f` at each of three parties over the local channels.
    fn three<F: Fn(LocalNetwork) + Sync>(f: F) {
        let nets = LocalNetwork::new_3_parties();
        std::thread::scope(|scope| {
            for net in nets {
                let f = &f;
                scope.spawn(move || f(net));
            }
        });
    }

    #[test]
    fn messages_of_every_size_pass_in_bounded_frames() {
        let max = 64;
        let sizes = [0usize, 1, max - HEADER, max - HEADER + 1, max, 5 * max + 3];
        three(|net| {
            let chunked = Chunked::with_max(&net, max);
            let (next, prev) = ((net.id() + 1) % 3, (net.id() + 2) % 3);
            for size in sizes {
                let data: Bytes = (0..size).map(|i| (i * 7 + net.id()) as u8).collect();
                chunked.send(next, data).unwrap();
                let got = chunked.recv(prev).unwrap();
                let want: Vec<u8> = (0..size).map(|i| (i * 7 + prev) as u8).collect();
                assert_eq!(got.as_ref(), want.as_slice(), "size {size}");
            }
            // every frame on the wire is at most `max` bytes
            let raw = Chunked::with_max(&net, max);
            raw.send(next, Bytes::from(vec![1u8; 3 * max])).unwrap();
            let mut frames = vec![];
            let mut total = 0;
            while total < 3 * max + HEADER {
                let f = net.recv(prev).unwrap();
                total += f.len();
                frames.push(f.len());
            }
            assert!(frames.iter().all(|n| *n <= max), "{frames:?}");
            assert_eq!(frames.len(), 4);
        });
    }

    /// A length header past [`MAX_MESSAGE`] is refused before anything is
    /// reserved for it.
    #[test]
    fn a_claimed_length_past_the_cap_is_refused() {
        three(|net| {
            let (next, prev) = ((net.id() + 1) % 3, (net.id() + 2) % 3);
            for len in [MAX_MESSAGE as u64 + 1, u64::MAX] {
                net.send(next, Bytes::copy_from_slice(&len.to_le_bytes()))
                    .unwrap();
                let err = Chunked::new(&net).recv(prev).unwrap_err().to_string();
                assert!(err.contains("over the"), "{err}");
            }
        });
    }
}
