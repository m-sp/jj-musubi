//! Carrying a connection over a link that doesn't tell a dead peer.
//!
//! ssh ends a connection whose other side has gone quiet, and a local socket one whose other
//! side has gone. TCP over tailscale-rs does neither: it has no keepalive and no timeout, and
//! writing succeeds for as long as its buffer has room. So what a tailnet link carries is
//! framed here, and nothing that ssh or a local socket carries is.
//!
//! Whoever is connected to first sends [`LINK`] and an [`Answer`]. After [`Answer::Welcome`],
//! each side sends frames, each a big-endian `u16` and then:
//!
//! - for `0`, nothing: a heartbeat, sent when there's been nothing else to send for [`BEAT`];
//! - for up to [`MAX_DATA`], that many bytes of what is carried;
//! - for [`END`], nothing: the sender has no more to send.
//!
//! A side that hears nothing for [`SILENCE`] ends the connection, whatever it is doing.
//!
//! Such a link's shutdown does nothing, and a socket closed with bytes unread can keep both
//! sides from ever finishing. So a side that is done sends [`END`] and reads until the other
//! side has closed, and a side that gets [`END`], having read everything, closes.

use std::io;
use std::time::Duration;

use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt as _;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt as _;
use tokio::io::BufReader;
use tokio::time::Instant;

/// What a link starts with: its protocol and version. Every change to what follows changes it.
pub const LINK: &[u8] = b"musubi-tailnet-1\n";

/// How long a side with nothing to send waits before sending a heartbeat.
pub const BEAT: Duration = Duration::from_secs(10);

/// How long without a byte from the other side ends a connection: within the minute ssh
/// takes to (`ssh::connect_command` in musubi), and room for three heartbeats to be late.
pub const SILENCE: Duration = Duration::from_secs(45);

/// How long a side that has ended waits for the other to close.
pub const LINGER: Duration = Duration::from_secs(15);

/// The most bytes a frame carries.
pub const MAX_DATA: usize = 16 * 1024;

/// How much of the link is read at a time: as much as a tailnet socket buffers.
const READ_BUFFER: usize = 64 * 1024;

/// The frame that ends what a side sends.
pub const END: u16 = u16::MAX;

/// What the side connected to says before it carries anything. Each answer's byte is fixed: a
/// machine reads it by number, whichever answers its build has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Answer {
    /// Frames follow.
    Welcome = 0,
    /// No hub is running there.
    NoHub = 2,
    /// The machine connecting may not use the hub.
    NotAllowed = 1,
    /// The side connected to couldn't tell which machine is connecting, so it can't tell
    /// whether that machine may use the hub.
    Unidentified = 3,
}

impl Answer {
    const ALL: [Self; 4] = [
        Self::Welcome,
        Self::NoHub,
        Self::NotAllowed,
        Self::Unidentified,
    ];

    /// Sends this answer.
    pub async fn send(self, to: &mut (impl AsyncWrite + Unpin)) -> io::Result<()> {
        let mut message = LINK.to_vec();
        message.push(self as u8);
        to.write_all(&message).await?;
        to.flush().await
    }

    /// Reads an answer, refusing what isn't one of this version. The caller limits the wait.
    pub async fn read(from: &mut (impl AsyncRead + Unpin)) -> io::Result<Self> {
        let mut link = [0; LINK.len()];
        from.read_exact(&mut link).await?;
        if link != LINK {
            return Err(invalid(
                "what answered isn't a musubi hub that speaks this machine's tailnet protocol",
            ));
        }
        let said = from.read_u8().await?;
        Self::ALL
            .into_iter()
            .find(|&answer| answer as u8 == said)
            .ok_or_else(|| invalid("the hub's answer over the tailnet isn't one this knows"))
    }
}

/// How a connection ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    /// The other side ended or closed it.
    Closed,
    /// Nothing came from the other side for [`SILENCE`].
    Silent,
    /// What this side delivers to stopped reading.
    Stalled,
    /// The other side didn't close within [`LINGER`] of this side's ending.
    NotClosed,
    /// The other side sent what isn't a frame.
    Invalid,
}

impl Ended {
    /// Whether the link's socket may never finish closing.
    pub fn may_strand(self) -> bool {
        self != Self::Closed
    }
}

fn invalid(why: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, why)
}

/// Carries what `local` reads and writes over `peer`, the link, until either ends. Both are
/// closed on return, by being dropped.
pub async fn relay<P, L>(peer: P, local: L) -> Ended
where
    P: AsyncRead + AsyncWrite + Unpin,
    L: AsyncRead + AsyncWrite + Unpin,
{
    let (from_peer, to_peer) = tokio::io::split(peer);
    let (from_local, to_local) = tokio::io::split(local);
    tokio::select! {
        // First, so that what came before the link broke is delivered.
        biased;
        ended = receive(from_peer, to_local) => ended,
        ended = send(from_local, to_peer) => ended,
    }
}

/// Delivers the data in the frames `from` carries to `to`, until they end.
///
/// One deadline, [`SILENCE`] after the last byte, covers waiting for the next and delivering
/// it: a link that is dead behind a local side that has stopped reading ends as soon.
///
/// Reads go through a buffer as large as the socket's, so that a frame and its header are one
/// read of the link, not one each: on a tailnet each is a round trip to its network stack.
/// The buffer may read past [`END`], which nothing honest sends anything after, and what it
/// read past is dropped with it.
async fn receive(from: impl AsyncRead + Unpin, mut to: impl AsyncWrite + Unpin) -> Ended {
    let mut from = BufReader::with_capacity(READ_BUFFER, from);
    let mut deadline = Instant::now() + SILENCE;
    let mut buf = vec![0; MAX_DATA];
    // Whether what this delivers to still takes it. Once it doesn't, what comes is read and
    // thrown away, so that the link can close.
    let mut delivering = true;
    loop {
        let mut header = [0; 2];
        let mut have = 0;
        while have < header.len() {
            match tokio::time::timeout_at(deadline, from.read(&mut header[have..])).await {
                Err(_) => return Ended::Silent,
                Ok(Err(_) | Ok(0)) => return Ended::Closed,
                Ok(Ok(read)) => {
                    have += read;
                    deadline = Instant::now() + SILENCE;
                }
            }
        }
        let header = u16::from_be_bytes(header);
        if header == END {
            return Ended::Closed;
        }
        let mut left = usize::from(header);
        if left > MAX_DATA {
            return Ended::Invalid;
        }
        while left > 0 {
            let read = match tokio::time::timeout_at(deadline, from.read(&mut buf[..left])).await {
                Err(_) => return Ended::Silent,
                Ok(Err(_) | Ok(0)) => return Ended::Closed,
                Ok(Ok(read)) => read,
            };
            left -= read;
            deadline = Instant::now() + SILENCE;
            if !delivering {
                continue;
            }
            let delivered = async {
                to.write_all(&buf[..read]).await?;
                to.flush().await
            };
            match tokio::time::timeout_at(deadline, delivered).await {
                Err(_) => return Ended::Stalled,
                Ok(Err(_)) => delivering = false,
                Ok(Ok(())) => {}
            }
        }
    }
}

/// Frames what `from` reads onto `to`, with heartbeats while it reads nothing, and once it
/// ends, says so and waits for the other side to close. [`receive`] hears that, and times a
/// write that blocks, since a dead peer is a silent one.
async fn send(mut from: impl AsyncRead + Unpin, mut to: impl AsyncWrite + Unpin) -> Ended {
    let mut frame = vec![0; 2 + MAX_DATA];
    loop {
        let len = match tokio::time::timeout(BEAT, from.read(&mut frame[2..])).await {
            Err(_) => 0,
            Ok(Err(_) | Ok(0)) => break,
            Ok(Ok(len)) => len,
        };
        // MAX_DATA fits in a u16, short of END.
        frame[..2].copy_from_slice(&(len as u16).to_be_bytes());
        let written = async {
            to.write_all(&frame[..2 + len]).await?;
            to.flush().await
        };
        if written.await.is_err() {
            return Ended::Closed;
        }
    }
    let ending = async {
        to.write_all(&END.to_be_bytes()).await?;
        to.flush().await?;
        std::future::pending::<io::Result<()>>().await
    };
    match tokio::time::timeout(LINGER, ending).await {
        Ok(_) => Ended::Closed,
        Err(_) => Ended::NotClosed,
    }
}

/// What the fuzz target for this module reaches.
#[cfg(any(fuzzing, test))]
pub mod fuzzing {
    use std::io;
    use std::pin::Pin;
    use std::task::Context;
    use std::task::Poll;

    use tokio::io::AsyncRead;
    use tokio::io::AsyncWrite;
    use tokio::io::ReadBuf;

    use super::END;
    use super::Ended;
    use super::MAX_DATA;

    /// Reads at most `most` bytes at a time from `data`, as a link may split it anywhere,
    /// counting how far it has read.
    struct Chunked<'a> {
        data: &'a [u8],
        read: usize,
        most: usize,
    }

    impl AsyncRead for Chunked<'_> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let start = self.read;
            let len = (self.data.len() - start)
                .min(self.most)
                .min(buf.remaining());
            buf.put_slice(&self.data[start..start + len]);
            self.read += len;
            Poll::Ready(Ok(()))
        }
    }

    /// Takes `room` bytes, then fails, as a local side that has gone does.
    struct Failing {
        took: Vec<u8>,
        room: usize,
    }

    impl AsyncWrite for Failing {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let room = self.room - self.took.len();
            if room == 0 {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            let len = buf.len().min(room);
            self.took.extend_from_slice(&buf[..len]);
            Poll::Ready(Ok(len))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Reads `input` as an answer, and as frames: its first byte says how much each read of
    /// the link gets, its next two how much the local side takes before it fails, and the rest
    /// is what the link carries. Checks that an answer has one encoding; that how the frames
    /// end, and what they deliver, is what reading them whole gives, or a prefix of it once
    /// the local side fails; and that the link is read on to their end regardless.
    pub async fn link(input: &[u8]) {
        let mut rest = input;
        if let Ok(answer) = super::Answer::read(&mut rest).await {
            let mut encoded = vec![];
            answer.send(&mut encoded).await.expect("writing to memory");
            assert_eq!(encoded, &input[..input.len() - rest.len()]);
        }

        let [most, high, low, carried @ ..] = input else {
            return;
        };
        let mut link = Chunked {
            data: carried,
            read: 0,
            most: usize::from(*most) + 1,
        };
        let mut local = Failing {
            took: vec![],
            room: usize::from(u16::from_be_bytes([*high, *low])),
        };
        let ended = super::receive(&mut link, &mut local).await;
        let (whole_ended, whole, end) = read_whole(carried);
        assert_eq!(ended, whole_ended);
        assert!(whole.starts_with(&local.took), "delivered what wasn't sent");
        if local.room >= whole.len() {
            assert_eq!(local.took, whole);
        }
        assert!(link.read >= end, "stopped reading before the frames ended");
    }

    /// How frames read whole end, what they deliver, and where they end.
    fn read_whole(input: &[u8]) -> (Ended, Vec<u8>, usize) {
        let mut data = vec![];
        let mut at = 0;
        loop {
            let Some(header) = input.get(at..at + 2) else {
                return (Ended::Closed, data, input.len());
            };
            let header = u16::from_be_bytes([header[0], header[1]]);
            at += 2;
            if header == END {
                return (Ended::Closed, data, at);
            }
            let len = usize::from(header);
            if len > MAX_DATA {
                return (Ended::Invalid, data, at);
            }
            let frame = &input[at..(at + len).min(input.len())];
            data.extend_from_slice(frame);
            at += frame.len();
            if frame.len() < len {
                return (Ended::Closed, data, input.len());
            }
        }
    }

    /// [`link`], on a runtime of its own, which its deadlines need.
    pub fn link_blocking(input: &[u8]) {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("making a runtime")
            .block_on(link(input));
    }
}

#[cfg(test)]
mod tests;
