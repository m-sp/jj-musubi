//! A peer that stops answering, as one killed or suspended does over a tailnet: the stream
//! stays open and nothing comes. Time is tokio's paused clock.

use std::sync::Arc;
use std::sync::Mutex;

use async_trait::async_trait;
use bytes::Bytes;
use hegel::TestCase;
use hegel::generators as gs;
use tokio::io::DuplexStream;

use super::*;
use crate::MemoryNetwork;
use crate::StreamTransport;
use crate::Transport as _;
use crate::TransportError;
use crate::stream::Connector;
use crate::stream::Reader;
use crate::stream::WhileDisconnected;
use crate::stream::Writer;

/// The socket buffer tailscale-rs gives each direction.
const BUFFER: usize = 64 * 1024;

/// Long enough for anything that would end by itself to have.
const HOUR: Duration = Duration::from_secs(3600);

#[tokio::test(start_paused = true)]
async fn a_peer_that_says_nothing_is_dropped_within_a_minute() {
    // Suspended, idle, before anything has been sent: before the hub's greeting, too.
    let (link, _peer) = tokio::io::duplex(BUFFER);
    let (local, _ours) = tokio::io::duplex(BUFFER);
    let began = Instant::now();
    assert_eq!(relay(link, local).await, Ended::Silent);
    assert_eq!(began.elapsed(), SILENCE);
    assert!(SILENCE < Duration::from_secs(60));
}

/// Writes succeed until the buffer is full and then block, so they say nothing of the peer.
#[tokio::test(start_paused = true)]
async fn a_write_that_blocks_does_not_hide_a_silent_peer() {
    let (link, _peer) = tokio::io::duplex(64);
    let (local, mut ours) = tokio::io::duplex(BUFFER);
    ours.write_all(&[7; 4096]).await.unwrap();
    let began = Instant::now();
    assert_eq!(relay(link, local).await, Ended::Silent);
    assert_eq!(began.elapsed(), SILENCE);
}

#[tokio::test(start_paused = true)]
async fn a_peer_silent_partway_through_a_frame_is_dropped() {
    let (link, mut peer) = tokio::io::duplex(BUFFER);
    let (local, _ours) = tokio::io::duplex(BUFFER);
    peer.write_all(&[0, 10, 1, 2, 3]).await.unwrap();
    let began = Instant::now();
    assert_eq!(relay(link, local).await, Ended::Silent);
    assert_eq!(began.elapsed(), SILENCE);
}

#[tokio::test(start_paused = true)]
async fn a_local_side_that_stops_reading_does_not_hide_a_silent_peer() {
    let (link, mut peer) = tokio::io::duplex(BUFFER);
    let (local, _ours) = tokio::io::duplex(16);
    let mut frame = vec![0, 64];
    frame.extend([7; 64]);
    peer.write_all(&frame).await.unwrap();
    let began = Instant::now();
    assert_eq!(relay(link, local).await, Ended::Stalled);
    assert_eq!(began.elapsed(), SILENCE);
}

/// A slow link that moves at all stays, as it does over ssh: any byte counts, not only a
/// whole frame.
#[tokio::test(start_paused = true)]
async fn a_slow_frame_is_not_silence() {
    let (link, mut peer) = tokio::io::duplex(BUFFER);
    let (local, mut ours) = tokio::io::duplex(BUFFER);
    let relaying = tokio::spawn(relay(link, local));
    for byte in [0, 3, b'a', b'b', b'c'] {
        tokio::time::sleep(SILENCE - Duration::from_secs(1)).await;
        peer.write_u8(byte).await.unwrap();
    }
    let mut got = [0; 3];
    ours.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"abc");
    assert!(!relaying.is_finished());
}

#[tokio::test(start_paused = true)]
async fn an_idle_link_whose_peer_is_alive_stays() {
    let (a, b) = tokio::io::duplex(BUFFER);
    let (near, _near) = tokio::io::duplex(BUFFER);
    let (far, _far) = tokio::io::duplex(BUFFER);
    tokio::select! {
        ended = relay(a, near) => panic!("the near side ended: {ended:?}"),
        ended = relay(b, far) => panic!("the far side ended: {ended:?}"),
        () = tokio::time::sleep(HOUR) => {}
    }
}

/// Shutdown does nothing on a tailnet stream, so ending is in the frames: what was sent
/// arrives whole, then the end, and neither socket is left with bytes unread.
#[hegel::test]
fn what_is_sent_arrives_whole_and_then_the_end(tc: TestCase) {
    let sizes = tc.draw(gs::vecs(gs::integers::<usize>().max_value(40_000)).max_size(6));
    let buffer = tc.draw(gs::integers::<usize>().min_value(1).max_value(BUFFER));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap();
    runtime.block_on(async {
        let sent: Vec<u8> = sizes
            .iter()
            .enumerate()
            .flat_map(|(index, &size)| vec![index as u8 + 1; size])
            .collect();
        let (a, b) = tokio::io::duplex(buffer);
        let (near, mut ours) = tokio::io::duplex(BUFFER);
        let (far, mut theirs) = tokio::io::duplex(BUFFER);
        let near = tokio::spawn(relay(a, near));
        let far = tokio::spawn(relay(b, far));
        let writing = async {
            ours.write_all(&sent).await.unwrap();
            drop(ours);
        };
        let reading = async {
            let mut got = vec![];
            theirs.read_to_end(&mut got).await.unwrap();
            got
        };
        let ((), got) = tokio::join!(writing, reading);
        assert_eq!(got, sent);
        assert_eq!(far.await.unwrap(), Ended::Closed);
        assert_eq!(near.await.unwrap(), Ended::Closed);
    });
}

/// The peer keeps sending as this side ends: that is read and thrown away, not left to fill
/// the socket, where it would keep the peer's close from ever arriving.
#[tokio::test(start_paused = true)]
async fn ending_reads_what_is_still_coming() {
    let (link, peer) = tokio::io::duplex(1024);
    let (local, ours) = tokio::io::duplex(BUFFER);
    drop(ours);
    let relaying = tokio::spawn(relay(link, local));
    let (mut from_us, mut to_us) = tokio::io::split(peer);
    for _ in 0..4 {
        let mut frame = (MAX_DATA as u16).to_be_bytes().to_vec();
        frame.extend(vec![3; MAX_DATA]);
        to_us.write_all(&frame).await.unwrap();
    }
    assert_eq!(from_us.read_u16().await.unwrap(), END);
    drop((from_us, to_us));
    assert_eq!(relaying.await.unwrap(), Ended::Closed);
}

#[tokio::test(start_paused = true)]
async fn a_peer_that_never_closes_is_let_go() {
    let (link, _peer) = tokio::io::duplex(BUFFER);
    let (local, ours) = tokio::io::duplex(BUFFER);
    drop(ours);
    let began = Instant::now();
    let ended = relay(link, local).await;
    assert_eq!(ended, Ended::NotClosed);
    assert!(ended.may_strand());
    assert_eq!(began.elapsed(), LINGER);
}

#[tokio::test(start_paused = true)]
async fn what_is_not_a_frame_ends_the_link() {
    for header in [MAX_DATA as u16 + 1, END - 1] {
        let (link, mut peer) = tokio::io::duplex(BUFFER);
        let (local, _ours) = tokio::io::duplex(BUFFER);
        peer.write_u16(header).await.unwrap();
        assert_eq!(relay(link, local).await, Ended::Invalid);
    }
}

#[tokio::test]
async fn only_this_version_answers() {
    for answer in Answer::ALL {
        let mut said = vec![];
        answer.send(&mut said).await.unwrap();
        assert_eq!(Answer::read(&mut said.as_slice()).await.unwrap(), answer);
    }
    for said in [&b"musubi-tailnet-2\n\0"[..], b"musubi-tailnet-1\n\x04"] {
        let err = Answer::read(&mut &said[..]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}

/// [`fuzzing::link`]'s check holds of what honest and malformed peers send, on every run.
#[hegel::test]
fn frames_deliver_what_reading_them_whole_gives(tc: TestCase) {
    let frames = tc.draw(
        gs::vecs(gs::sampled_from(vec![
            vec![0, 0],
            vec![0, 3, b'a', b'b', b'c'],
            vec![0x40, 0x01],
            vec![0xff, 0xff],
            vec![0, 9, 1],
            vec![5],
        ]))
        .max_size(6),
    );
    // How much each read of the link gets, and how much the local side takes before it fails.
    let most = tc.draw(gs::integers::<u8>());
    let room = tc.draw(gs::integers::<u16>().max_value(12));
    let mut input = vec![most];
    input.extend(room.to_be_bytes());
    input.extend(frames.concat());
    fuzzing::link_blocking(&input);
}

/// Hands over one stream, and then has none.
struct Once(Mutex<Option<DuplexStream>>);

#[async_trait]
impl Connector for Once {
    async fn connect(&self) -> io::Result<(Reader, Writer)> {
        let Some(stream) = self.0.lock().unwrap().take() else {
            return Err(io::Error::other("the hub is gone"));
        };
        let (read, write) = tokio::io::split(stream);
        Ok((Box::new(read), Box::new(write)))
    }
}

/// What this is for: a hub suspended with a request in flight fails it within a minute, as a
/// dead ssh does, rather than at the request's own deadline.
#[tokio::test(start_paused = true)]
async fn a_suspended_hub_fails_the_requests_in_flight() {
    let network = MemoryNetwork::new(0, 1 << 20);
    let hub = network.connect();
    let mut asked = hub.subscribe("rpc").await.unwrap();

    let (a, b) = tokio::io::duplex(BUFFER);
    let (near, ours) = tokio::io::duplex(BUFFER);
    let (far, theirs) = tokio::io::duplex(BUFFER);
    tokio::spawn(relay(a, near));
    let far = tokio::spawn(async move {
        let (read, write) = tokio::io::split(theirs);
        let serving = crate::stream::serve(Arc::new(network.connect()), read, write);
        // Held beside the relay, so that suspending closes nothing.
        let relaying = relay(b, far);
        tokio::pin!(serving, relaying);
        let suspended = async {
            asked.next().await.expect("a request");
        };
        tokio::select! {
            _ = &mut serving => panic!("the hub stopped serving"),
            _ = &mut relaying => panic!("the relay stopped"),
            () = suspended => {}
        }
        std::future::pending::<()>().await;
    });

    let once = Arc::new(Once(Mutex::new(Some(ours))));
    let client = StreamTransport::connect_with(once, WhileDisconnected::NextAttempt)
        .await
        .unwrap();
    let began = Instant::now();
    let err = client
        .request("rpc", Bytes::from_static(b"push"), HOUR)
        .await
        .unwrap_err();
    assert!(matches!(err, TransportError::Disconnected), "{err:?}");
    assert!(began.elapsed() <= SILENCE + Duration::from_secs(1));
    assert!(!far.is_finished());
}

/// Machines and hubs of other builds read an answer by its byte, so each keeps its own.
#[test]
fn answers_keep_their_bytes() {
    let bytes = Answer::ALL.map(|answer| (answer, answer as u8));
    assert_eq!(
        bytes,
        [
            (Answer::Welcome, 0),
            (Answer::NoHub, 2),
            (Answer::NotAllowed, 1),
            (Answer::Unidentified, 3),
        ]
    );
}
