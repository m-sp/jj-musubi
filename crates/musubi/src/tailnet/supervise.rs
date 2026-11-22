//! Running a node so that whatever goes wrong in it can be thrown away whole.
//!
//! tailscale-rs 0.7.1 can't be relied on to free what a node holds: a socket whose peer died
//! is never freed, nor is a connect given up on, and stopping a device needn't stop all its
//! tasks. And after a panic in it, it may take one peer's packets for another's (see
//! `gate`). So each node runs on a tokio runtime of its own, which is dropped, and everything
//! on it with it, to replace the node: a *generation*.
//!
//! Its threads, and the thread that drives it, are marked, and a panic hook, which runs
//! before unwinding and so before tailscale-rs can restart anything, stops trusting the
//! generation of a marked thread at once: see [`Trust`]. Panics elsewhere are left as they
//! were, since musubi catches jj-lib's on purpose.

use std::cell::RefCell;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::Once;
use std::sync::PoisonError;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;

use futures::future::BoxFuture;
use musubi_transport::heartbeat::Ended;

use crate::backoff::Backoff;

/// How many connections may have ended so that their sockets may never be freed before the
/// node is replaced to free them: each may hold 128 KiB.
const MAX_STRANDED: usize = 64;

/// How long a node may go without reaching anything, after failing to, before it is replaced,
/// if nothing else uses it: its links to the tailnet may be what's broken.
const STUCK: Duration = Duration::from_secs(300);

/// How long the machine may sleep before the node is replaced on waking.
const SLEPT: Duration = Duration::from_secs(60);

/// How often to look at how worn a generation is, and for the machine having slept, which a
/// minute of sleep replaces it for. Its trust is not looked at: losing it wakes the supervisor.
const LOOK: Duration = Duration::from_secs(5);

/// How long to wait for a generation's tasks to go.
const SHUTDOWN: Duration = Duration::from_secs(5);

thread_local! {
    /// The generation a thread belongs to, if it is a node's.
    static GENERATION: RefCell<Option<Trust>> = const { RefCell::new(None) };
}

/// Whether a generation's node can still be believed. Lost at the first panic on any of its
/// threads, from inside the panic hook, which also wakes whoever waits for it to go.
#[derive(Clone, Default)]
pub struct Trust(Arc<TrustState>);

#[derive(Default)]
struct TrustState {
    lost: AtomicBool,
    gone: tokio::sync::Notify,
}

impl Trust {
    pub fn lost(&self) -> bool {
        self.0.lost.load(Ordering::SeqCst)
    }

    /// An error once the node can't be believed, for whatever reads from it.
    pub fn check(&self) -> std::io::Result<()> {
        if self.lost() {
            return Err(std::io::Error::other(
                "this machine's tailnet node failed, and is being replaced",
            ));
        }
        Ok(())
    }

    fn lose(&self) {
        self.0.lost.store(true, Ordering::SeqCst);
        // Stored, so that a waiter that starts later still hears it.
        self.0.gone.notify_one();
    }

    /// Waits until the node can't be believed.
    async fn until_lost(&self) {
        loop {
            let gone = self.0.gone.notified();
            if self.lost() {
                return;
            }
            gone.await;
        }
    }

    /// Marks this thread as one of this generation's.
    fn mark(&self) {
        GENERATION.with(|generation| *generation.borrow_mut() = Some(self.clone()));
    }

    fn unmark() {
        GENERATION.with(|generation| *generation.borrow_mut() = None);
    }
}

/// Sets the hook that loses a generation's trust when one of its threads panics, keeping the
/// hook there was. Called before any node starts, and before the threads that might set
/// hooks of their own do: two threads setting hooks at once could lose one.
pub fn prepare() {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            // `try_with`: a panic as a thread's locals are dropped finds them gone.
            GENERATION
                .try_with(|generation| {
                    if let Ok(generation) = generation.try_borrow()
                        && let Some(trust) = generation.as_ref()
                    {
                        trust.lose();
                    }
                })
                .ok();
            previous(info);
        }));
    });
}

/// How a generation's connections went: what decides that it's worn out.
#[derive(Default)]
pub struct Usage {
    live: AtomicUsize,
    stranded: AtomicUsize,
    /// Since when it has failed to reach anything, with no success since.
    stuck: Mutex<Option<Instant>>,
}

/// A connection in use, until dropped.
pub struct InUse(Arc<Usage>);

impl Drop for InUse {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Usage {
    pub fn in_use(self: &Arc<Self>) -> InUse {
        self.live.fetch_add(1, Ordering::SeqCst);
        InUse(self.clone())
    }

    /// A link was made: the node works.
    pub fn reached(&self) {
        *self.stuck.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// Nothing answered.
    pub fn unanswered(&self) {
        self.stuck
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_or_insert_with(Instant::now);
    }

    /// A connection ended, as `ended` says. Silence is the peer's, as when it sleeps, not this
    /// node's: a client that finds its hub silent says so with [`Usage::unanswered`].
    pub fn ended(&self, ended: Ended) {
        if ended.may_strand() {
            self.stranded.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Why the generation should be replaced, at `now`, if it should.
    fn worn_out(&self, now: Instant) -> Option<String> {
        let stranded = self.stranded.load(Ordering::SeqCst);
        if stranded >= MAX_STRANDED {
            return Some(format!(
                "{stranded} connections ended without closing, whose sockets tailscale-rs \
                 never frees"
            ));
        }
        let stuck = *self.stuck.lock().unwrap_or_else(PoisonError::into_inner);
        if self.live.load(Ordering::SeqCst) == 0
            && let Some(since) = stuck
            && now.duration_since(since) >= STUCK
        {
            return Some(format!(
                "it has reached nothing for {} minutes",
                STUCK.as_secs() / 60
            ));
        }
        None
    }
}

/// What one generation is given.
pub struct Generation {
    pub trust: Trust,
    pub usage: Arc<Usage>,
}

/// How a generation ended.
pub enum Over {
    /// It wants replacing, for this reason.
    Replace(String),
    /// It couldn't start, for this reason: try again later.
    Failed(String),
}

/// Runs generations, each made by `run` on a runtime of its own, on a thread named `name`,
/// telling `over` once each has ended, whichever way, and its runtime has gone,
/// one after another for as long as the process lives.
pub fn spawn(
    name: &'static str,
    run: impl Fn(Generation) -> BoxFuture<'static, Over> + Send + 'static,
    over: impl Fn(&Over) + Send + 'static,
) {
    prepare();
    std::thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || {
            let mut backoff = Backoff::new(Duration::from_secs(5), Duration::from_secs(60));
            loop {
                let ended = one(name, &run);
                over(&ended);
                let wait = match ended {
                    Over::Replace(why) => {
                        tracing::warn!("replacing this machine's tailnet node: {why}");
                        backoff.reset();
                        Duration::from_secs(1)
                    }
                    Over::Failed(why) => {
                        let wait = backoff.next();
                        tracing::warn!(
                            "this machine's tailnet node didn't start, trying again in {}s: {why}",
                            wait.as_secs()
                        );
                        wait
                    }
                };
                std::thread::sleep(wait);
            }
        })
        .expect("spawning a thread");
}

/// Runs one generation until it is over, and drops it.
fn one(name: &'static str, run: &(impl Fn(Generation) -> BoxFuture<'static, Over> + Send)) -> Over {
    let trust = Trust::default();
    let usage = Arc::new(Usage::default());
    let marking = trust.clone();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name(name)
        .on_thread_start(move || marking.mark())
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => return Over::Failed(format!("making a runtime: {err}")),
    };
    trust.mark();
    let generation = Generation {
        trust: trust.clone(),
        usage: usage.clone(),
    };
    let running = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runtime.block_on(watch(run(generation), &trust, &usage))
    }));
    Trust::unmark();
    runtime.shutdown_timeout(SHUTDOWN);
    running.unwrap_or_else(|_| Over::Replace("it panicked".to_owned()))
}

/// Runs `generation` until it is over, it panics, it wears out, or the machine wakes.
async fn watch(generation: BoxFuture<'static, Over>, trust: &Trust, usage: &Usage) -> Over {
    let looking = async {
        let mut look = tokio::time::interval(LOOK);
        let (mut wall, mut clock) = (SystemTime::now(), Instant::now());
        loop {
            look.tick().await;
            let (now_wall, now) = (SystemTime::now(), Instant::now());
            if let Some(why) = usage.worn_out(now) {
                return Over::Replace(why);
            }
            // `Instant` stops while the machine sleeps; the wall clock doesn't.
            let slept = now_wall
                .duration_since(wall)
                .unwrap_or_default()
                .saturating_sub(now - clock);
            if slept > SLEPT {
                return Over::Replace(format!(
                    "the machine woke after about {}s asleep",
                    slept.as_secs()
                ));
            }
            (wall, clock) = (now_wall, now);
        }
    };
    tokio::select! {
        biased;
        () = trust.until_lost() => Over::Replace("it panicked".to_owned()),
        over = generation => over,
        over = looking => over,
    }
}

#[cfg(test)]
mod tests {
    use futures::FutureExt as _;
    use tokio::sync::mpsc;

    use super::*;

    /// Something a generation holds, which says when it is dropped.
    struct Held(mpsc::UnboundedSender<&'static str>);

    impl Drop for Held {
        fn drop(&mut self) {
            self.0.send("dropped").ok();
        }
    }

    /// A panic on one of a generation's threads loses its trust before anything unwinds, and
    /// the generation is replaced with everything it held, while panics on other threads,
    /// which musubi catches on purpose, change nothing.
    #[test]
    fn a_panic_in_a_node_replaces_it_whole() {
        prepare();
        // Elsewhere: the hook leaves it be.
        let elsewhere = std::thread::spawn(|| panic!("not a node's")).join();
        assert!(elsewhere.is_err());

        let (said, mut heard) = mpsc::unbounded_channel();
        let generations = Arc::new(AtomicUsize::new(0));
        let counted = generations.clone();
        let over = one("musubi-test-node", &move |generation: Generation| {
            counted.fetch_add(1, Ordering::SeqCst);
            let held = Held(said.clone());
            let trust = generation.trust.clone();
            let said = said.clone();
            async move {
                // Outlives the panic: what the runtime drops.
                tokio::spawn(async move {
                    let _held = held;
                    std::future::pending::<()>().await;
                });
                let checked = tokio::spawn(async move {
                    assert!(!trust.lost());
                    // What a read would do after the panic: refuse.
                    std::panic::catch_unwind(|| panic!("in tailscale-rs")).ok();
                    said.send(if trust.check().is_err() {
                        "distrusted"
                    } else {
                        "trusted"
                    })
                    .ok();
                });
                checked.await.ok();
                std::future::pending::<Over>().await
            }
            .boxed()
        });
        assert!(matches!(over, Over::Replace(why) if why == "it panicked"));
        assert_eq!(generations.load(Ordering::SeqCst), 1);
        // In either order: the supervisor, woken by the hook, drops the runtime while the task
        // that panicked may still be finishing its poll.
        let mut said = vec![heard.try_recv().unwrap(), heard.try_recv().unwrap()];
        said.sort_unstable();
        assert_eq!(said, ["distrusted", "dropped"]);
    }

    #[test]
    fn a_node_whose_sockets_may_never_be_freed_is_replaced() {
        let usage = Arc::new(Usage::default());
        let now = Instant::now();
        for _ in 0..MAX_STRANDED - 1 {
            usage.ended(Ended::NotClosed);
        }
        usage.ended(Ended::Closed);
        assert_eq!(usage.worn_out(now), None);
        usage.ended(Ended::Stalled);
        assert!(usage.worn_out(now).is_some());
    }

    /// One that has reached nothing for a while is replaced, unless something still uses it.
    #[test]
    fn a_node_that_reaches_nothing_is_replaced_once_unused() {
        let usage = Arc::new(Usage::default());
        let now = Instant::now();
        let later = now + STUCK;
        assert_eq!(usage.worn_out(later), None);
        let in_use = usage.in_use();
        usage.unanswered();
        assert_eq!(usage.worn_out(later + STUCK), None);
        drop(in_use);
        assert!(usage.worn_out(later + STUCK).is_some());
        usage.reached();
        assert_eq!(usage.worn_out(later + STUCK), None);
    }

    /// A hub whose last client goes to sleep, and so silent, has nothing wrong with its own
    /// node, which stays.
    #[test]
    fn a_peer_that_goes_silent_wears_nothing_out() {
        let usage = Arc::new(Usage::default());
        let in_use = usage.in_use();
        usage.ended(Ended::Silent);
        drop(in_use);
        assert_eq!(usage.worn_out(Instant::now() + STUCK * 10), None);
    }
}
