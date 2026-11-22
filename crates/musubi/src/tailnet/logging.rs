//! Keeping tailscale-rs's secrets out of the log.

use tracing::Level;
use tracing::Metadata;
use tracing::Subscriber;
use tracing_subscriber::layer::Layer;

/// A layer that lets tailscale-rs log warnings and errors only, whatever the filter beneath
/// it says: at `trace` it logs each registration request's body, which holds the auth key
/// (`ts_control::client::register`), and the network map.
pub fn without_secrets<S: Subscriber>() -> impl Layer<S> {
    tracing_subscriber::filter::filter_fn(may_log)
}

fn may_log(metadata: &Metadata<'_>) -> bool {
    *metadata.level() <= Level::WARN || !is_tailscales(metadata.target())
}

/// Whether `target` is one of tailscale-rs's crates: `tailscale`, and each `ts_*`.
fn is_tailscales(target: &str) -> bool {
    let krate = target.split("::").next().unwrap_or_default();
    krate == "tailscale" || krate.starts_with("ts_")
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::Arc;
    use std::sync::Mutex;

    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::layer::SubscriberExt as _;

    use super::*;

    #[derive(Clone, Default)]
    struct Kept(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Kept {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// The most a user can ask for, and by each way of asking, still logs no auth key.
    #[test]
    fn no_filter_logs_an_auth_key() {
        for filter in [
            "trace",
            "ts_control=trace",
            "ts_control::client::register=trace",
            "[register]=trace",
        ] {
            let kept = Kept::default();
            let writer = kept.clone();
            let subscriber = tracing_subscriber::fmt()
                .with_env_filter(EnvFilter::new(filter))
                .with_writer(move || writer.clone())
                .with_ansi(false)
                .finish()
                .with(without_secrets());
            tracing::subscriber::with_default(subscriber, || {
                // As `ts_control::client::register` logs it, inside the span it makes.
                let span = tracing::info_span!(target: "ts_control::client::register", "register");
                let _in_span = span.enter();
                tracing::trace!(target: "ts_control::client::register", body = "key-example");
                tracing::debug!(target: "tailscale", "key-example");
                tracing::info!(target: "ts_runtime::dataplane", "key-example");
                tracing::warn!(target: "ts_control::client::register", "registration failed");
                tracing::trace!(target: "musubi::tailnet", "its own");
            });
            let log = String::from_utf8(kept.0.lock().unwrap().clone()).unwrap();
            assert!(!log.contains("key-example"), "{filter}: {log}");
            if filter == "trace" {
                assert!(
                    log.contains("registration failed") && log.contains("its own"),
                    "{log}"
                );
            }
        }
    }
}
