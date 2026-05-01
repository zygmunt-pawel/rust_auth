use std::time::Duration;
use tokio::time::{Instant, sleep_until};

/// Returned by `start_pad`. Drop or call `.finish()` at the end of an issue/verify path
/// to ensure the call always takes at least `target` duration.
pub(crate) struct PadGuard {
    deadline: Instant,
}

pub(crate) fn start_pad(target: Duration) -> PadGuard {
    PadGuard { deadline: Instant::now() + target }
}

impl PadGuard {
    pub async fn finish(self) {
        sleep_until(self.deadline).await;
    }
}

pub(crate) const ISSUE_PAD: Duration = Duration::from_millis(100);
pub(crate) const VERIFY_PAD: Duration = Duration::from_millis(100);

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant as StdInstant;

    #[tokio::test]
    async fn pad_extends_short_path() {
        let pad = start_pad(Duration::from_millis(50));
        let started = StdInstant::now();
        // simulate fast path
        tokio::time::sleep(Duration::from_millis(5)).await;
        pad.finish().await;
        assert!(started.elapsed() >= Duration::from_millis(50));
    }

    #[tokio::test]
    async fn pad_does_not_shorten_long_path() {
        let pad = start_pad(Duration::from_millis(20));
        let started = StdInstant::now();
        tokio::time::sleep(Duration::from_millis(60)).await;
        pad.finish().await;
        assert!(started.elapsed() >= Duration::from_millis(60));
        // sleep_until on past instant returns immediately, total ≈60ms not 80ms.
        assert!(started.elapsed() < Duration::from_millis(100));
    }
}
