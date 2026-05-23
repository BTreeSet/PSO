use std::time::Duration;

pub const MAX_REFRESH_COUNT: u32 = 4;
pub const MIN_CERT_REFRESH_DELAY: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefreshDecision {
    Wait(Duration),
    Exhausted,
}

#[derive(Clone, Debug)]
pub struct RefreshScheduler {
    max_refresh_count: u32,
    minimum_delay: Duration,
}

impl Default for RefreshScheduler {
    fn default() -> Self {
        Self {
            max_refresh_count: MAX_REFRESH_COUNT,
            minimum_delay: MIN_CERT_REFRESH_DELAY,
        }
    }
}

impl RefreshScheduler {
    pub fn next_after_success(&self, now_ms: u64, refresh_at_ms: u64) -> RefreshDecision {
        RefreshDecision::Wait(Duration::from_millis(refresh_at_ms.saturating_sub(now_ms)))
    }

    pub fn next_after_failure(
        &self,
        now_ms: u64,
        expires_at_ms: u64,
        refresh_count: u32,
        retry_after: Option<Duration>,
    ) -> RefreshDecision {
        if let Some(retry_after) = retry_after {
            return RefreshDecision::Wait(retry_after.max(self.minimum_delay));
        }

        if refresh_count >= self.max_refresh_count {
            return RefreshDecision::Exhausted;
        }

        let midpoint_ms = ((now_ms as u128 + expires_at_ms as u128) / 2) as u64;
        let floor_ms = now_ms.saturating_add(self.minimum_delay.as_millis() as u64);
        RefreshDecision::Wait(Duration::from_millis(
            midpoint_ms.max(floor_ms).saturating_sub(now_ms),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_waits_until_refresh_target() {
        let scheduler = RefreshScheduler::default();
        assert_eq!(
            scheduler.next_after_success(1_000, 61_000),
            RefreshDecision::Wait(Duration::from_secs(60))
        );
    }

    #[test]
    fn failure_uses_midpoint_with_minimum_floor() {
        let scheduler = RefreshScheduler::default();
        assert_eq!(
            scheduler.next_after_failure(1_000, 11_000, 0, None),
            RefreshDecision::Wait(Duration::from_secs(30))
        );
        assert_eq!(
            scheduler.next_after_failure(1_000, 121_000, 0, None),
            RefreshDecision::Wait(Duration::from_secs(60))
        );
    }

    #[test]
    fn failure_stops_after_max_refresh_count() {
        let scheduler = RefreshScheduler::default();
        assert_eq!(
            scheduler.next_after_failure(1_000, 121_000, MAX_REFRESH_COUNT, None),
            RefreshDecision::Exhausted
        );
    }
}
