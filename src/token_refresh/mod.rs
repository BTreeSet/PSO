use std::convert::TryFrom;
use std::time::Duration;

pub const ACCESS_TOKEN_REFRESH_MARGIN_MS: i64 = 60_000;
pub const ACCESS_TOKEN_REFRESH_TARGET_PERCENT: i64 = 75;
pub const ACCESS_TOKEN_REFRESH_RETRY_STEP_PERCENT: i64 = 5;
const MIN_REFRESH_RETRY_DELAY_MS: i64 = 1_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenRefreshWindow {
    pub refresh_at_ms: i64,
    pub expires_at_ms: i64,
}

impl TokenRefreshWindow {
    pub fn from_expires_in(now_ms: i64, expires_in_secs: u64) -> Option<Self> {
        let lifetime_ms = i64::try_from(expires_in_secs).ok()?.checked_mul(1_000)?;
        if lifetime_ms <= 0 {
            return None;
        }

        let expires_at_ms = now_ms.checked_add(lifetime_ms)?;
        let refresh_delay_ms = lifetime_ms
            .checked_mul(ACCESS_TOKEN_REFRESH_TARGET_PERCENT)?
            .checked_div(100)?;
        let refresh_at_ms = now_ms.checked_add(refresh_delay_ms)?;

        Some(Self {
            refresh_at_ms,
            expires_at_ms,
        })
    }

    pub fn should_reuse(self, now_ms: i64) -> bool {
        let margin_deadline = now_ms.saturating_add(ACCESS_TOKEN_REFRESH_MARGIN_MS);
        margin_deadline < self.refresh_at_ms && margin_deadline < self.expires_at_ms
    }

    pub fn retry_step_ms(self) -> i64 {
        let retry_step_ms = (self.expires_at_ms.saturating_sub(self.refresh_at_ms))
            / ACCESS_TOKEN_REFRESH_RETRY_STEP_PERCENT;
        retry_step_ms.max(MIN_REFRESH_RETRY_DELAY_MS)
    }

    pub fn next_attempt_at(self, failure_count: u32) -> i64 {
        let retry_step_ms = self.retry_step_ms();
        let offset_ms = retry_step_ms.saturating_mul(i64::from(failure_count));
        self.refresh_at_ms
            .saturating_add(offset_ms)
            .min(self.expires_at_ms)
    }

    pub fn delay_until_next_attempt(self, now_ms: i64, failure_count: u32) -> Duration {
        Duration::from_millis(
            self.next_attempt_at(failure_count)
                .saturating_sub(now_ms)
                .max(0) as u64,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_refresh_and_retry_targets_from_lifetime() {
        let window = TokenRefreshWindow::from_expires_in(1_000, 120).expect("window");

        assert_eq!(window.refresh_at_ms, 91_000);
        assert_eq!(window.expires_at_ms, 121_000);
        assert_eq!(window.retry_step_ms(), 6_000);
        assert_eq!(window.next_attempt_at(0), 91_000);
        assert_eq!(window.next_attempt_at(1), 97_000);
        assert_eq!(window.next_attempt_at(5), 121_000);
    }

    #[test]
    fn reuse_stops_before_refresh_margin() {
        let window = TokenRefreshWindow {
            refresh_at_ms: 80_000,
            expires_at_ms: 100_000,
        };

        assert!(window.should_reuse(0));
        assert!(!window.should_reuse(59_999));
        assert!(!window.should_reuse(95_000));
    }
}
