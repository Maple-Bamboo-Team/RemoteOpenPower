use crate::{client, protocol::WakeResult};
use std::{
    collections::HashSet,
    time::{Duration, Instant},
};

pub const RECOVERY_TIMEOUT: Duration = Duration::from_secs(13 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Waiting,
    Complete,
    Partial,
    Rejected,
}

pub struct Progress {
    pub created_at: Instant,
    pub accepted: HashSet<String>,
    pub online: HashSet<String>,
    pub started_at: Option<Instant>,
    pub deadline: Instant,
}

impl Progress {
    pub fn new(now: Instant) -> Self {
        Self {
            created_at: now,
            accepted: HashSet::new(),
            online: HashSet::new(),
            started_at: None,
            deadline: now + client::RECEIPT_TIMEOUT,
        }
    }

    pub fn can_recover(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.created_at) < RECOVERY_TIMEOUT
    }

    pub fn receive(&mut self, results: &[WakeResult], now: Instant) {
        self.accepted = results
            .iter()
            .filter(|item| item.accepted)
            .map(|item| item.host_id.clone())
            .collect();
        self.online.retain(|id| self.accepted.contains(id));
        let first_receipt = *self.started_at.get_or_insert(now);
        self.deadline = first_receipt + client::WAKE_WAIT_TIMEOUT;
    }

    pub fn observe(&mut self, host_id: &str) -> bool {
        self.accepted.contains(host_id) && self.online.insert(host_id.to_owned())
    }

    pub fn outcome(&self, targets: &[String]) -> Outcome {
        if self.started_at.is_none() {
            return Outcome::Waiting;
        }
        if self.accepted.is_empty() {
            return Outcome::Rejected;
        }
        if !self.accepted.is_subset(&self.online) {
            return Outcome::Waiting;
        }
        if targets.iter().all(|id| self.online.contains(id)) {
            Outcome::Complete
        } else {
            Outcome::Partial
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_expires_even_if_no_receipt_arrived_or_receipts_repeat() {
        let now = Instant::now();
        let mut progress = Progress::new(now);
        assert!(progress.can_recover(now + RECOVERY_TIMEOUT - Duration::from_millis(1)));
        assert!(!progress.can_recover(now + RECOVERY_TIMEOUT));
        progress.receive(&[], now + Duration::from_secs(60));
        assert!(!progress.can_recover(now + RECOVERY_TIMEOUT));
    }

    #[test]
    fn recovered_receipt_preserves_first_local_wait_and_partial_is_not_success() {
        let now = Instant::now();
        let mut progress = Progress::new(now);
        let results = vec![
            WakeResult {
                host_id: "a".into(),
                accepted: true,
                error_code: None,
            },
            WakeResult {
                host_id: "b".into(),
                accepted: false,
                error_code: Some(crate::protocol::WakeErrorCode::RateLimited),
            },
        ];
        progress.receive(&results, now);
        progress.receive(&results, now + Duration::from_secs(40));
        assert_eq!(progress.deadline, now + client::WAKE_WAIT_TIMEOUT);
        assert!(progress.observe("a"));
        assert!(!progress.observe("b"));
        assert_eq!(
            progress.outcome(&["a".into(), "b".into()]),
            Outcome::Partial
        );
        assert_eq!(progress.outcome(&["a".into()]), Outcome::Complete);
        progress.receive(&results[1..], now);
        assert_eq!(progress.outcome(&["b".into()]), Outcome::Rejected);
    }
}
