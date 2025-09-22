// rate limiting for incoming connections
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct RateLimiter {
    state: Arc<Mutex<RateLimiterState>>,
}

struct RateLimiterState {
    attempts: HashMap<IpAddr, Vec<Instant>>,
    max_attempts: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_attempts: usize, window: Duration) -> Self {
        Self {
            state: Arc::new(Mutex::new(RateLimiterState {
                attempts: HashMap::new(),
                max_attempts,
                window,
            })),
        }
    }

    pub fn check(&self, addr: IpAddr) -> bool {
        let now = Instant::now();
        let mut state = self.state.lock();

        let window = state.window;
        let max_attempts = state.max_attempts;

        let attempts = state.attempts.entry(addr).or_insert_with(Vec::new);
        attempts.retain(|t| now.duration_since(*t) < window);
        if state.attempts.len() > 1000 {
            state.attempts.retain(|_, v| !v.is_empty());
        }

        if attempts.len() >= max_attempts {
            false
        } else {
            attempts.push(now);
            true
        }
    }
}
