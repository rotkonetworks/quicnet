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
        
        // cleanup old entries periodically (before getting mutable ref)
        if state.attempts.len() > 1000 {
            let mut empty_keys = Vec::new();
            for (k, v) in state.attempts.iter_mut() {
                v.retain(|t| now.duration_since(*t) < window);
                if v.is_empty() {
                    empty_keys.push(*k);
                }
            }
            for k in empty_keys {
                state.attempts.remove(&k);
            }
        }
        
        let attempts = state.attempts.entry(addr).or_default();
        attempts.retain(|t| now.duration_since(*t) < window);
        
        if attempts.len() >= max_attempts {
            false
        } else {
            attempts.push(now);
            true
        }
    }
}
