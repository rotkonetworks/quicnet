// relay coordination for nat traversal without being evil
//
// design goals:
// - relays learn nothing about who talks to whom
// - no persistent state that can be subpoenaed
// - resist traffic analysis through timing/volume correlation
// - make relay operators legally boring

use crate::identity::{Identity, PeerId};
use anyhow::Result;
use blake3::Hasher;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio::time::Instant;

mod rendezvous;
mod selection;

pub use rendezvous::RendezvousProtocol;
pub use selection::RelaySelector;

// how long ephemeral data lives before mandatory deletion
const EPHEMERAL_TTL: Duration = Duration::from_secs(120);

// relay roles in the network
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayMode {
    // accepts client connections, forwards to rendezvous
    Entry,
    // coordinates rendezvous between peers
    Rendezvous,
    // can perform either role
    Both,
}

// ephemeral message at rendezvous point
// deliberately minimal metadata
pub struct RendezvousMessage {
    // encrypted blob only readable by intended recipient
    ciphertext: Vec<u8>,
    // random per-session identifier
    ephemeral_id: [u8; 16],
    // when this must be deleted
    expiry: Instant,
}

// relay node that knows nothing and remembers less
pub struct RelayNode {
    identity: Identity,
    mode: RelayMode,
    // ephemeral storage with automatic expiry
    rendezvous_cache: Arc<RwLock<HashMap<[u8; 32], RendezvousMessage>>>,
    // tracks bandwidth for dos resistance
    rate_limiter: Arc<RwLock<HashMap<[u8; 16], TokenBucket>>>,
}

// token bucket for rate limiting without tracking identities
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    // tokens per second
    rate: f64,
    // max tokens in bucket
    capacity: f64,
}

impl TokenBucket {
    fn new(rate: f64, capacity: f64) -> Self {
        Self {
            tokens: capacity,
            last_refill: Instant::now(),
            rate,
            capacity,
        }
    }

    // returns true if request allowed
    fn try_consume(&mut self, tokens: f64) -> bool {
        self.refill();
        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.last_refill = now;
    }
}

impl RelayNode {
    pub fn new(identity: Identity, mode: RelayMode) -> Self {
        let node = Self {
            identity,
            mode,
            rendezvous_cache: Arc::new(RwLock::new(HashMap::new())),
            rate_limiter: Arc::new(RwLock::new(HashMap::new())),
        };

        // spawn janitor task for automatic cleanup
        let cache = node.rendezvous_cache.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                let now = Instant::now();
                let mut cache = cache.write().await;
                // delete expired messages, no logs, no traces
                cache.retain(|_, msg| msg.expiry > now);
            }
        });

        node
    }

    // derive deterministic rendezvous point for two peers
    // both peers calculate same value independently
    pub fn calculate_rendezvous(peer_a: &PeerId, peer_b: &PeerId) -> [u8; 32] {
        let mut hasher = Hasher::new();

        // canonical ordering so both peers get same result
        let (first, second) = if peer_a.as_bytes() < peer_b.as_bytes() {
            (peer_a, peer_b)
        } else {
            (peer_b, peer_a)
        };

        hasher.update(first.as_bytes());
        hasher.update(second.as_bytes());

        // include daily epoch for automatic rotation
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() / 86400;
        hasher.update(&epoch.to_le_bytes());

        *hasher.finalize().as_bytes()
    }

    // store rendezvous message without learning content
    pub async fn store_rendezvous(
        &self,
        rendezvous_id: [u8; 32],
        ciphertext: Vec<u8>,
        ephemeral_id: [u8; 16],
    ) -> Result<()> {
        // rate limit by ephemeral id
        let mut limiters = self.rate_limiter.write().await;
        let limiter = limiters
            .entry(ephemeral_id)
            .or_insert_with(|| TokenBucket::new(10.0, 100.0));

        if !limiter.try_consume(1.0) {
            anyhow::bail!("rate limited");
        }
        drop(limiters);

        // store with automatic expiry
        let message = RendezvousMessage {
            ciphertext,
            ephemeral_id,
            expiry: Instant::now() + EPHEMERAL_TTL,
        };

        let mut cache = self.rendezvous_cache.write().await;

        // limit total cache size for dos resistance
        if cache.len() > 10000 {
            anyhow::bail!("cache full");
        }

        cache.insert(rendezvous_id, message);
        Ok(())
    }

    // retrieve and delete rendezvous message
    // each message can only be retrieved once
    pub async fn retrieve_rendezvous(&self, rendezvous_id: [u8; 32]) -> Option<Vec<u8>> {
        let mut cache = self.rendezvous_cache.write().await;
        cache.remove(&rendezvous_id).map(|msg| msg.ciphertext)
    }

    // check if we should accept relay role for this request
    pub fn accepts_role(&self, requested: RelayMode) -> bool {
        match self.mode {
            RelayMode::Both => true,
            mode => mode == requested,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_rendezvous() {
        let peer_a = PeerId::from_bytes(&[1u8; 32]);
        let peer_b = PeerId::from_bytes(&[2u8; 32]);

        // both peers calculate same rendezvous point
        let rv1 = RelayNode::calculate_rendezvous(&peer_a, &peer_b);
        let rv2 = RelayNode::calculate_rendezvous(&peer_b, &peer_a);
        assert_eq!(rv1, rv2);

        // different peer pairs get different points
        let peer_c = PeerId::from_bytes(&[3u8; 32]);
        let rv3 = RelayNode::calculate_rendezvous(&peer_a, &peer_c);
        assert_ne!(rv1, rv3);
    }
}