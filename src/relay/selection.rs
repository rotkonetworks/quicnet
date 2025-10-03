// relay selection with anti-correlation and reputation tracking
//
// ensures peers don't pick predictable relays that adversaries
// can camp on, while avoiding obviously bad/slow relays

use crate::identity::PeerId;
use anyhow::Result;
use arrayref::array_ref;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

// relay info with reputation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayInfo {
    pub peer_id: PeerId,
    pub endpoint: SocketAddr,
    // geographic hint for latency optimization (optional)
    pub region: Option<String>,
    // whether relay operator is known/vouched
    pub trusted: bool,
}

// reputation data for relay selection
#[derive(Debug, Clone)]
struct RelayReputation {
    // successful connections through this relay
    successes: u64,
    // failed connections through this relay
    failures: u64,
    // average latency in milliseconds
    avg_latency_ms: f64,
    // last time we successfully used this relay
    last_success: Option<SystemTime>,
    // consecutive failures (for circuit breaker)
    consecutive_failures: u32,
}

impl RelayReputation {
    fn new() -> Self {
        Self {
            successes: 0,
            failures: 0,
            avg_latency_ms: 0.0,
            last_success: None,
            consecutive_failures: 0,
        }
    }

    // calculate relay score for selection
    fn score(&self) -> f64 {
        // circuit breaker: dead relays get zero score
        if self.consecutive_failures > 5 {
            return 0.0;
        }

        // success rate component
        let total = self.successes + self.failures;
        let success_rate = if total > 0 {
            self.successes as f64 / total as f64
        } else {
            0.5  // neutral for new relays
        };

        // latency component (lower is better)
        let latency_score = if self.avg_latency_ms > 0.0 {
            100.0 / (self.avg_latency_ms + 100.0)
        } else {
            0.5
        };

        // recency bonus
        let recency_score = if let Some(last) = self.last_success {
            let age = SystemTime::now()
                .duration_since(last)
                .unwrap_or(Duration::from_secs(0));

            if age < Duration::from_hours(1) {
                1.0
            } else if age < Duration::from_days(1) {
                0.8
            } else {
                0.6
            }
        } else {
            0.5
        };

        // weighted combination
        success_rate * 0.5 + latency_score * 0.3 + recency_score * 0.2
    }
}

pub struct RelaySelector {
    // available relays
    relays: Vec<RelayInfo>,
    // reputation tracking
    reputation: Arc<RwLock<HashMap<PeerId, RelayReputation>>>,
    // entropy source for selection
    seed: [u8; 32],
}

impl RelaySelector {
    pub fn new(relays: Vec<RelayInfo>) -> Self {
        // random seed for this session
        let seed = rand::random();

        Self {
            relays,
            reputation: Arc::new(RwLock::new(HashMap::new())),
            seed,
        }
    }

    // select entry relay (first hop)
    pub async fn select_entry(&self) -> Result<RelayInfo> {
        self.select_relay(None).await
    }

    // select rendezvous relay ensuring it's different from entry
    pub async fn select_rendezvous(&self, exclude_entry: &SocketAddr) -> Result<RelayInfo> {
        // exclude relays on same /24 subnet as entry
        let exclude_subnet = Self::subnet_prefix(exclude_entry);
        self.select_relay(Some(exclude_subnet)).await
    }

    // select relay with weighted random selection
    async fn select_relay(&self, exclude_subnet: Option<[u8; 3]>) -> Result<RelayInfo> {
        let reputation = self.reputation.read().await;

        // calculate scores for all eligible relays
        let mut candidates: Vec<(RelayInfo, f64)> = Vec::new();

        for relay in &self.relays {
            // skip relays on excluded subnet
            if let Some(subnet) = exclude_subnet {
                if Self::subnet_prefix(&relay.endpoint) == subnet {
                    continue;
                }
            }

            // get reputation score
            let rep = reputation
                .get(&relay.peer_id)
                .cloned()
                .unwrap_or_else(RelayReputation::new);

            let score = rep.score();

            // boost trusted relays slightly
            let final_score = if relay.trusted {
                score * 1.2
            } else {
                score
            };

            if final_score > 0.0 {
                candidates.push((relay.clone(), final_score));
            }
        }

        if candidates.is_empty() {
            anyhow::bail!("no eligible relays available");
        }

        // weighted random selection
        let total_weight: f64 = candidates.iter().map(|(_, s)| s).sum();
        let mut rng = self.deterministic_rng();
        let selection = rng * total_weight;

        let mut cumulative = 0.0;
        for (relay, score) in candidates {
            cumulative += score;
            if cumulative >= selection {
                return Ok(relay);
            }
        }

        // shouldn't happen but return last as fallback
        Ok(candidates.last().unwrap().0.clone())
    }

    // report successful relay use
    pub async fn report_success(
        &self,
        relay_id: &PeerId,
        latency_ms: u64,
    ) {
        let mut reputation = self.reputation.write().await;
        let rep = reputation.entry(*relay_id).or_insert_with(RelayReputation::new);

        rep.successes += 1;
        rep.consecutive_failures = 0;
        rep.last_success = Some(SystemTime::now());

        // update rolling average latency
        if rep.avg_latency_ms == 0.0 {
            rep.avg_latency_ms = latency_ms as f64;
        } else {
            rep.avg_latency_ms = rep.avg_latency_ms * 0.9 + latency_ms as f64 * 0.1;
        }
    }

    // report relay failure
    pub async fn report_failure(&self, relay_id: &PeerId) {
        let mut reputation = self.reputation.write().await;
        let rep = reputation.entry(*relay_id).or_insert_with(RelayReputation::new);

        rep.failures += 1;
        rep.consecutive_failures += 1;
    }

    // extract /24 subnet prefix for correlation resistance
    fn subnet_prefix(addr: &SocketAddr) -> [u8; 3] {
        match addr {
            SocketAddr::V4(v4) => {
                let octets = v4.ip().octets();
                [octets[0], octets[1], octets[2]]
            }
            SocketAddr::V6(v6) => {
                // use /48 prefix for ipv6
                let segments = v6.ip().segments();
                [
                    (segments[0] >> 8) as u8,
                    segments[0] as u8,
                    (segments[1] >> 8) as u8,
                ]
            }
        }
    }

    // deterministic but unpredictable rng for this selector
    fn deterministic_rng(&self) -> f64 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.seed);
        hasher.update(&SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .to_le_bytes());

        let hash = hasher.finalize();
        let bytes = array_ref![hash.as_bytes(), 0, 8];
        let num = u64::from_le_bytes(*bytes);

        // convert to 0.0..1.0 range
        num as f64 / u64::MAX as f64
    }
}

// load relay list from config file
pub fn load_relay_config(path: &std::path::Path) -> Result<Vec<RelayInfo>> {
    let contents = std::fs::read_to_string(path)?;
    let relays: Vec<RelayInfo> = toml::from_str(&contents)?;
    Ok(relays)
}

// default hardcoded bootstrap relays for mvp
pub fn default_relays() -> Vec<RelayInfo> {
    vec![
        // these would be the initial curated set
        // run by different operators in different jurisdictions
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subnet_exclusion() {
        let addr1: SocketAddr = "192.168.1.1:4434".parse().unwrap();
        let addr2: SocketAddr = "192.168.1.2:4434".parse().unwrap();
        let addr3: SocketAddr = "192.168.2.1:4434".parse().unwrap();

        assert_eq!(
            RelaySelector::subnet_prefix(&addr1),
            RelaySelector::subnet_prefix(&addr2)
        );

        assert_ne!(
            RelaySelector::subnet_prefix(&addr1),
            RelaySelector::subnet_prefix(&addr3)
        );
    }
}