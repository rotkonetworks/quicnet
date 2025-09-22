// builder pattern for peer configuration
use anyhow::Result;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;
use crate::{Identity, Peer};
use crate::security::{RateLimiter, AuditLog};

pub struct ServerBuilder {
    identity: Option<Identity>,
    bind_addr_str: Option<String>,
    authorized_peers: Option<String>,
    rate_limiter: Option<RateLimiter>,
    audit_log: Option<AuditLog>,
}

impl ServerBuilder {
    pub fn new() -> Self {
        Self {
            identity: None,
            bind_addr_str: None,
            authorized_peers: None,
            rate_limiter: None,
            audit_log: None,
        }
    }

    pub fn identity(mut self, identity: Identity) -> Self {
        self.identity = Some(identity);
        self
    }

    pub fn bind<S: Into<String>>(mut self, addr: S) -> Self {
        self.bind_addr_str = Some(addr.into());
        self
    }

    pub fn authorized_peers_file(mut self, path: &str) -> Self {
        self.authorized_peers = Some(path.to_string());
        self
    }

    pub fn rate_limit(mut self, max_attempts: usize, window: Duration) -> Self {
        self.rate_limiter = Some(RateLimiter::new(max_attempts, window));
        self
    }

    pub fn audit_log(mut self, path: &str) -> Self {
        self.audit_log = Some(AuditLog::new(path));
        self
    }

    pub fn build(self) -> Result<Peer> {
        let identity = self.identity.ok_or_else(|| anyhow::anyhow!("identity required"))?;
        let bind_addr = parse_socket_addr(self.bind_addr_str.as_deref().unwrap_or("[::]:4433"))?;
        let mut peer = Peer::new(bind_addr, identity)?;
        peer.rate_limiter = self.rate_limiter;
        peer.audit_log = self.audit_log.unwrap_or_else(AuditLog::disabled);
        peer.authorized_peers_file = self.authorized_peers.map(Into::into);
        Ok(peer)
    }
}

pub struct ClientBuilder {
    identity: Option<Identity>,
    known_hosts: Option<String>,
}

impl ClientBuilder {
    pub fn new() -> Self {
        Self {
            identity: None,
            known_hosts: None,
        }
    }

    pub fn identity(mut self, identity: Identity) -> Self {
        self.identity = Some(identity);
        self
    }

    pub fn known_hosts(mut self, path: &str) -> Self {
        self.known_hosts = Some(path.to_string());
        self
    }

    pub async fn connect<A: Into<SocketAddr>>(self, _addr: A) -> Result<Peer> {
        let identity = self.identity.ok_or_else(|| anyhow::anyhow!("identity required"))?;
        let peer = Peer::new("[::]:0".parse()?, identity)?;
        // TODO: handle known_hosts and connect to addr
        Ok(peer)
    }
}

fn parse_socket_addr(input: &str) -> Result<SocketAddr> {
    if input.starts_with('[') && input.ends_with(']') {
        return Ok(format!("{}:4433", input).parse()?);
    }
    if let Ok(addr) = input.parse::<SocketAddr>() {
        return Ok(addr);
    }
    input
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("cannot resolve: {}", input))
}
