// builder pattern for server and client configuration
use anyhow::Result;
use std::net::SocketAddr;
use std::time::Duration;
use crate::{Identity, Server, Client};
use crate::security::{RateLimiter, AuditLog};

pub struct ServerBuilder {
    identity: Option<Identity>,
    bind_addr: Option<SocketAddr>,
    authorized_peers: Option<String>,
    rate_limiter: Option<RateLimiter>,
    audit_log: Option<AuditLog>,
}

impl ServerBuilder {
    pub fn new() -> Self {
        Self {
            identity: None,
            bind_addr: None,
            authorized_peers: None,
            rate_limiter: None,
            audit_log: None,
        }
    }
    
    pub fn identity(mut self, identity: Identity) -> Self {
        self.identity = Some(identity);
        self
    }
    
    pub fn bind<A: Into<SocketAddr>>(mut self, addr: A) -> Self {
        self.bind_addr = Some(addr.into());
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
    
    pub fn build(self) -> Result<Server> {
        let identity = self.identity.ok_or_else(|| anyhow::anyhow!("identity required"))?;
        let bind_addr = self.bind_addr.unwrap_or_else(|| "[::]:4433".parse().unwrap());
        
        let mut server = Server::bind(bind_addr, identity)?;
        server.rate_limiter = self.rate_limiter;
        server.audit_log = self.audit_log.unwrap_or_else(AuditLog::disabled);
        server.authorized_peers_file = self.authorized_peers;
        
        Ok(server)
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
    
    pub async fn connect<A: Into<SocketAddr>>(self, _addr: A) -> Result<Client> {
        let identity = self.identity.ok_or_else(|| anyhow::anyhow!("identity required"))?;
        let client = Client::new("[::]:0".parse()?, identity)?;
        // TODO: handle known_hosts and connect to addr
        Ok(client)
    }
}
