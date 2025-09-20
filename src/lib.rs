pub mod auth;
pub mod identity;
pub mod server;
pub mod client;
pub mod authorized_peers;
pub mod known_hosts;
pub mod pending_peers;
pub mod manage;

pub use identity::{Identity, PeerId};
pub use server::Server;
pub use client::Client;
pub use known_hosts::{KnownHosts, Trust};
pub use authorized_peers::AuthorizedPeers;
pub use pending_peers::PendingPeers;

pub const DEFAULT_PORT: u16 = 4433;
pub const DEFAULT_IDENTITY: &str = ".quicnet/identity";

pub mod transport;
pub mod security;

pub use transport::{AuthenticatedStream, ServerBuilder, ClientBuilder};
pub use security::{RateLimiter, AuditLog, AuditEvent};
