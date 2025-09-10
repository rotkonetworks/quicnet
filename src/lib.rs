pub mod auth;
pub mod identity;
pub mod server;
pub mod client;

#[cfg(feature = "coordinator")]
pub mod coordinator;

pub use identity::{Identity, PeerId};
pub use server::Server;
pub use client::Client;

pub const DEFAULT_PORT: u16 = 4433;
pub const DEFAULT_IDENTITY: &str = ".ssh/id_quicnet";
