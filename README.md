# README.md

minimal peer-to-peer network protocol using QUIC transport and ed25519 identities.

## Build and Development Commands

### Building
```bash
cargo build                           # Debug build
cargo build --release                 # Release build with optimizations
cargo build --features webtransport   # Build with webtransport support
```

### Testing
```bash
cargo test                   # Run all tests
cargo test <TESTNAME>        # Run specific test by name
cargo test --no-fail-fast    # Run all tests even if some fail
```

### Code Quality
```bash
cargo fmt           # Format code using rustfmt
cargo clippy        # Run linter to catch common mistakes
cargo clippy --fix  # Automatically apply lint fixes
```

### Running
```bash
cargo run -- -l              # Run server mode
cargo run -- localhost       # Run client mode
cargo run --example shell    # Run shell example
cargo run --example chat     # Run chat example
```

## Architecture Overview

quicnet is a minimal peer-to-peer network protocol built on QUIC transport with
Ed25519 identity-based authentication. The architecture binds cryptographic
identities directly to the TLS layer, eliminating the need for certificate
authorities.

### Core Identity System
- **PeerId**: 32-byte Ed25519 public key, encoded in base256 format
- **Identity**: Ed25519 keypair stored in SSH-compatible format (default:
`~/.quicnet/id_ed25519`)
- TLS certificates are self-signed and derived from the Ed25519 identity
- The SPKI (Subject Public Key Info) in the X.509 certificate equals the PeerId,
preventing MITM attacks

### Module Structure

**Core Modules** (`src/`)
- `identity.rs`: Ed25519 keypair management, SSH key parsing, PeerId generation
- `client.rs`: QUIC client with identity-bound TLS verification
- `server.rs`: QUIC server with rate limiting and audit logging capabilities
- `auth.rs`: Application-layer challenge-response authentication protocol

**Transport Layer** (`src/transport/`)
- `stream.rs`: Authenticated bidirectional stream abstraction
- `builder.rs`: Server and client configuration builders
- `web_compat.rs`: WebTransport compatibility layer (optional feature)

**Security Features** (`src/security/`)
- `rate_limit.rs`: Connection rate limiting per IP
- `audit.rs`: Security event logging system

**Peer Management**
- `authorized_peers.rs`: Whitelist of allowed peer identities
- `known_hosts.rs`: Trust-on-first-use store for peer identities
- `pending_peers.rs`: Queue for peers awaiting authorization

### Protocol Flow
1. Client initiates QUIC connection with self-signed Ed25519 certificate
2. Server accepts with its own Ed25519 certificate
3. Both sides verify the peer's SPKI matches expected PeerId (if provided)
4. Application-layer challenge-response confirms mutual authentication
5. First bi-stream is opened for stdin/stdout piping

### Key Design Decisions
- No DNS or certificate authorities required - identities are cryptographic keys
- TLS binding prevents relay MITM attacks during handshake
- Compatible with SSH Ed25519 keys for easy key management
- Supports both direct connections and WebTransport (via optional feature flag)
