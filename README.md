# quicnet

minimal peer-to-peer network protocol using QUIC transport and ed25519 identities.

## what it is

quicnet provides encrypted, authenticated connections without dns or certificate
authorities. every peer has an ed25519 identity. peers connect directly using ip
addresses and verify each other cryptographically.

think of it as ssh meets netcat over quic — your identity is your keypair, not a
domain name.

## installation

```bash
cargo install --path .
```

## quick start

```bash
# server (auto-generates ~/.ssh/id_quicnet on first run)
quicnet -l

# client
quicnet localhost

# explicit peer verification (prevents active MITM)
quicnet εωSÎйШΜX5О4бЙìΚсÅίnÎАйÙМëжúEðЩÄÑ@localhost
```

## usage

### server mode

```bash
quicnet -l                      # listen on default port 4433
quicnet -l -p 6667              # listen on specific port
quicnet -l -b 192.168.1.100     # bind to address
quicnet -l -i ~/.ssh/id_ed25519 # use specific identity
quicnet -l --echo               # echo mode for testing
```

### client mode

```bash
quicnet example.com
quicnet example.com:6667

# peer-id pinning (recommended) - using b256 or hex encoded 32-char ids
quicnet εωSÎйШΜX5О4бЙìΚсÅίnÎАйÙМëжúEðЩÄÑ@example.com:6667

# ipv6
quicnet [2001:db8::1]:4433
quicnet alice@[2001:db8::1]:4433

# explicit identity file
quicnet -i ~/.ssh/id_ed25519 example.com
```

note on relay: --via and the coordinator module are experimental and not
yet wired to provide a reliable relay. direct connections are supported today.

## protocol design (updated)

### identity & transport binding

- your ed25519 keypair defines your PeerId (b256 encoded 32-byte pubkey).
- TLS certificate is self-signed Ed25519 derived from the same key.
- client verifies the server cert's SPKI equals expected PeerId when given.
- this prevents relay MITM during the initial QUIC/TLS handshake.

### authentication

application-layer challenge-response (ed25519) remains, but is now redundant
for MITM because TLS is bound to identity. it still provides clear app semantics.

### wire format

first bi-stream is used for stdin/stdout piping (client opens, server accepts).

## security

- transport encryption: TLS 1.3 over QUIC (rustls), cipher suites as chosen by
rustls
- identity binding: X.509 SPKI = ed25519 PeerId (prevents active MITM with
pinned id)
- optional app-layer ed25519 challenge-response

### visible

quic packet headers/timing, remote ip/port, public peer ids.

## limitations

- openssh key parser is simplified; may not handle all formats.
- relay/coordinator is experimental and not wired to --via yet.
- trust-on-first-use store is not implemented in this pass.

## license

mit or apache-2.0, at your option
