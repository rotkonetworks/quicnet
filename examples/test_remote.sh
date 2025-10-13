#!/bin/bash

echo "=== Testing Remote Session ==="

echo "1. Testing native build..."
cargo build --example remote_session --features remote

echo -e "\n2. Testing WebTransport build..."
cargo build --example remote_session --features webtransport

echo -e "\n3. Usage examples:"
echo "Native server:  cargo run --example remote_session --features remote -- server"
echo "Native client:  cargo run --example remote_session --features remote -- client <addr>"
echo "Web bridge:     cargo run --example remote_session --features webtransport -- web"
echo "Web client:     open http://localhost:8080 in browser"

echo -e "\n4. Features available:"
echo "- Native QUIC remote desktop with X11 screen capture and uinput injection"
echo "- WebTransport bridge for browser-based remote access"
echo "- WebP compression for efficient screen transmission"
echo "- Full keyboard and mouse support"

echo -e "\nSetup complete!"