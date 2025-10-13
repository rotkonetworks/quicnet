# pushup.sh - Engineering Roadmap

Browser-based Linux workspaces using QUIC/WebTransport + hardware video encoding.

## What Works Now
- ✅ QUIC/WebTransport video streaming
- ✅ Hardware H.264 encoding (VAAPI, 60fps)
- ✅ Basic HTML client with stats
- ✅ Container architecture (one IPv6 per container)

## What's Broken
- ❌ Software H.264 (no keyframes, WebCodecs fails)
- ❌ XSHM disabled (Send trait issues)
- ❌ Hardcoded ports/addresses
- ❌ No proper UI framework
- ❌ Manual container management
- ❌ No audio streaming (PulseAudio → browser)
- ❌ No input device streaming (webcam/mic → remote)

## Engineering Priorities

### 1. Library Structure
```
quicnet/
├── core/           # QUIC + video encoding
├── server/         # Container orchestration
├── client/         # Dioxus web app
└── examples/       # Current proof-of-concept
```

### 2. Client Rewrite (Dioxus)
Replace basic HTML with proper Rust web app:
```rust
fn App(cx: Scope) -> Element {
    render! {
        WorkspaceSelector {}
        VideoStream {}
        RemoteControl {}
        StatsOverlay {}
    }
}
```

### 3. Container Orchestration
- IPv6 + dynamic ports (no hardcoding)
- Kubernetes/Docker Compose deployment
- GPU assignment per container
- Workspace persistence (bind mounts)

### 4. Fix XSHM
- Solve Send trait issues with X11 pointers
- 10x performance improvement (3ms vs 30ms capture)
- Critical for competitive performance

### 5. Fix Software H.264
- Force keyframe generation in openh264
- Proper annex-b format for WebCodecs
- Fallback when hardware encoding unavailable

### 6. Audio Streaming (PulseAudio)
- Capture remote audio output (speakers/system sounds)
- Encode to Opus/AAC over QUIC stream
- WebAudio API playback in browser
- Low-latency audio pipeline (<50ms)

### 7. Input Device Streaming
- **Webcam upload**: Browser → QUIC → /dev/video0 on remote
- **Microphone upload**: WebRTC → QUIC → PulseAudio input
- **File uploads**: Drag & drop → QUIC → remote filesystem
- Virtual device creation in containers

## Technical Debt
- Clean up unused imports/warnings
- Remove hardcoded certificate hashes
- Error handling (currently just unwrap/expect)
- Logging framework (replace eprintln!)
- Configuration management

## Infrastructure Needs
- Multi-region deployment (Docker Swarm/K8s)
- Load balancing for WebTransport
- Container image builds (bspwm + tools + PulseAudio)
- Monitoring (GPU/audio usage per container)
- Storage for persistent workspaces
- Virtual device management (webcam/mic routing)

## Next Steps
1. **Refactor into proper library structure**
2. **Build Dioxus client**
3. **Container orchestration scripts**
4. **Fix XSHM performance**
5. **Deploy to cheap GPU provider**