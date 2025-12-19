use anyhow::Result;
use quicnet::{Identity, Peer};
use tokio::io::AsyncReadExt;
use x11rb::connection::Connection;

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
enum VideoCodec {
    WebP,
    H264Software,
    H264Hardware,
}

#[cfg(feature = "webtransport")]
use std::process::{Command, Stdio};

// Simple H.264 encoder using ffmpeg for hardware acceleration
struct H264Encoder {
    width: u32,
    height: u32,
}

#[cfg(feature = "webtransport")]
impl H264Encoder {
    fn new_hardware(width: u32, height: u32) -> Result<Self> {
        eprintln!("Initializing H.264 hardware encoder {}x{}", width, height);
        Ok(H264Encoder { width, height })
    }

    fn encode_frame(&self, rgba_data: &[u8]) -> Result<Vec<u8>> {
        // Use ffmpeg for fast H.264 encoding with hardware acceleration
        let mut cmd = Command::new("ffmpeg")
            .args([
                "-f", "rawvideo",
                "-pix_fmt", "rgba",
                "-s", &format!("{}x{}", self.width, self.height),
                "-r", "60", // 60 FPS
                "-i", "-", // stdin
                "-c:v", "h264_vaapi", // Hardware encoder (fallback to libx264 if needed)
                "-preset", "ultrafast",
                "-tune", "zerolatency",
                "-b:v", "8M", // 8 Mbps
                "-f", "h264",
                "-"
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;

        if let Some(stdin) = cmd.stdin.take() {
            std::io::Write::write_all(&mut &stdin, rgba_data)?;
        }

        let output = cmd.wait_with_output()?;
        Ok(output.stdout)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install crypto provider");

    let args: Vec<_> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("server") => run_server().await,
        Some("web") => run_web_bridge().await,
        Some("client") => {
            let server = args.get(2).ok_or_else(|| anyhow::anyhow!("need server"))?;
            run_client(server).await
        }
        _ => {
            eprintln!("server: {} server", args[0]);
            eprintln!("web:    {} web", args[0]);
            eprintln!("client: {} client <addr>", args[0]);
            std::process::exit(1);
        }
    }
}

async fn run_server() -> Result<()> {
    let identity = Identity::load_or_generate()?;
    let peer = Peer::new("[::]:7777".parse()?, identity)?;

    eprintln!("native session on {}", peer.local_addr()?);
    eprintln!("peer: {}", peer.identity().peer_id());

    while let Some(incoming) = peer.accept().await {
        tokio::spawn(async move {
            if let Err(e) = handle_session(incoming).await {
                eprintln!("session: {e}");
            }
        });
    }
    Ok(())
}

#[cfg(feature = "webtransport")]
async fn run_web_bridge() -> Result<()> {
    use quicnet::transport::web_compat::WebCompatServer;

    let identity = Identity::load_or_generate()?;
    let server = WebCompatServer::new("[::]:8443".parse()?, identity).await?;

    eprintln!("webtransport bridge on https://localhost:8443");
    eprintln!("cert hash: {}", server.cert_hash());

    // serve web client
    tokio::spawn(serve_web_client(server.cert_hash().to_string()));

    while let Some(session) = server.accept_webtransport().await {
        tokio::spawn(async move {
            if let Err(e) = handle_web_session(session).await {
                eprintln!("web session: {e}");
            }
        });
    }
    Ok(())
}

#[cfg(feature = "webtransport")]
async fn handle_web_session(
    session: h3_webtransport::server::WebTransportSession<h3_quinn::Connection, bytes::Bytes>,
) -> Result<()> {
    use std::sync::Arc;
    eprintln!("web client connected");

    let session = Arc::new(session);

    // spawn input receiver
    let session_input = session.clone();
    tokio::spawn(async move {
        if let Err(e) = web_input_handler(session_input).await {
            eprintln!("web input: {e}");
        }
    });

    // screen capture sender
    web_screen_sender(session).await
}

#[cfg(feature = "webtransport")]
async fn web_input_handler(
    session: std::sync::Arc<h3_webtransport::server::WebTransportSession<h3_quinn::Connection, bytes::Bytes>>,
) -> Result<()> {
    let uinput = setup_uinput()?;

    // wait for first stream (persistent input stream)
    match session.accept_bi().await {
        Ok(Some(h3_webtransport::server::AcceptedBi::BidiStream(_, stream))) => {
            let (_, mut recv) = h3::quic::BidiStream::split(stream);

            loop {
                let mut buf = [0u8; 8];
                match recv.read_exact(&mut buf).await {
                    Ok(_) => {
                        let typ = u16::from_le_bytes([buf[0], buf[1]]);
                        let code = u16::from_le_bytes([buf[2], buf[3]]);
                        let value = i32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);

                        inject_event(uinput, typ, code, value)?;
                    }
                    Err(_) => break,
                }
            }
        }
        _ => {}
    }

    Ok(())
}

#[cfg(feature = "webtransport")]
async fn web_screen_sender(
    session: std::sync::Arc<h3_webtransport::server::WebTransportSession<h3_quinn::Connection, bytes::Bytes>>,
) -> Result<()> {
    web_screen_sender_with_codec(session, VideoCodec::H264Hardware).await
}

#[cfg(feature = "webtransport")]
async fn web_screen_sender_with_codec(
    session: std::sync::Arc<h3_webtransport::server::WebTransportSession<h3_quinn::Connection, bytes::Bytes>>,
    codec: VideoCodec,
) -> Result<()> {
    use x11rb::protocol::{composite, damage, shm, xproto};
    use x11rb::protocol::xproto::ImageFormat;

    let (x11, screen_num) = x11rb::connect(None)?;
    let screen = x11.setup().roots[screen_num].clone();
    let root = screen.root;
    let width = screen.width_in_pixels;
    let height = screen.height_in_pixels;

    eprintln!("Screen capture: {}x{}", width, height);

    // Check for XComposite extension (like OBS)
    let composite_available = composite::query_version(&x11, 0, 4)
        .map(|cookie| cookie.reply().is_ok())
        .unwrap_or(false);

    // Check for DAMAGE extension for efficient change detection
    let damage_available = damage::query_version(&x11, 1, 1)
        .map(|cookie| cookie.reply().is_ok())
        .unwrap_or(false);

    // Check for MIT-SHM extension for faster memory transfer
    let shm_available = shm::query_version(&x11)
        .map(|cookie| cookie.reply().is_ok())
        .unwrap_or(false);

    eprintln!("XComposite: {}, DAMAGE: {}, MIT-SHM: {}",
              composite_available, damage_available, shm_available);

    // For now, just use the extensions for information
    // Full XComposite implementation is complex and would need more setup

    let mut frame_counter = 0u32;
    let mut last_frame_hash = 0u64;
    let quality = 40.0; // Start with lower quality for speed
    let target_fps = 60.0; // 60 FPS for hardware encoding
    let frame_time = std::time::Duration::from_secs_f64(1.0 / target_fps);

    // Initialize encoder based on codec choice
    let h264_encoder = match codec {
        VideoCodec::H264Hardware | VideoCodec::H264Software => {
            match H264Encoder::new_hardware(width as u32, height as u32) {
                Ok(enc) => {
                    eprintln!("H.264 hardware encoder initialized successfully");
                    Some(enc)
                }
                Err(e) => {
                    eprintln!("Failed to initialize H.264 encoder: {}, falling back to WebP", e);
                    None
                }
            }
        }
        VideoCodec::WebP => None,
    };

    let final_codec = if h264_encoder.is_some() {
        match codec {
            VideoCodec::H264Hardware => VideoCodec::H264Hardware,
            VideoCodec::H264Software => VideoCodec::H264Software,
            _ => VideoCodec::H264Hardware,
        }
    } else {
        VideoCodec::WebP
    };

    eprintln!("Using codec: {:?}", final_codec);

    // Channel for async encoding (small buffer to avoid memory buildup)
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(u32, Vec<u8>, String)>(1);

    // Spawn encoder task
    let session_clone = session.clone();
    tokio::spawn(async move {
        while let Some((frame_id, encoded_data, content_type)) = rx.recv().await {
            eprintln!("Sending frame {} ({}) to client, size: {} bytes", frame_id, content_type, encoded_data.len());
            if let Ok(mut stream) = session_clone.open_bi(session_clone.session_id()).await {
                use tokio::io::AsyncWriteExt;

                // Send frame header with content type info
                let content_type_bytes = content_type.as_bytes();
                let header_size = 8 + 1 + content_type_bytes.len();
                let mut data = Vec::with_capacity(header_size + encoded_data.len());

                data.extend_from_slice(&frame_id.to_le_bytes());
                data.extend_from_slice(&(encoded_data.len() as u32).to_le_bytes());
                data.extend_from_slice(&[content_type_bytes.len() as u8]);
                data.extend_from_slice(content_type_bytes);
                data.extend_from_slice(&encoded_data);

                match stream.write_all(&data).await {
                    Ok(_) => eprintln!("Frame {} sent successfully", frame_id),
                    Err(e) => eprintln!("Error sending frame {}: {}", frame_id, e),
                }
            } else {
                eprintln!("Failed to open stream for frame {}", frame_id);
            }
        }
    });

    let _last_capture = std::time::Instant::now();

    loop {
        let loop_start = std::time::Instant::now();

        // Basic timing-based capture for now
        let should_capture = true;

        if !should_capture {
            tokio::time::sleep(std::time::Duration::from_millis(16)).await;
            continue;
        }

        // Regular root window capture (optimized timing)
        let img = xproto::get_image(
            &x11,
            ImageFormat::Z_PIXMAP,
            root,
            0, 0,
            width, height,
            !0,
        )?.reply()?;

        // Simple change detection - only skip if completely identical for multiple samples
        let sample_size = std::cmp::min(2048, img.data.len()); // Bigger sample
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        use std::hash::{Hash, Hasher};

        // Sample from multiple parts of the screen
        for i in 0..4 {
            let start = (i * img.data.len() / 4).min(img.data.len().saturating_sub(sample_size / 4));
            let end = (start + sample_size / 4).min(img.data.len());
            if start < end {
                img.data[start..end].hash(&mut hasher);
            }
        }
        let frame_hash = hasher.finish();

        // Only skip if same hash AND we've sent at least 10 frames already
        if frame_hash == last_frame_hash && frame_counter > 10 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            continue;
        }
        last_frame_hash = frame_hash;

        // Convert BGRA to RGBA (optimized)
        let mut rgba = img.data;
        rgba.chunks_exact_mut(4).for_each(|chunk| {
            chunk.swap(0, 2);
        });

        // Encode in background thread (non-blocking)
        let width_u32 = width as u32;
        let height_u32 = height as u32;
        let quality_copy = quality;
        let frame_id = frame_counter;
        frame_counter = frame_counter.wrapping_add(1);

        // Send to encoder if not busy
        if tx.capacity() > 0 {
            let tx_clone = tx.clone();
            let codec_copy = final_codec;
            eprintln!("Encoding frame {} with {:?}", frame_id, codec_copy);

            match codec_copy {
                VideoCodec::H264Hardware | VideoCodec::H264Software => {
                    if h264_encoder.is_some() {
                        // Clone encoder parameters for the blocking task
                        let encoder_width = width as u32;
                        let encoder_height = height as u32;
                        tokio::task::spawn_blocking(move || {
                            let encoder = H264Encoder::new_hardware(encoder_width, encoder_height);
                            match encoder.and_then(|enc| enc.encode_frame(&rgba)) {
                                Ok(h264_data) => {
                                    if !h264_data.is_empty() {
                                        eprintln!("Frame {} H.264 encoded, size: {} bytes", frame_id, h264_data.len());
                                        let _ = tx_clone.blocking_send((frame_id, h264_data, "video/h264".to_string()));
                                    }
                                }
                                Err(e) => {
                                    eprintln!("H.264 encoding failed: {}", e);
                                }
                            }
                        });
                    } else {
                        // Fallback to WebP if H.264 encoder failed
                        tokio::task::spawn_blocking(move || {
                            let encoder = webp::Encoder::from_rgba(&rgba, width_u32, height_u32);
                            let webp_data = encoder.encode(quality_copy).to_vec();
                            eprintln!("Frame {} WebP encoded (fallback), size: {} bytes", frame_id, webp_data.len());
                            let _ = tx_clone.blocking_send((frame_id, webp_data, "image/webp".to_string()));
                        });
                    }
                }
                VideoCodec::WebP => {
                    tokio::task::spawn_blocking(move || {
                        let encoder = webp::Encoder::from_rgba(&rgba, width_u32, height_u32);
                        let webp_data = encoder.encode(quality_copy).to_vec();
                        eprintln!("Frame {} WebP encoded, size: {} bytes", frame_id, webp_data.len());
                        let _ = tx_clone.blocking_send((frame_id, webp_data, "image/webp".to_string()));
                    });
                }
            }
        } else {
            eprintln!("Encoder busy, skipping frame {}", frame_id);
        }

        // Maintain target frame rate
        let elapsed = loop_start.elapsed();
        if elapsed < frame_time {
            tokio::time::sleep(frame_time - elapsed).await;
        }
    }
}

#[cfg(feature = "webtransport")]
async fn serve_web_client(cert_hash: String) -> Result<()> {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    eprintln!("web client on http://localhost:8080");

    loop {
        let (mut stream, _) = listener.accept().await?;
        let cert_hash = cert_hash.clone();

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;

            let html = format!(r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>remote session</title>
<style>
body {{ margin: 0; overflow: hidden; background: #000; }}
canvas {{ display: block; image-rendering: pixelated; cursor: none; }}
#info {{ position: absolute; top: 10px; left: 10px; color: #0f0; font-family: monospace; z-index: 100; }}
#stats {{ position: absolute; top: 40px; left: 10px; color: #0f0; font-family: monospace; z-index: 100; font-size: 12px; }}
#controls {{ position: absolute; top: 10px; right: 10px; z-index: 100; }}
button {{
    background: #333; color: #0f0; border: 1px solid #0f0;
    padding: 8px 16px; margin: 0 4px; font-family: monospace;
    cursor: pointer; border-radius: 3px;
}}
button:hover {{ background: #555; }}
button:disabled {{ opacity: 0.5; cursor: not-allowed; }}
.active {{ background: #0f0 !important; color: #000 !important; }}
</style>
</head>
<body>
<div id="info">connecting...</div>
<div id="stats">
    FPS: <span id="fps">0</span> | Codec: <span id="codec">-</span> | Bitrate: <span id="bitrate">0</span> Kbps | Frames: <span id="frameCount">0</span>
</div>
<div id="controls">
    <button id="enableInput">Enable Input</button>
    <button id="disableInput">Disable Input</button>
    <button id="quality">Quality: 85%</button>
    <button id="codecBtn">Codec: H.264</button>
</div>
<canvas id="screen"></canvas>

<script>
const info = document.getElementById('info');
const canvas = document.getElementById('screen');
const ctx = canvas.getContext('2d');
const enableBtn = document.getElementById('enableInput');
const disableBtn = document.getElementById('disableInput');
const qualityBtn = document.getElementById('quality');
const fpsSpan = document.getElementById('fps');
const codecSpan = document.getElementById('codec');
const bitrateSpan = document.getElementById('bitrate');
const frameCountSpan = document.getElementById('frameCount');

let inputEnabled = false;
let inputStream = null;
let currentQuality = 85;

// Performance tracking
let frameCount = 0;
let totalBytes = 0;
let lastFpsTime = performance.now();
let lastBitrateTime = performance.now();
let currentCodec = 'Unknown';

// H.264 decoder
let h264Decoder = null;
let isDecoderReady = false;

// Initialize H.264 decoder
function initH264Decoder() {{
    if ('VideoDecoder' in window) {{
        h264Decoder = new VideoDecoder({{
            output: (frame) => {{
                // Draw the decoded frame to canvas
                if (canvas.width !== frame.displayWidth || canvas.height !== frame.displayHeight) {{
                    canvas.width = frame.displayWidth;
                    canvas.height = frame.displayHeight;
                    canvas.style.width = Math.min(window.innerWidth, frame.displayWidth) + 'px';
                    canvas.style.height = Math.min(window.innerHeight, frame.displayHeight) + 'px';
                }}

                ctx.drawImage(frame, 0, 0);
                frame.close();
            }},
            error: (error) => {{
                console.error('H.264 decoder error:', error);
                info.textContent = 'H.264 decoder error: ' + error.message;
            }}
        }});

        h264Decoder.configure({{
            codec: 'avc1.42001E', // H.264 baseline profile
            optimizeForLatency: true
        }});

        isDecoderReady = true;
        console.log('H.264 decoder initialized');
    }} else {{
        console.warn('WebCodecs not supported, H.264 decoding unavailable');
    }}
}}

// key mappings (Linux input event codes)
const keyMap = {{
    'KeyW': 17, 'KeyA': 30, 'KeyS': 31, 'KeyD': 32,
    'Space': 57, 'Enter': 28, 'Escape': 1, 'ShiftLeft': 42, 'ControlLeft': 29,
    'ArrowUp': 103, 'ArrowDown': 108, 'ArrowLeft': 105, 'ArrowRight': 106,
    'Digit1': 2, 'Digit2': 3, 'Digit3': 4, 'Digit4': 5, 'Digit5': 6,
    'KeyQ': 16, 'KeyE': 18, 'KeyR': 19, 'KeyT': 20, 'KeyY': 21,
}};

(async () => {{
    try {{
        const transport = new WebTransport('https://localhost:8443', {{
            serverCertificateHashes: [{{
                algorithm: 'sha-256',
                value: new Uint8Array('{}'
                    .match(/../g).map(h => parseInt(h, 16))).buffer
            }}]
        }});

        await transport.ready;
        info.textContent = 'connected';

        // Initialize H.264 decoder
        initH264Decoder();

        // setup input stream
        inputStream = await transport.createBidirectionalStream();
        const inputWriter = inputStream.writable.getWriter();

        // control buttons
        enableBtn.addEventListener('click', async () => {{
            inputEnabled = true;
            enableBtn.classList.add('active');
            disableBtn.classList.remove('active');
            await canvas.requestPointerLock();
            info.textContent = 'input enabled - ESC to release';
        }});

        disableBtn.addEventListener('click', () => {{
            inputEnabled = false;
            enableBtn.classList.remove('active');
            disableBtn.classList.add('active');
            if (document.pointerLockElement) {{
                document.exitPointerLock();
            }}
            info.textContent = 'input disabled';
        }});

        qualityBtn.addEventListener('click', () => {{
            currentQuality = currentQuality === 85 ? 65 : currentQuality === 65 ? 45 : 85;
            qualityBtn.textContent = `Quality: ${{currentQuality}}%`;
        }});

        document.addEventListener('pointerlockchange', () => {{
            if (document.pointerLockElement !== canvas && inputEnabled) {{
                inputEnabled = false;
                enableBtn.classList.remove('active');
                disableBtn.classList.add('active');
                info.textContent = 'input disabled';
            }}
        }});

        // keyboard input
        document.addEventListener('keydown', async e => {{
            if (!inputEnabled) return;
            const code = keyMap[e.code];
            if (code !== undefined) {{
                e.preventDefault();
                const buf = new Uint8Array(8);
                new DataView(buf.buffer).setUint16(0, 1, true); // EV_KEY
                new DataView(buf.buffer).setUint16(2, code, true);
                new DataView(buf.buffer).setInt32(4, 1, true); // press
                try {{
                    await inputWriter.write(buf);
                }} catch (e) {{
                    console.warn('input write failed:', e);
                }}
            }}
        }});

        document.addEventListener('keyup', async e => {{
            if (!inputEnabled) return;
            const code = keyMap[e.code];
            if (code !== undefined) {{
                e.preventDefault();
                const buf = new Uint8Array(8);
                new DataView(buf.buffer).setUint16(0, 1, true);
                new DataView(buf.buffer).setUint16(2, code, true);
                new DataView(buf.buffer).setInt32(4, 0, true); // release
                try {{
                    await inputWriter.write(buf);
                }} catch (e) {{
                    console.warn('input write failed:', e);
                }}
            }}
        }});

        // mouse movement
        document.addEventListener('mousemove', async e => {{
            if (!inputEnabled) return;

            const dx = e.movementX;
            const dy = e.movementY;

            if (Math.abs(dx) > 0) {{
                const buf = new Uint8Array(8);
                new DataView(buf.buffer).setUint16(0, 2, true); // EV_REL
                new DataView(buf.buffer).setUint16(2, 0, true); // REL_X
                new DataView(buf.buffer).setInt32(4, dx, true);
                try {{
                    await inputWriter.write(buf);
                }} catch (e) {{
                    console.warn('input write failed:', e);
                }}
            }}

            if (Math.abs(dy) > 0) {{
                const buf = new Uint8Array(8);
                new DataView(buf.buffer).setUint16(0, 2, true); // EV_REL
                new DataView(buf.buffer).setUint16(2, 1, true); // REL_Y
                new DataView(buf.buffer).setInt32(4, dy, true);
                try {{
                    await inputWriter.write(buf);
                }} catch (e) {{
                    console.warn('input write failed:', e);
                }}
            }}
        }});

        // mouse clicks
        document.addEventListener('mousedown', async e => {{
            if (!inputEnabled) return;
            e.preventDefault();
            const btnCode = e.button === 0 ? 272 : e.button === 2 ? 273 : 274; // BTN_LEFT, BTN_RIGHT, BTN_MIDDLE
            const buf = new Uint8Array(8);
            new DataView(buf.buffer).setUint16(0, 1, true); // EV_KEY
            new DataView(buf.buffer).setUint16(2, btnCode, true);
            new DataView(buf.buffer).setInt32(4, 1, true);
            try {{
                await inputWriter.write(buf);
            }} catch (e) {{
                console.warn('input write failed:', e);
            }}
        }});

        document.addEventListener('mouseup', async e => {{
            if (!inputEnabled) return;
            e.preventDefault();
            const btnCode = e.button === 0 ? 272 : e.button === 2 ? 273 : 274;
            const buf = new Uint8Array(8);
            new DataView(buf.buffer).setUint16(0, 1, true);
            new DataView(buf.buffer).setUint16(2, btnCode, true);
            new DataView(buf.buffer).setInt32(4, 0, true);
            try {{
                await inputWriter.write(buf);
            }} catch (e) {{
                console.warn('input write failed:', e);
            }}
        }});

        // receive frames via bidirectional streams
        (async () => {{
            const reader = transport.incomingBidirectionalStreams.getReader();

            while (true) {{
                const {{ value: stream, done }} = await reader.read();
                if (done) break;

                const reader2 = stream.readable.getReader();

                try {{
                    // read basic header (8 bytes: frameId + size)
                    let basicHeader = new Uint8Array(8);
                    let headerOffset = 0;

                    while (headerOffset < 8) {{
                        const {{ value: chunk }} = await reader2.read();
                        if (!chunk) break;
                        const copySize = Math.min(chunk.length, 8 - headerOffset);
                        basicHeader.set(chunk.slice(0, copySize), headerOffset);
                        headerOffset += copySize;

                        // save extra data if we read too much
                        if (chunk.length > copySize) {{
                            var extraData = chunk.slice(copySize);
                        }}
                    }}

                    if (headerOffset < 8) continue;

                    const frameId = new DataView(basicHeader.buffer).getUint32(0, true);
                    const size = new DataView(basicHeader.buffer).getUint32(4, true);

                    // read content type length (1 byte)
                    let contentTypeLenBuf = new Uint8Array(1);
                    if (!extraData || extraData.length === 0) {{
                        const {{ value: chunk }} = await reader2.read();
                        if (!chunk) continue;
                        contentTypeLenBuf[0] = chunk[0];
                        if (chunk.length > 1) {{
                            extraData = chunk.slice(1);
                        }} else {{
                            extraData = new Uint8Array(0);
                        }}
                    }} else {{
                        contentTypeLenBuf[0] = extraData[0];
                        extraData = extraData.slice(1);
                    }}

                    const contentTypeLen = contentTypeLenBuf[0];

                    // read content type string
                    let contentTypeData = new Uint8Array(contentTypeLen);
                    let ctOffset = 0;
                    if (extraData && extraData.length > 0) {{
                        const copySize = Math.min(extraData.length, contentTypeLen);
                        contentTypeData.set(extraData.slice(0, copySize), 0);
                        ctOffset = copySize;
                        extraData = extraData.slice(copySize);
                    }}

                    while (ctOffset < contentTypeLen) {{
                        const {{ value: chunk }} = await reader2.read();
                        if (!chunk) break;
                        const copySize = Math.min(chunk.length, contentTypeLen - ctOffset);
                        contentTypeData.set(chunk.slice(0, copySize), ctOffset);
                        ctOffset += copySize;
                        if (chunk.length > copySize) {{
                            extraData = chunk.slice(copySize);
                        }}
                    }}

                    const contentType = new TextDecoder().decode(contentTypeData);
                    currentCodec = contentType === 'video/h264' ? 'H.264' : 'WebP';

                    console.log(`Received frame ${{frameId}}, size: ${{size}} bytes`);

                    // read frame data
                    let frameData = new Uint8Array(size);
                    let offset = 0;

                    // use extra data from header read if any
                    if (extraData && extraData.length > 0) {{
                        const copySize = Math.min(extraData.length, size);
                        frameData.set(extraData.slice(0, copySize), 0);
                        offset = copySize;
                    }}

                    while (offset < size) {{
                        const {{ value: chunk }} = await reader2.read();
                        if (!chunk) break;
                        const copySize = Math.min(chunk.length, size - offset);
                        frameData.set(chunk.slice(0, copySize), offset);
                        offset += copySize;
                    }}

                    if (offset < size) {{
                        console.warn(`Frame ${{frameId}} incomplete: got ${{offset}}/${{size}} bytes`);
                        continue;
                    }}

                    // Update performance stats
                    frameCount++;
                    totalBytes += size;
                    const now = performance.now();

                    // Update FPS every second
                    if (now - lastFpsTime >= 1000) {{
                        const fps = Math.round((frameCount * 1000) / (now - lastFpsTime));
                        fpsSpan.textContent = fps;
                        frameCount = 0;
                        lastFpsTime = now;
                    }}

                    // Update bitrate every 2 seconds
                    if (now - lastBitrateTime >= 2000) {{
                        const bitrate = Math.round((totalBytes * 8) / ((now - lastBitrateTime) / 1000) / 1000);
                        bitrateSpan.textContent = bitrate;
                        totalBytes = 0;
                        lastBitrateTime = now;
                    }}

                    // Update UI
                    codecSpan.textContent = currentCodec;
                    frameCountSpan.textContent = parseInt(frameCountSpan.textContent) + 1;

                    // Decode based on content type
                    if (contentType === 'video/h264') {{
                        // Use WebCodecs H.264 decoder
                        if (isDecoderReady && h264Decoder) {{
                            try {{
                                const chunk = new EncodedVideoChunk({{
                                    type: 'key', // Assume keyframe for now
                                    timestamp: performance.now() * 1000, // Convert to microseconds
                                    data: frameData
                                }});

                                h264Decoder.decode(chunk);
                                console.log(`H.264 frame ${{frameId}} decoded, size: ${{size}} bytes`);
                            }} catch (error) {{
                                console.error(`H.264 decode error for frame ${{frameId}}:`, error);
                                info.textContent = `H.264 decode error: ${{error.message}}`;
                            }}
                        }} else {{
                            console.log(`H.264 frame ${{frameId}} received but decoder not ready`);
                            info.textContent = `H.264 decoder not ready`;
                        }}
                    }} else {{
                        // Handle WebP/other image formats
                        const blob = new Blob([frameData], {{ type: contentType }});
                        const img = new Image();
                        img.onload = () => {{
                            if (canvas.width !== img.width || canvas.height !== img.height) {{
                                canvas.width = img.width;
                                canvas.height = img.height;
                                canvas.style.width = Math.min(window.innerWidth, img.width) + 'px';
                                canvas.style.height = Math.min(window.innerHeight, img.height) + 'px';
                            }}
                            ctx.drawImage(img, 0, 0);
                            console.log(`Frame ${{frameId}} displayed`);
                        }};
                        img.onerror = () => {{
                            console.error(`Failed to decode frame ${{frameId}}`);
                        }};
                        img.src = URL.createObjectURL(blob);
                    }}
                }} finally {{
                    reader2.releaseLock();
                }}
            }}
        }})();

    }} catch (e) {{
        info.textContent = 'error: ' + e.message;
        console.error(e);
    }}
}})();
</script>
</body>
</html>"#, cert_hash);

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/html\r\n\r\n{}",
                html.len(),
                html
            );

            use tokio::io::AsyncWriteExt;
            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}

#[cfg(not(feature = "webtransport"))]
async fn run_web_bridge() -> Result<()> {
    eprintln!("rebuild with --features webtransport");
    std::process::exit(1);
}

async fn run_client(server: &str) -> Result<()> {
    let addr: std::net::SocketAddr = server.parse()?;
    let identity = Identity::load_or_generate()?;
    let peer = Peer::new("[::]:0".parse()?, identity)?;

    eprintln!("connecting to {}", addr);
    let (conn, _) = peer.dial(addr, None).await?;

    // spawn input sender
    let input_conn = conn.clone();
    tokio::spawn(async move {
        if let Err(e) = input_sender(input_conn).await {
            eprintln!("input: {e}");
        }
    });

    // display frames
    frame_displayer(conn).await
}

async fn handle_session(incoming: quicnet::IncomingConnection) -> Result<()> {
    let (conn, peer_id) = incoming.accept().await?;
    eprintln!("[{}] session start", peer_id.short());

    // input injection stream
    let input_conn = conn.clone();
    tokio::spawn(async move {
        if let Err(e) = input_injector(input_conn).await {
            eprintln!("input: {e}");
        }
    });

    // screen capture stream
    screen_capturer(conn).await?;

    eprintln!("[{}] session end", peer_id.short());
    Ok(())
}

async fn input_injector(conn: quinn::Connection) -> Result<()> {
    let (_send, mut recv) = conn.accept_bi().await?;
    let uinput = setup_uinput()?;

    loop {
        let mut buf = [0u8; 8];
        recv.read_exact(&mut buf).await?;

        let typ = u16::from_le_bytes([buf[0], buf[1]]);
        let code = u16::from_le_bytes([buf[2], buf[3]]);
        let value = i32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);

        inject_event(uinput, typ, code, value)?;
    }
}

fn setup_uinput() -> Result<i32> {
    let uinput = unsafe {
        let fd = libc::open(b"/dev/uinput\0".as_ptr() as *const _, libc::O_WRONLY | libc::O_NONBLOCK);
        if fd < 0 {
            anyhow::bail!("cannot open /dev/uinput");
        }

        // enable key events
        libc::ioctl(fd, ui_set_evbit(), ev_key() as libc::c_uint);
        libc::ioctl(fd, ui_set_evbit(), ev_rel() as libc::c_uint);

        // enable all keys
        for k in 0..256 {
            libc::ioctl(fd, ui_set_keybit(), k as libc::c_uint);
        }

        // enable mouse
        libc::ioctl(fd, ui_set_relbit(), rel_x() as libc::c_uint);
        libc::ioctl(fd, ui_set_relbit(), rel_y() as libc::c_uint);
        libc::ioctl(fd, ui_set_keybit(), btn_left() as libc::c_uint);
        libc::ioctl(fd, ui_set_keybit(), btn_right() as libc::c_uint);
        libc::ioctl(fd, ui_set_keybit(), btn_middle() as libc::c_uint);

        // create device
        let mut setup: UinputSetup = std::mem::zeroed();
        setup.id.bustype = bus_usb();
        setup.id.vendor = 0x1234;
        setup.id.product = 0x5678;
        let name = b"quicnet-input\0";
        setup.name[..name.len()].copy_from_slice(name);

        libc::ioctl(fd, ui_dev_setup(), &setup as *const UinputSetup as *const libc::c_void);
        libc::ioctl(fd, ui_dev_create());

        fd
    };

    Ok(uinput)
}

fn inject_event(uinput: i32, typ: u16, code: u16, value: i32) -> Result<()> {
    unsafe {
        let mut ev: InputEvent = std::mem::zeroed();
        libc::gettimeofday(&mut ev.time, std::ptr::null_mut());
        ev.type_ = typ;
        ev.code = code;
        ev.value = value;

        libc::write(uinput, &ev as *const _ as *const _, std::mem::size_of::<InputEvent>());

        // emit syn
        ev.type_ = ev_syn();
        ev.code = syn_report();
        ev.value = 0;
        libc::write(uinput, &ev as *const _ as *const _, std::mem::size_of::<InputEvent>());
    }
    Ok(())
}

async fn screen_capturer(conn: quinn::Connection) -> Result<()> {
    let (mut send, _recv) = conn.open_bi().await?;

    // connect to x11
    let (x11, screen_num) = x11rb::connect(None)?;
    let screen = x11.setup().roots[screen_num].clone();
    let root = screen.root;
    let width = screen.width_in_pixels;
    let height = screen.height_in_pixels;

    eprintln!("capturing {}x{}", width, height);

    loop {
        // capture screen
        let img = x11rb::protocol::xproto::get_image(
            &x11,
            x11rb::protocol::xproto::ImageFormat::Z_PIXMAP,
            root,
            0,
            0,
            width,
            height,
            !0,
        )?.reply()?;

        // convert bgra -> rgba if needed
        let mut rgba = img.data.clone();
        for chunk in rgba.chunks_exact_mut(4) {
            chunk.swap(0, 2); // bgra -> rgba
        }

        // encode webp in blocking task to avoid Send issues
        let webp_data = tokio::task::spawn_blocking(move || {
            let encoder = webp::Encoder::from_rgba(&rgba, width as u32, height as u32);
            encoder.encode(85.0).to_vec()
        }).await?;

        // send frame
        send.write_all(&(webp_data.len() as u32).to_le_bytes()).await?;
        send.write_all(&webp_data).await?;

        // 60fps
        tokio::time::sleep(tokio::time::Duration::from_millis(16)).await;
    }
}

async fn input_sender(conn: quinn::Connection) -> Result<()> {
    let (mut send, _recv) = conn.open_bi().await?;

    // grab input from /dev/input/event*
    let events = find_input_devices()?;

    // read all event devices and multiplex to single stream
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<[u8; 8]>();

    for event_path in events {
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Ok(mut f) = tokio::fs::File::open(&event_path).await {
                let mut buf = vec![0u8; std::mem::size_of::<InputEvent>()];
                loop {
                    if f.read_exact(&mut buf).await.is_err() {
                        break;
                    }

                    // extract type/code/value
                    let ev: &InputEvent = unsafe { &*(buf.as_ptr() as *const InputEvent) };

                    // send compact format
                    let mut packet = [0u8; 8];
                    packet[0..2].copy_from_slice(&ev.type_.to_le_bytes());
                    packet[2..4].copy_from_slice(&ev.code.to_le_bytes());
                    packet[4..8].copy_from_slice(&ev.value.to_le_bytes());

                    let _ = tx.send(packet);
                }
            }
        });
    }

    // forward all input events to single stream
    while let Some(packet) = rx.recv().await {
        let _ = send.write_all(&packet).await;
    }

    Ok(())
}

async fn frame_displayer(conn: quinn::Connection) -> Result<()> {
    let (_send, mut recv) = conn.accept_bi().await?;

    // first frame to get dimensions
    let mut size_buf = [0u8; 4];
    recv.read_exact(&mut size_buf).await?;
    let size = u32::from_le_bytes(size_buf) as usize;

    let mut frame_data = vec![0u8; size];
    recv.read_exact(&mut frame_data).await?;

    let decoder = webp::Decoder::new(&frame_data);
    let img = decoder.decode().ok_or_else(|| anyhow::anyhow!("decode fail"))?;

    let width = img.width() as usize;
    let height = img.height() as usize;

    // create window
    let mut window = minifb::Window::new(
        "remote session",
        width,
        height,
        minifb::WindowOptions::default(),
    )?;

    window.set_target_fps(60);

    loop {
        recv.read_exact(&mut size_buf).await?;
        let size = u32::from_le_bytes(size_buf) as usize;

        if frame_data.len() < size {
            frame_data.resize(size, 0);
        }
        recv.read_exact(&mut frame_data[..size]).await?;

        let decoder = webp::Decoder::new(&frame_data[..size]);
        if let Some(img) = decoder.decode() {
            // convert rgba -> u32 buffer
            let buffer: Vec<u32> = img.chunks_exact(4)
                .map(|p| {
                    let r = p[0] as u32;
                    let g = p[1] as u32;
                    let b = p[2] as u32;
                    (r << 16) | (g << 8) | b
                })
                .collect();

            window.update_with_buffer(&buffer, width, height)?;
        }

        if !window.is_open() {
            break;
        }
    }

    Ok(())
}

fn find_input_devices() -> Result<Vec<String>> {
    let mut devices = vec![];
    for entry in std::fs::read_dir("/dev/input")? {
        let entry = entry?;
        let path = entry.path();
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.starts_with("event") {
                devices.push(path.to_string_lossy().to_string());
            }
        }
    }
    Ok(devices)
}

// uinput constants
const fn ui_set_evbit() -> u64 { 0x40045564 }
const fn ui_set_keybit() -> u64 { 0x40045565 }
const fn ui_set_relbit() -> u64 { 0x40045566 }
const fn ui_dev_setup() -> u64 { 0x405c5503 }
const fn ui_dev_create() -> u64 { 0x5501 }

const fn ev_syn() -> u16 { 0x00 }
const fn ev_key() -> u16 { 0x01 }
const fn ev_rel() -> u16 { 0x02 }
const fn syn_report() -> u16 { 0 }
const fn rel_x() -> u16 { 0x00 }
const fn rel_y() -> u16 { 0x01 }
const fn btn_left() -> u16 { 0x110 }
const fn btn_right() -> u16 { 0x111 }
const fn btn_middle() -> u16 { 0x112 }
const fn bus_usb() -> u16 { 0x03 }

#[repr(C)]
struct InputEvent {
    time: libc::timeval,
    type_: u16,
    code: u16,
    value: i32,
}

#[repr(C)]
struct UinputSetup {
    id: InputId,
    name: [u8; 80],
    ff_effects_max: u32,
}

#[repr(C)]
struct InputId {
    bustype: u16,
    vendor: u16,
    product: u16,
    version: u16,
}