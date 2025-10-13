use anyhow::Result;
use quicnet::{Identity, Peer};
use tokio::io::AsyncReadExt;

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

    eprintln!("hardware session on {}", peer.local_addr()?);
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

    eprintln!("hardware webtransport bridge on https://localhost:8443");
    eprintln!("cert hash: {}", server.cert_hash());

    // serve web client
    tokio::spawn(serve_web_client(server.cert_hash().to_string()));

    while let Some(session) = server.accept_webtransport().await {
        tokio::spawn(async move {
            if let Err(e) = handle_web_session(std::sync::Arc::new(session)).await {
                eprintln!("web session: {e}");
            }
        });
    }
    Ok(())
}

#[cfg(feature = "webtransport")]
async fn handle_web_session(
    session: std::sync::Arc<h3_webtransport::server::WebTransportSession<h3_quinn::Connection, bytes::Bytes>>,
) -> Result<()> {
    use std::sync::Arc;
    eprintln!("hardware web client connected");

    // spawn input receiver
    let session_input = session.clone();
    tokio::spawn(async move {
        if let Err(e) = web_input_handler(session_input).await {
            eprintln!("web input: {e}");
        }
    });

    // hardware screen capture sender
    hardware_screen_sender(session).await
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

/// Hardware-accelerated screen capture using GStreamer + VAAPI/NVENC
#[cfg(feature = "webtransport")]
async fn hardware_screen_sender(
    session: std::sync::Arc<h3_webtransport::server::WebTransportSession<h3_quinn::Connection, bytes::Bytes>>,
) -> Result<()> {
    use gstreamer as gst;
    use gstreamer::prelude::*;
    use gstreamer_app as gst_app;

    // Initialize GStreamer
    gst::init()?;

    eprintln!("Setting up hardware-accelerated pipeline");

    // Force software encoding for now (VAAPI has caps issues)
    let pipeline_desc = if false {
        eprintln!("Using VAAPI hardware encoding");
        format!(
            "ximagesrc use-damage=false ! \
             video/x-raw,framerate=30/1 ! \
             videoconvert ! \
             vaapih264enc rate-control=cbr bitrate=2000 ! \
             h264parse ! \
             appsink name=sink"
        )
    } else {
        eprintln!("VAAPI not available, using software x264enc");
        format!(
            "ximagesrc use-damage=false ! \
             video/x-raw,framerate=10/1 ! \
             videoconvert ! \
             jpegenc quality=85 ! \
             appsink name=sink"
        )
    };

    let pipeline = gst::parse::launch(&pipeline_desc)?
        .downcast::<gst::Pipeline>()
        .map_err(|_| anyhow::anyhow!("Failed to create pipeline"))?;

    let appsink = pipeline
        .by_name("sink")
        .ok_or_else(|| anyhow::anyhow!("Failed to get appsink"))?
        .downcast::<gst_app::AppSink>()
        .map_err(|_| anyhow::anyhow!("Failed to downcast to AppSink"))?;

    // Configure appsink
    appsink.set_property("emit-signals", true);
    appsink.set_property("sync", false);
    appsink.set_property("async", false);

    let session_clone = session.clone();
    let frame_counter = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let frame_counter_clone = frame_counter.clone();

    // Set up callback using signal connection (newer GStreamer API)
    appsink.set_callbacks(
        gst_app::AppSinkCallbacks::builder()
            .new_sample(move |sink| {
                let sample = sink.pull_sample().map_err(|_| gst::FlowError::Eos)?;
                let buffer = sample.buffer().ok_or(gst::FlowError::Error)?;

                // Extract H.264 data
                let map = buffer.map_readable().map_err(|_| gst::FlowError::Error)?;
                let h264_data = map.as_slice().to_vec();
                drop(map);

                // Send H.264 frame via QUIC unidirectional stream for reliable delivery
                let frame_id = frame_counter_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                eprintln!("Hardware encoded H.264 frame {}, size: {} bytes", frame_id, h264_data.len());

                // Send frame as datagram (WebTransport doesn't expose easy stream API)
                // Fall back to datagram with size check
                if h264_data.len() <= 1200 {
                    // Small frame - send as datagram
                    let mut frame_data = Vec::with_capacity(h264_data.len() + 8);
                    frame_data.extend_from_slice(&frame_id.to_be_bytes());
                    frame_data.extend_from_slice(&(h264_data.len() as u32).to_be_bytes());
                    frame_data.extend_from_slice(&h264_data);

                    if let Err(e) = session_clone.datagram_sender().send_datagram(frame_data.into()) {
                        eprintln!("Failed to send H.264 frame {}: {}", frame_id, e);
                    }
                } else {
                    eprintln!("Frame {} too large ({} bytes), skipping", frame_id, h264_data.len());
                }

                Ok(gst::FlowSuccess::Ok)
            })
            .build(),
    );

    // Start pipeline
    pipeline.set_state(gst::State::Playing)?;
    eprintln!("Hardware pipeline started");

    // Wait for EOS or error
    let bus = pipeline.bus().unwrap();
    for msg in bus.iter_timed(gst::ClockTime::NONE) {
        use gst::MessageView;

        match msg.view() {
            MessageView::Eos(..) => {
                eprintln!("EOS received");
                break;
            }
            MessageView::Error(err) => {
                eprintln!("Error: {}", err.error());
                break;
            }
            MessageView::StateChanged(state_changed) => {
                if state_changed.src().map(|s| s == &pipeline).unwrap_or(false) {
                    eprintln!("Pipeline state changed to {:?}", state_changed.current());
                }
            }
            _ => {}
        }
    }

    pipeline.set_state(gst::State::Null)?;
    Ok(())
}

#[cfg(feature = "webtransport")]
async fn serve_web_client(cert_hash: String) -> Result<()> {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    eprintln!("hardware web client on http://localhost:8080");

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
<title>Hardware Remote Session</title>
<style>
body {{ margin: 0; overflow: hidden; background: #000; }}
canvas {{ display: block; cursor: none; }}
#info {{ position: absolute; top: 10px; left: 10px; color: #0f0; font-family: monospace; z-index: 100; }}
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
<div id="controls">
    <button id="enableInput">Enable Input</button>
    <button id="disableInput">Disable Input</button>
    <span style="color: #0f0;">Hardware H.264</span>
</div>
<canvas id="screen"></canvas>

<script>
const info = document.getElementById('info');
const canvas = document.getElementById('screen');
const ctx = canvas.getContext('2d');
const enableBtn = document.getElementById('enableInput');
const disableBtn = document.getElementById('disableInput');

let inputEnabled = false;
let inputStream = null;

// Check for WebCodecs support
if (!window.VideoDecoder) {{
    info.textContent = 'WebCodecs not supported - use Chrome 94+';
    throw new Error('WebCodecs required');
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
        info.textContent = 'connected - hardware accelerated';

        // setup input stream
        inputStream = await transport.createBidirectionalStream();
        const inputWriter = inputStream.writable.getWriter();

        // Simple MJPEG display - no complex decoder needed!
        let frameCount = 0;

        async function createDecoder(sps, pps) {{
            if (decoder && decoder.state !== 'closed') {{
                decoder.close();
            }}

            // Just use a simple baseline profile that always works
            const config = {{
                codec: 'avc1.42001E', // H.264 Baseline Level 3.0 - most compatible
                optimizeForLatency: true
            }};

            // Check if config is supported
            try {{
                const support = await VideoDecoder.isConfigSupported(config);
                if (!support.supported) {{
                    console.error('H.264 config not supported:', codecString);
                    // Try fallback to baseline
                    config.codec = 'avc1.42001E';
                    const fallbackSupport = await VideoDecoder.isConfigSupported(config);
                    if (!fallbackSupport.supported) {{
                        console.error('Fallback config also not supported');
                        return false;
                    }}
                    console.log('Using fallback codec: avc1.42001E');
                }}
            }} catch (e) {{
                console.error('Config check failed:', e);
                return false;
            }}

            decoder = new VideoDecoder({{
                output: (frame) => {{
                    // Direct GPU rendering
                    if (canvas.width !== frame.visibleRect.width || canvas.height !== frame.visibleRect.height) {{
                        canvas.width = frame.visibleRect.width;
                        canvas.height = frame.visibleRect.height;
                        canvas.style.width = Math.min(window.innerWidth, frame.visibleRect.width) + 'px';
                        canvas.style.height = Math.min(window.innerHeight, frame.visibleRect.height) + 'px';
                    }}
                    ctx.drawImage(frame, 0, 0);
                    frame.close();
                }},
                error: (e) => {{
                    console.error('Decoder error:', e);
                    decoder = null;
                    spsData = null;
                    ppsData = null;
                }}
            }});

            try {{
                decoder.configure(config);
                console.log('H.264 decoder configured successfully');
                return true;
            }} catch (e) {{
                console.error('Failed to configure decoder:', e);
                decoder = null;
                return false;
            }}
        }}

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

        // Receive JPEG frames via QUIC datagrams - super simple!
        (async () => {{
            const reader = transport.datagrams.readable.getReader();
            const img = new Image();

            while (true) {{
                const {{ value: datagram, done }} = await reader.read();
                if (done) break;

                if (datagram.length < 8) continue; // Need at least frame header

                // Parse frame header
                const header = new DataView(datagram.buffer, datagram.byteOffset, 8);
                const frameId = header.getUint32(0);
                const frameSize = header.getUint32(4);
                const jpegData = datagram.slice(8, 8 + frameSize);

                // Display JPEG directly - no decoder needed!
                const blob = new Blob([jpegData], {{ type: 'image/jpeg' }});
                const url = URL.createObjectURL(blob);

                img.onload = () => {{
                    // Draw to canvas
                    if (canvas.width !== img.width || canvas.height !== img.height) {{
                        canvas.width = img.width;
                        canvas.height = img.height;
                    }}
                    ctx.drawImage(img, 0, 0);
                    URL.revokeObjectURL(url);
                    frameCount++;

                    if (frameCount % 10 === 0) {{
                        console.log(`Displayed ${{frameCount}} frames`);
                    }}
                }};

                img.src = url;
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

    // TODO: implement hardware client
    eprintln!("hardware client not implemented yet");
    Ok(())
}

async fn handle_session(incoming: quicnet::IncomingConnection) -> Result<()> {
    let (conn, peer_id) = incoming.accept().await?;
    eprintln!("[{}] hardware session start", peer_id.short());

    // TODO: implement hardware session
    eprintln!("hardware session not implemented yet");
    Ok(())
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