use anyhow::Result;
use quicnet::{Identity, Peer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(feature = "video")]
use {
    openh264::{encoder::Encoder, decoder::Decoder},
    x11rb::connection::Connection,
    x11rb::protocol::xproto::*,
    image::RgbImage,
};

#[derive(Debug, Clone, Copy)]
enum VideoCodec {
    Mjpeg,
    H264,
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install crypto provider");

    let args: Vec<_> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("server") => run_server().await,
        Some("client") => {
            let server = args.get(2).ok_or_else(|| anyhow::anyhow!("need server"))?;
            let preference = args.get(3).map(|s| s.as_str());
            run_client(server, preference).await
        }
        _ => {
            eprintln!("server: {} server", args[0]);
            eprintln!("client: {} client <addr> [mjpeg|h264]", args[0]);
            std::process::exit(1);
        }
    }
}

async fn run_server() -> Result<()> {
    let identity = Identity::load_or_generate()?;
    let peer = Peer::new("[::]:8888".parse()?, identity)?;

    eprintln!("video stream server on {}", peer.local_addr()?);
    eprintln!("peer: {}", peer.identity().peer_id());

    while let Some(incoming) = peer.accept().await {
        tokio::spawn(async move {
            if let Err(e) = handle_session(incoming).await {
                eprintln!("session error: {e}");
            }
            eprintln!("session ended");
        });
    }
    Ok(())
}

#[cfg(feature = "video")]
async fn handle_session(incoming: quicnet::IncomingConnection) -> Result<()> {
    let (conn, peer_id) = incoming.accept().await?;
    eprintln!("[{}] video session start", peer_id.short());

    // Accept bidirectional stream from client
    let (send, mut recv) = conn.accept_bi().await?;

    // Simple protocol: first byte indicates codec
    eprintln!("[{}] waiting for codec byte from client...", peer_id.short());
    let mut codec_byte = [0u8; 1];
    recv.read_exact(&mut codec_byte).await?;
    eprintln!("[{}] received codec byte: {}", peer_id.short(), codec_byte[0]);

    let codec = match codec_byte[0] {
        1 => VideoCodec::H264,
        _ => VideoCodec::Mjpeg,
    };

    eprintln!("[{}] using codec: {:?}", peer_id.short(), codec);

    // Start streaming based on codec
    let result = match codec {
        VideoCodec::Mjpeg => stream_mjpeg(send).await,
        VideoCodec::H264 => stream_h264(send).await,
    };

    match result {
        Ok(_) => eprintln!("[{}] stream ended normally", peer_id.short()),
        Err(e) => eprintln!("[{}] stream error: {}", peer_id.short(), e),
    }

    Ok(())
}

#[cfg(feature = "video")]
async fn stream_mjpeg(mut send: quinn::SendStream) -> Result<()> {

    // Setup X11 screen capture
    let (conn, screen_num) = x11rb::connect(None)?;
    let screen = &conn.setup().roots[screen_num];
    let root = screen.root;

    loop {
        // Capture screen
        let geometry = conn.get_geometry(root)?.reply()?;
        let image = conn.get_image(
            ImageFormat::Z_PIXMAP,
            root,
            0, 0,
            geometry.width,
            geometry.height,
            !0,
        )?.reply()?;

        // Convert to RGB
        let mut rgb_image = RgbImage::new(geometry.width as u32, geometry.height as u32);
        for (i, pixel) in image.data.chunks_exact(4).enumerate() {
            let x = (i as u32) % (geometry.width as u32);
            let y = (i as u32) / (geometry.width as u32);
            rgb_image.put_pixel(x, y, image::Rgb([pixel[2], pixel[1], pixel[0]]));
        }

        // Encode to JPEG
        let mut jpeg_data = Vec::new();
        let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut jpeg_data, 85);
        encoder.encode_image(&rgb_image)?;

        // Send frame with size header
        send.write_all(&(jpeg_data.len() as u32).to_be_bytes()).await?;
        send.write_all(&jpeg_data).await?;

        // Reduce to 2 FPS to prevent browser overload
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

#[cfg(feature = "video")]
async fn stream_h264(mut send: quinn::SendStream) -> Result<()> {

    // Setup H.264 encoder
    let mut encoder = Encoder::new()?;

    // Setup X11 screen capture
    let (conn, screen_num) = x11rb::connect(None)?;
    let screen = &conn.setup().roots[screen_num];
    let root = screen.root;

    loop {
        // Capture screen
        let geometry = conn.get_geometry(root)?.reply()?;
        let image = conn.get_image(
            ImageFormat::Z_PIXMAP,
            root,
            0, 0,
            geometry.width,
            geometry.height,
            !0,
        )?.reply()?;

        // Convert to YUV for H.264 encoder
        let yuv = bgra_to_yuv(&image.data, geometry.width as usize, geometry.height as usize);

        // Encode to H.264
        let bitstream_vec = {
            let bitstream = encoder.encode(&yuv)?;
            bitstream.to_vec()
        };

        // Send complete frame only if non-empty (openh264 already provides proper format)
        if !bitstream_vec.is_empty() {
            send.write_all(&(bitstream_vec.len() as u32).to_be_bytes()).await?;
            send.write_all(&bitstream_vec).await?;
        }

        // Reduce to 2 FPS to prevent browser overload
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

#[cfg(feature = "video")]
fn bgra_to_yuv(bgra: &[u8], width: usize, height: usize) -> openh264::formats::YUVBuffer {
    use openh264::formats::YUVBuffer;

    // Fast RGB to YUV420 conversion (BT.709 standard)
    let y_plane_size = width * height;
    let uv_plane_size = y_plane_size / 4;

    let mut y_plane = Vec::with_capacity(y_plane_size);
    let mut u_plane = Vec::with_capacity(uv_plane_size);
    let mut v_plane = Vec::with_capacity(uv_plane_size);

    // First convert BGRA to RGB
    let mut rgb_data = Vec::with_capacity(width * height * 3);
    for bgra_pixel in bgra.chunks_exact(4) {
        rgb_data.extend_from_slice(&[bgra_pixel[2], bgra_pixel[1], bgra_pixel[0]]); // BGR -> RGB
    }

    // Convert RGB to YUV420 with 2x2 subsampling
    for y in (0..height).step_by(2) {
        for x in (0..width).step_by(2) {
            let mut u_sum = 0i32;
            let mut v_sum = 0i32;
            let mut sample_count = 0;

            // Process 2x2 block
            for dy in 0..2 {
                for dx in 0..2 {
                    let py = y + dy;
                    let px = x + dx;

                    if py >= height || px >= width {
                        continue;
                    }

                    let rgb_idx = (py * width + px) * 3;
                    let r = rgb_data[rgb_idx] as i32;
                    let g = rgb_data[rgb_idx + 1] as i32;
                    let b = rgb_data[rgb_idx + 2] as i32;

                    // BT.709 RGB to YUV conversion
                    let y_val = (66 * r + 129 * g + 25 * b + 128) >> 8;
                    let u_val = (-38 * r - 74 * g + 112 * b + 128) >> 8;
                    let v_val = (112 * r - 94 * g - 18 * b + 128) >> 8;

                    y_plane.push((y_val + 16).clamp(0, 255) as u8);
                    u_sum += u_val;
                    v_sum += v_val;
                    sample_count += 1;
                }
            }

            if sample_count > 0 {
                u_plane.push(((u_sum / sample_count) + 128).clamp(0, 255) as u8);
                v_plane.push(((v_sum / sample_count) + 128).clamp(0, 255) as u8);
            }
        }
    }

    // Combine planes for openh264
    let mut combined_yuv = Vec::with_capacity(y_plane_size + uv_plane_size * 2);
    combined_yuv.extend_from_slice(&y_plane);
    combined_yuv.extend_from_slice(&u_plane);
    combined_yuv.extend_from_slice(&v_plane);

    YUVBuffer::from_vec(combined_yuv, width, height)
}

async fn run_client(server: &str, preference: Option<&str>) -> Result<()> {
    let addr: std::net::SocketAddr = server.parse()?;
    let identity = Identity::load_or_generate()?;
    let peer = Peer::new("[::]:0".parse()?, identity)?;

    eprintln!("connecting to {}", addr);
    let (conn, _) = peer.dial(addr, None).await?;

    let (mut send, mut recv) = conn.open_bi().await?;

    // Determine best codec to use
    let codec = match preference {
        Some("mjpeg") => {
            eprintln!("user requested MJPEG");
            VideoCodec::Mjpeg
        }
        Some("h264") => {
            eprintln!("user requested H.264");
            VideoCodec::H264
        }
        _ => {
            // Auto-detect: try H.264 first, fallback to MJPEG
            eprintln!("auto-detecting codec support...");
            #[cfg(feature = "video")]
            {
                match openh264::decoder::Decoder::new() {
                    Ok(_) => {
                        eprintln!("H.264 decoder available, using H.264");
                        VideoCodec::H264
                    }
                    Err(_) => {
                        eprintln!("H.264 decoder not available, falling back to MJPEG");
                        VideoCodec::Mjpeg
                    }
                }
            }
            #[cfg(not(feature = "video"))]
            {
                eprintln!("video feature disabled, using MJPEG");
                VideoCodec::Mjpeg
            }
        }
    };

    // Send codec choice to server
    let codec_byte = match codec {
        VideoCodec::H264 => 1u8,
        VideoCodec::Mjpeg => 0u8,
    };
    eprintln!("sending codec byte: {}", codec_byte);
    send.write_all(&[codec_byte]).await?;
    eprintln!("codec byte sent successfully");

    eprintln!("negotiated codec: {:?}", codec);

    // Receive and display frames
    let result = match codec {
        VideoCodec::Mjpeg => receive_mjpeg(recv).await,
        VideoCodec::H264 => receive_h264(recv).await,
    };

    match result {
        Ok(_) => eprintln!("stream ended normally"),
        Err(e) => eprintln!("stream error: {}", e),
    }

    Ok(())
}

async fn receive_mjpeg(mut recv: quinn::RecvStream) -> Result<()> {

    loop {
        // Read frame size
        let mut size_buf = [0u8; 4];
        if recv.read_exact(&mut size_buf).await.is_err() {
            break;
        }
        let size = u32::from_be_bytes(size_buf) as usize;

        // Read JPEG data
        let mut jpeg_data = vec![0u8; size];
        recv.read_exact(&mut jpeg_data).await?;

        eprintln!("received MJPEG frame: {} bytes", size);

        // In a real app, you'd display this
        // For now, just print stats
    }

    Ok(())
}

#[cfg(feature = "video")]
async fn receive_h264(mut recv: quinn::RecvStream) -> Result<()> {

    let mut decoder = Decoder::new()?;

    loop {
        // Read frame size
        let mut size_buf = [0u8; 4];
        if recv.read_exact(&mut size_buf).await.is_err() {
            break;
        }
        let size = u32::from_be_bytes(size_buf) as usize;

        // Read complete H.264 frame
        let mut frame_data = vec![0u8; size];
        recv.read_exact(&mut frame_data).await?;

        eprintln!("received H.264 frame: {} bytes", size);

        if !frame_data.is_empty() {
            // Try to decode the complete frame
            if let Some(_yuv) = decoder.decode(&frame_data)? {
                eprintln!("successfully decoded H.264 frame");
                // In a real app, you'd convert YUV to RGB and display
            } else {
                eprintln!("H.264 frame received but not ready for display yet");
            }
        } else {
            eprintln!("received empty H.264 frame - encoder issue");
        }
    }

    Ok(())
}

#[cfg(not(feature = "video"))]
async fn handle_session(_: quicnet::IncomingConnection) -> Result<()> {
    eprintln!("video feature not enabled");
    Ok(())
}

#[cfg(not(feature = "video"))]
async fn receive_h264(_: quinn::RecvStream) -> Result<()> {
    eprintln!("video feature not enabled");
    Ok(())
}