use anyhow::Result;
use quicnet::{Identity, transport::web_compat::WebCompatServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Clone, Copy)]
enum VideoCodec {
    Mjpeg,
    H264,
    H264Hardware,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install default crypto provider
    rustls::crypto::aws_lc_rs::default_provider().install_default().map_err(|_| anyhow::anyhow!("Failed to install crypto provider"))?;
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("server") => run_server().await,
        _ => {
            eprintln!("Usage: {} server", args[0]);
            std::process::exit(1);
        }
    }
}

async fn run_server() -> Result<()> {
    let identity = Identity::load_or_generate()?;
    let addr = "127.0.0.1:8443".parse()?;

    let server = WebCompatServer::new(addr, identity).await?;
    eprintln!("WebTransport video server started");
    eprintln!("Certificate hash: {}", server.cert_hash());
    eprintln!("Update your HTML client with this hash!");

    loop {
        if let Some(session) = server.accept_webtransport().await {
            eprintln!("WebTransport session accepted");

            tokio::spawn(async move {
                if let Err(e) = handle_webtransport_session(session).await {
                    eprintln!("Session error: {e}");
                }
            });
        }
    }
}

async fn handle_webtransport_session(
    session: h3_webtransport::server::WebTransportSession<h3_quinn::Connection, bytes::Bytes>
) -> Result<()> {
    // Accept bidirectional stream with timeout
    let (send, mut recv) = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        session.accept_bi()
    ).await {
        Ok(Ok(Some(h3_webtransport::server::AcceptedBi::BidiStream(_, stream)))) => {
            h3::quic::BidiStream::split(stream)
        }
        Ok(Ok(_)) => return Err(anyhow::anyhow!("Unexpected stream type")),
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Err(anyhow::anyhow!("Connection timeout")),
    };

    // Read codec preference with timeout
    let mut codec_byte = [0u8; 1];
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        recv.read_exact(&mut codec_byte)
    ).await??;

    let codec = match codec_byte[0] {
        1 => VideoCodec::H264,
        2 => VideoCodec::H264Hardware,
        _ => VideoCodec::Mjpeg,
    };

    eprintln!("Client requested: {:?}", codec);

    // Start streaming with proper error propagation
    let result = match codec {
        VideoCodec::Mjpeg => stream_mjpeg_webtransport(send).await,
        VideoCodec::H264 => stream_h264_webtransport(send).await,
        VideoCodec::H264Hardware => {
            #[cfg(feature = "hardware")]
            {
                stream_h264_hardware_webtransport(send).await
            }
            #[cfg(not(feature = "hardware"))]
            {
                eprintln!("Hardware encoding not available, falling back to software");
                stream_h264_webtransport(send).await
            }
        }
    };

    if let Err(ref e) = result {
        eprintln!("Streaming error: {}", e);
    }

    result
}

async fn stream_mjpeg_webtransport(mut send: h3_webtransport::stream::SendStream<h3_quinn::SendStream<bytes::Bytes>, bytes::Bytes>) -> Result<()> {
    #[cfg(feature = "video")]
    {
        use x11rb::connection::Connection;
        use x11rb::protocol::xproto::*;
        use image::{RgbImage, ImageBuffer};

        let (conn, screen_num) = x11rb::connect(None)?;
        let screen = &conn.setup().roots[screen_num];

        // Cache screen dimensions
        let screen_width = screen.width_in_pixels;
        let screen_height = screen.height_in_pixels;

        loop {
            // Batch X11 requests for efficiency
            let image_cookie = conn.get_image(
                ImageFormat::Z_PIXMAP,
                screen.root,
                0, 0,
                screen_width, screen_height,
                !0
            )?;
            let cursor_cookie = conn.query_pointer(screen.root)?;

            // Wait for both responses simultaneously
            let (reply, cursor_reply) = (image_cookie.reply()?, cursor_cookie.reply()?);

            // Convert BGRA to RGB with optimized cursor overlay
            let width = screen_width as usize;
            let height = screen_height as usize;
            let pixel_count = width * height;

            // Pre-allocate with exact capacity to avoid reallocations
            let mut rgb_data = Vec::with_capacity(pixel_count * 3);

            // Draw proper arrow cursor
            let cursor_x = cursor_reply.root_x as i32;
            let cursor_y = cursor_reply.root_y as i32;

            // First pass: convert all pixels to RGB
            for bgra in reply.data.chunks_exact(4) {
                rgb_data.extend_from_slice(&[bgra[2], bgra[1], bgra[0]]);
            }

            // Second pass: draw cursor as black arrow with white outline
            let cursor_pixels = [
                // Arrow shape (x_offset, y_offset, is_white_outline)
                (0, 0, false), (1, 0, true), (2, 0, true),
                (0, 1, false), (1, 1, false), (2, 1, true), (3, 1, true),
                (0, 2, false), (1, 2, false), (2, 2, false), (3, 2, true), (4, 2, true),
                (0, 3, false), (1, 3, false), (2, 3, false), (3, 3, true), (4, 3, true),
                (0, 4, false), (1, 4, false), (2, 4, true), (3, 4, true),
                (0, 5, false), (1, 5, false), (2, 5, true), (3, 5, true),
                (0, 6, false), (1, 6, true), (2, 6, true),
                (0, 7, false), (1, 7, true), (2, 7, true),
                (0, 8, false), (1, 8, true),
                (0, 9, false), (1, 9, true),
                (0, 10, true),
            ];

            for (dx, dy, is_outline) in cursor_pixels {
                let px = cursor_x + dx;
                let py = cursor_y + dy;

                if px >= 0 && py >= 0 && (px as usize) < width && (py as usize) < height {
                    let idx = (py as usize * width + px as usize) * 3;
                    if idx + 2 < rgb_data.len() {
                        let color = if is_outline { [255, 255, 255] } else { [0, 0, 0] };
                        rgb_data[idx..idx + 3].copy_from_slice(&color);
                    }
                }
            }

            let rgb_image: RgbImage = ImageBuffer::from_raw(
                width as u32,
                height as u32,
                rgb_data
            ).ok_or_else(|| anyhow::anyhow!("Failed to create RGB image"))?;

            // Encode as JPEG with optimized quality/speed balance
            let mut jpeg_data = Vec::with_capacity(65536); // Pre-allocate 64KB
            let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut jpeg_data, 75);
            encoder.encode_image(&rgb_image)?;

            // Send frame efficiently in single write operation
            let frame_size = jpeg_data.len() as u32;
            let mut frame_buffer = Vec::with_capacity(4 + jpeg_data.len());
            frame_buffer.extend_from_slice(&frame_size.to_be_bytes());
            frame_buffer.extend_from_slice(&jpeg_data);

            send.write_all(&frame_buffer).await?;

            // 30 FPS for fluid motion
            tokio::time::sleep(std::time::Duration::from_millis(33)).await;
        }
    }

    #[cfg(not(feature = "video"))]
    {
        let message = b"Video feature not enabled";
        send.write_all(&(message.len() as u32).to_be_bytes()).await?;
        send.write_all(message).await?;

        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
}

async fn stream_h264_webtransport(mut send: h3_webtransport::stream::SendStream<h3_quinn::SendStream<bytes::Bytes>, bytes::Bytes>) -> Result<()> {
    #[cfg(feature = "video")]
    {
        use x11rb::connection::Connection;
        use x11rb::protocol::xproto::{self, *};
        use openh264::encoder::Encoder;
        use std::ffi::c_void;
        use std::ptr;

        let (conn, screen_num) = x11rb::connect(None)?;
        let screen = &conn.setup().roots[screen_num];

        // H.264 encoder with default settings (openh264 handles keyframes automatically)
        let mut encoder = Encoder::new()?;

        eprintln!("H.264 encoder created, starting screen capture...");
        eprintln!("Screen resolution: {}x{}", screen.width_in_pixels, screen.height_in_pixels);
        eprintln!("Encoding resolution: {}x{} (downscaled 2x for performance)", screen.width_in_pixels / 2, screen.height_in_pixels / 2);

        let screen_width = screen.width_in_pixels;
        let screen_height = screen.height_in_pixels;

        let mut frame_count = 0;
        let mut last_frame_hash: Option<u64> = None;
        let mut skip_count = 0;

        eprintln!("Using regular X11 screen capture for software H.264 (XSHM disabled for now)");

        loop {
            let start_time = std::time::Instant::now();
            frame_count += 1;

            // Regular X11 screen capture
            let capture_start = std::time::Instant::now();
            let img = conn.get_image(
                ImageFormat::Z_PIXMAP,
                screen.root,
                0, 0,
                screen_width, screen_height,
                !0
            )?.reply()?;
            let image_data = img.data;
            let capture_time = capture_start.elapsed();

            // Fast change detection - hash a sample of pixels
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            use std::hash::Hasher;

            // Sample every 100th pixel for speed
            for i in (0..image_data.len()).step_by(400) {
                hasher.write_u8(image_data[i]);
            }
            let current_hash = hasher.finish();

            // Skip if frame hasn't changed
            if let Some(last_hash) = last_frame_hash {
                if current_hash == last_hash {
                    skip_count += 1;
                    if skip_count % 100 == 0 {
                        eprintln!("Skipped {} unchanged frames", skip_count);
                    }

                    // Send empty frame to maintain stream
                    let mut frame_buffer = Vec::with_capacity(4);
                    frame_buffer.extend_from_slice(&(0u32).to_be_bytes());
                    send.write_all(&frame_buffer).await?;

                    // Much faster sleep since no processing needed
                    tokio::time::sleep(std::time::Duration::from_millis(16)).await;
                    continue;
                }
            }
            last_frame_hash = Some(current_hash);

            // Scale down resolution for performance - capture at half resolution
            let scale_factor = 2;
            let target_width = (screen_width / scale_factor) as usize;
            let target_height = (screen_height / scale_factor) as usize;
            let y_size = target_width * target_height;
            let uv_size = y_size / 4;
            let mut yuv_data = vec![0u8; y_size + uv_size * 2];

            // Downsample and convert BGRA to YUV420 - skip every other pixel
            let original_width = screen_width as usize;
            for y in 0..target_height {
                for x in 0..target_width {
                    let src_x = x * scale_factor as usize;
                    let src_y = y * scale_factor as usize;
                    let src_idx = (src_y * original_width + src_x) * 4;

                    if src_idx + 3 < image_data.len() {
                        let r = image_data[src_idx + 2] as i32;
                        let g = image_data[src_idx + 1] as i32;
                        let b = image_data[src_idx + 0] as i32;

                        // Standard BT.601 RGB to YUV conversion
                        let y_val = ((66 * r + 129 * g + 25 * b + 128) >> 8) + 16;
                        yuv_data[y * target_width + x] = y_val.clamp(0, 255) as u8;
                    }
                }
            }

            // Simple UV subsampling for downscaled image
            let mut uv_idx = 0;
            for y in (0..target_height).step_by(2) {
                for x in (0..target_width).step_by(2) {
                    if uv_idx >= uv_size { break; }

                    let src_x = x * scale_factor as usize;
                    let src_y = y * scale_factor as usize;
                    let src_idx = (src_y * original_width + src_x) * 4;

                    if src_idx + 3 < image_data.len() {
                        let r = image_data[src_idx + 2] as i32;
                        let g = image_data[src_idx + 1] as i32;
                        let b = image_data[src_idx + 0] as i32;

                        // BT.601 RGB to UV conversion
                        let u = ((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128;
                        let v = ((112 * r - 94 * g - 18 * b + 128) >> 8) + 128;

                        yuv_data[y_size + uv_idx] = u.clamp(0, 255) as u8;
                        yuv_data[y_size + uv_size + uv_idx] = v.clamp(0, 255) as u8;
                        uv_idx += 1;
                    }
                }
            }

            let width = target_width;
            let height = target_height;

            let yuv = openh264::formats::YUVBuffer::from_vec(yuv_data, width, height);

            // Encode frame
            let encode_start = std::time::Instant::now();
            let bitstream_vec = {
                let bitstream = encoder.encode(&yuv)?;
                bitstream.to_vec()
            };
            let encode_time = encode_start.elapsed();

            // Send H.264 data with debugging
            let send_start = std::time::Instant::now();
            if !bitstream_vec.is_empty() {
                // Debug: Check if this is a keyframe by looking at NAL unit type
                let is_keyframe = bitstream_vec.len() > 4 &&
                    bitstream_vec[0] == 0x00 && bitstream_vec[1] == 0x00 &&
                    bitstream_vec[2] == 0x00 && bitstream_vec[3] == 0x01 &&
                    (bitstream_vec[4] & 0x1F) == 5; // IDR frame

                if frame_count <= 5 || is_keyframe {
                    eprintln!("Frame {}: size={} bytes, keyframe={}", frame_count, bitstream_vec.len(), is_keyframe);
                }

                let mut frame_buffer = Vec::with_capacity(4 + bitstream_vec.len());
                frame_buffer.extend_from_slice(&(bitstream_vec.len() as u32).to_be_bytes());
                frame_buffer.extend_from_slice(&bitstream_vec);
                send.write_all(&frame_buffer).await?;
            } else {
                // Empty frame - skip or force keyframe
                if frame_count <= 5 {
                    eprintln!("Frame {}: Empty frame from encoder - this might cause WebCodecs issues", frame_count);
                }

                // Send empty frame to maintain stream
                let mut frame_buffer = Vec::with_capacity(4);
                frame_buffer.extend_from_slice(&(0u32).to_be_bytes());
                send.write_all(&frame_buffer).await?;
            }
            let send_time = send_start.elapsed();

            let total_time = start_time.elapsed();

            // Log performance every 30 frames
            if frame_count % 30 == 0 {
                eprintln!("Frame {}: capture={:?} encode={:?} send={:?} total={:?} size={}",
                    frame_count, capture_time, encode_time, send_time, total_time, bitstream_vec.len());
            }

            // 30 FPS for better performance/quality balance
            tokio::time::sleep(std::time::Duration::from_millis(33)).await;
        }
    }

    #[cfg(not(feature = "video"))]
    {
        let message = b"Video feature not enabled";
        send.write_all(&(message.len() as u32).to_be_bytes()).await?;
        send.write_all(message).await?;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
}

#[cfg(feature = "video")]
fn bgra_to_yuv420_with_cursor(
    bgra: &[u8],
    width: usize,
    height: usize,
    cursor_reply: &x11rb::protocol::xproto::QueryPointerReply
) -> openh264::formats::YUVBuffer {
    use openh264::formats::YUVBuffer;

    // First convert BGRA to RGB with cursor overlay
    let mut rgb_data = Vec::with_capacity(width * height * 3);
    let cursor_x = cursor_reply.root_x as i32;
    let cursor_y = cursor_reply.root_y as i32;

    for (i, bgra_pixel) in bgra.chunks_exact(4).enumerate() {
        let y = i / width;
        let x = i % width;

        let is_cursor = is_cursor_pixel(x as i32, y as i32, cursor_x, cursor_y);

        if is_cursor {
            rgb_data.extend_from_slice(&[255, 255, 255]); // White cursor
        } else {
            rgb_data.extend_from_slice(&[bgra_pixel[2], bgra_pixel[1], bgra_pixel[0]]); // BGR -> RGB
        }
    }

    // Fast RGB to YUV420 conversion (BT.709 standard)
    let y_plane_size = width * height;
    let uv_plane_size = y_plane_size / 4;

    let mut y_plane = Vec::with_capacity(y_plane_size);
    let mut u_plane = Vec::with_capacity(uv_plane_size);
    let mut v_plane = Vec::with_capacity(uv_plane_size);

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

#[cfg(feature = "video")]
fn is_cursor_pixel(x: i32, y: i32, cursor_x: i32, cursor_y: i32) -> bool {
    let dx = x - cursor_x;
    let dy = y - cursor_y;

    // Arrow cursor pattern
    matches!((dx, dy),
        (0, 0..=10) |
        (1, 0..=8) |
        (2, 0..=6) |
        (3, 0..=4) |
        (4, 0..=2) |
        (-1..=1, 6..=8)
    )
}

// Hardware-accelerated H.264 encoding using GStreamer with AMD AMF
#[cfg(feature = "hardware")]
async fn stream_h264_hardware_webtransport(mut send: h3_webtransport::stream::SendStream<h3_quinn::SendStream<bytes::Bytes>, bytes::Bytes>) -> Result<()> {
    use gstreamer as gst;
    use gstreamer::prelude::*;
    use gstreamer_app as gst_app;
    use std::sync::{Arc, Mutex};

    gst::init()?;
    eprintln!("GStreamer initialized for hardware encoding");

    // Create GStreamer pipeline for AMD AMF hardware encoding
    // Pipeline: appsrc -> videoconvert -> amfh264enc -> h264parse -> appsink
    let pipeline = gst::Pipeline::new();

    // Elements
    let appsrc = gst::ElementFactory::make("appsrc")
        .property_from_str("format", "time")
        .property_from_str("caps",
            &format!("video/x-raw,format=BGRx,width={},height={},framerate=30/1",
                    1920, 1080)) // Will be dynamic based on screen
        .build()?;

    let videoconvert = gst::ElementFactory::make("videoconvert").build()?;

    // Try AMD AMF first, then fallback to other hardware encoders
    let hwencoder = if let Ok(encoder) = gst::ElementFactory::make("amfh264enc")
        .property_from_str("usage", "ultra-low-latency")
        .property_from_str("rate-control", "cbr")
        .property("bitrate", &2000000u32) // 2Mbps
        .property("max-bitrate", &4000000u32) // 4Mbps max
        .property("gop-size", &30u32) // GOP size
        .property("b-frames", &0u32) // No B-frames for low latency
        .build() {
        eprintln!("Using AMD AMF hardware encoder");
        encoder
    } else if let Ok(encoder) = gst::ElementFactory::make("vaapih264enc")
        .property("bitrate", &2000u32) // kbps
        .property("keyframe-period", &30u32)
        .build() {
        eprintln!("Using VAAPI hardware encoder");
        encoder
    } else {
        // Fallback to software encoding
        eprintln!("No hardware encoder available, using software x264");
        gst::ElementFactory::make("x264enc")
            .property_from_str("tune", "zerolatency")
            .property_from_str("preset", "ultrafast")
            .property("bitrate", &2000u32)
            .build()?
    };

    let h264parse = gst::ElementFactory::make("h264parse")
        .property_from_str("config-interval", "1") // Insert SPS/PPS frequently
        .build()?;

    let appsink = gst::ElementFactory::make("appsink")
        .property_from_str("caps", "video/x-h264,stream-format=byte-stream,alignment=au")
        .property("emit-signals", &true)
        .property("sync", &false)
        .build()?;

    // Add elements to pipeline
    pipeline.add_many([&appsrc, &videoconvert, &hwencoder, &h264parse, &appsink])?;

    // Link elements
    gst::Element::link_many([&appsrc, &videoconvert, &hwencoder, &h264parse, &appsink])?;

    // Setup X11 screen capture with XSHM (same as before)
    use x11rb::connection::Connection;
    use x11rb::protocol::xproto::*;
    use std::ffi::c_void;
    use std::ptr;

    let (conn, screen_num) = x11rb::connect(None)?;
    let screen = &conn.setup().roots[screen_num];
    let screen_width = screen.width_in_pixels;
    let screen_height = screen.height_in_pixels;

    eprintln!("Hardware encoder ready - Screen: {}x{}", screen_width, screen_height);

    eprintln!("Hardware encoder with regular X11 screen capture (XSHM available in software version)");

    // Setup output handler for encoded frames
    let encoded_frames = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let encoded_frames_clone = Arc::clone(&encoded_frames);

    let appsink = appsink.dynamic_cast::<gst_app::AppSink>().unwrap();
    appsink.set_callbacks(
        gst_app::AppSinkCallbacks::builder()
            .new_sample(move |appsink| {
                let sample = appsink.pull_sample().map_err(|_| gst::FlowError::Eos)?;
                let buffer = sample.buffer().ok_or(gst::FlowError::Error)?;
                let map = buffer.map_readable().map_err(|_| gst::FlowError::Error)?;

                // Store encoded frame
                let mut frames = encoded_frames_clone.lock().unwrap();
                frames.push(map.as_slice().to_vec());

                Ok(gst::FlowSuccess::Ok)
            })
            .build(),
    );

    // Start pipeline
    pipeline.set_state(gst::State::Playing)?;
    eprintln!("Hardware encoding pipeline started");

    let appsrc = appsrc.dynamic_cast::<gst_app::AppSrc>().unwrap();
    let mut frame_count = 0;

    loop {
        let start_time = std::time::Instant::now();
        frame_count += 1;

        // Regular X11 screen capture for hardware encoding
        let capture_start = std::time::Instant::now();
        let img = conn.get_image(
            ImageFormat::Z_PIXMAP,
            screen.root,
            0, 0,
            screen_width, screen_height,
            !0
        )?.reply()?;
        let image_data = img.data;
        let capture_time = capture_start.elapsed();

        // Create GStreamer buffer from captured frame
        let mut buffer = gst::Buffer::with_size(image_data.len()).unwrap();
        {
            let buffer_ref = buffer.get_mut().unwrap();
            let mut map = buffer_ref.map_writable().unwrap();
            map.copy_from_slice(&image_data);
        }

        // Set timestamp for proper frame rate
        let timestamp = frame_count as u64 * 33_333_333; // 30 FPS
        buffer.get_mut().unwrap().set_pts(gst::ClockTime::from_nseconds(timestamp));

        // Push frame to hardware encoder
        let push_start = std::time::Instant::now();
        match appsrc.push_buffer(buffer) {
            Ok(_) => {},
            Err(gst::FlowError::Flushing) => {
                eprintln!("Pipeline flushing, stopping");
                break;
            }
            Err(e) => {
                eprintln!("Error pushing buffer: {e}");
                continue;
            }
        }
        let push_time = push_start.elapsed();

        // Check for encoded frames and send them
        let send_start = std::time::Instant::now();
        let mut frames_to_send = Vec::new();
        {
            let mut frames = encoded_frames.lock().unwrap();
            frames_to_send.extend(frames.drain(..));
        }

        for frame_data in frames_to_send {
            if !frame_data.is_empty() {
                // Send frame with size header
                let mut frame_buffer = Vec::with_capacity(4 + frame_data.len());
                frame_buffer.extend_from_slice(&(frame_data.len() as u32).to_be_bytes());
                frame_buffer.extend_from_slice(&frame_data);

                if let Err(e) = send.write_all(&frame_buffer).await {
                    eprintln!("Send error: {e}");
                    break;
                }
            }
        }
        let send_time = send_start.elapsed();

        let total_time = start_time.elapsed();

        // Performance stats every 30 frames
        if frame_count % 30 == 0 {
            eprintln!("Frame {}: capture={:.1}ms, push={:.1}ms, send={:.1}ms, total={:.1}ms (Hardware encoder)",
                frame_count,
                capture_time.as_secs_f64() * 1000.0,
                push_time.as_secs_f64() * 1000.0,
                send_time.as_secs_f64() * 1000.0,
                total_time.as_secs_f64() * 1000.0
            );
        }

        // Target 30 FPS (33.33ms per frame)
        let target_frame_time = std::time::Duration::from_millis(33);
        if total_time < target_frame_time {
            tokio::time::sleep(target_frame_time - total_time).await;
        }
    }

    // Cleanup
    pipeline.set_state(gst::State::Null)?;
    Ok(())
}