// examples/webtransport_chat.rs
#[cfg(not(feature = "webtransport"))]
fn main() {
    eprintln!("webtransport support not enabled");
    eprintln!("run with: cargo run --features webtransport --example webtransport_chat");
}

#[cfg(feature = "webtransport")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use anyhow::Result;
    use quicnet::{Identity, transport::web_compat::WebCompatServer};
    use tokio::sync::broadcast;
    use h3::quic::BidiStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install crypto provider");
    
    let identity = Identity::load_or_generate()?;
    let server = WebCompatServer::new("[::]:4433".parse()?, identity).await?;
    
    tokio::spawn(serve_frontend(server.cert_hash().to_string()));
    
    let (tx, _) = broadcast::channel(256);
    let mut user_id = 0u64;
    
    eprintln!("chat server ready");
    eprintln!("open http://localhost:8080 in chrome/firefox");
    
    while let Some(session) = server.accept_webtransport().await {
        user_id += 1;
        let tx = tx.clone();
        tokio::spawn(handle_session(session, tx, user_id));
    }
    
    Ok(())
}

#[cfg(feature = "webtransport")]
async fn handle_session(
    session: h3_webtransport::server::WebTransportSession<h3_quinn::Connection, bytes::Bytes>,
    tx: tokio::sync::broadcast::Sender<String>,
    user_id: u64,
) -> anyhow::Result<()> {
    use h3::quic::BidiStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    
    eprintln!("[user_{}] connected", user_id);
    
    let mut rx = tx.subscribe();
    let _ = tx.send(format!("user_{} joined", user_id));
    
    // send welcome message
    if let Ok(mut stream) = session.open_bi(session.session_id()).await {
        let _ = stream.write_all(format!("welcome user_{}", user_id).as_bytes()).await;
        let _ = stream.shutdown();
    }
    
    loop {
        tokio::select! {
            // handle incoming messages from client
            stream = session.accept_bi() => {
                if let Some(h3_webtransport::server::AcceptedBi::BidiStream(_, stream)) = stream? {
                    let tx = tx.clone();
                    let user = format!("user_{}", user_id);
                    
                    tokio::spawn(async move {
                        let (mut send, mut recv) = BidiStream::split(stream);
                        let mut buf = vec![0u8; 1024];
                        
                        if let Ok(n) = recv.read(&mut buf).await {
                            if n > 0 {
                                let msg = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                                eprintln!("[{}] {}", user, msg);
                                let _ = tx.send(format!("{}: {}", user, msg));
                                // echo back acknowledgment
                                let _ = send.write_all(b"ack").await;
                                let _ = send.shutdown();
                            }
                        }
                    });
                }
            }
            
            // broadcast messages to this client
            Ok(msg) = rx.recv() => {
                if let Ok(mut stream) = session.open_bi(session.session_id()).await {
                    let _ = stream.write_all(msg.as_bytes()).await;
                    let _ = stream.shutdown();
                }
            }
            
            else => break
        }
    }
    
    let _ = tx.send(format!("user_{} left", user_id));
    eprintln!("[user_{}] disconnected", user_id);
    Ok(())
}

#[cfg(feature = "webtransport")]
async fn serve_frontend(cert_hash: String) {
    use tokio::net::TcpListener;
    use tokio::io::AsyncWriteExt;
    
    let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();
    eprintln!("serving frontend at http://localhost:8080");
    
    loop {
        let (mut stream, _) = listener.accept().await.unwrap();
        let cert_hash = cert_hash.clone();
        
        tokio::spawn(async move {
            // read http request (ignore it)
            let mut buf = [0u8; 1024];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
            
            let html = format!(r#"<!DOCTYPE html>
<html>
<head>
<title>quicnet webtransport chat</title>
<style>
body {{ 
  font-family: 'Courier New', monospace; 
  background: #0a0a0a; 
  color: #00ff00; 
  padding: 20px;
  margin: 0;
}}
h1 {{
  text-shadow: 0 0 10px #00ff00;
  margin-bottom: 20px;
}}
#messages {{ 
  height: 400px; 
  overflow-y: auto; 
  border: 1px solid #00ff00; 
  padding: 15px;
  margin: 20px 0;
  background: rgba(0, 255, 0, 0.02);
  font-size: 14px;
  line-height: 1.4;
}}
#messages div {{
  margin-bottom: 5px;
  animation: glow 0.5s;
}}
@keyframes glow {{
  from {{ opacity: 0; }}
  to {{ opacity: 1; }}
}}
#input {{ 
  width: calc(100% - 10px);
  background: #0a0a0a; 
  color: #00ff00; 
  border: 1px solid #00ff00;
  padding: 10px;
  font-family: 'Courier New', monospace;
  font-size: 14px;
}}
#input:focus {{
  outline: none;
  box-shadow: 0 0 5px #00ff00;
}}
#status {{
  margin: 10px 0;
  font-size: 12px;
  opacity: 0.8;
}}
.error {{ color: #ff0000; }}
</style>
</head>
<body>
<h1>quicnet // webtransport chat</h1>
<div id="status">connecting...</div>
<div id="messages"></div>
<input id="input" placeholder="type message and press enter..." autofocus>

<script>
const log = (msg, isError = false) => {{
  const div = document.createElement('div');
  if (isError) div.className = 'error';
  div.textContent = `[${{new Date().toLocaleTimeString()}}] ${{msg}}`;
  document.getElementById('messages').appendChild(div);
  div.scrollIntoView();
}};

const hexToBuffer = (hex) => {{
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {{
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }}
  return bytes.buffer;
}};

(async () => {{
  try {{
    const transport = new WebTransport('https://localhost:4433', {{
      serverCertificateHashes: [{{
        algorithm: 'sha-256',
        value: hexToBuffer('{}')
      }}]
    }});
    
    document.getElementById('status').textContent = 'establishing connection...';
    await transport.ready;
    document.getElementById('status').textContent = 'connected';
    
    // listen for incoming messages
    (async () => {{
      const reader = transport.incomingBidirectionalStreams.getReader();
      while (true) {{
        const {{ value: stream, done }} = await reader.read();
        if (done) break;
        
        const reader2 = stream.readable.getReader();
        try {{
          const {{ value }} = await reader2.read();
          if (value) {{
            const msg = new TextDecoder().decode(value);
            log(msg);
          }}
        }} finally {{
          reader2.releaseLock();
        }}
      }}
    }})();
    
    // send messages on enter
    document.getElementById('input').addEventListener('keydown', async (e) => {{
      if (e.key === 'Enter' && e.target.value.trim()) {{
        try {{
          const stream = await transport.createBidirectionalStream();
          const writer = stream.writable.getWriter();
          await writer.write(new TextEncoder().encode(e.target.value));
          await writer.close();
          e.target.value = '';
        }} catch (err) {{
          log(`send error: ${{err.message}}`, true);
        }}
      }}
    }});
    
    transport.closed.then(() => {{
      log('connection closed', true);
      document.getElementById('status').textContent = 'disconnected';
    }});
    
  }} catch (err) {{
    log(`error: ${{err.message}}`, true);
    document.getElementById('status').textContent = 'connection failed';
  }}
}})();
</script>
</body>
</html>"#, cert_hash);
            
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n{}",
                html.len(), html
            );
            
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}
