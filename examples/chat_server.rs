// webtransport compatibility bridge for quicnet chat server
#[cfg(not(feature = "webtransport"))]
fn main() {
    eprintln!("webtransport support not enabled");
    eprintln!("run with: cargo run --features webtransport --example webtransport_chat");
}

#[cfg(feature = "webtransport")]
use quicnet::{AuthenticatedStream, Identity, ServerBuilder};
#[cfg(feature = "webtransport")]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
#[cfg(feature = "webtransport")]
use tokio::sync::{broadcast, Mutex};
#[cfg(feature = "webtransport")]
use std::collections::VecDeque;
#[cfg(feature = "webtransport")]
use std::sync::Arc;

#[cfg(feature = "webtransport")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install crypto provider");

    let identity = Identity::load_or_generate()?;

    // primary quicnet server on 4433
    let server = ServerBuilder::new()
        .identity(identity.clone())
        .bind("[::]:4433")
        .build()?;

    eprintln!("quicnet chat server on {}", server.local_addr()?);
    eprintln!("peer id: {}", server.identity().peer_id());

    let (tx, _) = broadcast::channel(256);
    let history = Arc::new(Mutex::new(VecDeque::<String>::new()));

    // spawn webtransport bridge on 8443
    let bridge_tx = tx.clone();
    let bridge_history = history.clone();
    let bridge_identity = identity.clone();
    tokio::spawn(async move {
        if let Err(e) = run_webtransport_bridge(bridge_identity, bridge_tx, bridge_history).await {
            eprintln!("webtransport bridge error: {}", e);
        }
    });

    // main quicnet accept loop
    while let Some(stream) = server.accept_authenticated().await {
        let tx = tx.clone();
        let history = history.clone();
        tokio::spawn(handle_quicnet_chat(stream, tx, history));
    }
    Ok(())
}

#[cfg(feature = "webtransport")]
async fn handle_quicnet_chat(
    stream: AuthenticatedStream,
    tx: broadcast::Sender<String>,
    history: Arc<Mutex<VecDeque<String>>>,
) -> anyhow::Result<()> {
    let peer_id = stream.peer_id();
    let nick = peer_id.short();

    let join_msg = format!("*** {} has joined\n", nick);
    let _ = tx.send(join_msg.clone());
    
    // add to history
    {
        let mut hist = history.lock().await;
        hist.push_back(join_msg);
        if hist.len() > 10 {
            hist.pop_front();
        }
    }

    let mut rx = tx.subscribe();
    let (mut send, recv) = stream.split();
    
    // send history to new user
    {
        let hist = history.lock().await;
        for msg in hist.iter() {
            let _ = send.write_all(msg.as_bytes()).await;
        }
    }
    
    let mut reader = tokio::io::BufReader::new(recv);

    loop {
        let mut line = String::new();
        tokio::select! {
            result = reader.read_line(&mut line) => {
                match result {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        let msg = format!("<{}> {}", nick, line);
                        let _ = tx.send(msg.clone());
                        
                        // add to history
                        let mut hist = history.lock().await;
                        hist.push_back(msg);
                        if hist.len() > 10 {
                            hist.pop_front();
                        }
                    }
                }
            }
            Ok(msg) = rx.recv() => {
                if send.write_all(msg.as_bytes()).await.is_err() {
                    break;
                }
            }
        }
    }

    let leave_msg = format!("*** {} has left\n", nick);
    let _ = tx.send(leave_msg.clone());
    
    // add to history
    let mut hist = history.lock().await;
    hist.push_back(leave_msg);
    if hist.len() > 10 {
        hist.pop_front();
    }
    
    Ok(())
}

#[cfg(feature = "webtransport")]
async fn run_webtransport_bridge(
    identity: Identity,
    tx: broadcast::Sender<String>,
    history: Arc<Mutex<VecDeque<String>>>,
) -> anyhow::Result<()> {
    use quicnet::transport::web_compat::WebCompatServer;

    let server = WebCompatServer::new("[::]:8443".parse()?, identity).await?;
    tokio::spawn(serve_frontend(server.cert_hash().to_string()));

    eprintln!("webtransport bridge on https://localhost:8443");
    eprintln!("web interface at http://localhost:8080");

    while let Some(session) = server.accept_webtransport().await {
        let tx = tx.clone();
        let history = history.clone();
        tokio::spawn(handle_web_session(session, tx, history));
    }
    Ok(())
}

#[cfg(feature = "webtransport")]
async fn handle_web_session(
    session: h3_webtransport::server::WebTransportSession<h3_quinn::Connection, bytes::Bytes>,
    tx: broadcast::Sender<String>,
    history: Arc<Mutex<VecDeque<String>>>,
) -> anyhow::Result<()> {
    // generate ephemeral identity for web client
    let web_identity = quicnet::Identity::generate();
    let nick = web_identity.peer_id().short();
    eprintln!("[{}] connected via webtransport", nick);

    let mut rx = tx.subscribe();
    let join_msg = format!("*** {} has joined\n", nick);
    let _ = tx.send(join_msg.clone());
    
    // add to history
    {
        let mut hist = history.lock().await;
        hist.push_back(join_msg);
        if hist.len() > 10 {
            hist.pop_front();
        }
    }

    // send welcome
    if let Ok(mut stream) = session.open_bi(session.session_id()).await {
        let _ = stream.write_all(format!("Welcome! You are {}\n", web_identity.peer_id()).as_bytes()).await;
        let _ = stream.shutdown();
    }
    
    // send history as separate messages
    {
        let hist = history.lock().await;
        for msg in hist.iter() {
            if let Ok(mut stream) = session.open_bi(session.session_id()).await {
                let _ = stream.write_all(msg.trim_end().as_bytes()).await;
                let _ = stream.shutdown();
            }
        }
    }

    loop {
        tokio::select! {
            stream = session.accept_bi() => {
                match stream {
                    Ok(Some(h3_webtransport::server::AcceptedBi::BidiStream(_, stream))) => {
                        let tx = tx.clone();
                        let nick = nick.clone();
                        let history = history.clone();

                        tokio::spawn(async move {
                            use tokio::io::AsyncReadExt;
                            let (mut send, mut recv) = h3::quic::BidiStream::split(stream);
                            let mut buf = vec![0u8; 1024];

                            if let Ok(n) = recv.read(&mut buf).await {
                                if n > 0 {
                                    let msg_text = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                                    let msg = format!("<{}> {}\n", nick, msg_text);
                                    let _ = tx.send(msg.clone());
                                    
                                    // add to history
                                    let mut hist = history.lock().await;
                                    hist.push_back(msg);
                                    if hist.len() > 10 {
                                        hist.pop_front();
                                    }
                                    
                                    let _ = send.write_all(b"ack").await;
                                    let _ = send.shutdown();
                                }
                            }
                        });
                    }
                    Ok(None) => break,
                    Err(_) => continue,
                    _ => continue,
                }
            }

            Ok(msg) = rx.recv() => {
                if let Ok(mut stream) = session.open_bi(session.session_id()).await {
                    let _ = stream.write_all(msg.trim_end().as_bytes()).await;
                    let _ = stream.shutdown();
                }
            }

            else => break
        }
    }

    let leave_msg = format!("*** {} has left\n", nick);
    let _ = tx.send(leave_msg.clone());
    
    // add to history
    let mut hist = history.lock().await;
    hist.push_back(leave_msg);
    if hist.len() > 10 {
        hist.pop_front();
    }
    
    eprintln!("[{}] disconnected", nick);
    Ok(())
}

#[cfg(feature = "webtransport")]
async fn serve_frontend(cert_hash: String) {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();

    loop {
        let (mut stream, _) = listener.accept().await.unwrap();
        let cert_hash = cert_hash.clone();

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;

            let html = format!(
                r#"<!DOCTYPE html>
<html>
<head>
<title>quicnet web bridge</title>
<style>
body {{ font-family: monospace; background: #000; color: #0f0; padding: 20px; }}
#messages {{ height: 400px; overflow-y: auto; border: 1px solid #0f0; padding: 10px; margin: 20px 0; }}
#input {{ width: 100%; background: #000; color: #0f0; border: 1px solid #0f0; padding: 10px; font-family: monospace; }}
</style>
</head>
<body>
<h1>quicnet chat (web bridge)</h1>
<div id="messages"></div>
<input id="input" placeholder="type and press enter..." autofocus>

<script>
const log = msg => {{
  const div = document.createElement('div');
  div.textContent = msg;
  document.getElementById('messages').appendChild(div);
  div.scrollIntoView();
}};

(async () => {{
  const transport = new WebTransport('https://localhost:8443', {{
    serverCertificateHashes: [{{
      algorithm: 'sha-256',
      value: new Uint8Array('{}' .match(/../g).map(h => parseInt(h, 16))).buffer
    }}]
  }});

  await transport.ready;
  log('connected to quicnet server via webtransport bridge');

  // incoming
  (async () => {{
    const reader = transport.incomingBidirectionalStreams.getReader();
    while (true) {{
      const {{ value: stream, done }} = await reader.read();
      if (done) break;
      const reader2 = stream.readable.getReader();
      try {{
        const {{ value }} = await reader2.read();
        if (value) {{
          const text = new TextDecoder().decode(value);
          log(text);
        }}
      }} finally {{
        reader2.releaseLock();
      }}
    }}
  }})();

  // send on enter
  document.getElementById('input').addEventListener('keydown', async e => {{
    if (e.key === 'Enter' && e.target.value.trim()) {{
      const stream = await transport.createBidirectionalStream();
      const writer = stream.writable.getWriter();
      await writer.write(new TextEncoder().encode(e.target.value));
      await writer.close();
      e.target.value = '';
    }}
  }});
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
