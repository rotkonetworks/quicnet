// remote shell server using quicnet transport
use anyhow::Result;
use quicnet::{AuthenticatedStream, Identity, ServerBuilder};
use std::process::Stdio;
use std::time::Duration;
use tokio::io;
use tokio::process::Command;

#[tokio::main]
async fn main() -> Result<()> {
    // install crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install crypto provider");

    let identity = Identity::load_or_generate()?;

    let server = ServerBuilder::new()
        .identity(identity)
        .bind("[::]:4433")
        .authorized_peers_file(".quicnet/shell_authorized")
        .rate_limit(10, Duration::from_secs(60))
        .audit_log("/var/log/quicnet-shell.log")
        .build()?;

    eprintln!("shell server listening on {}", server.local_addr()?);
    eprintln!("peer id: {}", server.identity().peer_id());

    while let Some(stream) = server.accept_authenticated().await {
        tokio::spawn(handle_shell(stream));
    }
    Ok(())
}

async fn handle_shell(stream: AuthenticatedStream) -> Result<()> {
    let peer_id = stream.peer_id();
    eprintln!("[{}] shell session started", peer_id.short());

    let mut child = Command::new("/bin/bash")
        .arg("-i") // interactive
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();

    let (mut send, mut recv) = stream.split();

    // bidirectional copy
    tokio::select! {
        _ = io::copy(&mut stdout, &mut send) => {},
        _ = io::copy(&mut recv, &mut stdin) => {},
    }

    eprintln!("[{}] shell session ended", peer_id.short());
    Ok(())
}
