// remote shell server using quicnet transport
use anyhow::Result;
use quicnet::{ServerBuilder, Identity, AuthenticatedStream};
use tokio::process::Command;
use tokio::io;
use std::process::Stdio;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
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
    eprintln!("[{}] shell session started", stream.peer_id().short());
    
    let mut child = Command::new("/bin/bash")
        .arg("-i")  // interactive
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
    
    eprintln!("[{}] shell session ended", stream.peer_id().short());
    Ok(())
}
