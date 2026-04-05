use std::time::Duration;
use wtransport::endpoint::IncomingSession;
use wtransport::tls::Sha256DigestFmt;
use wtransport::Endpoint;
use wtransport::Identity;
use wtransport::ServerConfig;

const BIND_PORT: u16 = 4433;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a self-signed certificate for localhost (valid 14 days, as Chrome requires).
    let identity = Identity::self_signed(["localhost", "127.0.0.1", "::1"])
        .expect("failed to generate self-signed identity");

    // Print the certificate hash so the user can paste it into the browser client.
    let cert_hash = identity
        .certificate_chain()
        .as_slice()
        .first()
        .expect("certificate chain is empty")
        .hash();

    let hash_hex = cert_hash.fmt(Sha256DigestFmt::DottedHex);

    eprintln!("======================================================");
    eprintln!("  WebTransport Datagram Demo Server");
    eprintln!("======================================================");
    eprintln!();
    eprintln!("  Listening on: https://localhost:{BIND_PORT}");
    eprintln!();
    eprintln!("  Certificate SHA-256 hash:");
    eprintln!("  {hash_hex}");
    eprintln!();
    eprintln!("  Append to your index.html URL as a fragment:");
    eprintln!("  file:///path/to/static/index.html#{hash_hex}");
    eprintln!();
    eprintln!("======================================================");

    let config = ServerConfig::builder()
        .with_bind_default(BIND_PORT)
        .with_identity(identity)
        .keep_alive_interval(Some(Duration::from_secs(3)))
        .build();

    let server = Endpoint::server(config)?;

    eprintln!("[server] Ready — waiting for connections...");

    loop {
        let incoming_session = server.accept().await;
        tokio::spawn(handle_session(incoming_session));
    }
}

async fn handle_session(incoming: IncomingSession) {
    if let Err(e) = handle_session_impl(incoming).await {
        eprintln!("[session] Ended with error: {e}");
    }
}

async fn handle_session_impl(
    incoming: IncomingSession,
) -> Result<(), Box<dyn std::error::Error>> {
    let session_request = incoming.await?;

    eprintln!(
        "[session] New request — authority: '{}', path: '{}'",
        session_request.authority(),
        session_request.path()
    );

    let connection = session_request.accept().await?;
    eprintln!("[session] Connected — listening for datagrams...");

    loop {
        let datagram = connection.receive_datagram().await?;
        let payload = std::str::from_utf8(&datagram).unwrap_or("<invalid utf-8>");

        // Build a timestamped reply.
        let now = chrono_lite_now();
        let reply = format!("[{now}] server says: {payload}");

        eprintln!("[datagram] recv: {payload}");
        eprintln!("[datagram] send: {reply}");

        connection.send_datagram(reply.as_bytes())?;
    }
}

/// Cheap wall-clock timestamp without pulling in the `chrono` crate.
fn chrono_lite_now() -> String {
    use std::time::SystemTime;
    let d = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs();
    let h = (secs / 3600) % 24;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    let ms = d.subsec_millis();
    format!("{h:02}:{m:02}:{s:02}.{ms:03}")
}
