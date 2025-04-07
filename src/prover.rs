use std::collections::HashMap;
use std::error::Error;
use std::path::PathBuf;
use std::str::FromStr;

use http_body_util::Empty;
use hyper::{body::Bytes, Request, Uri};
use hyper_util::rt::TokioIo;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tlsn_formats::spansy::Spanned;

use notary_client::{Accepted, NotarizationRequest, NotaryClient};
use tlsn_common::config::ProtocolConfig;
use tlsn_core::{request::RequestConfig, transcript::TranscriptCommitConfig, CryptoProvider};
use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};
use tlsn_prover::{Prover, ProverConfig};
use tlsn_core::{presentation::Presentation, attestation::Attestation, Secrets};

// For server fixture TLS certificate handling
use tlsn_tls_core::verify::WebPkiVerifier; 
use tls_server_fixture::CA_CERT_DER;

// Constants for server fixture
const SERVER_DOMAIN: &str = "tlsnotary.org";
const DEFAULT_FIXTURE_PORT: u16 = 4000;

// Constants for notary
const DEFAULT_NOTARY_HOST: &str = "127.0.0.1";
const DEFAULT_NOTARY_PORT: u16 = 7047;

// Constants for data limits - exactly matching the example
const MAX_SENT_DATA: usize = 1 << 12; // 4KB 
const MAX_RECV_DATA: usize = 1 << 14; // 16KB

// HTTP headers - exactly matching the example
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36";

/// Creates a crypto provider that accepts the server-fixture's self-signed certificate
/// 
/// This is only required for testing with the server-fixture. In
/// production, use `CryptoProvider::default()` instead.
fn get_crypto_provider_with_server_fixture() -> CryptoProvider {
    // Custom root store with server-fixture certificate
    let mut root_store = tlsn_tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tlsn_tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    CryptoProvider {
        cert: WebPkiVerifier::new(root_store, None),
        ..Default::default()
    }
}

/// Performs TLS notarization of an HTTPS request
pub async fn notarize(
    url: &str,
    method: &str,
    headers: HashMap<String, String>,
    _body: Option<String>,
    notary_host: Option<String>,
    notary_port: Option<u16>,
    outfile_prefix: &str,
) -> Result<(), Box<dyn Error>> {
    // For now, we're always using the server fixture to match the working example
    let use_fixture = true;
    
    // Parse the URL to extract the path
    let uri = Uri::from_str(url)?;
    let path = uri.path_and_query().map_or("/", |p| p.as_str());
    
    // Configure connection details
    let notary_host = notary_host.unwrap_or_else(|| DEFAULT_NOTARY_HOST.to_string());
    let notary_port = notary_port.unwrap_or(DEFAULT_NOTARY_PORT);
    
    // Server details depend on if we're using the fixture or real server
    let server_host = if use_fixture { "127.0.0.1" } else { uri.host().ok_or("URL must have a host")? };
    let server_port = if use_fixture { DEFAULT_FIXTURE_PORT } else { uri.port_u16().unwrap_or(443) };
    
    println!("Connecting to notary server at {}:{}...", notary_host, notary_port);
    
    // Build notary client
    let notary_client = NotaryClient::builder()
        .host(notary_host)
        .port(notary_port)
        .enable_tls(false) // Local notary doesn't need TLS
        .build()?;
    
    // Create notarization request
    let notarization_request = NotarizationRequest::builder()
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        .build()?;
    
    // Send the request to the notary
    let Accepted {
        io: notary_connection,
        id: session_id,
        ..
    } = notary_client
        .request_notarization(notarization_request)
        .await?;
    
    println!("Notary session established with ID: {}", session_id);
    
    // Configure the prover using server fixture's domain
    let server_name = if use_fixture { SERVER_DOMAIN } else { server_host };
    let prover_config = ProverConfig::builder()
        .server_name(server_name)
        .protocol_config(
            ProtocolConfig::builder()
                .max_sent_data(MAX_SENT_DATA)
                .max_recv_data(MAX_RECV_DATA)
                .build()?
        )
        .crypto_provider(get_crypto_provider_with_server_fixture())
        .build()?;
    
    println!("Setting up TLS session with notary...");
    
    // Set up the prover with the notary connection
    let prover = Prover::new(prover_config)
        .setup(notary_connection.compat())
        .await?;
    
    println!("Connecting to server at {}:{}...", server_host, server_port);
    
    // Connect to the server
    let client_socket = tokio::net::TcpStream::connect((server_host, server_port)).await?;
    
    println!("Performing MPC TLS handshake...");
    
    // Perform the MPC TLS handshake
    let (mpc_tls_connection, prover_fut) = prover.connect(client_socket.compat()).await?;
    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());
    
    // Spawn the prover task to run in the background
    let prover_task = tokio::spawn(prover_fut);
    
    // Create the HTTP client
    let (mut request_sender, connection) = 
        hyper::client::conn::http1::handshake(mpc_tls_connection).await?;
    
    // Spawn the HTTP connection task
    tokio::spawn(connection);
    
    // Build HTTP request
    let mut request_builder = Request::builder()
        .uri(path)
        .method(hyper::Method::from_str(method)?)
        .header("Host", server_name)
        .header("Accept", "*/*")
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header("User-Agent", USER_AGENT);
        
    // Add custom headers if any
    for (key, value) in headers {
        request_builder = request_builder.header(&key, &value);
    }
    
    // Use Empty body just like the example - this is critical
    let request = request_builder.body(Empty::<Bytes>::new())?;
    
    println!("Starting an MPC TLS connection with the server");
    
    // Send the request and wait for response
    let response = request_sender.send_request(request).await?;
    
    println!("Got a response from the server: {}", response.status());
    
    // Wait for the prover task to complete
    let prover = prover_task.await??;
    
    // Start the notarization process
    let mut prover = prover.start_notarize();
    
    // Parse the HTTP transcript
    let transcript = HttpTranscript::parse(prover.transcript())?;
    
    // Log information about the response body
    if let Some(body) = transcript.responses.first().and_then(|r| r.body.as_ref()) {
        let body_bytes = body.content.span().as_bytes();
        let body_text = String::from_utf8_lossy(body_bytes);
        println!("Response body size: {} bytes", body_text.len());
    }
    
    // Commit to the transcript
    let mut builder = TranscriptCommitConfig::builder(prover.transcript());
    DefaultHttpCommitter::default().commit_transcript(&mut builder, &transcript)?;
    prover.transcript_commit(builder.build()?);
    
    // Finalize the notarization
    println!("Finalizing notarization...");
    let (attestation, secrets) = prover.finalize(&RequestConfig::default()).await?;
    
    // Save attestation and secrets
    let attestation_path = format!("{}.attestation.bin", outfile_prefix);
    let secrets_path = format!("{}.secrets.bin", outfile_prefix);
    
    println!("Saving attestation to {}...", attestation_path);
    tokio::fs::write(&attestation_path, bincode::serialize(&attestation)?).await?;
    
    println!("Saving secrets to {}...", secrets_path);
    tokio::fs::write(&secrets_path, bincode::serialize(&secrets)?).await?;
    
    println!("Notarization complete!");
    println!("Attestation saved to: {}", attestation_path);
    println!("Secrets saved to: {}", secrets_path);
    
    Ok(())
}

/// Creates a verifiable presentation from an attestation
pub async fn create_presentation(
    attestation_path: PathBuf,
    secrets_path: PathBuf,
    presentation_path: PathBuf,
    redact_request_headers: Vec<String>,
    redact_response_headers: Vec<String>,
    redact_request_body: bool,
    redact_response_body: bool,
) -> Result<(), Box<dyn Error>> {
    println!("Loading attestation from {}...", attestation_path.display());
    let attestation_data = tokio::fs::read(&attestation_path).await?;
    let attestation: Attestation = bincode::deserialize(&attestation_data)?;
    
    println!("Loading secrets from {}...", secrets_path.display());
    let secrets_data = tokio::fs::read(&secrets_path).await?;
    let secrets: Secrets = bincode::deserialize(&secrets_data)?;
    
    // Parse the HTTP transcript
    let transcript = HttpTranscript::parse(secrets.transcript())?;
    
    // Build transcript proof
    let mut builder = secrets.transcript_proof_builder();
    
    // Selective disclosure of request
    let request = &transcript.requests[0];
    
    // Reveal basic request structure
    builder.reveal_sent(&request.without_data())?;
    builder.reveal_sent(&request.request.target)?;
    
    // Selectively reveal headers
    for header in &request.headers {
        let header_name = header.name.as_str();
        if !redact_request_headers.iter().any(|h| h.eq_ignore_ascii_case(header_name)) {
            // Reveal this header
            builder.reveal_sent(header)?;
        } else {
            // Only reveal header name, not value
            builder.reveal_sent(&header.without_value())?;
        }
    }
    
    // Handle request body
    if !redact_request_body {
        if let Some(body) = &request.body {
            builder.reveal_sent(body)?;
        }
    }
    
    // Selective disclosure of response
    let response = &transcript.responses[0];
    
    // Reveal basic response structure
    builder.reveal_recv(&response.without_data())?;
    
    // Selectively reveal response headers
    for header in &response.headers {
        let header_name = header.name.as_str();
        if !redact_response_headers.iter().any(|h| h.eq_ignore_ascii_case(header_name)) {
            // Reveal this header
            builder.reveal_recv(header)?;
        } else {
            // Only reveal header name, not value
            builder.reveal_recv(&header.without_value())?;
        }
    }
    
    // Handle response body
    if !redact_response_body {
        if let Some(body) = &response.body {
            builder.reveal_recv(&body.content)?;
        }
    }
    
    // Build the transcript proof
    let transcript_proof = builder.build()?;
    
    // Create the presentation
    let provider = get_crypto_provider_with_server_fixture();
    let mut builder = attestation.presentation_builder(&provider);
    
    builder
        .identity_proof(secrets.identity_proof())
        .transcript_proof(transcript_proof);
    
    let presentation = builder.build()?;
    
    // Save the presentation
    println!("Saving presentation to {}...", presentation_path.display());
    tokio::fs::write(&presentation_path, bincode::serialize(&presentation)?).await?;
    
    println!("Presentation created successfully!");
    
    Ok(())
}

/// Verifies a presentation
pub async fn verify_presentation(
    presentation_path: PathBuf,
) -> Result<(), Box<dyn Error>> {
    println!("Loading presentation from {}...", presentation_path.display());
    let presentation_data = tokio::fs::read(&presentation_path).await?;
    let presentation: Presentation = bincode::deserialize(&presentation_data)?;
    
    // Create crypto provider that can verify the server fixture's certificate
    let provider = get_crypto_provider_with_server_fixture();
    
    // Get verifying key info
    let key = presentation.verifying_key();
    println!("Verifying presentation signed by {} key: {}", key.alg, hex::encode(&key.data));
    
    // Verify the presentation
    let output = presentation.verify(&provider)?;
    
    // Display verification results
    println!("\nVerification successful!");
    
    if let Some(server_name) = output.server_name {
        println!("Server: {}", server_name);
    }
    
    // ConnectionInfo is not optional in the current API
    let connection_info = output.connection_info;
    let time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(connection_info.time);
    let time_str = chrono::DateTime::<chrono::Utc>::from(time).to_rfc3339();
    println!("Connection time: {}", time_str);
    
    if let Some(mut transcript) = output.transcript {
        // Mark undisclosed data with 'X'
        transcript.set_unauthed(b'X');
        
        // Display sent data
        println!("\nData sent:\n");
        println!("{}", String::from_utf8_lossy(transcript.sent_unsafe()));
        
        // Display received data
        println!("\nData received:\n");
        println!("{}", String::from_utf8_lossy(transcript.received_unsafe()));
    }
    
    Ok(())
}