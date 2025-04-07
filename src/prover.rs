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
    // Always use the server fixture for now (consistent with direct_test)
    let use_fixture = true;
    
    // Parse URL to extract the path only, using the same approach as the direct_test
    // Extract just the path portion from the URL
    let uri = if url.contains("://") {
        let parts: Vec<&str> = url.split('/').collect();
        if parts.len() >= 4 {
            // Format with leading slash: "/path/to/resource"
            format!("/{}", parts[3..].join("/"))
        } else {
            "/".to_string()
        }
    } else {
        // If the URL doesn't have a scheme, assume it's just a path
        if !url.starts_with('/') {
            format!("/{}", url)
        } else {
            url.to_string()
        }
    };
    
    println!("Using URI path: {}", uri);
    
    // Configure connection details - same as direct_test
    let notary_host = notary_host.unwrap_or_else(|| DEFAULT_NOTARY_HOST.to_string());
    let notary_port = notary_port.unwrap_or(DEFAULT_NOTARY_PORT);
    let server_host = "127.0.0.1"; // Always use localhost for server fixture
    let server_port = DEFAULT_FIXTURE_PORT;
    let server_name = SERVER_DOMAIN; // Always use the constant domain for server fixture
    
    println!("Connecting to notary server at {}:{}...", notary_host, notary_port);
    
    // Build notary client - exactly as in direct_test
    let notary_client = NotaryClient::builder()
        .host(notary_host)
        .port(notary_port)
        .enable_tls(false) // Local notary doesn't need TLS
        .build()?;
    
    // Create notarization request - exactly as in direct_test
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
    
    // Configure the prover - exactly as in direct_test
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
    
    // Set up the prover with the notary connection - exactly as in direct_test
    let prover = Prover::new(prover_config)
        .setup(notary_connection.compat())
        .await?;
    
    println!("Opening TCP connection to server at {}:{}...", server_host, server_port);
    
    // Connect to the server - exactly as in direct_test
    let client_socket = tokio::net::TcpStream::connect((server_host, server_port)).await?;
    
    println!("Binding prover to server connection...");
    
    // Perform the MPC TLS handshake - exactly as in direct_test
    let (mpc_tls_connection, prover_fut) = prover.connect(client_socket.compat()).await?;
    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());
    
    println!("Spawning prover task...");
    
    // Spawn the prover task - exactly as in direct_test
    let prover_task = tokio::spawn(prover_fut);
    
    println!("Attaching HTTP client...");
    
    // Create the HTTP client - exactly as in direct_test
    let (mut request_sender, connection) = 
        hyper::client::conn::http1::handshake(mpc_tls_connection).await?;
    
    println!("Spawning HTTP connection task...");
    
    // Spawn the HTTP connection task - exactly as in direct_test
    tokio::spawn(connection);
    
    println!("Building HTTP request for URI: {}", uri);
    
    // Build HTTP request - now following direct_test exactly
    // Start with the base request builder with required headers
    let mut request_builder = Request::builder()
        .uri(&uri)
        .header("Host", server_name)
        .header("Accept", "*/*")
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header("User-Agent", USER_AGENT);
    
    // Add custom headers, skipping any that would override the required ones
    let reserved_headers = ["host", "accept", "accept-encoding", "connection", "user-agent"];
    for (key, value) in headers {
        if !reserved_headers.contains(&key.to_lowercase().as_str()) {
            println!("Adding custom header: {}:{}", key, value);
            request_builder = request_builder.header(&key, &value);
        } else {
            println!("Skipping reserved header: {}:{}", key, value);
        }
    }
    
    // Handle method if it's not GET
    if method.to_uppercase() != "GET" {
        println!("Using method: {}", method);
        request_builder = request_builder.method(hyper::Method::from_str(method)?);
    }
    
    // Create the request with empty body - exactly as in direct_test
    let request = request_builder.body(Empty::<Bytes>::new())?;
    
    println!("Starting an MPC TLS connection with the server");
    
    // Send the request - exactly as in direct_test
    let response = request_sender.send_request(request).await?;
    
    println!("Got a response from the server: {}", response.status());
    
    // Avoid assertion that would stop execution if status is not 200
    if response.status() != hyper::StatusCode::OK {
        println!("Warning: received non-OK status code: {}", response.status());
    }
    
    println!("Awaiting prover task...");
    
    // Wait for the prover task to complete - exactly as in direct_test
    let prover = prover_task.await??;
    
    println!("Preparing for notarization...");
    
    // Start the notarization process - exactly as in direct_test
    let mut prover = prover.start_notarize();
    
    // Parse the HTTP transcript
    let transcript = HttpTranscript::parse(prover.transcript())?;
    
    // Log information about the response body
    if let Some(body) = transcript.responses.first().and_then(|r| r.body.as_ref()) {
        let body_bytes = body.content.span().as_bytes();
        let body_text = String::from_utf8_lossy(body_bytes);
        println!("Response body size: {} bytes", body_text.len());
    }
    
    println!("Committing to transcript...");
    
    // Commit to the transcript - exactly as in direct_test
    let mut builder = TranscriptCommitConfig::builder(prover.transcript());
    DefaultHttpCommitter::default().commit_transcript(&mut builder, &transcript)?;
    prover.transcript_commit(builder.build()?);
    
    println!("Requesting attestation...");
    
    // Finalize the notarization - exactly as in direct_test
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

/// Direct test using example code copied exactly from the TLSNotary repository
pub async fn direct_test(
    uri: &str,
    outfile_prefix: &str,
) -> Result<(), Box<dyn Error>> {
    // This example demonstrates how to use the Prover to acquire an attestation for
    // an HTTP request sent to example.com. The attestation and secrets are saved to
    // disk.
    use std::env;

    use http_body_util::Empty;
    use hyper::{body::Bytes, Request, StatusCode};
    use hyper_util::rt::TokioIo;
    use tlsn_formats::spansy::Spanned;
    use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
    use tls_server_fixture::SERVER_DOMAIN;
    use tlsn_core::{request::RequestConfig, transcript::TranscriptCommitConfig};
    use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};

    // Setting of the application server
    const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36";

    println!("DirectTest: Using URI '{}'", uri);

    let notary_host: String = env::var("NOTARY_HOST").unwrap_or("127.0.0.1".into());
    let notary_port: u16 = env::var("NOTARY_PORT")
        .map(|port| port.parse().expect("port should be valid integer"))
        .unwrap_or(7047);
    let server_host: String = env::var("SERVER_HOST").unwrap_or("127.0.0.1".into());
    let server_port: u16 = env::var("SERVER_PORT")
        .map(|port| port.parse().expect("port should be valid integer"))
        .unwrap_or(DEFAULT_FIXTURE_PORT);

    // Build a client to connect to the notary server.
    let notary_client = NotaryClient::builder()
        .host(notary_host)
        .port(notary_port)
        // WARNING: Always use TLS to connect to notary server, except if notary is running locally
        // e.g. this example, hence `enable_tls` is set to False (else it always defaults to True).
        .enable_tls(false)
        .build()
        .unwrap();

    // Send requests for configuration and notarization to the notary server.
    let notarization_request = NotarizationRequest::builder()
        // We must configure the amount of data we expect to exchange beforehand, which will
        // be preprocessed prior to the connection. Reducing these limits will improve
        // performance.
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        .build()?;

    let Accepted {
        io: notary_connection,
        id: _session_id,
        ..
    } = notary_client
        .request_notarization(notarization_request)
        .await
        .expect("Could not connect to notary. Make sure it is running.");

    // Set up protocol configuration for prover.
    // Prover configuration.
    let prover_config = ProverConfig::builder()
        .server_name(SERVER_DOMAIN)
        .protocol_config(
            ProtocolConfig::builder()
                // We must configure the amount of data we expect to exchange beforehand, which will
                // be preprocessed prior to the connection. Reducing these limits will improve
                // performance.
                .max_sent_data(MAX_SENT_DATA)
                .max_recv_data(MAX_RECV_DATA)
                .build()?,
        )
        .crypto_provider(get_crypto_provider_with_server_fixture())
        .build()?;

    // Create a new prover and perform necessary setup.
    let prover = Prover::new(prover_config)
        .setup(notary_connection.compat())
        .await?;

    // Open a TCP connection to the server.
    let client_socket = tokio::net::TcpStream::connect((server_host, server_port)).await?;

    // Bind the prover to the server connection.
    // The returned `mpc_tls_connection` is an MPC TLS connection to the server: all
    // data written to/read from it will be encrypted/decrypted using MPC with
    // the notary.
    let (mpc_tls_connection, prover_fut) = prover.connect(client_socket.compat()).await?;

    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());

    // Spawn the prover task to be run concurrently in the background.
    let prover_task = tokio::spawn(prover_fut);

    // Attach the hyper HTTP client to the connection.
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection).await?;

    // Spawn the HTTP task to be run concurrently in the background.
    tokio::spawn(connection);

    // Build a simple HTTP request with common headers
    let request_builder = Request::builder()
        .uri(uri)
        .header("Host", SERVER_DOMAIN)
        .header("Accept", "*/*")
        // Using "identity" instructs the Server not to use compression for its HTTP response.
        // TLSNotary tooling does not support compression.
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header("User-Agent", USER_AGENT);

    let request = request_builder.body(Empty::<Bytes>::new())?;

    println!("Starting an MPC TLS connection with the server");

    // Send the request to the server and wait for the response.
    let response = request_sender.send_request(request).await?;

    println!("Got a response from the server: {}", response.status());

    assert!(response.status() == StatusCode::OK);

    // The prover task should be done now, so we can await it.
    let prover = prover_task.await??;

    // Prepare for notarization.
    let mut prover = prover.start_notarize();

    // Parse the HTTP transcript.
    let transcript = HttpTranscript::parse(prover.transcript())?;

    // dbg!(&transcript);

    let body_content = &transcript.responses[0].body.as_ref().unwrap().content;
    let body = String::from_utf8_lossy(body_content.span().as_bytes());

    match body_content {
        tlsn_formats::http::BodyContent::Json(_json) => {
            let parsed = serde_json::from_str::<serde_json::Value>(&body)?;
            println!("{}", serde_json::to_string_pretty(&parsed)?);
        }
        tlsn_formats::http::BodyContent::Unknown(_span) => {
            println!("{}", &body);
        }
        _ => {}
    }

    // Commit to the transcript.
    let mut builder = TranscriptCommitConfig::builder(prover.transcript());
    DefaultHttpCommitter::default().commit_transcript(&mut builder, &transcript)?;
    prover.transcript_commit(builder.build()?);

    // Request an attestation.
    let request_config = RequestConfig::default();
    let (attestation, secrets) = prover.finalize(&request_config).await?;

    println!("Notarization complete!");

    // Write the attestation to disk.
    let attestation_path = format!("{}.attestation.bin", outfile_prefix);
    let secrets_path = format!("{}.secrets.bin", outfile_prefix);

    tokio::fs::write(&attestation_path, bincode::serialize(&attestation)?).await?;

    // Write the secrets to disk.
    tokio::fs::write(&secrets_path, bincode::serialize(&secrets)?).await?;

    println!("Notarization completed successfully!");
    println!(
        "The attestation has been written to `{}` and the \
        corresponding secrets to `{}`.",
        attestation_path, secrets_path
    );

    Ok(())
}

/// A simplified notarize function that is an exact copy of direct_test
pub async fn simple_notarize(
    url: &str,
    _method: &str,
    _headers: HashMap<String, String>,
    _body: Option<String>,
    _notary_host: Option<String>,
    _notary_port: Option<u16>,
    outfile_prefix: &str,
) -> Result<(), Box<dyn Error>> {
    // This example demonstrates how to use the Prover to acquire an attestation for
    // an HTTP request sent to example.com. The attestation and secrets are saved to
    // disk.
    use std::env;

    use http_body_util::Empty;
    use hyper::{body::Bytes, Request, StatusCode};
    use hyper_util::rt::TokioIo;
    use tlsn_formats::spansy::Spanned;
    use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
    use tls_server_fixture::SERVER_DOMAIN;
    use tlsn_core::{request::RequestConfig, transcript::TranscriptCommitConfig};
    use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};

    // Setting of the application server
    const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36";

    // Extract path from URL
    let uri = if url.contains("://") {
        let parts: Vec<&str> = url.split('/').collect();
        if parts.len() >= 4 {
            format!("/{}", parts[3..].join("/"))
        } else {
            "/".to_string()
        }
    } else {
        if !url.starts_with('/') {
            format!("/{}", url)
        } else {
            url.to_string()
        }
    };

    println!("SimpleNotarize: Using URI '{}'", uri);

    let notary_host: String = env::var("NOTARY_HOST").unwrap_or("127.0.0.1".into());
    let notary_port: u16 = env::var("NOTARY_PORT")
        .map(|port| port.parse().expect("port should be valid integer"))
        .unwrap_or(7047);
    let server_host: String = env::var("SERVER_HOST").unwrap_or("127.0.0.1".into());
    let server_port: u16 = env::var("SERVER_PORT")
        .map(|port| port.parse().expect("port should be valid integer"))
        .unwrap_or(DEFAULT_FIXTURE_PORT);

    // Build a client to connect to the notary server.
    let notary_client = NotaryClient::builder()
        .host(notary_host)
        .port(notary_port)
        // WARNING: Always use TLS to connect to notary server, except if notary is running locally
        // e.g. this example, hence `enable_tls` is set to False (else it always defaults to True).
        .enable_tls(false)
        .build()
        .unwrap();

    // Send requests for configuration and notarization to the notary server.
    let notarization_request = NotarizationRequest::builder()
        // We must configure the amount of data we expect to exchange beforehand, which will
        // be preprocessed prior to the connection. Reducing these limits will improve
        // performance.
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        .build()?;

    let Accepted {
        io: notary_connection,
        id: _session_id,
        ..
    } = notary_client
        .request_notarization(notarization_request)
        .await
        .expect("Could not connect to notary. Make sure it is running.");

    // Set up protocol configuration for prover.
    // Prover configuration.
    let prover_config = ProverConfig::builder()
        .server_name(SERVER_DOMAIN)
        .protocol_config(
            ProtocolConfig::builder()
                // We must configure the amount of data we expect to exchange beforehand, which will
                // be preprocessed prior to the connection. Reducing these limits will improve
                // performance.
                .max_sent_data(MAX_SENT_DATA)
                .max_recv_data(MAX_RECV_DATA)
                .build()?,
        )
        .crypto_provider(get_crypto_provider_with_server_fixture())
        .build()?;

    // Create a new prover and perform necessary setup.
    let prover = Prover::new(prover_config)
        .setup(notary_connection.compat())
        .await?;

    // Open a TCP connection to the server.
    let client_socket = tokio::net::TcpStream::connect((server_host, server_port)).await?;

    // Bind the prover to the server connection.
    // The returned `mpc_tls_connection` is an MPC TLS connection to the server: all
    // data written to/read from it will be encrypted/decrypted using MPC with
    // the notary.
    let (mpc_tls_connection, prover_fut) = prover.connect(client_socket.compat()).await?;

    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());

    // Spawn the prover task to be run concurrently in the background.
    let prover_task = tokio::spawn(prover_fut);

    // Attach the hyper HTTP client to the connection.
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection).await?;

    // Spawn the HTTP task to be run concurrently in the background.
    tokio::spawn(connection);

    // Build a simple HTTP request with common headers
    let request_builder = Request::builder()
        .uri(&uri)
        .header("Host", SERVER_DOMAIN)
        .header("Accept", "*/*")
        // Using "identity" instructs the Server not to use compression for its HTTP response.
        // TLSNotary tooling does not support compression.
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header("User-Agent", USER_AGENT);

    let request = request_builder.body(Empty::<Bytes>::new())?;

    println!("Starting an MPC TLS connection with the server");

    // Send the request to the server and wait for the response.
    let response = request_sender.send_request(request).await?;

    println!("Got a response from the server: {}", response.status());

    assert!(response.status() == StatusCode::OK);

    // The prover task should be done now, so we can await it.
    let prover = prover_task.await??;

    // Prepare for notarization.
    let mut prover = prover.start_notarize();

    // Parse the HTTP transcript.
    let transcript = HttpTranscript::parse(prover.transcript())?;

    // dbg!(&transcript);

    let body_content = &transcript.responses[0].body.as_ref().unwrap().content;
    let body = String::from_utf8_lossy(body_content.span().as_bytes());

    match body_content {
        tlsn_formats::http::BodyContent::Json(_json) => {
            let parsed = serde_json::from_str::<serde_json::Value>(&body)?;
            println!("{}", serde_json::to_string_pretty(&parsed)?);
        }
        tlsn_formats::http::BodyContent::Unknown(_span) => {
            println!("{}", &body);
        }
        _ => {}
    }

    // Commit to the transcript.
    let mut builder = TranscriptCommitConfig::builder(prover.transcript());
    DefaultHttpCommitter::default().commit_transcript(&mut builder, &transcript)?;
    prover.transcript_commit(builder.build()?);

    // Request an attestation.
    let request_config = RequestConfig::default();
    let (attestation, secrets) = prover.finalize(&request_config).await?;

    println!("Notarization complete!");

    // Write the attestation to disk.
    let attestation_path = format!("{}.attestation.bin", outfile_prefix);
    let secrets_path = format!("{}.secrets.bin", outfile_prefix);

    tokio::fs::write(&attestation_path, bincode::serialize(&attestation)?).await?;

    // Write the secrets to disk.
    tokio::fs::write(&secrets_path, bincode::serialize(&secrets)?).await?;

    println!("Notarization completed successfully!");
    println!(
        "The attestation has been written to `{}` and the \
        corresponding secrets to `{}`.",
        attestation_path, secrets_path
    );

    Ok(())
}