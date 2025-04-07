use crate::error::{Proof, ProverError};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::{Request, Uri};
use hyper_util::rt::{TokioIo, TokioExecutor};
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::client::legacy::connect::HttpConnector;
use log::{debug, info, warn, error};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr, str::FromStr};

use notary_client::{NotaryClient, NotarizationRequest, Accepted};
use tlsn_common::config::ProtocolConfig;
use tlsn_core::{transcript::Idx, CryptoProvider, request::RequestConfig, transcript::TranscriptCommitConfig};
use tlsn_formats::http::{DefaultHttpCommitter, HttpTranscript, BodyContent};
use tlsn_prover::{state::Prove, Prover, ProverConfig};
use tokio::net::TcpStream;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use hex;

// Constants
const MAX_SENT_DATA: usize = 1 << 16; // 64KB
const MAX_RECV_DATA: usize = 1 << 20; // 1MB
const DEFAULT_MPC_TIMEOUT_SECS: u64 = 300; // Default MPC timeout - Fallback if API unavailable (5 minutes)
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36";

/// Structure representing the MPC parameters returned by the notary API
#[derive(Debug, Serialize, Deserialize)]
struct MpcParams {
    max_sent_data: usize,
    max_recv_data: usize,
    timeout_seconds: u64,
    version: String,
    supported_features: Vec<String>,
}

pub struct TlsnProver {
    notary_host: String, 
    notary_port: u16,
    notary_api_port: u16,
}

/// Creates a default crypto provider for TLSNotary
fn get_crypto_provider() -> CryptoProvider {
    CryptoProvider::default()
}

/// Fetches MPC parameters from the notary API
async fn fetch_mpc_params(host: &str, api_port: u16) -> Result<MpcParams, ProverError> {
    // Create the client 
    let http_connector = HttpConnector::new();
    let client: HyperClient<HttpConnector, Full<Bytes>> = HyperClient::builder(TokioExecutor::new())
        .build(http_connector);
    
    // Build the request URL
    let url = format!("http://{}:{}/api/mpcparams", host, api_port);
    let uri = Uri::from_str(&url)
        .map_err(|e| ProverError::ConfigError(format!("Invalid URL: {}", e)))?;
    
    // Create and send the request
    info!("Fetching MPC parameters from {}", url);
    let response = client.get(uri)
        .await
        .map_err(|e| ProverError::RequestError(format!("Failed to fetch MPC parameters: {}", e)))?;
    
    // Check response status
    if !response.status().is_success() {
        return Err(ProverError::RequestError(format!(
            "Failed to fetch MPC parameters, status: {}", 
            response.status()
        )));
    }
    
    // Read the response body
    let body = response.collect().await
        .map_err(|e| ProverError::RequestError(format!("Failed to read response body: {}", e)))?
        .to_bytes();
    
    // Parse the JSON
    serde_json::from_slice::<MpcParams>(&body)
        .map_err(|e| ProverError::ConfigError(format!("Failed to parse MPC parameters: {}", e)))
}

impl TlsnProver {
    pub fn new(notary_host: String, notary_port: u16, notary_api_port: u16) -> Self {
        Self {
            notary_host,
            notary_port,
            notary_api_port,
        }
    }
    
    pub async fn notarize(
        &mut self,
        url: String,
        method: String,
        headers: Option<Vec<(String, String)>>,
        body: Option<String>,
        selective_disclosure: Option<Vec<(String, String)>>,
    ) -> Result<Proof, ProverError> {
        // Parse the URL
        let uri = Uri::from_str(&url)
            .map_err(|e| ProverError::ConfigError(format!("Invalid URL: {}", e)))?;
        
        // Ensure it's an HTTPS URL
        let scheme = uri.scheme_str().unwrap_or("http");
        if scheme != "https" {
            return Err(ProverError::ConfigError(
                "Only HTTPS URLs are supported".to_string(),
            ));
        }
        
        // Extract host and port
        let server_domain = uri.host().ok_or_else(|| {
            ProverError::ConfigError("URL must contain a valid hostname".to_string())
        })?;
        
        let server_port = uri.port_u16().unwrap_or(443);
        
        // Create server address
        let server_addr = format!("{}:{}", server_domain, server_port);
        let socket_addr = tokio::net::lookup_host(&server_addr)
            .await
            .map_err(|e| {
                ProverError::RequestError(format!("Failed to resolve hostname: {}", e))
            })?
            .next()
            .ok_or_else(|| {
                ProverError::RequestError("Failed to resolve hostname".to_string())
            })?;
        
        // Fetch MPC parameters from the notary API first to better configure our request
        info!("FLOW: [1/10] Fetching MPC parameters from notary API");
        let mpc_params = match fetch_mpc_params(&self.notary_host, self.notary_api_port).await {
            Ok(params) => {
                info!("Successfully fetched MPC parameters from notary API");
                debug!("MPC params: max_sent={}, max_recv={}, timeout={}s", 
                       params.max_sent_data, params.max_recv_data, params.timeout_seconds);
                params
            }
            Err(e) => {
                warn!("Failed to fetch MPC parameters: {}. Using defaults.", e);
                MpcParams {
                    max_sent_data: MAX_SENT_DATA,
                    max_recv_data: MAX_RECV_DATA,
                    timeout_seconds: DEFAULT_MPC_TIMEOUT_SECS,
                    version: "1.0".to_string(),
                    supported_features: vec!["selective_disclosure".to_string()],
                }
            }
        };
        
        // STEP 1: Build client to connect to notary server
        info!("FLOW: [2/10] Building notary client");
        let notary_client = NotaryClient::builder()
            .host(&self.notary_host)
            .port(self.notary_port)
            // Local notary doesn't need TLS
            .enable_tls(false)
            .build()
            .map_err(|e| ProverError::ConfigError(format!("Failed to build notary client: {}", e)))?;
            
        // STEP 2: Send notarization request
        info!("FLOW: [3/10] Creating notarization request");
        let notarization_request = NotarizationRequest::builder()
            .max_sent_data(mpc_params.max_sent_data)
            .max_recv_data(mpc_params.max_recv_data)
            .build()
            .map_err(|e| ProverError::ConfigError(format!("Failed to build notarization request: {}", e)))?;
            
        // STEP 3: Request notarization
        info!("FLOW: [4/10] Requesting notarization from notary server");
        let Accepted {
            io: notary_connection,
            id: session_id,
            ..
        } = notary_client
            .request_notarization(notarization_request)
            .await
            .map_err(|e| ProverError::TlsnConnectionError(format!("Failed to connect to notary: {}", e)))?;
            
        info!("Successfully established notarization session with ID: {}", session_id);
        
        // STEP 4: Set up prover configuration
        info!("FLOW: [5/10] Setting up TLSNotary prover configuration");
        info!("Protocol settings: max_sent_data={}, max_recv_data={}", 
               mpc_params.max_sent_data, mpc_params.max_recv_data);
               
        let prover_config = ProverConfig::builder()
            .server_name(server_domain)
            .protocol_config(
                ProtocolConfig::builder()
                    .max_sent_data(mpc_params.max_sent_data)
                    .max_recv_data(mpc_params.max_recv_data)
                    .build()
                    .map_err(|e| {
                        error!("CONFIG ERROR: Invalid protocol config: {}", e);
                        ProverError::ConfigError(format!("Invalid protocol config: {}", e))
                    })?,
            )
            .crypto_provider(get_crypto_provider())
            .build()
            .map_err(|e| {
                error!("CONFIG ERROR: Failed to build prover config: {}", e);
                ProverError::ConfigError(format!("Failed to build prover config: {}", e))
            })?;
            
        // STEP 5: Create prover and perform necessary setup
        info!("FLOW: [6/10] Creating prover and performing setup");
        let prover = match Prover::new(prover_config).setup(notary_connection.compat()).await {
            Ok(p) => {
                info!("Setup phase completed successfully");
                p
            },
            Err(e) => {
                error!("SETUP ERROR: Failed in setup phase: {}", e);
                error!("Detailed error: {:?}", e);
                return Err(ProverError::TlsnProtocolError(format!("Failed in setup phase: {}", e)));
            }
        };
        
        // STEP 6: Connect to the target server
        info!("FLOW: [7/10] Connecting to target server: {}", server_addr);
        let client_socket = match TcpStream::connect(socket_addr).await {
            Ok(socket) => {
                info!("Successfully connected to target server: {}", server_addr);
                socket
            },
            Err(e) => {
                error!("CONNECT ERROR: Failed to connect to server: {}", e);
                return Err(ProverError::RequestError(format!("Failed to connect to server: {}", e)));
            }
        };
        
        // STEP 7: Bind prover to server connection
        info!("FLOW: [8/10] Establishing MPC TLS connection to target server");
        let (mpc_tls_connection, prover_fut) = match prover.connect(client_socket.compat()).await {
            Ok(result) => {
                info!("Successfully established MPC TLS connection to target server");
                result
            },
            Err(e) => {
                error!("CONNECT ERROR: Failed to establish MPC TLS connection: {}", e);
                error!("Detailed error: {:?}", e);
                return Err(ProverError::TlsnProtocolError(format!(
                    "Failed to establish MPC TLS connection: {}", e
                )));
            }
        };
        
        // Wrap the connection for use with hyper
        let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());
        
        // Spawn the prover task to run in the background
        let prover_task = tokio::spawn(prover_fut);
        
        // Attach hyper HTTP client to the connection
        let (mut request_sender, connection) = match hyper::client::conn::http1::handshake(mpc_tls_connection).await {
            Ok(result) => {
                info!("HTTP handshake successful");
                result
            },
            Err(e) => {
                error!("HTTP ERROR: Failed in HTTP handshake: {}", e);
                return Err(ProverError::RequestError(format!("Failed in HTTP handshake: {}", e)));
            }
        };
        
        // Spawn the HTTP task to be run in the background
        tokio::spawn(connection);
        
        // Build the request with proper headers for TLSNotary
        let mut request_builder = Request::builder()
            .uri(uri.clone())
            .method(method.as_str())
            .header("Host", server_domain)
            .header("Accept", "*/*")
            // Using "identity" instructs the Server not to use compression 
            // TLSNotary tooling does not support compression
            .header("Accept-Encoding", "identity")
            .header("Connection", "close")
            .header("User-Agent", USER_AGENT);
        
        // Add custom headers if provided
        if let Some(header_list) = headers {
            for (key, value) in header_list {
                request_builder = request_builder.header(key, value);
            }
        }
        
        // Prepare the request body
        let request_body = match body {
            Some(body_str) => {
                // Set content-length header if not already set
                if !request_builder.headers_ref().unwrap().contains_key("content-length") {
                    request_builder = request_builder.header("content-length", body_str.len());
                }
                
                // Create body
                http_body_util::Full::new(Bytes::from(body_str)).boxed()
            }
            None => Empty::<Bytes>::new().boxed(),
        };
        
        // Finalize the request
        let request = request_builder
            .body(request_body)
            .map_err(|e| ProverError::RequestError(format!("Failed to build request: {}", e)))?;
        
        // Send the request and wait for response
        info!("FLOW: [9/10] Sending {} request to {}", method, url);
        let response = request_sender
            .send_request(request)
            .await
            .map_err(|e| ProverError::RequestError(format!("Failed to send request: {}", e)))?;
        
        // Check response status
        let status = response.status();
        info!("Received response with status: {}", status);
        
        // Wait for the prover task to complete
        let prover = prover_task
            .await
            .map_err(|e| {
                ProverError::TlsnProtocolError(format!("Prover task failed: {}", e))
            })?
            .map_err(|e| {
                ProverError::TlsnProtocolError(format!("Prover connection failed: {}", e))
            })?;
        
        // STEP 10: Prepare for notarization
        info!("FLOW: [10/10] Preparing notarization");
        let mut prover = prover.start_notarize();
        
        // Parse the HTTP transcript
        let transcript = match HttpTranscript::parse(prover.transcript()) {
            Ok(t) => {
                info!("Successfully parsed HTTP transcript");
                t
            },
            Err(e) => {
                error!("TRANSCRIPT ERROR: Failed to parse transcript: {}", e);
                return Err(ProverError::TlsnProtocolError(format!("Failed to parse transcript: {}", e)));
            }
        };
        
        // Log transcript information for debugging
        if let Some(body) = transcript.responses.first().and_then(|r| r.body.as_ref()) {
            match &body.content {
                BodyContent::Json(_) => {
                    info!("Response contains JSON content");
                }
                BodyContent::Html(_) => {
                    info!("Response contains HTML content");
                }
                _ => {
                    info!("Response contains unknown content type");
                }
            }
        }
        
        // Apply selective disclosure if requested
        let builder = if let Some(disclosure_options) = selective_disclosure {
            info!("Applying selective disclosure rules");
            self.apply_selective_disclosure_to_transcript(&mut prover, &transcript, disclosure_options)?
        } else {
            // By default, commit entire transcript
            info!("No selective disclosure specified, committing entire transcript");
            let mut builder = TranscriptCommitConfig::builder(prover.transcript());
            DefaultHttpCommitter::default().commit_transcript(&mut builder, &transcript)
                .map_err(|e| ProverError::TlsnProtocolError(format!("Failed to commit transcript: {}", e)))?;
            builder
        };
        
        // Commit to the transcript
        prover.transcript_commit(builder.build()
            .map_err(|e| ProverError::TlsnProtocolError(format!("Failed to build transcript config: {}", e)))?);
            
        // Request attestation
        let request_config = RequestConfig::default();
        
        // Finalize notarization
        info!("Finalizing notarization");
        let (attestation, secrets) = match prover.finalize(&request_config).await {
            Ok((a, s)) => {
                info!("Notarization completed successfully");
                (a, s)
            },
            Err(e) => {
                error!("FINALIZE ERROR: Failed to finalize: {}", e);
                return Err(ProverError::TlsnProtocolError(format!("Failed to finalize: {}", e)));
            }
        };
        
        // For now, we'll just create a simple proof structure rather than using the binary format
        // In a real implementation, you'd save the attestation and secrets to be verified later
        info!("Creating proof");
        let proof_json = serde_json::json!({
            "notarized": true,
            "url": url,
            "method": method,
            "status": status.as_u16(),
            "headers": response.headers()
                .iter()
                .map(|(k, v)| (k.to_string(), String::from_utf8_lossy(v.as_bytes()).to_string()))
                .collect::<HashMap<String, String>>(),
            "server": server_domain,
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "session_id": session_id,
            "commitment": hex::encode(attestation.commitment()), // Real commitment from attestation
        });
        
        Ok(Proof::new(proof_json))
    }
    
    fn apply_selective_disclosure_to_transcript(
        &self,
        prover: &mut Prover<tlsn_prover::state::Notarize>,
        transcript: &HttpTranscript,
        disclosure_options: Vec<(String, String)>,
    ) -> Result<TranscriptCommitConfig, ProverError> {
        // Create a transcript commit config builder
        let mut builder = TranscriptCommitConfig::builder(prover.transcript());
        
        // We'll create a custom committer based on disclosure options
        // For now, as a simple implementation, we'll just commit the entire transcript
        // In a real implementation, you would selectively commit parts based on disclosure_options
        DefaultHttpCommitter::default().commit_transcript(&mut builder, transcript)
            .map_err(|e| ProverError::TlsnProtocolError(format!("Failed to commit transcript: {}", e)))?;
            
        // This is a simplified implementation - a real one would parse the disclosure options
        // and selectively commit parts of the transcript
        
        Ok(builder)
    }
}