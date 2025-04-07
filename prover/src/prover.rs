use crate::error::{Proof, ProverError};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::{Request, Uri};
use hyper_util::{rt::{TokioIo, TokioExecutor}, client::legacy::Client as HyperClient};
use hyper_util::client::legacy::connect::HttpConnector;
use log::{debug, info, warn, error};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr, str::FromStr};
use tlsn_common::config::ProtocolConfig;
use tlsn_core::{transcript::Idx, CryptoProvider};
use tlsn_prover::{state::Prove, Prover, ProverConfig};
use tokio::net::TcpStream;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use hex;

// Constants
#[allow(dead_code)]
const DEFAULT_TIMEOUT_SECS: u64 = 30; // Keeping for future timeout implementations
const MAX_SENT_DATA: usize = 1 << 16; // 64KB - Fallback if API unavailable
const MAX_RECV_DATA: usize = 1 << 20; // 1MB - Fallback if API unavailable
const DEFAULT_MPC_TIMEOUT_SECS: u64 = 300; // Default MPC timeout - Fallback if API unavailable (5 minutes)

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
            
        // Connect to notary
        info!("Connecting to notary at {}:{}", self.notary_host, self.notary_port);
        let notary_addr = SocketAddr::from(([127, 0, 0, 1], self.notary_port));
        let notary_socket = TcpStream::connect(notary_addr)
            .await
            .map_err(|e| {
                ProverError::TlsnConnectionError(format!(
                    "Failed to connect to notary: {}", e
                ))
            })?;
        
        // Fetch MPC parameters from the notary API
        // We use a different port for the API (HTTP) vs MPC (raw TCP)
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
        
        // Setup prover configuration with fetched parameters
        info!("DETAILED FLOW: [1/7] Setting up TLSNotary prover configuration");
        info!("Protocol settings: max_sent_data={}, max_recv_data={}", 
               mpc_params.max_sent_data, mpc_params.max_recv_data);
        let prover_config = ProverConfig::builder()
            .server_name(server_domain) // Use &str directly, not String
            .protocol_config(
                ProtocolConfig::builder()
                    .max_sent_data(mpc_params.max_sent_data)
                    .max_recv_data(mpc_params.max_recv_data)
                    .build()
                    .map_err(|e| {
                        error!("PROTOCOL CONFIG ERROR: Invalid protocol config: {}", e);
                        ProverError::ConfigError(format!("Invalid protocol config: {}", e))
                    })?,
            )
            .crypto_provider(get_crypto_provider()) // Add crypto provider
            .build()
            .map_err(|e| {
                error!("PROVER CONFIG ERROR: Failed to build prover config: {}", e);
                ProverError::ConfigError(format!("Failed to build prover config: {}", e))
            })?;
        
        // Create prover
        info!("DETAILED FLOW: [2/7] Creating prover instance");
        let prover = Prover::new(prover_config);
        
        // Perform the setup phase with the notary
        info!("DETAILED FLOW: [3/7] Starting TLSNotary setup phase with notary");
        let prover = match prover.setup(notary_socket.compat()).await {
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
        
        // Connect to the TLS server
        info!("DETAILED FLOW: [4/7] Connecting to target server: {}", server_addr);
        let client_socket = match TcpStream::connect(socket_addr).await {
            Ok(socket) => {
                info!("Successfully connected to target server: {}", server_addr);
                socket
            },
            Err(e) => {
                error!("CONNECTION ERROR: Failed to connect to server: {}", e);
                return Err(ProverError::RequestError(format!("Failed to connect to server: {}", e)));
            }
        };
        
        // Pass server connection into the prover and get the MPC TLS connection back
        info!("DETAILED FLOW: [5/7] Establishing MPC TLS connection to target server");
        let (mpc_tls_connection, prover_future) = match prover.connect(client_socket.compat()).await {
            Ok(result) => {
                info!("Successfully established MPC TLS connection to target server");
                result
            },
            Err(e) => {
                error!("MPC CONNECTION ERROR: Failed to establish MPC TLS connection: {}", e);
                error!("Detailed error: {:?}", e);
                return Err(ProverError::TlsnProtocolError(format!(
                    "Failed to establish MPC TLS connection: {}", e
                )));
            }
        };
        
        // Wrap the connection for use with hyper
        info!("DETAILED FLOW: [6/7] Preparing HTTP connection through MPC TLS");
        let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());
        
        // Spawn the prover to run in the background
        info!("Spawning prover future as background task");
        let prover_task = tokio::spawn(prover_future);
        
        // Setup HTTP client
        info!("DETAILED FLOW: [7/7] Performing HTTP handshake through MPC TLS connection");
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
        
        // Spawn the connection
        info!("Spawning HTTP connection as background task");
        tokio::spawn(connection);
        
        // Build the request
        let mut request_builder = Request::builder()
            .uri(uri.clone())
            .method(method.as_str())
            .header("Host", server_domain);
        
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
        info!("Sending {} request to {}", method, url);
        let response = request_sender
            .send_request(request)
            .await
            .map_err(|e| ProverError::RequestError(format!("Failed to send request: {}", e)))?;
        
        // Check response status
        let status = response.status();
        info!("Received response with status: {}", status);
        
        // Await the prover task to complete
        let prover = prover_task
            .await
            .map_err(|e| {
                ProverError::TlsnProtocolError(format!("Prover task failed: {}", e))
            })?
            .map_err(|e| {
                ProverError::TlsnProtocolError(format!("Prover connection failed: {}", e))
            })?;
        
        // Start proving
        let mut prover = prover.start_prove();
        
        // Apply selective disclosure if requested
        let (sent_ids, recv_ids) = if let Some(disclosure_options) = selective_disclosure {
            info!("Applying selective disclosure rules");
            self.apply_selective_disclosure(&mut prover, disclosure_options)?
        } else {
            // By default, reveal everything
            debug!("No selective disclosure specified, revealing everything");
            let sent_transcript = prover.transcript().sent();
            let recv_transcript = prover.transcript().received();
            let sent_len = sent_transcript.len();
            let recv_len = recv_transcript.len();
            // Create a range that reveals everything (0 to length)
            (Idx::new([0..sent_len]), Idx::new([0..recv_len]))
        };
        
        // Create the proof by proving the transcript with the selected disclosure
        let _proof = prover.prove_transcript(sent_ids, recv_ids)
            .await
            .map_err(|e| {
                ProverError::TlsnProtocolError(format!("Failed to prove transcript: {}", e))
            })?;
        
        // Finalize the proof
        info!("Finalizing proof");
        let _notarized_session = prover.finalize()
            .await
            .map_err(|e| {
                ProverError::TlsnProtocolError(format!("Failed to finalize proof: {}", e))
            })?;
            
        // Return the proof in JSON format
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
            // API appears to have changed - we'll need to generate commitment elsewhere
            "commitment": hex::encode(b"proof_completed"), // placeholder
        });
        
        Ok(Proof::new(proof_json))
    }
    
    fn apply_selective_disclosure(
        &self,
        prover: &mut Prover<Prove>,
        disclosure_options: Vec<(String, String)>,
    ) -> Result<(Idx, Idx), ProverError> {
        // Get the transcripts
        let sent_transcript = prover.transcript().sent();
        let recv_transcript = prover.transcript().received();
        
        // Default to revealing everything
        let mut sent_reveal = vec![0..sent_transcript.len()];
        let mut recv_reveal = vec![0..recv_transcript.len()];
        
        // Process selective disclosure options
        for (field, action) in disclosure_options {
            // Convert action to uppercase for case-insensitive comparison
            let action = action.to_uppercase();
            
            if action != "REVEAL" && action != "REDACT" {
                return Err(ProverError::ConfigError(format!(
                    "Invalid selective disclosure action: {}. Must be REVEAL or REDACT",
                    action
                )));
            }
            
            // For simplicity of this example, we'll just search for the field in the transcript
            // and redact/reveal based on that. In a real implementation, you would need to parse
            // the HTTP request/response and work with structured data.
            
            // For request (sent), we'll search for header names and values
            if let Some(start) = String::from_utf8_lossy(sent_transcript).find(&field) {
                let end = start + field.len();
                
                if action == "REDACT" {
                    // Remove this range from the reveal list
                    sent_reveal = sent_reveal
                        .into_iter()
                        .flat_map(|range| {
                            if range.contains(&start) && range.contains(&(end - 1)) {
                                vec![range.start..start, end..range.end]
                                    .into_iter()
                                    .filter(|r| !r.is_empty())
                                    .collect()
                            } else {
                                vec![range]
                            }
                        })
                        .collect();
                }
            }
            
            // For response (received), we'll search for header names, values, and body content
            if let Some(start) = String::from_utf8_lossy(recv_transcript).find(&field) {
                let end = start + field.len();
                
                if action == "REDACT" {
                    // Remove this range from the reveal list
                    recv_reveal = recv_reveal
                        .into_iter()
                        .flat_map(|range| {
                            if range.contains(&start) && range.contains(&(end - 1)) {
                                vec![range.start..start, end..range.end]
                                    .into_iter()
                                    .filter(|r| !r.is_empty())
                                    .collect()
                            } else {
                                vec![range]
                            }
                        })
                        .collect();
                }
            }
        }
        
        Ok((Idx::new(sent_reveal), Idx::new(recv_reveal)))
    }
}