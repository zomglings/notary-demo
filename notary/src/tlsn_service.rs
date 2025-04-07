use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use eyre::Result;
use log::{info, error};
use tlsn_common::config::ProtocolConfigValidator;
use tlsn_core::attestation::AttestationConfig;
use tlsn_verifier::Verifier;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_util::compat::TokioAsyncReadCompatExt;
use uuid::Uuid;

use crate::db::Database;

// Maximum time to wait for MPC connection to complete
pub const MPC_TIMEOUT_SECS: u64 = 300; // Increase from 60 to 300 seconds (5 minutes)

// Maximum transcript sizes
pub const MAX_SENT_DATA: usize = 1 << 16; // 64KB
pub const MAX_RECV_DATA: usize = 1 << 20; // 1MB

// TLSNotary protocol version
pub const TLSN_VERSION: &str = "1.0";

// Supported features
pub const SUPPORTED_FEATURES: &[&str] = &["selective_disclosure"];

/// The TLS Notary MPC service that runs on port 7150
pub struct TlsnService {
    port: u16,
    host: String,
    db: Database,
}

impl TlsnService {
    pub fn new(host: String, port: u16, db: Database) -> Self {
        Self {
            port,
            host,
            db,
        }
    }

    pub async fn run(self) -> std::io::Result<()> {
        let addr = format!("{}:{}", self.host, self.port);
        let addr: SocketAddr = addr.parse().expect("Invalid socket address");
        let listener = TcpListener::bind(addr).await?;
        
        info!("TLSNotary MPC service listening on {}", addr);
        
        let db = Arc::new(self.db);
        
        loop {
            match listener.accept().await {
                Ok((socket, peer_addr)) => {
                    info!("New TLSNotary MPC connection from {}", peer_addr);
                    let db_clone = db.clone();
                    
                    // Spawn a new task to handle the connection
                    tokio::spawn(async move {
                        if let Err(e) = handle_notary_connection(socket, peer_addr, db_clone).await {
                            error!("Error handling notary connection from {}: {}", peer_addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Error accepting connection: {}", e);
                }
            }
        }
    }
}

/// Handles a new connection from a prover by executing the TLSNotary protocol
async fn handle_notary_connection<T>(
    socket: T, 
    peer_addr: SocketAddr,
    db: Arc<Database>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Generate a unique session ID for this connection
    let session_id = Uuid::new_v4().to_string();
    info!("Starting TLSNotary session {} with {}", session_id, peer_addr);
    info!("DETAILED FLOW: [1/5] Initializing TLSNotary session");
    
    // Create a protocol config validator with reasonable limits
    info!("DETAILED FLOW: [2/5] Creating protocol validator with max_sent_data={}, max_recv_data={}", 
           MAX_SENT_DATA, MAX_RECV_DATA);
    let protocol_config_validator = ProtocolConfigValidator::builder()
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        .build()?;
    
    // Configure the verifier with the protocol settings
    info!("DETAILED FLOW: [3/5] Configuring verifier with protocol settings");
    let verifier_config = tlsn_verifier::VerifierConfig::builder()
        .protocol_config_validator(protocol_config_validator)
        .build()?;
    
    // Create the verifier instance
    info!("DETAILED FLOW: [4/5] Creating verifier instance");
    let verifier = Verifier::new(verifier_config);
    
    // Create attestation config
    info!("DETAILED FLOW: [5/5] Creating attestation config and starting notarization process");
    let att_config = AttestationConfig::builder()
        // We'll not specify signature algorithms for now
        .build()?;
        
    // Execute the notarization protocol with timeout
    info!("Starting notarize() with timeout of {} seconds", MPC_TIMEOUT_SECS);
    let result = timeout(
        Duration::from_secs(MPC_TIMEOUT_SECS),
        verifier.notarize(socket.compat(), &att_config)
    ).await;
    
    // Handle the result
    match result {
        Ok(protocol_result) => {
            match protocol_result {
                Ok(attestation) => {
                    info!("SUCCESS: Notarization completed successfully for session {}", session_id);
                    
                    // For now, we'll use a fixed domain since the API might differ
                    // between TLSNotary versions
                    let domain = "notarized.example.com".to_string();
                    
                    // Serialize the attestation for storage
                    info!("Serializing attestation for storage");
                    let proof_json = serde_json::to_string(&attestation)?;
                    
                    // Store the proof in the database
                    info!("Storing proof in database");
                    match db.insert_proof(&domain, &proof_json) {
                        Ok(proof_id) => {
                            info!(
                                "SUCCESS: Notarization proof stored successfully for session {}, proof ID: {}", 
                                session_id, 
                                proof_id
                            );
                        }
                        Err(e) => {
                            error!("DB ERROR: Failed to store proof for session {}: {}", session_id, e);
                            return Err(format!("Failed to store proof: {}", e).into());
                        }
                    }
                }
                Err(e) => {
                    error!("PROTOCOL ERROR: Notarization failed for session {}: {}", session_id, e);
                    error!("Detailed error type: {:?}", e);
                    return Err(Box::new(e));
                }
            }
        },
        Err(e) => {
            // Tokio's timeout error doesn't have is_elapsed method, just always consider it a timeout
            let msg = format!("MPC protocol timed out after {} seconds", MPC_TIMEOUT_SECS);
            error!("TIMEOUT ERROR: Session {}: {}", session_id, msg);
            error!("Error details: {:?}", e);
            return Err(msg.into());
        }
    }
    
    Ok(())
}