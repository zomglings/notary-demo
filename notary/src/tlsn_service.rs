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
const MPC_TIMEOUT_SECS: u64 = 60;

// Maximum transcript sizes
const MAX_SENT_DATA: usize = 1 << 16; // 64KB
const MAX_RECV_DATA: usize = 1 << 20; // 1MB

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
    
    // Create a protocol config validator with reasonable limits
    let protocol_config_validator = ProtocolConfigValidator::builder()
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        .build()?;
    
    // Configure the verifier with the protocol settings
    let verifier_config = tlsn_verifier::VerifierConfig::builder()
        .protocol_config_validator(protocol_config_validator)
        .build()?;
    
    // Create the verifier instance
    let verifier = Verifier::new(verifier_config);
    
    // Create attestation config
    let att_config = AttestationConfig::builder()
        // We'll not specify signature algorithms for now
        .build()?;
        
    // Execute the notarization protocol with timeout
    let result = timeout(
        Duration::from_secs(MPC_TIMEOUT_SECS),
        verifier.notarize(socket.compat(), &att_config)
    ).await;
    
    // Handle the result
    match result {
        Ok(protocol_result) => {
            match protocol_result {
                Ok(attestation) => {
                    info!("Notarization completed successfully for session {}", session_id);
                    
                    // For now, we'll use a fixed domain since the API might differ
                    // between TLSNotary versions
                    let domain = "notarized.example.com".to_string();
                    
                    // Serialize the attestation for storage
                    let proof_json = serde_json::to_string(&attestation)?;
                    
                    // Store the proof in the database
                    match db.insert_proof(&domain, &proof_json) {
                        Ok(proof_id) => {
                            info!(
                                "Notarization proof stored successfully for session {}, proof ID: {}", 
                                session_id, 
                                proof_id
                            );
                        }
                        Err(e) => {
                            error!("Failed to store proof for session {}: {}", session_id, e);
                            return Err(format!("Failed to store proof: {}", e).into());
                        }
                    }
                }
                Err(e) => {
                    error!("Notarization failed for session {}: {}", session_id, e);
                    return Err(Box::new(e));
                }
            }
        },
        Err(_) => {
            let msg = format!("MPC protocol timed out after {} seconds", MPC_TIMEOUT_SECS);
            error!("Session {}: {}", session_id, msg);
            return Err(msg.into());
        }
    }
    
    Ok(())
}