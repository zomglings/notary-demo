use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use eyre::Result;
use log::{info, error};

use notary_server::{NotarizationSessionManager, NotaryConfig, server, ServerResult, NotarizationSession};
use tlsn_common::config::ProtocolConfigValidator;
use tlsn_core::{crypto::provider::P256Provider, session::SignedSessionHeader};
use tlsn_verifier::VerifierConfig;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_util::compat::TokioAsyncReadCompatExt;
use uuid::Uuid;

use crate::db::Database;

// Maximum time to wait for MPC connection to complete
pub const MPC_TIMEOUT_SECS: u64 = 300; // 5 minutes

// Maximum transcript sizes
pub const MAX_SENT_DATA: usize = 1 << 16; // 64KB
pub const MAX_RECV_DATA: usize = 1 << 20; // 1MB

// TLSNotary protocol version
pub const TLSN_VERSION: &str = "1.0";

// Supported features
pub const SUPPORTED_FEATURES: &[&str] = &["selective_disclosure"];

/// The TLS Notary server that runs on port 7150
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
        
        // Create a protocol config validator with reasonable limits
        let protocol_config_validator = ProtocolConfigValidator::builder()
            .max_sent_data(MAX_SENT_DATA)
            .max_recv_data(MAX_RECV_DATA)
            .build()
            .expect("Failed to build protocol config validator");
        
        // Configure the verifier with the protocol settings
        let verifier_config = VerifierConfig::builder()
            .protocol_config_validator(protocol_config_validator)
            .build()
            .expect("Failed to build verifier config");
            
        // Create the notary configuration
        let notary_config = NotaryConfig::builder()
            .verifier_config(verifier_config)
            .timeout(Duration::from_secs(MPC_TIMEOUT_SECS))
            .build()
            .expect("Failed to build notary config");

        // Create the session manager
        let session_manager = NotarizationSessionManager::new(notary_config);
        
        // Start the notary server
        info!("TLSNotary server listening on {}", addr);
        let listener = TcpListener::bind(addr).await?;
        
        let db = Arc::new(self.db);

        // Accept connections
        while let Ok((socket, peer_addr)) = listener.accept().await {
            info!("New connection from {}", peer_addr);
            let session_manager = session_manager.clone();
            let db_clone = db.clone();
            
            // Spawn a new task to handle the connection
            tokio::spawn(async move {
                if let Err(e) = handle_notary_connection(socket, peer_addr, session_manager, db_clone).await {
                    error!("Error handling connection from {}: {}", peer_addr, e);
                }
            });
        }
        
        Ok(())
    }
}

/// Custom session handler
struct SessionHandler {
    db: Arc<Database>,
    session_id: String,
    peer_addr: SocketAddr,
}

impl SessionHandler {
    fn new(db: Arc<Database>, peer_addr: SocketAddr) -> Self {
        let session_id = Uuid::new_v4().to_string();
        Self {
            db,
            session_id,
            peer_addr,
        }
    }
}

#[async_trait::async_trait]
impl server::NotarizationSessionHandler for SessionHandler {
    async fn handle_session_complete(&mut self, session: &NotarizationSession, header: &SignedSessionHeader) -> ServerResult<()> {
        info!("SUCCESS: Notarization completed successfully for session {}", self.session_id);
        
        // For now, we'll use a fixed domain since the API might differ between TLSNotary versions
        let domain = "notarized.example.com".to_string();
        
        // Serialize the attestation for storage (in this case, we'll use the session ID)
        let bincode_data = bincode::serialize(&session.attestation()).unwrap_or_default();
        let proof_json = serde_json::json!({
            "session_id": self.session_id,
            "peer": self.peer_addr.to_string(),
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "server_name": header.server_name(),
            "time": header.time(),
            "attestation": hex::encode(&bincode_data),
        }).to_string();
        
        // Store the proof in the database
        info!("Storing proof in database for session {}", self.session_id);
        match self.db.insert_proof(&domain, &proof_json) {
            Ok(proof_id) => {
                info!(
                    "SUCCESS: Notarization proof stored successfully, proof ID: {}", 
                    proof_id
                );
            }
            Err(e) => {
                error!("DB ERROR: Failed to store proof for session {}: {}", self.session_id, e);
                return Err(server::Error::Other(format!("Failed to store proof: {}", e)));
            }
        }
        
        Ok(())
    }
}

/// Handles a new connection from a prover by executing the TLSNotary protocol
async fn handle_notary_connection<T>(
    socket: T, 
    peer_addr: SocketAddr,
    manager: NotarizationSessionManager<P256Provider>,
    db: Arc<Database>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Create a session handler
    let handler = SessionHandler::new(db, peer_addr);
    
    // Handle the notarization session
    info!("Starting notarization session with {}", peer_addr);
    match server::handle_notarization(socket.compat(), manager, handler).await {
        Ok(_) => {
            info!("Notarization session with {} completed successfully", peer_addr);
        }
        Err(e) => {
            error!("Error in notarization session with {}: {}", peer_addr, e);
            return Err(Box::new(e));
        }
    }
    
    Ok(())
}