use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::Utc;

use crate::db::Database;

// Status codes for notarization process
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NotarizationStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
}

// Details about a notarization session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotarizationSession {
    pub id: String,
    pub status: NotarizationStatus,
    pub url: String,
    pub start_time: SystemTime,
    pub end_time: Option<SystemTime>,
    pub error: Option<String>,
    pub proof_id: Option<String>,
}

// Request to start a notarization
#[derive(Debug, Deserialize)]
pub struct NotarizeRequest {
    pub url: String,
    pub method: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub body: Option<String>,
}

// Response for a notarization request
#[derive(Debug, Serialize)]
pub struct NotarizeResponse {
    pub session_id: String,
    pub status: NotarizationStatus,
    pub message: String,
}

// Response for a notarization status check
#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub session_id: String,
    pub status: NotarizationStatus,
    pub proof_id: Option<String>,
    pub error: Option<String>,
}

// Response for a proof request
#[derive(Debug, Serialize)]
pub struct ProofResponse {
    pub proof_id: String,
    pub tls_domain: String,
    pub created_at: String,
    pub verified: bool,
    pub proof: String,
}

// Sessions store
#[derive(Clone)]
pub struct SessionStore {
    sessions: Arc<Mutex<HashMap<String, NotarizationSession>>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn create_session(&self, url: String) -> String {
        let session_id = Uuid::new_v4().to_string();
        let session = NotarizationSession {
            id: session_id.clone(),
            status: NotarizationStatus::Pending,
            url,
            start_time: SystemTime::now(),
            end_time: None,
            error: None,
            proof_id: None,
        };

        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(session_id.clone(), session);
        session_id
    }

    pub fn get_session(&self, session_id: &str) -> Option<NotarizationSession> {
        let sessions = self.sessions.lock().unwrap();
        sessions.get(session_id).cloned()
    }

    pub fn update_session(&self, session: NotarizationSession) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(session.id.clone(), session);
    }
}

// TLSNotary service
pub struct TlsnService {
    port: u16,
    host: String,
    db: Database,
    sessions: SessionStore,
}

impl TlsnService {
    pub fn new(host: String, port: u16, db: Database) -> Self {
        Self {
            port,
            host,
            db,
            sessions: SessionStore::new(),
        }
    }

    pub async fn run(self) -> std::io::Result<()> {
        let sessions = self.sessions.clone();
        let db = web::Data::new(self.db);
        
        let addr = format!("{}:{}", self.host, self.port);
        let socket_addr: SocketAddr = addr.parse().unwrap();
        
        log::info!("Starting TLSNotary service on {}", addr);
        
        let server = HttpServer::new(move || {
            App::new()
                .app_data(web::Data::new(sessions.clone()))
                .app_data(db.clone())
                .route("/notarize", web::post().to(notarize))
                .route("/status/{session_id}", web::get().to(check_status))
                .route("/proof/{proof_id}", web::get().to(get_proof))
        })
        .bind(socket_addr)?
        .run();
        
        server.await
    }
}

// Handler for /notarize
async fn notarize(
    req: web::Json<NotarizeRequest>,
    sessions: web::Data<SessionStore>,
    db: web::Data<Database>,
) -> impl Responder {
    let url = req.url.clone();
    if !url.starts_with("https://") {
        return HttpResponse::BadRequest().json(NotarizeResponse {
            session_id: "".to_string(),
            status: NotarizationStatus::Failed,
            message: "Only HTTPS URLs are supported".to_string(),
        });
    }

    let session_id = sessions.create_session(url.clone());
    let mut session = sessions.get_session(&session_id).unwrap();
    session.status = NotarizationStatus::InProgress;
    sessions.update_session(session.clone());

    // Spawn a task to perform the notarization
    let sessions_clone = sessions.clone();
    let db_clone = db.clone();
    let method = req.method.clone().unwrap_or_else(|| "GET".to_string());
    let headers = req.headers.clone().unwrap_or_default();
    let body = req.body.clone();
    let session_id_clone = session_id.clone();

    tokio::spawn(async move {
        let result = perform_notarization(
            &url, 
            &method, 
            &headers, 
            body.as_deref(),
        ).await;

        let mut session = sessions_clone.get_session(&session_id_clone).unwrap();
        session.end_time = Some(SystemTime::now());

        match result {
            Ok(proof) => {
                // Extract domain from URL
                let domain = extract_domain_from_url(&url).unwrap_or("unknown".to_string());
                
                // Create a proof record in the database
                let proof_json = serde_json::to_string(&proof).unwrap();
                match db_clone.insert_proof(&domain, &proof_json) {
                    Ok(proof_id) => {
                        session.status = NotarizationStatus::Completed;
                        session.proof_id = Some(proof_id);
                    }
                    Err(e) => {
                        session.status = NotarizationStatus::Failed;
                        session.error = Some(format!("Failed to store proof: {}", e));
                    }
                }
            }
            Err(e) => {
                session.status = NotarizationStatus::Failed;
                session.error = Some(format!("Notarization failed: {}", e));
            }
        }

        sessions_clone.update_session(session);
    });

    HttpResponse::Accepted().json(NotarizeResponse {
        session_id,
        status: NotarizationStatus::InProgress,
        message: "Notarization started".to_string(),
    })
}

// Handler for /status/{session_id}
async fn check_status(
    path: web::Path<String>,
    sessions: web::Data<SessionStore>,
) -> impl Responder {
    let session_id = path.into_inner();
    
    match sessions.get_session(&session_id) {
        Some(session) => {
            HttpResponse::Ok().json(StatusResponse {
                session_id: session.id,
                status: session.status,
                proof_id: session.proof_id,
                error: session.error,
            })
        }
        None => {
            HttpResponse::NotFound().json(StatusResponse {
                session_id: session_id.clone(),
                status: NotarizationStatus::Failed,
                proof_id: None,
                error: Some("Session not found".to_string()),
            })
        }
    }
}

// Handler for /proof/{proof_id}
async fn get_proof(
    path: web::Path<String>,
    db: web::Data<Database>,
) -> impl Responder {
    let proof_id = path.into_inner();
    
    match db.get_proof_by_id(&proof_id) {
        Ok(proof) => {
            // TODO: Perform actual verification using TLSNotary verifier
            // This is a placeholder for now
            let verified = true;
            
            HttpResponse::Ok().json(ProofResponse {
                proof_id: proof.id,
                tls_domain: proof.tls_domain,
                created_at: proof.created_at.to_rfc3339(),
                verified,
                proof: proof.proof_json,
            })
        }
        Err(_) => {
            HttpResponse::NotFound().json(serde_json::json!({
                "error": format!("Proof with ID '{}' not found", proof_id)
            }))
        }
    }
}

// Helper function to extract domain from URL
fn extract_domain_from_url(url: &str) -> Option<String> {
    url.split("://")
        .nth(1)
        .and_then(|s| s.split('/').next())
        .map(|s| s.to_string())
}

// Perform the actual notarization using TLSNotary
async fn perform_notarization(
    url: &str,
    method: &str,
    headers: &HashMap<String, String>,
    body: Option<&str>,
) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
    // This is a simplified implementation that would need to be expanded
    // with proper TLSNotary integration following the example at:
    // https://github.com/tlsnotary/tlsn/tree/main/crates/examples/interactive
    
    // For now, we'll just simulate a successful notarization
    // In a real implementation, we would use TLSNotary to actually notarize the HTTPS request
    
    // Extract the domain from the URL
    let domain = extract_domain_from_url(url).unwrap_or_else(|| "unknown".to_string());
    
    // Create a placeholder proof
    let proof = serde_json::json!({
        "url": url,
        "method": method,
        "domain": domain,
        "timestamp": Utc::now().to_rfc3339(),
        "success": true,
        "headers": headers,
        "body_provided": body.is_some(),
        "notarized": true,
        "notary_id": Uuid::new_v4().to_string()
    });
    
    Ok(proof)
}