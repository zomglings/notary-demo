use crate::db::{Database, DatabaseError};
use crate::tlsn_service::{MAX_SENT_DATA, MAX_RECV_DATA, MPC_TIMEOUT_SECS, TLSN_VERSION, SUPPORTED_FEATURES};
use actix_cors::Cors;
use actix_web::{
    dev::Server,
    get, post,
    web::{self, Data, Json, Path},
    App, HttpResponse, HttpServer, Responder, middleware::Logger,
};
use serde::{Deserialize, Serialize};
use std::net::TcpListener;
use std::sync::Arc;

pub struct ApiServer {
    server: Server,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofIdResponse {
    id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofListItem {
    id: String,
    tls_domain: String,
    created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationRequest {
    proof_uuid: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationResponse {
    is_valid: bool,
    message: String,
    disclosed_fields: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MpcParams {
    max_sent_data: usize,
    max_recv_data: usize,
    timeout_seconds: u64,
    version: String,
    supported_features: Vec<String>,
}

impl ApiServer {
    pub async fn new(
        listener: TcpListener,
        database: Database,
    ) -> Result<Self, std::io::Error> {
        let db = Data::new(Arc::new(database));

        let server = HttpServer::new(move || {
            // Set up CORS
            let cors = Cors::default()
                .allow_any_origin()
                .allow_any_method()
                .allow_any_header()
                .max_age(3600);

            App::new()
                .wrap(cors)
                .wrap(Logger::new("%a '%r' %s %b '%{Referer}i' '%{User-Agent}i' %T"))
                .app_data(db.clone())
                .service(get_all_proofs)
                .service(get_proof_by_id)
                .service(verify_proof)
                .service(get_mpc_params)
        })
        .listen(listener)?
        .run();

        Ok(Self { server })
    }

    pub async fn run_until_stopped(self) -> Result<(), std::io::Error> {
        self.server.await
    }
}


#[get("/proofs")]
async fn get_all_proofs(db: web::Data<Arc<Database>>) -> impl Responder {
    let result = db.list_all_proofs();

    match result {
        Ok(proofs) => {
            let proof_items: Vec<ProofListItem> = proofs
                .into_iter()
                .map(|p| ProofListItem {
                    id: p.id,
                    tls_domain: p.tls_domain,
                    created_at: p.created_at.to_rfc3339(),
                })
                .collect();

            HttpResponse::Ok().json(proof_items)
        }
        Err(e) => {
            log::error!("Failed to retrieve proofs: {:?}", e);
            HttpResponse::InternalServerError().body(format!("Failed to retrieve proofs: {}", e))
        }
    }
}

#[get("/proofs/{uuid}")]
async fn get_proof_by_id(
    db: web::Data<Arc<Database>>,
    path: Path<String>,
) -> impl Responder {
    let uuid = path.into_inner();
    let result = db.get_proof_by_id(&uuid);

    match result {
        Ok(proof) => HttpResponse::Ok().json(proof),
        Err(DatabaseError::ProofNotFound(_)) => {
            HttpResponse::NotFound().body(format!("Proof with ID {} not found", uuid))
        }
        Err(e) => {
            log::error!("Failed to retrieve proof: {:?}", e);
            HttpResponse::InternalServerError().body(format!("Failed to retrieve proof: {}", e))
        }
    }
}

#[post("/verifier/verify")]
async fn verify_proof(
    db: web::Data<Arc<Database>>,
    request: Json<VerificationRequest>,
) -> impl Responder {
    // In a real implementation, this would use tlsn-verifier to cryptographically verify the proof
    // For now, we'll just check if the proof exists and return a mock response
    
    let result = db.get_proof_by_id(&request.proof_uuid);
    
    match result {
        Ok(proof) => {
            // Mock verification - parse the JSON to extract disclosed fields
            let disclosed_fields = match serde_json::from_str::<serde_json::Value>(&proof.proof_json) {
                Ok(value) => Some(value),
                Err(_) => None,
            };
            
            HttpResponse::Ok().json(VerificationResponse {
                is_valid: true,
                message: "Proof verification successful".to_string(),
                disclosed_fields,
            })
        }
        Err(DatabaseError::ProofNotFound(_)) => {
            HttpResponse::NotFound().body(format!("Proof with ID {} not found", request.proof_uuid))
        }
        Err(e) => {
            log::error!("Failed to verify proof: {:?}", e);
            HttpResponse::InternalServerError().body(format!("Failed to verify proof: {}", e))
        }
    }
}

#[get("/api/mpcparams")]
async fn get_mpc_params() -> impl Responder {
    // Convert supported_features from &[&str] to Vec<String>
    let features: Vec<String> = SUPPORTED_FEATURES.iter()
        .map(|s| s.to_string())
        .collect();
        
    let params = MpcParams {
        max_sent_data: MAX_SENT_DATA,
        max_recv_data: MAX_RECV_DATA,
        timeout_seconds: MPC_TIMEOUT_SECS,
        version: TLSN_VERSION.to_string(),
        supported_features: features,
    };
    
    HttpResponse::Ok().json(params)
}

// Helper function to convert from DatabaseError to HttpResponse
impl From<DatabaseError> for HttpResponse {
    fn from(error: DatabaseError) -> Self {
        match error {
            DatabaseError::ProofNotFound(id) => {
                HttpResponse::NotFound().body(format!("Proof with ID {} not found", id))
            }
            _ => HttpResponse::InternalServerError().body(format!("Database error: {}", error)),
        }
    }
} 