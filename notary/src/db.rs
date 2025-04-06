use chrono::{DateTime, Utc};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OpenFlags};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("Failed to execute SQLite operation: {0}")]
    SqliteError(#[from] rusqlite::Error),
    
    #[error("Failed to serialize or deserialize JSON: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("Proof with ID {0} not found")]
    #[allow(dead_code)]
    ProofNotFound(String),
    
    #[error("Invalid date format in database: {0}")]
    InvalidDateFormat(String),

    #[error("Connection pool error: {0}")]
    PoolError(#[from] r2d2::Error),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NotarizedProof {
    pub id: String,
    pub tls_domain: String,
    pub proof_json: String,
    pub created_at: DateTime<Utc>,
}

pub struct Database {
    pool: Pool<SqliteConnectionManager>,
}

impl Database {
    pub fn new(db_path: &str) -> Result<Self, DatabaseError> {
        let manager = if db_path == ":memory:" {
            // For in-memory databases used in testing
            SqliteConnectionManager::memory()
        } else {
            // For persistent databases, use WAL mode with normal sync
            let manager = SqliteConnectionManager::file(db_path)
                .with_flags(OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE);
            manager
        };
        
        let pool = Pool::builder()
            .max_size(10) // Maximum number of connections in the pool
            .build(manager)?;
        
        // Initialize the database schema
        let conn = pool.get()?;
        
        // Enable WAL mode and normal sync on persistent connections
        if db_path != ":memory:" {
            conn.pragma_update(None, "journal_mode", "WAL")?;
            conn.pragma_update(None, "synchronous", "NORMAL")?;
        }
        
        // Create the table if it doesn't exist
        conn.execute(
            "CREATE TABLE IF NOT EXISTS notarized_proofs (
                id TEXT PRIMARY KEY,
                tls_domain TEXT NOT NULL,
                proof_json TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;
        
        Ok(Self { pool })
    }
    
    #[allow(dead_code)]
    pub fn insert_proof(&self, tls_domain: &str, proof_json: &str) -> Result<String, DatabaseError> {
        let conn = self.pool.get()?;
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        
        conn.execute(
            "INSERT INTO notarized_proofs (id, tls_domain, proof_json, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![id, tls_domain, proof_json, now.to_rfc3339()],
        )?;
        
        Ok(id)
    }
    
    #[allow(dead_code)]
    pub fn get_proof_by_id(&self, id: &str) -> Result<NotarizedProof, DatabaseError> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT id, tls_domain, proof_json, created_at FROM notarized_proofs WHERE id = ?1",
        )?;
        
        let proof = stmt.query_row(params![id], |row| {
            let id: String = row.get(0)?;
            let tls_domain: String = row.get(1)?;
            let proof_json: String = row.get(2)?;
            let created_at_str: String = row.get(3)?;
            
            Ok((id, tls_domain, proof_json, created_at_str))
        });
        
        match proof {
            Ok((id, tls_domain, proof_json, created_at_str)) => {
                let created_at = DateTime::parse_from_rfc3339(&created_at_str)
                    .map_err(|e| DatabaseError::InvalidDateFormat(e.to_string()))?
                    .with_timezone(&Utc);
                
                Ok(NotarizedProof {
                    id,
                    tls_domain,
                    proof_json,
                    created_at,
                })
            },
            Err(rusqlite::Error::QueryReturnedNoRows) => Err(DatabaseError::ProofNotFound(id.to_string())),
            Err(e) => Err(DatabaseError::SqliteError(e)),
        }
    }
    
    pub fn list_all_proofs(&self) -> Result<Vec<NotarizedProof>, DatabaseError> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT id, tls_domain, proof_json, created_at FROM notarized_proofs ORDER BY created_at DESC",
        )?;
        
        let rows = stmt.query_map([], |row| {
            let id: String = row.get(0)?;
            let tls_domain: String = row.get(1)?;
            let proof_json: String = row.get(2)?;
            let created_at_str: String = row.get(3)?;
            
            Ok((id, tls_domain, proof_json, created_at_str))
        })?;
        
        let mut proofs = Vec::new();
        for row_result in rows {
            let (id, tls_domain, proof_json, created_at_str) = row_result?;
            
            let created_at = DateTime::parse_from_rfc3339(&created_at_str)
                .map_err(|e| DatabaseError::InvalidDateFormat(e.to_string()))?
                .with_timezone(&Utc);
            
            proofs.push(NotarizedProof {
                id,
                tls_domain,
                proof_json,
                created_at,
            });
        }
        
        Ok(proofs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    
    #[test]
    fn test_database_crud_operations() -> Result<(), DatabaseError> {
        // Create in-memory database for testing
        let db = Database::new(":memory:")?;
        
        // Test insertion
        let test_domain = "api.example.com";
        let test_proof = r#"{"sample": "proof data"}"#;
        let id = db.insert_proof(test_domain, test_proof)?;
        
        // Test retrieval
        let proof = db.get_proof_by_id(&id)?;
        assert_eq!(proof.id, id);
        assert_eq!(proof.tls_domain, test_domain);
        assert_eq!(proof.proof_json, test_proof);
        
        // Test listing
        let all_proofs = db.list_all_proofs()?;
        assert_eq!(all_proofs.len(), 1);
        assert_eq!(all_proofs[0].id, id);
        
        Ok(())
    }
    
    #[test]
    fn test_multiple_insertions_and_ordering() -> Result<(), DatabaseError> {
        let db = Database::new(":memory:")?;
        
        // Insert multiple proofs with different domains
        let domains = ["api1.example.com", "api2.example.com", "api3.example.com"];
        let mut ids = Vec::new();
        
        for (i, domain) in domains.iter().enumerate() {
            let proof_json = json!({
                "index": i,
                "sample": format!("Test data for {}", domain)
            }).to_string();
            
            let id = db.insert_proof(domain, &proof_json)?;
            ids.push(id);
        }
        
        // Verify all proofs were inserted
        let all_proofs = db.list_all_proofs()?;
        assert_eq!(all_proofs.len(), domains.len());
        
        // Verify ordering (most recent first)
        for (i, proof) in all_proofs.iter().enumerate() {
            let expected_domain = domains[domains.len() - 1 - i];
            assert_eq!(proof.tls_domain, expected_domain);
        }
        
        Ok(())
    }
    
    #[test]
    fn test_proof_not_found() {
        let db = Database::new(":memory:").unwrap();
        
        // Try to retrieve a non-existent proof
        let result = db.get_proof_by_id("non-existent-uuid");
        
        // Verify it returns ProofNotFound error
        match result {
            Err(DatabaseError::ProofNotFound(id)) => {
                assert_eq!(id, "non-existent-uuid");
            },
            _ => panic!("Expected ProofNotFound error, got {:?}", result),
        }
    }
} 