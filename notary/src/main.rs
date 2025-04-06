mod db;

use crate::db::{Database, DatabaseError};
use std::path::Path;

fn main() -> Result<(), DatabaseError> {
    // Initialize database
    let db_path = "notary_proofs.db";
    
    // Check if database exists and print status
    let db_exists = Path::new(db_path).exists();
    if db_exists {
        println!("Using existing database at: {}", db_path);
    } else {
        println!("Creating new database at: {}", db_path);
    }
    
    let db = Database::new(db_path)?;
    println!("Database initialized successfully!");
    
    // List existing proofs
    let proofs = db.list_all_proofs()?;
    println!("Found {} existing notarized proofs", proofs.len());
    
    for proof in proofs {
        println!("ID: {}, Domain: {}, Created: {}", 
                proof.id, 
                proof.tls_domain, 
                proof.created_at);
    }
    
    Ok(())
}
