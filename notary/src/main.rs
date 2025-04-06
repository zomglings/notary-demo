use notary::api::ApiServer;
use notary::db::Database;
use std::net::TcpListener;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging with a more detailed format
    // Format: time level module message 
    if std::env::var("RUST_LOG").is_err() {
        // Safe as we're just configuring the logger environment variable
        unsafe { std::env::set_var("RUST_LOG", "info"); }
    }
    
    env_logger::builder()
        .format_timestamp(Some(env_logger::TimestampPrecision::Millis))
        .format_module_path(true)
        .init();
    
    log::info!("Logger initialized with HTTP request logging enabled");
    log::info!("Request format: IP 'METHOD /path HTTP/x.x' STATUS BYTES 'REFERER' 'USER-AGENT' TIME");
    
    // Initialize database
    let db_path = "notary_proofs.db";
    
    // Check if database exists and print status
    let db_exists = Path::new(db_path).exists();
    if db_exists {
        log::info!("Using existing database at: {}", db_path);
    } else {
        log::info!("Creating new database at: {}", db_path);
    }
    
    let database = Database::new(db_path)?;
    log::info!("Database initialized successfully!");
    
    // List existing proofs
    let proofs = database.list_all_proofs()?;
    log::info!("Found {} existing notarized proofs", proofs.len());
    
    // Start the API server
    let address = "127.0.0.1:8080";
    log::info!("Starting notary server on: {}", address);
    
    let listener = TcpListener::bind(address)?;
    let server = ApiServer::new(listener, database).await?;
    
    log::info!("Server started successfully. Press Ctrl+C to stop.");
    
    server.run_until_stopped().await?;
    
    Ok(())
}
