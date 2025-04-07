use notary::api::ApiServer;
use notary::cli::{Cli, Commands};
use notary::db::{Database, DatabaseError};
use notary::tlsn_service::TlsnService;
use std::net::TcpListener;
use std::path::Path;
use std::io;
use clap::Parser;

// We need to wrap our error types to make handling easier
type AppResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::main]
async fn main() -> AppResult<()> {
    // Parse command-line arguments directly using clap
    let cli = Cli::parse();
    
    let result = match cli.command {
        Commands::Server { 
            host, 
            api_port,
            notary_port,
            use_custom_mpc,
            database, 
            log_level,
            pretty_logging 
        } => {
            // Initialize logging
            if std::env::var("RUST_LOG").is_err() {
                // Safe as we're just configuring the logger environment variable
                unsafe { std::env::set_var("RUST_LOG", log_level); }
            }
            
            // Configure logger
            if pretty_logging {
                env_logger::Builder::from_default_env()
                    .format_timestamp(Some(env_logger::TimestampPrecision::Millis))
                    .format_module_path(true)
                    .format_target(true)
                    .format_indent(Some(4))
                    .init();
            } else {
                env_logger::Builder::from_default_env()
                    .format_timestamp(Some(env_logger::TimestampPrecision::Millis))
                    .format_module_path(true)
                    .init();
            }
            
            log::info!("Logger initialized with HTTP request logging enabled");
            log::info!("Request format: IP 'METHOD /path HTTP/x.x' STATUS BYTES 'REFERER' 'USER-AGENT' TIME");
            
            // Initialize database
            let db_path = database;
            
            // Check if database exists and print status
            let db_exists = Path::new(&db_path).exists();
            if db_exists {
                log::info!("Using existing database at: {}", db_path);
            } else {
                log::info!("Creating new database at: {}", db_path);
            }
            
            let database = Database::new(&db_path)?;
            log::info!("Database initialized successfully!");
            
            // List existing proofs
            let proofs = database.list_all_proofs()?;
            log::info!("Found {} existing notarized proofs", proofs.len());
            
            // Start our custom TLSNotary service if using custom MPC
            if use_custom_mpc && notary_port > 0 {
                let notary_host = host.clone();
                let notary_database = database.clone();
                tokio::spawn(async move {
                    let tlsn_service = TlsnService::new(notary_host, notary_port, notary_database);
                    if let Err(e) = tlsn_service.run().await {
                        log::error!("TLSNotary service error: {}", e);
                    }
                });
                log::info!("Custom TLSNotary service started on {}:{}", host, notary_port);
            } else {
                log::info!("Using external notary-server. Make sure it's running on port 7047.");
            }
            
            // Start the API server
            let api_address = format!("{}:{}", host, api_port);
            log::info!("Starting API server on: {}", api_address);
            
            let listener = TcpListener::bind(&api_address)?;
            let server = ApiServer::new(listener, database).await?;
            
            log::info!("Server started successfully. Press Ctrl+C to stop.");
            
            server.run_until_stopped().await
        },
        
        Commands::List { database, format } => {
            // Use map_err to convert DatabaseError to io::Error
            let db = Database::new(&database).map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("Database error: {}", e))
            })?;
            
            // Get all proofs
            let proofs = db.list_all_proofs().map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("Database error: {}", e))
            })?;
            
            if format == "json" {
                // Output as JSON
                let json = serde_json::to_string_pretty(&proofs).map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, format!("JSON error: {}", e))
                })?;
                println!("{}", json);
            } else {
                // Output as text
                println!("Found {} proofs:", proofs.len());
                println!("{:<36} | {:<30} | {:<24}", "UUID", "TLS Domain", "Created At");
                println!("{}", "-".repeat(96));
                
                for proof in proofs {
                    println!("{:<36} | {:<30} | {:<24}", 
                        proof.id, 
                        proof.tls_domain,
                        proof.created_at.to_rfc3339()
                    );
                }
            }
            Ok(())
        },
        
        Commands::Show { proof_id, database, format } => {
            // Initialize database connection
            let db = Database::new(&database).map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("Database error: {}", e))
            })?;
            
            // Get the proof
            match db.get_proof_by_id(&proof_id) {
                Ok(proof) => {
                    if format == "json" {
                        // Output as JSON
                        let json = serde_json::to_string_pretty(&proof).map_err(|e| {
                            io::Error::new(io::ErrorKind::Other, format!("JSON error: {}", e))
                        })?;
                        println!("{}", json);
                    } else {
                        // Output as text
                        println!("Proof details:");
                        println!("UUID:       {}", proof.id);
                        println!("TLS Domain: {}", proof.tls_domain);
                        println!("Created At: {}", proof.created_at.to_rfc3339());
                        println!("Proof JSON:");
                        
                        // Try to pretty-print the JSON
                        match serde_json::from_str::<serde_json::Value>(&proof.proof_json) {
                            Ok(value) => {
                                let pretty = serde_json::to_string_pretty(&value).map_err(|e| {
                                    io::Error::new(io::ErrorKind::Other, format!("JSON error: {}", e))
                                })?;
                                println!("{}", pretty);
                            },
                            Err(_) => {
                                println!("{}", proof.proof_json);
                            }
                        }
                    }
                    Ok(())
                },
                Err(DatabaseError::ProofNotFound(_)) => {
                    eprintln!("Error: Proof with ID '{}' not found", proof_id);
                    std::process::exit(1);
                },
                Err(e) => {
                    Err(io::Error::new(io::ErrorKind::Other, format!("Database error: {}", e)))
                }
            }
        },
        
        Commands::Submit { domain, json, database } => {
            // Initialize database connection
            let db = Database::new(&database).map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("Database error: {}", e))
            })?;
            
            // Insert the proof
            match db.insert_proof(&domain, &json) {
                Ok(id) => {
                    println!("Proof submitted successfully!");
                    println!("UUID: {}", id);
                    Ok(())
                },
                Err(e) => {
                    Err(io::Error::new(io::ErrorKind::Other, format!("Database error: {}", e)))
                }
            }
        }
    };

    // Convert whatever error type we have into a boxed dyn Error
    result.map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
}
