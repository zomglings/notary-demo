mod prover;
mod cli;
mod error;

use clap::Parser;
use cli::{Cli, Commands};
use error::ProverError;
use hyper::StatusCode;
use log::info;
use prover::TlsnProver;
use std::process;
use eyre::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command-line arguments
    let cli = Cli::parse();
    
    // Initialize logging based on verbosity level
    let log_level = match cli.verbose {
        0 => env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
        1 => env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "debug"),
        _ => env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "trace"),
    };
    
    env_logger::Builder::from_env(log_level).init();
    
    info!("TLSNotary Prover v{}", env!("CARGO_PKG_VERSION"));
    
    match cli.command {
        Commands::Notarize { 
            url, 
            method, 
            headers, 
            body, 
            notary_host, 
            notary_port,
            selective_disclosure, 
            output_file 
        } => {
            // Create the prover client
            let mut prover = TlsnProver::new(notary_host, notary_port);
            
            // Execute notarization request
            let result = prover.notarize(
                url, 
                method, 
                headers, 
                body, 
                selective_disclosure
            ).await;
            
            match result {
                Ok(proof) => {
                    if let Some(output_path) = output_file {
                        // Write proof to file
                        match std::fs::write(output_path.clone(), proof.to_string()) {
                            Ok(_) => {
                                println!("✅ Notarization succeeded! Proof written to {}", output_path);
                            }
                            Err(e) => {
                                eprintln!("✅ Notarization succeeded but failed to write to file: {}", e);
                                println!("{}", proof);
                                process::exit(1);
                            }
                        }
                    } else {
                        // Print proof to stdout
                        println!("✅ Notarization succeeded!");
                        println!("{}", proof);
                    }
                }
                Err(e) => {
                    eprintln!("❌ Notarization failed: {}", e);
                    match e {
                        ProverError::TlsnConnectionError(_) => process::exit(2),
                        ProverError::TlsnProtocolError(_) => process::exit(3),
                        ProverError::RequestError(_) => process::exit(4),
                        ProverError::NotaryError(status) => {
                            if status == StatusCode::UNAUTHORIZED {
                                process::exit(5);
                            } else {
                                process::exit(6);
                            }
                        }
                        _ => process::exit(1),
                    }
                }
            }
        }
    }
    
    Ok(())
}
