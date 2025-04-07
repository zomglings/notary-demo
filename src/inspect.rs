use std::error::Error;
use std::fs;
use std::path::PathBuf;

use tlsn_core::{attestation::Attestation, Secrets};
use tlsn_formats::http::HttpTranscript;
use tlsn_formats::spansy::Spanned;

/// Inspect a TLSNotary attestation (and optionally secrets) file
pub async fn inspect_attestation(
    attestation_path: PathBuf,
    secrets_path: Option<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    println!("Inspecting attestation file: {}", attestation_path.display());
    
    // Read and deserialize the attestation
    let attestation_data = fs::read(&attestation_path)?;
    let attestation: Attestation = bincode::deserialize(&attestation_data)?;
    
    // Display attestation info
    println!("\n=== Attestation Info ===");
    println!("Attestation ID: {:?}", attestation.header.id);
    println!("Attestation version: {:?}", attestation.header.version);
    println!("Merkle root: {:?}", attestation.header.root);
    println!("Signature: {}", hex::encode(&attestation.signature.data));
    println!("Signature algorithm: {}", attestation.signature.alg);
    
    // If secrets file is provided, inspect that too
    if let Some(secrets_path) = secrets_path {
        println!("\nInspecting secrets file: {}", secrets_path.display());
        
        // Read and deserialize the secrets
        let secrets_data = fs::read(&secrets_path)?;
        let secrets: Secrets = bincode::deserialize(&secrets_data)?;
        
        println!("\n=== Secrets Info ===");
        
        // Extract transcript
        let transcript = secrets.transcript();
        let sent_len = transcript.sent().len();
        let recv_len = transcript.received().len();
        
        println!("Transcript size: {} bytes sent, {} bytes received", sent_len, recv_len);
        
        if sent_len == 0 && recv_len == 0 {
            println!("No transcript data available");
            return Ok(());
        }
        
        // Try to parse the HTTP transcript
        println!("\n=== HTTP Transcript ===");
        match HttpTranscript::parse(transcript) {
            Ok(http_transcript) => {
                // Display requests
                println!("\n--- Requests ---");
                for (i, request) in http_transcript.requests.iter().enumerate() {
                    println!("Request #{}", i + 1);
                    println!("  Method: {:?}", request.request.method);
                    println!("  Path: {:?}", request.request.target);
                    
                    println!("  Headers:");
                    for header in &request.headers {
                        println!("    {:?}: {:?}", header.name, header.value);
                    }
                    
                    if let Some(body) = &request.body {
                        let body_bytes = body.content.span().as_bytes();
                        match String::from_utf8(body_bytes.to_vec()) {
                            Ok(body_text) => println!("  Body: {}", body_text),
                            Err(_) => println!("  Body: <binary> ({} bytes)", body_bytes.len()),
                        }
                    } else {
                        println!("  Body: <none>");
                    }
                }
                
                // Display responses
                println!("\n--- Responses ---");
                for (i, response) in http_transcript.responses.iter().enumerate() {
                    println!("Response #{}", i + 1);
                    println!("  Status: {:?}", response.status);
                    
                    println!("  Headers:");
                    for header in &response.headers {
                        println!("    {:?}: {:?}", header.name, header.value);
                    }
                    
                    if let Some(body) = &response.body {
                        let body_bytes = body.content.span().as_bytes();
                        match String::from_utf8(body_bytes.to_vec()) {
                            Ok(body_text) => println!("  Body: {}", body_text),
                            Err(_) => println!("  Body: <binary> ({} bytes)", body_bytes.len()),
                        }
                    } else {
                        println!("  Body: <none>");
                    }
                }
            }
            Err(err) => {
                println!("Failed to parse HTTP transcript: {}", err);
                
                // Show raw transcript as a fallback
                println!("\n--- Raw Transcript ---");
                println!("Sent data:");
                let sent_data = String::from_utf8_lossy(transcript.sent());
                println!("{}", sent_data);
                println!("\nReceived data:");
                let recv_data = String::from_utf8_lossy(transcript.received());
                println!("{}", recv_data);
            }
        }
    }
    
    Ok(())
}