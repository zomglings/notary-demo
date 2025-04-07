use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use reqwest::{Certificate, Client};
use tls_server_fixture::CA_CERT_DER;

// Make a TLS request to the server fixture
pub async fn make_raw_tls_request(
    host: &str,
    port: u16,
    path: &str,
    server_name: &str,
    outfile: Option<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    // Create the URL
    let url = format!("https://{}:{}{}", host, port, path);
    println!("Connecting to {} (using TLS)", url);
    
    // Add the server fixture CA certificate to the client
    let ca_cert = Certificate::from_der(CA_CERT_DER)?;
    
    // Build a client with custom settings
    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .danger_accept_invalid_certs(true)     // Self-signed certificate
        .build()?;
    
    // Create HTTP request
    println!("Sending HTTP request to {}...", url);
    let response = client.get(&url)
        .header("Host", server_name)
        .send()
        .await?;
    
    // Get status code
    let status = response.status();
    println!("Response status: {}", status);
    
    // Get headers
    let headers = response.headers();
    println!("Response headers:");
    for (name, value) in headers.iter() {
        println!("  {}: {}", name, value.to_str().unwrap_or("<binary>"));
    }
    
    // Get response body
    let body = response.bytes().await?;
    
    // Output response body
    if let Some(output_path) = outfile {
        let mut file = File::create(output_path.clone())?;
        file.write_all(&body)?;
        println!("Response saved to: {}", output_path.display());
    } else {
        // Print to console
        match String::from_utf8(body.to_vec()) {
            Ok(body_text) => println!("\nResponse body:\n{}", body_text),
            Err(_) => println!("Response body is binary data ({} bytes)", body.len()),
        }
    }
    
    Ok(())
}