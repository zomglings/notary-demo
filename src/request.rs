use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use reqwest::{Client, Method, header::{HeaderMap, HeaderName, HeaderValue}};

/// Make an HTTP request
pub async fn make_request(
    url: &str,
    method_str: &str,
    headers: HashMap<String, String>,
    body: Option<String>,
    outfile: Option<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    // Create HTTP client
    let client = Client::new();
    
    // Parse method
    let method = match method_str.to_uppercase().as_str() {
        "GET" => Method::GET,
        "POST" => Method::POST,
        "PUT" => Method::PUT,
        "DELETE" => Method::DELETE,
        "HEAD" => Method::HEAD,
        "OPTIONS" => Method::OPTIONS,
        "PATCH" => Method::PATCH,
        other => return Err(format!("Unsupported HTTP method: {}", other).into()),
    };
    
    // Create request
    let mut request_builder = client.request(method, url);
    
    // Add headers
    let mut header_map = HeaderMap::new();
    for (key, value) in headers {
        let header_name = HeaderName::from_bytes(key.as_bytes())?;
        let header_value = HeaderValue::from_str(&value)?;
        header_map.insert(header_name, header_value);
    }
    request_builder = request_builder.headers(header_map);
    
    // Add body if present
    if let Some(body_content) = body {
        request_builder = request_builder.body(body_content);
    }
    
    // Send request
    println!("Sending HTTP request to {}...", url);
    let response = request_builder.send().await?;
    
    // Get response details
    let status = response.status();
    let headers = response.headers().clone();
    
    // Print status and headers
    println!("Response status: {} {}", status.as_u16(), status.canonical_reason().unwrap_or(""));
    println!("Response headers:");
    for (name, value) in headers.iter() {
        println!("  {}: {}", name, value.to_str().unwrap_or("<binary>"));
    }
    
    // Get response body
    let body_bytes = response.bytes().await?;
    
    // Handle body output
    if let Some(output_path) = outfile {
        // Save to file
        let mut file = File::create(output_path.clone())?;
        file.write_all(&body_bytes)?;
        println!("Response body saved to: {}", output_path.display());
    } else {
        // Print to console
        match String::from_utf8(body_bytes.to_vec()) {
            Ok(body_text) => println!("\nResponse body:\n{}", body_text),
            Err(_) => println!("Response body is binary data ({} bytes)", body_bytes.len()),
        }
    }
    
    Ok(())
}
