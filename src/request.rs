use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use reqwest::{Client, Method, header::{HeaderMap, HeaderName, HeaderValue}};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use url::Url;

/// Make an HTTP request
pub async fn make_request(
    url: &str,
    method_str: &str,
    headers: HashMap<String, String>,
    body: Option<String>,
    outfile: Option<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    // Parse URL
    let parsed_url = Url::parse(url)?;
    let is_http09 = headers.contains_key("X-Use-HTTP09");
    
    if is_http09 {
        // Use raw TCP for HTTP/0.9
        return make_http09_request(parsed_url, method_str, headers, body, outfile).await;
    }
    
    // Use reqwest for normal HTTP requests
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
        if key.starts_with("X-") {
            // Skip special headers
            continue;
        }
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

/// Make an HTTP/0.9 request using raw TCP
async fn make_http09_request(
    url: Url,
    method_str: &str,
    headers: HashMap<String, String>,
    body: Option<String>,
    outfile: Option<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    // HTTP/0.9 only supports GET
    if method_str != "GET" && method_str != "POST" {
        println!("Warning: HTTP/0.9 only supports GET, but will try to use {}", method_str);
    }
    
    // Get host and port
    let host = url.host_str().ok_or("Invalid URL: missing host")?;
    let port = url.port().unwrap_or(80);
    let addr = format!("{}:{}", host, port);
    
    println!("Connecting to {} using HTTP/0.9...", addr);
    
    // Connect to the server
    let mut stream = TcpStream::connect(addr).await?;
    
    // Prepare the HTTP/0.9 request
    // Format: "GET /path\r\n"
    let path = url.path();
    let mut request = format!("{} {}\r\n", method_str, path);
    
    // Add headers if any
    for (key, value) in &headers {
        if !key.starts_with("X-") {  // Skip special X- headers
            request.push_str(&format!("{}: {}\r\n", key, value));
        }
    }
    
    // Add empty line to separate headers from body
    request.push_str("\r\n");
    
    // Add body if present
    if let Some(body_content) = body {
        request.push_str(&body_content);
    }
    
    println!("Sending HTTP/0.9 request:\n{}", request);
    
    // Send the request
    stream.write_all(request.as_bytes()).await?;
    
    // Read the response with timeout
    let mut response_bytes = Vec::new();
    let mut buffer = vec![0u8; 8192]; // 8KB buffer for each read
    
    // Set a read timeout
    let mut attempts = 0;
    let max_attempts = 5;
    
    // Read in a loop until we get data or timeout
    loop {
        match stream.read(&mut buffer).await {
            Ok(0) => {
                // Connection closed by server with no data
                if response_bytes.is_empty() && attempts == 0 {
                    println!("Server closed connection without sending data");
                }
                break;
            }
            Ok(n) => {
                // Got some data
                response_bytes.extend_from_slice(&buffer[..n]);
                println!("Received {} bytes in this chunk", n);
                
                // If we've received enough data or no more is coming, exit
                if n < buffer.len() || attempts >= max_attempts {
                    break;
                }
                
                attempts += 1;
            }
            Err(e) => {
                println!("Error reading from server: {}", e);
                break;
            }
        }
    }
    
    println!("Received {} bytes total from server", response_bytes.len());
    
    // Print the raw hex data for debugging
    println!("Raw response (first 100 bytes):");
    let display_len = std::cmp::min(100, response_bytes.len());
    for i in 0..display_len {
        print!("{:02x} ", response_bytes[i]);
        if (i + 1) % 16 == 0 {
            println!();
        }
    }
    println!();
    
    // Check if response is a valid HTTP response
    let response_str = String::from_utf8_lossy(&response_bytes);
    if response_str.starts_with("HTTP/") {
        println!("Received HTTP response with headers");
        
        // Try to split headers and body
        if let Some(header_end) = response_str.find("\r\n\r\n") {
            let headers = &response_str[..header_end];
            let body = &response_bytes[header_end + 4..];
            
            println!("\nHeaders:\n{}", headers);
            
            // Handle body
            match String::from_utf8(body.to_vec()) {
                Ok(body_text) => println!("\nBody:\n{}", body_text),
                Err(_) => println!("\nBody: <binary data> ({} bytes)", body.len()),
            }
        }
    } else {
        // Treat as raw HTTP/0.9 response (no headers)
        println!("\nRaw HTTP/0.9 response:");
        match String::from_utf8(response_bytes.clone()) {
            Ok(body_text) => println!("{}", body_text),
            Err(_) => println!("<binary data> ({} bytes)", response_bytes.len()),
        }
    }
    
    // Handle file output if requested
    if let Some(output_path) = outfile {
        let mut file = File::create(output_path.clone())?;
        file.write_all(&response_bytes)?;
        println!("Response saved to: {}", output_path.display());
    }
    
    Ok(())
}
