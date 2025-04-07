use std::path::PathBuf;
use std::error::Error;
use std::process::{Command, Stdio};
use std::fs;
use std::io::Write;

const NOTARY_SERVER_PATH: &str = "vendor/tlsn/crates/notary/server";
const DEFAULT_BIN_NAME: &str = "notary-server";

/// Builds the notary server from the git submodule
pub async fn build(outfile: PathBuf) -> Result<PathBuf, Box<dyn Error>> {
    // Step 1: Ensure the submodule is initialized
    println!("Checking git submodule...");
    if !PathBuf::from(NOTARY_SERVER_PATH).exists() {
        println!("Initializing git submodule...");
        let status = Command::new("git")
            .args(["submodule", "update", "--init", "--recursive"])
            .status()?;
        
        if !status.success() {
            return Err("Failed to initialize git submodule".into());
        }
    }
    
    // Step 2: Build the notary server
    println!("Building the notary server from source (this may take a moment)...");
    let build_status = Command::new("cargo")
        .current_dir(NOTARY_SERVER_PATH)
        .args(["build", "--release"])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;
        
    if !build_status.success() {
        return Err("Failed to build notary server".into());
    }
    
    // Get the path to the built binary
    let default_bin_path = PathBuf::from(format!("vendor/tlsn/target/release/{}", DEFAULT_BIN_NAME));
    
    // Create parent directories if they don't exist
    if let Some(parent) = outfile.parent() {
        std::fs::create_dir_all(parent)?;
    }
    
    // Copy the binary to the specified output file path
    println!("Copying binary to: {}", outfile.display());
    std::fs::copy(&default_bin_path, &outfile)?;
    
    println!("Notary server built successfully: {}", outfile.display());
    Ok(outfile)
}

/// Runs the notary server
pub async fn serve(
    config_path: Option<PathBuf>, 
    certs_dir: Option<PathBuf>,
    notary_bin: PathBuf
) -> Result<(), Box<dyn Error>> {
    // Check if the binary exists
    if !notary_bin.exists() {
        return Err(format!("Notary server binary not found at: {}", notary_bin.display()).into());
    }

    // Run the notary server with appropriate config
    println!("Starting TLSNotary server: {}", notary_bin.display());
    let mut run_cmd = Command::new(notary_bin);
    
    // Add config file if provided
    if let Some(config) = config_path {
        run_cmd.arg("--config-file").arg(config);
    } else {
        run_cmd.arg("--tls-enabled").arg("false");
    }
    
    // Add certs-dir if provided (for user information)
    if let Some(certs_dir) = certs_dir {
        println!("Using certificates directory: {}", certs_dir.display());
        // Note: Currently, certs-dir isn't directly used as a command-line arg
        // but we display it for user information
    }
    
    // Execute the command, inheriting stdout and stderr
    let status = run_cmd
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;
    
    if !status.success() {
        return Err(format!("Notary server exited with status: {}", status).into());
    }
    
    Ok(())
}

/// Creates a configuration file for the notary server
pub fn configure(
    outfile: PathBuf,
    host: Option<String>,
    port: Option<u16>,
    tls_enabled: Option<bool>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    // Default configuration values
    let host = host.unwrap_or_else(|| "0.0.0.0".to_string());
    let port = port.unwrap_or(7047);
    let tls_enabled = tls_enabled.unwrap_or(false);
    
    // Default certificate and key paths
    let default_cert_path = "fixture/notary/notary.crt";
    let default_key_path = "fixture/notary/notary.key";
    
    // If TLS is enabled, make sure we have valid cert and key paths
    if tls_enabled {
        if tls_cert.is_none() && tls_key.is_none() {
            println!("Warning: TLS is enabled but no certificate or key paths provided.");
            println!("Using default paths: cert={}, key={}", default_cert_path, default_key_path);
        } else if tls_cert.is_none() {
            println!("Warning: TLS is enabled but no certificate path provided.");
            println!("Using default certificate path: {}", default_cert_path);
        } else if tls_key.is_none() {
            println!("Warning: TLS is enabled but no key path provided.");
            println!("Using default key path: {}", default_key_path);
        }
    }
    
    // Use provided paths or defaults
    let cert_path = match tls_cert {
        Some(path) => path.to_string_lossy().to_string(),
        None => default_cert_path.to_string(),
    };
    
    let key_path = match tls_key {
        Some(path) => path.to_string_lossy().to_string(),
        None => default_key_path.to_string(),
    };

    // Create the config file content
    let config_content = format!(r#"---
server:
  name: "notary-server"
  host: "{}"
  port: {}

notarization:
  max_sent_data: 16384 # 16KB
  max_recv_data: 262144 # 256KB

api_keys:
  enabled: false
  whitelist_path: ""

logging:
  level: "debug"
  # format: "compact" (default) | "json"
  format: "compact"

tls:
  enabled: {}
  private_key: "{}"
  certificate: "{}"
"#, host, port, tls_enabled, key_path, cert_path);

    // Create parent directories if they don't exist
    if let Some(parent) = outfile.parent() {
        fs::create_dir_all(parent)?;
    }
    
    // Write the configuration to the file
    let mut file = fs::File::create(&outfile)?;
    file.write_all(config_content.as_bytes())?;
    
    println!("Notary server configuration written to: {}", outfile.display());
    Ok(())
} 