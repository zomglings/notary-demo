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
    certs_dir: Option<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    // Default configuration values
    let host = host.unwrap_or_else(|| "0.0.0.0".to_string());
    let port = port.unwrap_or(7047);
    let tls_enabled = tls_enabled.unwrap_or(false);
    
    // The paths expected by the notary server
    let expected_fixture_dir = "fixture/notary";
    let expected_cert_path = "fixture/notary/notary.crt";
    let expected_key_path = "fixture/notary/notary.key";
    
    // If TLS is enabled and certificates are provided, copy them to the expected location
    if tls_enabled && certs_dir.is_some() {
        let certs_directory = certs_dir.unwrap();
        println!("TLS is enabled, copying certificates from: {}", certs_directory.display());
        
        // Check if the source files exist
        let src_cert = certs_directory.join("notary.crt");
        let src_key = certs_directory.join("notary.key");
        
        if !src_cert.exists() || !src_key.exists() {
            return Err(format!(
                "Certificate files not found. The certificate directory should contain 'notary.crt' and 'notary.key'. Looking for: {} and {}",
                src_cert.display(), src_key.display()
            ).into());
        }
        
        // Create the destination directory
        fs::create_dir_all(expected_fixture_dir)?;
        
        // Copy the certificate files
        println!("Copying certificate to: {}", expected_cert_path);
        fs::copy(&src_cert, expected_cert_path)?;
        
        println!("Copying private key to: {}", expected_key_path);
        fs::copy(&src_key, expected_key_path)?;
    } else if tls_enabled {
        println!("TLS is enabled, using default certificate paths.");
        println!("Make sure the certificate files exist at:");
        println!("  {}", expected_cert_path);
        println!("  {}", expected_key_path);
    }

    // Create the config file content with the standard paths expected by the server
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
  private_key: "fixture/notary/notary.key"
  certificate: "fixture/notary/notary.crt"
"#, host, port, tls_enabled);

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