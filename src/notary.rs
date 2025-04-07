use std::path::PathBuf;
use std::error::Error;
use std::process::{Command, Stdio};
use std::fs;
use std::io::Write;
use p256::ecdsa::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use pkcs8::{LineEnding, EncodePrivateKey, EncodePublicKey};

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

/// Generates ECDSA P-256 keys for the notary server
pub fn generate_keys(
    private_key_path: PathBuf,
    public_key_path: PathBuf,
) -> Result<(), Box<dyn Error>> {
    println!("Generating ECDSA P-256 key pair for notary server...");
    
    // Generate a new random ECDSA P-256 key pair
    let signing_key = SigningKey::random(&mut OsRng);
    
    // Get the corresponding verifying key (public key)
    let verifying_key = VerifyingKey::from(&signing_key);
    
    // Convert keys to PEM format
    let private_key_pem = signing_key.to_pkcs8_pem(LineEnding::LF)?;
    let public_key_pem = verifying_key.to_public_key_pem(LineEnding::LF)?;
    
    // Create parent directories if they don't exist
    if let Some(parent) = private_key_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = public_key_path.parent() {
        fs::create_dir_all(parent)?;
    }
    
    // Write keys to files
    fs::write(&private_key_path, private_key_pem.as_str())?;
    fs::write(&public_key_path, public_key_pem.as_str())?;
    
    println!("ECDSA P-256 keys generated successfully:");
    println!("  Private key: {}", private_key_path.display());
    println!("  Public key:  {}", public_key_path.display());
    
    Ok(())
}

/// Creates a configuration file for the notary server
pub fn configure(
    outfile: PathBuf,
    host: Option<String>,
    port: Option<u16>,
    tls_enabled: Option<bool>,
    tls_certificate: Option<PathBuf>,
    tls_private_key: Option<PathBuf>,
    notary_private_key: Option<PathBuf>,
    notary_public_key: Option<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    // Default configuration values
    let host = host.unwrap_or_else(|| "0.0.0.0".to_string());
    let port = port.unwrap_or(7047);
    let tls_enabled = tls_enabled.unwrap_or(false);
    
    // Handle certificate paths
    let certificate_path = tls_certificate.map(|p| p.to_string_lossy().to_string());
    let private_key_path = tls_private_key.map(|p| p.to_string_lossy().to_string());
    
    // If TLS is enabled, make sure certificate and key are provided
    if tls_enabled {
        if certificate_path.is_none() || private_key_path.is_none() {
            println!("Warning: TLS is enabled but certificate or key path is missing.");
            println!("Make sure the files exist at the locations specified in the configuration.");
        }
    }
    
    // Use default paths for notary keys if not provided
    let notary_private_key_path = notary_private_key
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "fixture/notary/notary.key".to_string());
    
    let notary_public_key_path = notary_public_key
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "fixture/notary/notary.pub".to_string());

    // Create the config file content using the TLSNotary server's expected format
    let config_content = format!(r#"---
server:
  name: "notary-server"
  host: "{}"
  port: {}
  html_info: |
    <head>
      <meta charset="UTF-8">
      <meta name="author" content="tlsnotary">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
    <body>
      <svg width="86" height="88" viewBox="0 0 86 88" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M25.5484 0.708986C25.5484 0.17436 26.1196 -0.167376 26.5923 0.0844205L33.6891 3.86446C33.9202 3.98756 34.0645 4.22766 34.0645 4.48902V9.44049H37.6129C38.0048 9.44049 38.3226 9.75747 38.3226 10.1485V21.4766L36.1936 20.0606V11.5645H34.0645V80.9919C34.0645 81.1134 34.0332 81.2328 33.9735 81.3388L30.4251 87.6388C30.1539 88.1204 29.459 88.1204 29.1878 87.6388L25.6394 81.3388C25.5797 81.2328 25.5484 81.1134 25.5484 80.9919V0.708986Z" fill="#243F5F"/>
        <path d="M21.2903 25.7246V76.7012H12.7742V34.2207H0V25.7246H21.2903Z" fill="#243F5F"/>
        <path d="M63.871 76.7012H72.3871V34.2207H76.6452V76.7012H85.1613V25.7246H63.871V76.7012Z" fill="#243F5F"/>
        <path d="M38.3226 25.7246H59.6129V34.2207H46.8387V46.9649H59.6129V76.7012H38.3226V68.2051H51.0968V55.4609H38.3226V25.7246Z" fill="#243F5F"/>
      </svg>
      <h1>Notary Server {{version}}!</h1>
      <ul>
        <li>public key: <pre>{{public_key}}</pre></li>
        <li>git commit hash: <a href="https://github.com/tlsnotary/tlsn/commit/{{git_commit_hash}}">{{git_commit_hash}}</a></li>
        <li><a href="healthcheck">health check</a></li>
        <li><a href="info">info</a></li>
      </ul>
    </body>

notarization:
  max_sent_data: 4096
  max_recv_data: 16384
  timeout: 1800

authorization:
  enabled: false
  whitelist_csv_path: null

logging:
  level: "DEBUG"
  filter: null
  format: "compact"

tls:
  enabled: {}
  private_key_pem_path: {}
  certificate_pem_path: {}

notary_key:
  private_key_pem_path: "{}"
  public_key_pem_path: "{}"
"#, 
    host, 
    port, 
    tls_enabled,
    private_key_path.map_or("null".to_string(), |p| format!("\"{}\"", p)),
    certificate_path.map_or("null".to_string(), |p| format!("\"{}\"", p)),
    format!("\"{}\"", notary_private_key_path),
    format!("\"{}\"", notary_public_key_path)
);

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