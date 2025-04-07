use std::path::PathBuf;
use std::error::Error;
use std::process::{Command, Stdio};
use std::fs;
use std::io::Write;
use p256::ecdsa::{SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey};
use k256::ecdsa::{SigningKey as K256SigningKey, VerifyingKey as K256VerifyingKey};
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

/// Generates ECDSA keys for the notary server
pub fn generate_keys(
    private_key_path: PathBuf,
    public_key_path: PathBuf,
    curve: &str,
) -> Result<(), Box<dyn Error>> {
    match curve.to_lowercase().as_str() {
        "p256" => generate_p256_keys(private_key_path, public_key_path),
        "secp256k1" => generate_secp256k1_keys(private_key_path, public_key_path),
        _ => Err(format!("Unsupported curve: {}. Supported values are 'p256' and 'secp256k1'.", curve).into())
    }
}

/// Generates ECDSA P-256 keys
fn generate_p256_keys(
    private_key_path: PathBuf,
    public_key_path: PathBuf,
) -> Result<(), Box<dyn Error>> {
    println!("Generating ECDSA P-256 key pair for notary server...");
    
    // Generate a new random ECDSA P-256 key pair
    let signing_key = P256SigningKey::random(&mut OsRng);
    
    // Get the corresponding verifying key (public key)
    let verifying_key = P256VerifyingKey::from(&signing_key);
    
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

/// Generates ECDSA secp256k1 keys
fn generate_secp256k1_keys(
    private_key_path: PathBuf,
    public_key_path: PathBuf,
) -> Result<(), Box<dyn Error>> {
    println!("Generating ECDSA secp256k1 key pair for notary server...");
    
    // Generate a new random ECDSA secp256k1 key pair
    let signing_key = K256SigningKey::random(&mut OsRng);
    
    // Get the corresponding verifying key (public key)
    let verifying_key = K256VerifyingKey::from(&signing_key);
    
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
    
    println!("ECDSA secp256k1 keys generated successfully:");
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
    
    // Format certificate paths for YAML
    let mut certificate_path_yaml = "null".to_string();
    let mut private_key_path_yaml = "null".to_string();
    
    // If TLS is enabled, make sure certificate and key are provided
    if tls_enabled {
        if let Some(path) = &tls_certificate {
            let path_str = path.to_string_lossy();
            certificate_path_yaml = if path_str.contains(' ') {
                format!("\"{}\"", path_str)
            } else {
                path_str.to_string()
            };
        } else {
            println!("Warning: TLS is enabled but certificate path is missing.");
        }
        
        if let Some(path) = &tls_private_key {
            let path_str = path.to_string_lossy();
            private_key_path_yaml = if path_str.contains(' ') {
                format!("\"{}\"", path_str)
            } else {
                path_str.to_string()
            };
        } else {
            println!("Warning: TLS is enabled but private key path is missing.");
        }
        
        if tls_certificate.is_none() || tls_private_key.is_none() {
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

    // Format paths for YAML
    let notary_private_key_yaml = if notary_private_key_path.contains(' ') {
        format!("\"{}\"", notary_private_key_path)
    } else {
        notary_private_key_path
    };
    
    let notary_public_key_yaml = if notary_public_key_path.contains(' ') {
        format!("\"{}\"", notary_public_key_path)
    } else {
        notary_public_key_path
    };

    // Create the config file content using the TLSNotary server's expected format
    let config_content = format!(r#"---
server:
  name: "notary-server"
  host: "{}"
  port: {}
  html_info: ""

notarization:
  max_sent_data: 16384 # 16KB
  max_recv_data: 262144 # 256KB
  timeout: 1800

authorization:
  enabled: false
  whitelist_csv_path: null

logging:
  level: "debug"
  filter: null
  format: "compact"

tls:
  enabled: {}
  private_key_pem_path: {}
  certificate_pem_path: {}

notary_key:
  private_key_pem_path: {}
  public_key_pem_path: {}
"#, 
    host, 
    port, 
    tls_enabled,
    private_key_path_yaml,
    certificate_path_yaml,
    notary_private_key_yaml,
    notary_public_key_yaml
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