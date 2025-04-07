use std::path::PathBuf;
use std::error::Error;
use std::process::{Command, Stdio};

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