use std::path::PathBuf;
use std::error::Error;
use std::process::{Command, Stdio};

/// Runs the notary server by building it from the git submodule
pub async fn serve(config_path: Option<PathBuf>, certs_dir: Option<PathBuf>) -> Result<(), Box<dyn Error>> {
    let notary_server_path = "vendor/tlsn/crates/notary/server";
    
    // Step 1: Ensure the submodule is initialized
    println!("Checking git submodule...");
    if !PathBuf::from(notary_server_path).exists() {
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
        .current_dir(notary_server_path)
        .args(["build", "--release"])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;
        
    if !build_status.success() {
        return Err("Failed to build notary server".into());
    }
    
    // Step 3: Run the notary server with appropriate config
    println!("Starting TLSNotary server...");
    let mut run_cmd = Command::new("cargo");
    run_cmd.current_dir(notary_server_path)
        .args(["run", "--release"]);
    
    // Add config file if provided
    if let Some(config) = config_path {
        run_cmd.arg("--").arg("--config-file").arg(config);
    } else {
        run_cmd.arg("--").arg("--tls-enabled").arg("false");
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