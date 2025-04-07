use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::path::PathBuf;

mod certs;
mod notary;
mod prover;
mod request;

#[derive(Parser)]
#[command(name = "stamp")]
#[command(about = "TLSNotary demo tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate self-signed certificates
    Certs {
        /// Domain name for the certificate
        #[arg(required = true)]
        domain: String,

        /// Additional domain aliases (Subject Alternative Names)
        #[arg(long, short = 'a')]
        aliases: Vec<String>,

        /// Output directory for the certificates
        #[arg(long, short = 'o', required = true)]
        outdir: PathBuf,

        /// Prefix for certificate filenames
        #[arg(long, short = 'p', default_value = "")]
        prefix: String,
    },
    /// TLSNotary commands
    Notary {
        #[command(subcommand)]
        command: NotaryCommands,
    },
    /// TLSNotary prover commands
    Prover {
        #[command(subcommand)]
        command: ProverCommands,
    },
    /// Make an HTTP request
    Request {
        /// URL to make the request to
        #[arg(required = true)]
        url: String,
        
        /// HTTP method (GET, POST, etc.)
        #[arg(long, default_value = "GET")]
        method: String,
        
        /// HTTP headers in format "key:value" 
        /// Use X-Use-HTTP09 header to force HTTP/0.9 mode for server fixture
        #[arg(long)]
        header: Vec<String>,
        
        /// HTTP request body
        #[arg(long)]
        body: Option<String>,
        
        /// File to save the response to
        #[arg(long)]
        outfile: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ProverCommands {
    /// Notarize an HTTPS request
    Notarize {
        /// URL to make the request to
        #[arg(required = true)]
        url: String,
        
        /// HTTP method (GET, POST, etc.)
        #[arg(long, default_value = "GET")]
        method: String,
        
        /// HTTP headers in format "key:value"
        #[arg(long)]
        header: Vec<String>,
        
        /// HTTP request body
        #[arg(long)]
        body: Option<String>,
        
        /// Notary server host
        #[arg(long)]
        notary_host: Option<String>,
        
        /// Notary server port
        #[arg(long)]
        notary_port: Option<u16>,
        
        /// Output file prefix for attestation and secrets
        #[arg(long, default_value = "notarization")]
        outfile: String,
    },
    
    /// Create a verifiable presentation from attestation
    Present {
        /// Path to the attestation file
        #[arg(long, required = true)]
        attestation: PathBuf,
        
        /// Path to the secrets file
        #[arg(long, required = true)]
        secrets: PathBuf,
        
        /// Path for the output presentation file
        #[arg(long, default_value = "presentation.bin")]
        outfile: PathBuf,
        
        /// Request headers to redact
        #[arg(long)]
        redact_request_header: Vec<String>,
        
        /// Response headers to redact
        #[arg(long)]
        redact_response_header: Vec<String>,
        
        /// Redact request body
        #[arg(long)]
        redact_request_body: bool,
        
        /// Redact response body
        #[arg(long)]
        redact_response_body: bool,
    },
    
    /// Verify a presentation
    Verify {
        /// Path to the presentation file
        #[arg(required = true)]
        presentation: PathBuf,
    },
}

#[derive(Subcommand)]
enum NotaryCommands {
    /// Generate ECDSA keys for the notary server
    Keygen {
        /// Path to output the private key
        #[arg(long, required = true)]
        private_key: PathBuf,
        
        /// Path to output the public key
        #[arg(long, required = true)]
        public_key: PathBuf,
        
        /// Elliptic curve to use (p256 or secp256k1)
        #[arg(long, default_value = "p256")]
        curve: String,
    },
    /// Build the TLSNotary server from source
    Build {
        /// Path to the output binary file
        #[arg(long, required = true)]
        outfile: PathBuf,
    },
    /// Create a configuration file for the notary server
    Configure {
        /// Path to the output configuration file
        #[arg(long, required = true)]
        outfile: PathBuf,
        
        /// Host address to bind the server to (default: 0.0.0.0)
        #[arg(long)]
        host: Option<String>,
        
        /// Port to run the server on (default: 7047)
        #[arg(long)]
        port: Option<u16>,
        
        /// Whether to enable TLS for the server (default: false)
        #[arg(long)]
        tls_enabled: Option<bool>,
        
        /// Path to the TLS certificate file
        #[arg(long)]
        tls_certificate: Option<PathBuf>,
        
        /// Path to the TLS private key file
        #[arg(long)]
        tls_private_key: Option<PathBuf>,
        
        /// Path to the notary private key file
        #[arg(long)]
        notary_private_key: Option<PathBuf>,
        
        /// Path to the notary public key file
        #[arg(long)]
        notary_public_key: Option<PathBuf>,
    },
    /// Run a TLSNotary server
    Serve {
        /// Path to the config file
        #[arg(long)]
        config: Option<PathBuf>,
        
        /// Path to the certificate directory
        #[arg(long)]
        certs_dir: Option<PathBuf>,
        
        /// Path to the notary server binary
        #[arg(long, required = true)]
        notary_bin: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Certs { domain, aliases, outdir, prefix } => {
            match certs::generate_certificates(&domain, &aliases, &outdir, &prefix) {
                Ok((cert_path, key_path)) => {
                    println!("Certificate: {}", cert_path.display());
                    println!("Private key: {}", key_path.display());
                }
                Err(err) => {
                    eprintln!("Error generating certificates: {}", err);
                    std::process::exit(1);
                }
            }
        }
        Commands::Request { url, method, header, body, outfile } => {
            // Create runtime for async code
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(err) => {
                    eprintln!("Error creating Tokio runtime: {}", err);
                    std::process::exit(1);
                }
            };
            
            // Parse headers
            let mut headers = HashMap::new();
            for h in header {
                if let Some((key, value)) = h.split_once(':') {
                    headers.insert(key.trim().to_string(), value.trim().to_string());
                } else {
                    eprintln!("Invalid header format: {}. Use 'key:value' format.", h);
                    std::process::exit(1);
                }
            }
            
            // Make HTTP request
            if let Err(err) = rt.block_on(request::make_request(&url, &method, headers, body, outfile)) {
                eprintln!("Error making HTTP request: {}", err);
                std::process::exit(1);
            }
        }
        Commands::Prover { command } => {
            // Create runtime for async code
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(err) => {
                    eprintln!("Error creating Tokio runtime: {}", err);
                    std::process::exit(1);
                }
            };
            
            match command {
                ProverCommands::Notarize { url, method, header, body, notary_host, notary_port, outfile } => {
                    // Parse headers
                    let mut headers = HashMap::new();
                    for h in header {
                        if let Some((key, value)) = h.split_once(':') {
                            headers.insert(key.trim().to_string(), value.trim().to_string());
                        } else {
                            eprintln!("Invalid header format: {}. Use 'key:value' format.", h);
                            std::process::exit(1);
                        }
                    }
                    
                    // Run notarization
                    if let Err(err) = rt.block_on(prover::notarize(&url, &method, headers, body, notary_host, notary_port, &outfile)) {
                        eprintln!("Error during notarization: {}", err);
                        std::process::exit(1);
                    }
                }
                ProverCommands::Present { attestation, secrets, outfile, redact_request_header, redact_response_header, redact_request_body, redact_response_body } => {
                    // Create presentation
                    if let Err(err) = rt.block_on(prover::create_presentation(
                        attestation,
                        secrets,
                        outfile,
                        redact_request_header,
                        redact_response_header,
                        redact_request_body,
                        redact_response_body,
                    )) {
                        eprintln!("Error creating presentation: {}", err);
                        std::process::exit(1);
                    }
                }
                ProverCommands::Verify { presentation } => {
                    // Verify presentation
                    if let Err(err) = rt.block_on(prover::verify_presentation(presentation)) {
                        eprintln!("Error verifying presentation: {}", err);
                        std::process::exit(1);
                    }
                }
            }
        }
        Commands::Notary { command } => {
            match command {
                NotaryCommands::Keygen { private_key, public_key, curve } => {
                    // Generate ECDSA keys for the notary server
                    if let Err(err) = notary::generate_keys(private_key, public_key, &curve) {
                        eprintln!("Error generating keys: {}", err);
                        std::process::exit(1);
                    }
                }
                NotaryCommands::Build { outfile } => {
                    // Create a runtime for async code
                    let rt = match tokio::runtime::Runtime::new() {
                        Ok(rt) => rt,
                        Err(err) => {
                            eprintln!("Error creating Tokio runtime: {}", err);
                            std::process::exit(1);
                        }
                    };
                    
                    // Run the build command
                    if let Err(err) = rt.block_on(notary::build(outfile)) {
                        eprintln!("Error building notary server: {}", err);
                        std::process::exit(1);
                    }
                }
                NotaryCommands::Configure { outfile, host, port, tls_enabled, tls_certificate, tls_private_key, notary_private_key, notary_public_key } => {
                    // Generate notary server configuration
                    if let Err(err) = notary::configure(
                        outfile, 
                        host, 
                        port, 
                        tls_enabled, 
                        tls_certificate, 
                        tls_private_key,
                        notary_private_key,
                        notary_public_key
                    ) {
                        eprintln!("Error generating configuration: {}", err);
                        std::process::exit(1);
                    }
                }
                NotaryCommands::Serve { config, certs_dir, notary_bin } => {
                    // Create a runtime for async code
                    let rt = match tokio::runtime::Runtime::new() {
                        Ok(rt) => rt,
                        Err(err) => {
                            eprintln!("Error creating Tokio runtime: {}", err);
                            std::process::exit(1);
                        }
                    };
                    
                    // Run the notary server
                    if let Err(err) = rt.block_on(notary::serve(config, certs_dir, notary_bin)) {
                        eprintln!("Error running notary server: {}", err);
                        std::process::exit(1);
                    }
                }
            }
        }
    }
}
