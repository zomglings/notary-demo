use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod certs;
mod notary;

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
}

#[derive(Subcommand)]
enum NotaryCommands {
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
        
        /// Path to a directory containing certificates to copy (should contain notary.crt and notary.key)
        #[arg(long)]
        certs_dir: Option<PathBuf>,
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
        Commands::Notary { command } => {
            match command {
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
                NotaryCommands::Configure { outfile, host, port, tls_enabled, certs_dir } => {
                    // Generate notary server configuration
                    if let Err(err) = notary::configure(outfile, host, port, tls_enabled, certs_dir) {
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
