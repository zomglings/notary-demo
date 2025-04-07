use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod certs;

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
    }
}
