use clap::{Parser, Subcommand, arg};

/// TLSNotary server command-line interface
///
/// Cryptographically notarize and verify HTTPS responses
#[derive(Parser, Debug)]
#[clap(author, version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Start the notary server
    Server {
        /// Host address to bind to
        #[arg(short = 'H', long, default_value = "127.0.0.1")]
        host: String,

        /// Port for the REST API server
        #[arg(long, default_value = "7048")]
        api_port: u16,

        /// Port for the notary MPC protocol (0 to disable)
        #[arg(long, default_value = "0")]
        notary_port: u16,
        
        /// Use custom MPC protocol (otherwise assume official notary-server is running separately)
        #[arg(long, default_value = "false")]
        use_custom_mpc: bool,

        /// Path to the SQLite database file
        #[arg(short, long, default_value = "notary_proofs.db")]
        database: String,

        /// Log level (off, error, warn, info, debug, trace)
        #[arg(short, long, default_value = "info")]
        log_level: String,

        /// Enable pretty logging
        #[arg(short = 'P', long, default_value = "false")]
        pretty_logging: bool,
    },
    
    /// List all stored proofs
    List {
        /// Path to the SQLite database file
        #[arg(short, long, default_value = "notary_proofs.db")]
        database: String,
        
        /// Output format (text or json)
        #[arg(short, long, default_value = "text")]
        format: String,
    },
    
    /// Show details of a specific proof
    Show {
        /// UUID of the proof to show
        proof_id: String,
        
        /// Path to the SQLite database file
        #[arg(short, long, default_value = "notary_proofs.db")]
        database: String,
        
        /// Output format (text or json)
        #[arg(short, long, default_value = "text")]
        format: String,
    },
    
    /// Submit a new proof (for testing)
    Submit {
        /// TLS domain for the proof
        #[arg(short = 'D', long)]
        domain: String,
        
        /// JSON content for the proof
        #[arg(short, long)]
        json: String,
        
        /// Path to the SQLite database file
        #[arg(short, long, default_value = "notary_proofs.db")]
        database: String,
    },
}

impl Cli {
    /// Parse command-line arguments
    pub fn parse_args() -> Self {
        Self::parse()
    }
} 