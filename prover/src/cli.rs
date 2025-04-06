use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::path::PathBuf;

/// TLSNotary Prover client
///
/// This tool allows you to create notarized proofs of HTTP(S) requests
#[derive(Parser, Debug)]
#[clap(author, version, about)]
pub struct Cli {
    /// Increase the verbosity level (can be used multiple times)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
    
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Notarize an HTTP(S) request with TLSNotary
    Notarize {
        /// URL to notarize
        #[arg(required = true)]
        url: String,
        
        /// HTTP method to use
        #[arg(short, long, default_value = "GET")]
        method: String,
        
        /// HTTP headers (format: key=value)
        #[arg(short = 'H', long, value_parser = parse_key_val)]
        headers: Option<Vec<(String, String)>>,
        
        /// Request body
        #[arg(short, long)]
        body: Option<String>,
        
        /// Notary host
        #[arg(long, default_value = "127.0.0.1")]
        notary_host: String,
        
        /// Notary port
        #[arg(long, default_value = "7150")]
        notary_port: u16,
        
        /// Fields to redact or reveal in selective disclosure
        /// Format: key=REVEAL or key=REDACT
        #[arg(short = 'S', long, value_parser = parse_key_val)]
        selective_disclosure: Option<Vec<(String, String)>>,
        
        /// Output file for the proof
        #[arg(short, long)]
        output_file: Option<String>,
    },
}

/// Parse a single key-value pair
fn parse_key_val(s: &str) -> Result<(String, String), String> {
    let pos = s.find('=').ok_or_else(|| format!("Invalid key=value: no `=` found in `{s}`"))?;
    Ok((s[..pos].to_string(), s[pos + 1..].to_string()))
}