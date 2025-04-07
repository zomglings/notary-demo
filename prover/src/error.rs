use hyper::StatusCode;
use std::fmt;
use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)] // Keeping all error variants for future use
pub enum ProverError {
    #[error("Failed to connect to TLSNotary server: {0}")]
    TlsnConnectionError(String),
    
    #[error("TLSNotary protocol error: {0}")]
    TlsnProtocolError(String),
    
    #[error("HTTP request error: {0}")]
    RequestError(String),
    
    #[error("Server responded with error: {0}")]
    NotaryError(StatusCode),
    
    #[error("Proof verification failed: {0}")]
    VerificationError(String),
    
    #[error("Failed to serialize or deserialize data: {0}")]
    SerializationError(String),
    
    #[error("Invalid configuration: {0}")]
    ConfigError(String),
    
    #[error("Internal error: {0}")]
    InternalError(String),
}

#[derive(Debug, Clone)]
pub struct Proof {
    data: serde_json::Value,
}

impl Proof {
    pub fn new(data: serde_json::Value) -> Self {
        Self { data }
    }
    
    pub fn to_string(&self) -> String {
        serde_json::to_string_pretty(&self.data).unwrap_or_else(|_| "{}".to_string())
    }
}

impl fmt::Display for Proof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}