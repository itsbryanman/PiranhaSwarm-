use thiserror::Error;

#[derive(Error, Debug)]
pub enum PiranhaError {
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),
    
    #[error("DNS resolution error: {0}")]
    DnsResolution(String),
    
    #[error("Packet capture error: {0}")]
    PacketCapture(String),
    
    #[error("Configuration error: {0}")]
    Config(#[from] serde_json::Error),
    
    #[error("Database error: {0}")]
    Database(String),
    
    #[error("SSH error: {0}")]
    Ssh(#[from] ssh2::Error),
    
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    
    #[error("Cryptography error: {0}")]
    Crypto(#[from] ring::error::Unspecified),
    
    #[error("Parse error: {0}")]
    Parse(String),
    
    #[error("Timeout error: {0}")]
    Timeout(String),
    
    #[error("Unknown error: {0}")]
    Unknown(String),
}

pub type Result<T> = std::result::Result<T, PiranhaError>;