use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use crate::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub network: NetworkConfig,
    pub logging: LoggingConfig,
    pub storage: StorageConfig,
    pub capture: CaptureConfig,
    pub analysis: AnalysisConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub interface: String,
    pub timeout_ms: u64,
    pub max_retries: u32,
    pub dns_servers: Vec<String>,
    pub proxy_rotation: bool,
    pub proxy_list: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
    pub output_file: Option<String>,
    pub structured: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub backend: String,
    pub connection_string: String,
    pub encryption_key: Option<String>,
    pub retention_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureConfig {
    pub buffer_size: usize,
    pub promiscuous: bool,
    pub capture_timeout: u64,
    pub packet_filter: Option<String>,
    pub max_packets: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    pub enable_geolocation: bool,
    pub geoip_database_path: Option<String>,
    pub fingerprint_timeout: u64,
    pub concurrent_scans: usize,
    pub tcp_timeout: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: NetworkConfig {
                interface: "eth0".to_string(),
                timeout_ms: 5000,
                max_retries: 3,
                dns_servers: vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()],
                proxy_rotation: false,
                proxy_list: vec![],
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                format: "json".to_string(),
                output_file: None,
                structured: true,
            },
            storage: StorageConfig {
                backend: "file".to_string(),
                connection_string: "./data".to_string(),
                encryption_key: None,
                retention_days: 30,
            },
            capture: CaptureConfig {
                buffer_size: 1024 * 1024,
                promiscuous: false,
                capture_timeout: 1000,
                packet_filter: None,
                max_packets: None,
            },
            analysis: AnalysisConfig {
                enable_geolocation: true,
                geoip_database_path: None,
                fingerprint_timeout: 10000,
                concurrent_scans: 10,
                tcp_timeout: 5000,
            },
        }
    }
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&content)?;
        Ok(config)
    }
    
    pub fn to_file(&self, path: &str) -> Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}