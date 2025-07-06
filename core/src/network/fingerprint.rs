use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;
use std::io::{Read, Write};
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use crate::{Result, PiranhaError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpFingerprint {
    pub target_ip: IpAddr,
    pub timestamp: u64,
    pub open_ports: Vec<u16>,
    pub service_banners: HashMap<u16, String>,
    pub tcp_stack_fingerprint: TcpStackFingerprint,
    pub service_versions: HashMap<u16, ServiceVersion>,
    pub response_times: HashMap<u16, Duration>,
    pub os_guess: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpStackFingerprint {
    pub window_size: u16,
    pub ttl: u8,
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    pub sack_permitted: bool,
    pub tcp_options: Vec<u8>,
    pub syn_ack_flags: u8,
    pub timestamp_option: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceVersion {
    pub service: String,
    pub version: Option<String>,
    pub product: Option<String>,
    pub extra_info: Option<String>,
    pub banner: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpFingerprint {
    pub server_header: Option<String>,
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub content_length: Option<usize>,
    pub response_time: Duration,
    pub technologies: Vec<String>,
}

pub struct TcpFingerprinter {
    timeout: Duration,
    max_ports: usize,
    common_ports: Vec<u16>,
    banner_probes: HashMap<u16, Vec<u8>>,
}

impl TcpFingerprinter {
    pub fn new(timeout: Duration, max_ports: usize) -> Self {
        let common_ports = vec![
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017,
        ];
        
        let mut banner_probes = HashMap::new();
        
        // HTTP probe
        banner_probes.insert(80, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec());
        banner_probes.insert(8080, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec());
        banner_probes.insert(443, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec());
        
        // FTP probe
        banner_probes.insert(21, b"HELP\r\n".to_vec());
        
        // SSH probe
        banner_probes.insert(22, b"SSH-2.0-OpenSSH_PiranhaSwarm\r\n".to_vec());
        
        // SMTP probe
        banner_probes.insert(25, b"EHLO localhost\r\n".to_vec());
        
        // DNS probe
        banner_probes.insert(53, b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01".to_vec());
        
        Self {
            timeout,
            max_ports,
            common_ports,
            banner_probes,
        }
    }
    
    pub async fn fingerprint_target(&self, target_ip: IpAddr) -> Result<TcpFingerprint> {
        let timestamp = crate::utils::current_timestamp();
        
        // Port scan
        let open_ports = self.scan_ports(target_ip).await?;
        
        // Banner grabbing
        let service_banners = self.grab_banners(target_ip, &open_ports).await?;
        
        // TCP stack fingerprinting
        let tcp_stack_fingerprint = self.fingerprint_tcp_stack(target_ip).await?;
        
        // Service version detection
        let service_versions = self.detect_service_versions(&service_banners).await?;
        
        // Response time measurement
        let response_times = self.measure_response_times(target_ip, &open_ports).await?;
        
        // OS detection based on fingerprints
        let os_guess = self.guess_os(&tcp_stack_fingerprint, &service_versions);
        
        Ok(TcpFingerprint {
            target_ip,
            timestamp,
            open_ports,
            service_banners,
            tcp_stack_fingerprint,
            service_versions,
            response_times,
            os_guess,
        })
    }
    
    async fn scan_ports(&self, target_ip: IpAddr) -> Result<Vec<u16>> {
        let mut open_ports = Vec::new();
        let mut tasks = Vec::new();
        
        for &port in &self.common_ports {
            let addr = SocketAddr::new(target_ip, port);
            let timeout_duration = self.timeout;
            
            let task = tokio::spawn(async move {
                match timeout(timeout_duration, TcpStream::connect(addr)).await {
                    Ok(Ok(_)) => Some(port),
                    _ => None,
                }
            });
            
            tasks.push(task);
        }
        
        for task in tasks {
            if let Ok(Some(port)) = task.await {
                open_ports.push(port);
            }
        }
        
        Ok(open_ports)
    }
    
    async fn grab_banners(&self, target_ip: IpAddr, open_ports: &[u16]) -> Result<HashMap<u16, String>> {
        let mut banners = HashMap::new();
        
        for &port in open_ports {
            if let Ok(banner) = self.grab_banner(target_ip, port).await {
                banners.insert(port, banner);
            }
        }
        
        Ok(banners)
    }
    
    async fn grab_banner(&self, target_ip: IpAddr, port: u16) -> Result<String> {
        let addr = SocketAddr::new(target_ip, port);
        
        let mut stream = timeout(self.timeout, TcpStream::connect(addr)).await
            .map_err(|_| PiranhaError::Timeout("Connection timeout".to_string()))?
            .map_err(|e| PiranhaError::Network(e))?;
        
        // Send probe if available
        if let Some(probe) = self.banner_probes.get(&port) {
            stream.write_all(probe).map_err(PiranhaError::Network)?;
        }
        
        // Read response
        let mut buffer = vec![0u8; 4096];
        stream.set_read_timeout(Some(self.timeout)).map_err(PiranhaError::Network)?;
        
        match stream.read(&mut buffer) {
            Ok(n) => {
                buffer.truncate(n);
                // Convert to string, replacing invalid UTF-8 with replacement character
                Ok(String::from_utf8_lossy(&buffer).to_string())
            }
            Err(_) => Ok(String::new()),
        }
    }
    
    async fn fingerprint_tcp_stack(&self, target_ip: IpAddr) -> Result<TcpStackFingerprint> {
        // This is a simplified version - real TCP stack fingerprinting would
        // require raw socket access and careful packet crafting
        
        // For now, we'll return a default fingerprint
        // In a real implementation, this would send various TCP packets
        // and analyze the responses
        
        Ok(TcpStackFingerprint {
            window_size: 65535,
            ttl: 64,
            mss: Some(1460),
            window_scale: Some(7),
            sack_permitted: true,
            tcp_options: vec![0x02, 0x04, 0x05, 0xb4],
            syn_ack_flags: 0x12,
            timestamp_option: true,
        })
    }
    
    async fn detect_service_versions(&self, banners: &HashMap<u16, String>) -> Result<HashMap<u16, ServiceVersion>> {
        let mut versions = HashMap::new();
        
        for (&port, banner) in banners {
            let service_version = self.parse_banner(port, banner);
            versions.insert(port, service_version);
        }
        
        Ok(versions)
    }
    
    fn parse_banner(&self, port: u16, banner: &str) -> ServiceVersion {
        let banner_lower = banner.to_lowercase();
        
        match port {
            21 => {
                // FTP banner parsing
                if banner_lower.contains("vsftpd") {
                    ServiceVersion {
                        service: "FTP".to_string(),
                        version: self.extract_version(&banner_lower, "vsftpd"),
                        product: Some("vsftpd".to_string()),
                        extra_info: None,
                        banner: banner.to_string(),
                    }
                } else if banner_lower.contains("proftpd") {
                    ServiceVersion {
                        service: "FTP".to_string(),
                        version: self.extract_version(&banner_lower, "proftpd"),
                        product: Some("ProFTPD".to_string()),
                        extra_info: None,
                        banner: banner.to_string(),
                    }
                } else {
                    ServiceVersion {
                        service: "FTP".to_string(),
                        version: None,
                        product: None,
                        extra_info: None,
                        banner: banner.to_string(),
                    }
                }
            }
            22 => {
                // SSH banner parsing
                if banner_lower.contains("openssh") {
                    ServiceVersion {
                        service: "SSH".to_string(),
                        version: self.extract_version(&banner_lower, "openssh_"),
                        product: Some("OpenSSH".to_string()),
                        extra_info: None,
                        banner: banner.to_string(),
                    }
                } else {
                    ServiceVersion {
                        service: "SSH".to_string(),
                        version: None,
                        product: None,
                        extra_info: None,
                        banner: banner.to_string(),
                    }
                }
            }
            80 | 8080 | 443 => {
                // HTTP banner parsing
                if banner_lower.contains("apache") {
                    ServiceVersion {
                        service: "HTTP".to_string(),
                        version: self.extract_version(&banner_lower, "apache/"),
                        product: Some("Apache".to_string()),
                        extra_info: None,
                        banner: banner.to_string(),
                    }
                } else if banner_lower.contains("nginx") {
                    ServiceVersion {
                        service: "HTTP".to_string(),
                        version: self.extract_version(&banner_lower, "nginx/"),
                        product: Some("nginx".to_string()),
                        extra_info: None,
                        banner: banner.to_string(),
                    }
                } else {
                    ServiceVersion {
                        service: "HTTP".to_string(),
                        version: None,
                        product: None,
                        extra_info: None,
                        banner: banner.to_string(),
                    }
                }
            }
            _ => {
                ServiceVersion {
                    service: "Unknown".to_string(),
                    version: None,
                    product: None,
                    extra_info: None,
                    banner: banner.to_string(),
                }
            }
        }
    }
    
    fn extract_version(&self, banner: &str, product: &str) -> Option<String> {
        if let Some(start) = banner.find(product) {
            let version_start = start + product.len();
            let version_part = &banner[version_start..];
            
            // Extract version number (digits, dots, and common version characters)
            let version: String = version_part.chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
                .collect();
            
            if version.is_empty() {
                None
            } else {
                Some(version)
            }
        } else {
            None
        }
    }
    
    async fn measure_response_times(&self, target_ip: IpAddr, open_ports: &[u16]) -> Result<HashMap<u16, Duration>> {
        let mut response_times = HashMap::new();
        
        for &port in open_ports {
            let addr = SocketAddr::new(target_ip, port);
            let start = std::time::Instant::now();
            
            match timeout(self.timeout, TcpStream::connect(addr)).await {
                Ok(Ok(_)) => {
                    let duration = start.elapsed();
                    response_times.insert(port, duration);
                }
                _ => {
                    // Connection failed or timed out
                    response_times.insert(port, self.timeout);
                }
            }
        }
        
        Ok(response_times)
    }
    
    fn guess_os(&self, tcp_fingerprint: &TcpStackFingerprint, service_versions: &HashMap<u16, ServiceVersion>) -> Option<String> {
        let mut os_indicators = Vec::new();
        
        // TTL-based OS detection
        match tcp_fingerprint.ttl {
            64 => os_indicators.push("Linux/Unix"),
            128 => os_indicators.push("Windows"),
            255 => os_indicators.push("Cisco/Network Device"),
            _ => {}
        }
        
        // Window size-based detection
        match tcp_fingerprint.window_size {
            65535 => os_indicators.push("Linux/BSD"),
            8192 => os_indicators.push("Windows"),
            _ => {}
        }
        
        // Service-based detection
        for service_version in service_versions.values() {
            if let Some(product) = &service_version.product {
                match product.as_str() {
                    "OpenSSH" => os_indicators.push("Linux/Unix"),
                    "Microsoft-IIS" => os_indicators.push("Windows"),
                    "Apache" => os_indicators.push("Linux/Unix"),
                    _ => {}
                }
            }
        }
        
        // Find most common indicator
        let mut counts = HashMap::new();
        for indicator in os_indicators {
            *counts.entry(indicator).or_insert(0) += 1;
        }
        
        counts.into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(os, _)| os.to_string())
    }
    
    pub async fn fingerprint_http_service(&self, target_ip: IpAddr, port: u16) -> Result<HttpFingerprint> {
        let addr = SocketAddr::new(target_ip, port);
        let start = std::time::Instant::now();
        
        let mut stream = timeout(self.timeout, TcpStream::connect(addr)).await
            .map_err(|_| PiranhaError::Timeout("Connection timeout".to_string()))?
            .map_err(|e| PiranhaError::Network(e))?;
        
        // Send HTTP request
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: PiranhaSwarm/1.0\r\n\r\n",
            target_ip
        );
        
        stream.write_all(request.as_bytes()).map_err(PiranhaError::Network)?;
        
        // Read response
        let mut buffer = vec![0u8; 8192];
        stream.set_read_timeout(Some(self.timeout)).map_err(PiranhaError::Network)?;
        
        let n = stream.read(&mut buffer).map_err(PiranhaError::Network)?;
        buffer.truncate(n);
        
        let response = String::from_utf8_lossy(&buffer);
        let response_time = start.elapsed();
        
        self.parse_http_response(&response, response_time)
    }
    
    fn parse_http_response(&self, response: &str, response_time: Duration) -> Result<HttpFingerprint> {
        let lines: Vec<&str> = response.lines().collect();
        
        if lines.is_empty() {
            return Err(PiranhaError::Parse("Empty HTTP response".to_string()));
        }
        
        // Parse status line
        let status_code = if let Some(status_line) = lines.first() {
            status_line.split_whitespace()
                .nth(1)
                .and_then(|code| code.parse().ok())
                .unwrap_or(0)
        } else {
            0
        };
        
        // Parse headers
        let mut headers = HashMap::new();
        let mut server_header = None;
        let mut content_length = None;
        
        for line in lines.iter().skip(1) {
            if line.is_empty() {
                break; // End of headers
            }
            
            if let Some(colon_pos) = line.find(':') {
                let header_name = line[..colon_pos].trim().to_lowercase();
                let header_value = line[colon_pos + 1..].trim().to_string();
                
                if header_name == "server" {
                    server_header = Some(header_value.clone());
                } else if header_name == "content-length" {
                    content_length = header_value.parse().ok();
                }
                
                headers.insert(header_name, header_value);
            }
        }
        
        // Detect technologies
        let technologies = self.detect_technologies(&headers, response);
        
        Ok(HttpFingerprint {
            server_header,
            status_code,
            headers,
            content_length,
            response_time,
            technologies,
        })
    }
    
    fn detect_technologies(&self, headers: &HashMap<String, String>, response: &str) -> Vec<String> {
        let mut technologies = Vec::new();
        
        // Check headers for technology indicators
        for (header_name, header_value) in headers {
            let header_lower = header_value.to_lowercase();
            
            match header_name.as_str() {
                "server" => {
                    if header_lower.contains("apache") {
                        technologies.push("Apache".to_string());
                    }
                    if header_lower.contains("nginx") {
                        technologies.push("nginx".to_string());
                    }
                    if header_lower.contains("iis") {
                        technologies.push("IIS".to_string());
                    }
                }
                "x-powered-by" => {
                    if header_lower.contains("php") {
                        technologies.push("PHP".to_string());
                    }
                    if header_lower.contains("asp.net") {
                        technologies.push("ASP.NET".to_string());
                    }
                }
                "x-generator" => {
                    technologies.push(header_value.clone());
                }
                _ => {}
            }
        }
        
        // Check response body for technology indicators
        let response_lower = response.to_lowercase();
        
        if response_lower.contains("wordpress") {
            technologies.push("WordPress".to_string());
        }
        if response_lower.contains("drupal") {
            technologies.push("Drupal".to_string());
        }
        if response_lower.contains("joomla") {
            technologies.push("Joomla".to_string());
        }
        if response_lower.contains("jquery") {
            technologies.push("jQuery".to_string());
        }
        if response_lower.contains("angular") {
            technologies.push("Angular".to_string());
        }
        if response_lower.contains("react") {
            technologies.push("React".to_string());
        }
        
        technologies
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    
    #[test]
    fn test_fingerprinter_creation() {
        let fingerprinter = TcpFingerprinter::new(Duration::from_secs(5), 1000);
        assert_eq!(fingerprinter.timeout, Duration::from_secs(5));
        assert_eq!(fingerprinter.max_ports, 1000);
    }
    
    #[test]
    fn test_version_extraction() {
        let fingerprinter = TcpFingerprinter::new(Duration::from_secs(5), 1000);
        
        let version = fingerprinter.extract_version("apache/2.4.41", "apache/");
        assert_eq!(version, Some("2.4.41".to_string()));
        
        let version = fingerprinter.extract_version("nginx/1.18.0", "nginx/");
        assert_eq!(version, Some("1.18.0".to_string()));
        
        let version = fingerprinter.extract_version("openssh_7.4", "openssh_");
        assert_eq!(version, Some("7.4".to_string()));
    }
    
    #[test]
    fn test_banner_parsing() {
        let fingerprinter = TcpFingerprinter::new(Duration::from_secs(5), 1000);
        
        let service_version = fingerprinter.parse_banner(22, "SSH-2.0-OpenSSH_7.4");
        assert_eq!(service_version.service, "SSH");
        assert_eq!(service_version.product, Some("OpenSSH".to_string()));
        assert_eq!(service_version.version, Some("7.4".to_string()));
        
        let service_version = fingerprinter.parse_banner(80, "Server: Apache/2.4.41");
        assert_eq!(service_version.service, "HTTP");
        assert_eq!(service_version.product, Some("Apache".to_string()));
        assert_eq!(service_version.version, Some("2.4.41".to_string()));
    }
    
    #[test]
    fn test_os_guessing() {
        let fingerprinter = TcpFingerprinter::new(Duration::from_secs(5), 1000);
        
        let tcp_fingerprint = TcpStackFingerprint {
            window_size: 65535,
            ttl: 64,
            mss: Some(1460),
            window_scale: Some(7),
            sack_permitted: true,
            tcp_options: vec![],
            syn_ack_flags: 0x12,
            timestamp_option: true,
        };
        
        let mut service_versions = HashMap::new();
        service_versions.insert(22, ServiceVersion {
            service: "SSH".to_string(),
            version: Some("7.4".to_string()),
            product: Some("OpenSSH".to_string()),
            extra_info: None,
            banner: "SSH-2.0-OpenSSH_7.4".to_string(),
        });
        
        let os_guess = fingerprinter.guess_os(&tcp_fingerprint, &service_versions);
        assert_eq!(os_guess, Some("Linux/Unix".to_string()));
    }
    
    #[test]
    fn test_technology_detection() {
        let fingerprinter = TcpFingerprinter::new(Duration::from_secs(5), 1000);
        
        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "Apache/2.4.41".to_string());
        headers.insert("x-powered-by".to_string(), "PHP/7.4.3".to_string());
        
        let response = "<html><head><meta name=\"generator\" content=\"WordPress 5.4\" /></head></html>";
        
        let technologies = fingerprinter.detect_technologies(&headers, response);
        
        assert!(technologies.contains(&"Apache".to_string()));
        assert!(technologies.contains(&"PHP".to_string()));
        assert!(technologies.contains(&"WordPress".to_string()));
    }
}