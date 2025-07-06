use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use trust_dns_resolver::config::*;
use trust_dns_resolver::Resolver;
use trust_dns_resolver::TokioAsyncResolver;
use serde::{Deserialize, Serialize};
use crate::{Result, PiranhaError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub domain: String,
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsAnalysis {
    pub domain: String,
    pub ip_addresses: Vec<IpAddr>,
    pub reverse_dns: HashMap<IpAddr, String>,
    pub mx_records: Vec<String>,
    pub ns_records: Vec<String>,
    pub txt_records: Vec<String>,
    pub cname_records: Vec<String>,
    pub subdomains: Vec<String>,
    pub dns_history: Vec<DnsRecord>,
    pub response_times: Vec<Duration>,
    pub authoritative_servers: Vec<String>,
    pub geo_distribution: HashMap<String, Vec<IpAddr>>,
}

pub struct DnsResolver {
    resolver: TokioAsyncResolver,
    timeout: Duration,
    max_retries: u32,
}

impl DnsResolver {
    pub fn new(dns_servers: Vec<String>, timeout: Duration, max_retries: u32) -> Result<Self> {
        let mut config = ResolverConfig::new();
        
        for server in dns_servers {
            let server_addr = server.parse()
                .map_err(|_| PiranhaError::DnsResolution(format!("Invalid DNS server: {}", server)))?;
            config.add_name_server(NameServerConfig::new(server_addr, Protocol::Udp));
        }
        
        let mut opts = ResolverOpts::default();
        opts.timeout = timeout;
        opts.attempts = max_retries as usize;
        
        let resolver = TokioAsyncResolver::tokio(config, opts);
        
        Ok(Self {
            resolver,
            timeout,
            max_retries,
        })
    }
    
    pub fn default() -> Result<Self> {
        let resolver = TokioAsyncResolver::tokio_from_system_conf()
            .map_err(|e| PiranhaError::DnsResolution(format!("Failed to create resolver: {}", e)))?;
        
        Ok(Self {
            resolver,
            timeout: Duration::from_secs(5),
            max_retries: 3,
        })
    }
    
    pub async fn resolve_comprehensive(&self, domain: &str) -> Result<DnsAnalysis> {
        let start_time = std::time::Instant::now();
        
        // Resolve A records
        let ip_addresses = self.resolve_a_records(domain).await?;
        
        // Reverse DNS lookups
        let mut reverse_dns = HashMap::new();
        for ip in &ip_addresses {
            if let Ok(hostname) = self.reverse_lookup(*ip).await {
                reverse_dns.insert(*ip, hostname);
            }
        }
        
        // Resolve other record types
        let mx_records = self.resolve_mx_records(domain).await.unwrap_or_default();
        let ns_records = self.resolve_ns_records(domain).await.unwrap_or_default();
        let txt_records = self.resolve_txt_records(domain).await.unwrap_or_default();
        let cname_records = self.resolve_cname_records(domain).await.unwrap_or_default();
        
        // Subdomain enumeration
        let subdomains = self.enumerate_subdomains(domain).await?;
        
        // Authoritative servers
        let authoritative_servers = self.get_authoritative_servers(domain).await?;
        
        // Geo distribution analysis
        let geo_distribution = self.analyze_geo_distribution(&ip_addresses).await?;
        
        let response_time = start_time.elapsed();
        
        Ok(DnsAnalysis {
            domain: domain.to_string(),
            ip_addresses,
            reverse_dns,
            mx_records,
            ns_records,
            txt_records,
            cname_records,
            subdomains,
            dns_history: vec![], // Would be populated from external DNS history service
            response_times: vec![response_time],
            authoritative_servers,
            geo_distribution,
        })
    }
    
    async fn resolve_a_records(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let response = self.resolver.lookup_ip(domain).await
            .map_err(|e| PiranhaError::DnsResolution(format!("A record lookup failed: {}", e)))?;
        
        Ok(response.iter().collect())
    }
    
    async fn reverse_lookup(&self, ip: IpAddr) -> Result<String> {
        let response = self.resolver.reverse_lookup(ip).await
            .map_err(|e| PiranhaError::DnsResolution(format!("Reverse lookup failed: {}", e)))?;
        
        Ok(response.iter().next()
            .map(|name| name.to_string())
            .unwrap_or_else(|| ip.to_string()))
    }
    
    async fn resolve_mx_records(&self, domain: &str) -> Result<Vec<String>> {
        let response = self.resolver.mx_lookup(domain).await
            .map_err(|e| PiranhaError::DnsResolution(format!("MX lookup failed: {}", e)))?;
        
        Ok(response.iter()
            .map(|mx| mx.exchange().to_string())
            .collect())
    }
    
    async fn resolve_ns_records(&self, domain: &str) -> Result<Vec<String>> {
        let response = self.resolver.ns_lookup(domain).await
            .map_err(|e| PiranhaError::DnsResolution(format!("NS lookup failed: {}", e)))?;
        
        Ok(response.iter()
            .map(|ns| ns.to_string())
            .collect())
    }
    
    async fn resolve_txt_records(&self, domain: &str) -> Result<Vec<String>> {
        let response = self.resolver.txt_lookup(domain).await
            .map_err(|e| PiranhaError::DnsResolution(format!("TXT lookup failed: {}", e)))?;
        
        Ok(response.iter()
            .map(|txt| txt.to_string())
            .collect())
    }
    
    async fn resolve_cname_records(&self, domain: &str) -> Result<Vec<String>> {
        match self.resolver.lookup(domain, trust_dns_resolver::proto::rr::RecordType::CNAME).await {
            Ok(response) => {
                Ok(response.record_iter()
                    .filter_map(|record| {
                        if let trust_dns_resolver::proto::rr::RData::CNAME(cname) = record.data() {
                            Some(cname.to_string())
                        } else {
                            None
                        }
                    })
                    .collect())
            }
            Err(_) => Ok(vec![]),
        }
    }
    
    async fn enumerate_subdomains(&self, domain: &str) -> Result<Vec<String>> {
        let common_subdomains = vec![
            "www", "mail", "ftp", "blog", "www1", "www2", "ns1", "ns2",
            "mx1", "mx2", "pop", "imap", "smtp", "secure", "vpn", "m",
            "mobile", "api", "dev", "staging", "test", "admin", "portal",
            "cdn", "static", "media", "assets", "images", "docs", "support",
            "help", "forums", "shop", "store", "news", "beta", "demo",
        ];
        
        let mut found_subdomains = Vec::new();
        
        for subdomain in common_subdomains {
            let full_domain = format!("{}.{}", subdomain, domain);
            
            match self.resolver.lookup_ip(&full_domain).await {
                Ok(_) => {
                    found_subdomains.push(full_domain);
                }
                Err(_) => {
                    // Subdomain doesn't exist, continue
                }
            }
        }
        
        Ok(found_subdomains)
    }
    
    async fn get_authoritative_servers(&self, domain: &str) -> Result<Vec<String>> {
        // Get the root domain for NS lookup
        let root_domain = self.extract_root_domain(domain);
        self.resolve_ns_records(&root_domain).await
    }
    
    fn extract_root_domain(&self, domain: &str) -> String {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() >= 2 {
            format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
        } else {
            domain.to_string()
        }
    }
    
    async fn analyze_geo_distribution(&self, ip_addresses: &[IpAddr]) -> Result<HashMap<String, Vec<IpAddr>>> {
        let mut geo_distribution = HashMap::new();
        
        // This would integrate with a GeoIP service
        // For now, we'll do basic IP range analysis
        for ip in ip_addresses {
            let region = self.estimate_region_from_ip(*ip);
            geo_distribution.entry(region).or_insert_with(Vec::new).push(*ip);
        }
        
        Ok(geo_distribution)
    }
    
    fn estimate_region_from_ip(&self, ip: IpAddr) -> String {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // Very basic region estimation based on IP ranges
                match octets[0] {
                    1..=2 => "IANA Reserved".to_string(),
                    8 => "Level 3 (US)".to_string(),
                    24 => "ARIN (North America)".to_string(),
                    172 => "Private".to_string(),
                    192 => "Private/Reserved".to_string(),
                    _ => "Unknown".to_string(),
                }
            }
            IpAddr::V6(_) => "IPv6".to_string(),
        }
    }
    
    pub async fn monitor_dns_changes(&self, domain: &str, interval: Duration) -> Result<tokio::sync::mpsc::Receiver<DnsRecord>> {
        let (tx, rx) = tokio::sync::mpsc::channel(100);
        let resolver = self.resolver.clone();
        let domain = domain.to_string();
        
        tokio::spawn(async move {
            let mut last_records = HashMap::new();
            
            loop {
                match resolver.lookup_ip(&domain).await {
                    Ok(response) => {
                        let current_ips: Vec<IpAddr> = response.iter().collect();
                        let current_key = format!("{}_A", domain);
                        
                        if let Some(last_ips) = last_records.get(&current_key) {
                            if last_ips != &current_ips {
                                // DNS record changed
                                for ip in &current_ips {
                                    let record = DnsRecord {
                                        domain: domain.clone(),
                                        record_type: "A".to_string(),
                                        value: ip.to_string(),
                                        ttl: 3600, // Default TTL
                                        timestamp: crate::utils::current_timestamp(),
                                    };
                                    
                                    if tx.send(record).await.is_err() {
                                        return;
                                    }
                                }
                            }
                        }
                        
                        last_records.insert(current_key, current_ips);
                    }
                    Err(_) => {
                        // DNS lookup failed, continue monitoring
                    }
                }
                
                tokio::time::sleep(interval).await;
            }
        });
        
        Ok(rx)
    }
    
    pub async fn perform_dns_walkthrough(&self, domain: &str) -> Result<Vec<DnsRecord>> {
        let mut records = Vec::new();
        let timestamp = crate::utils::current_timestamp();
        
        // A Records
        if let Ok(ips) = self.resolve_a_records(domain).await {
            for ip in ips {
                records.push(DnsRecord {
                    domain: domain.to_string(),
                    record_type: "A".to_string(),
                    value: ip.to_string(),
                    ttl: 3600,
                    timestamp,
                });
            }
        }
        
        // MX Records
        if let Ok(mx_records) = self.resolve_mx_records(domain).await {
            for mx in mx_records {
                records.push(DnsRecord {
                    domain: domain.to_string(),
                    record_type: "MX".to_string(),
                    value: mx,
                    ttl: 3600,
                    timestamp,
                });
            }
        }
        
        // NS Records
        if let Ok(ns_records) = self.resolve_ns_records(domain).await {
            for ns in ns_records {
                records.push(DnsRecord {
                    domain: domain.to_string(),
                    record_type: "NS".to_string(),
                    value: ns,
                    ttl: 3600,
                    timestamp,
                });
            }
        }
        
        // TXT Records
        if let Ok(txt_records) = self.resolve_txt_records(domain).await {
            for txt in txt_records {
                records.push(DnsRecord {
                    domain: domain.to_string(),
                    record_type: "TXT".to_string(),
                    value: txt,
                    ttl: 3600,
                    timestamp,
                });
            }
        }
        
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_dns_resolver_creation() {
        let resolver = DnsResolver::default();
        assert!(resolver.is_ok());
    }
    
    #[tokio::test]
    async fn test_domain_resolution() {
        let resolver = DnsResolver::default().unwrap();
        
        // Test with a known domain
        let result = resolver.resolve_comprehensive("example.com").await;
        assert!(result.is_ok());
        
        let analysis = result.unwrap();
        assert_eq!(analysis.domain, "example.com");
        assert!(!analysis.ip_addresses.is_empty());
    }
    
    #[test]
    fn test_root_domain_extraction() {
        let resolver = DnsResolver::default().unwrap();
        
        assert_eq!(resolver.extract_root_domain("www.example.com"), "example.com");
        assert_eq!(resolver.extract_root_domain("sub.domain.example.com"), "example.com");
        assert_eq!(resolver.extract_root_domain("example.com"), "example.com");
    }
    
    #[test]
    fn test_region_estimation() {
        let resolver = DnsResolver::default().unwrap();
        
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let region = resolver.estimate_region_from_ip(ip);
        assert_eq!(region, "Level 3 (US)");
        
        let private_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let region = resolver.estimate_region_from_ip(private_ip);
        assert_eq!(region, "Private/Reserved");
    }
}