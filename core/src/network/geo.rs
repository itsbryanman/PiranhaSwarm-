use std::collections::HashMap;
use std::net::IpAddr;
use std::fs::File;
use std::io::BufReader;
use serde::{Deserialize, Serialize};
use maxminddb::{MaxMindDBError, Reader};
use crate::{Result, PiranhaError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub ip: IpAddr,
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub timezone: Option<String>,
    pub asn: Option<u32>,
    pub asn_org: Option<String>,
    pub isp: Option<String>,
    pub accuracy_radius: Option<u16>,
    pub is_satellite: Option<bool>,
    pub is_anonymous_proxy: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoAnalysis {
    pub target_ips: Vec<IpAddr>,
    pub locations: Vec<GeoLocation>,
    pub country_distribution: HashMap<String, usize>,
    pub asn_distribution: HashMap<u32, usize>,
    pub distance_analysis: Vec<DistanceInfo>,
    pub anomaly_detection: GeoAnomalyReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistanceInfo {
    pub from_ip: IpAddr,
    pub to_ip: IpAddr,
    pub distance_km: f64,
    pub is_suspicious: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoAnomalyReport {
    pub unusual_locations: Vec<IpAddr>,
    pub vpn_indicators: Vec<IpAddr>,
    pub proxy_indicators: Vec<IpAddr>,
    pub tor_indicators: Vec<IpAddr>,
    pub datacenter_ips: Vec<IpAddr>,
    pub rapid_location_changes: Vec<LocationChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationChange {
    pub ip: IpAddr,
    pub from_location: GeoLocation,
    pub to_location: GeoLocation,
    pub time_diff_seconds: u64,
    pub distance_km: f64,
    pub impossible_travel: bool,
}

pub struct GeoLocator {
    city_reader: Option<Reader<Vec<u8>>>,
    asn_reader: Option<Reader<Vec<u8>>>,
    known_vpn_ranges: Vec<IpRange>,
    known_datacenter_ranges: Vec<IpRange>,
    tor_exit_nodes: Vec<IpAddr>,
}

#[derive(Debug, Clone)]
struct IpRange {
    start: IpAddr,
    end: IpAddr,
    description: String,
}

impl GeoLocator {
    pub fn new() -> Self {
        Self {
            city_reader: None,
            asn_reader: None,
            known_vpn_ranges: Self::load_known_vpn_ranges(),
            known_datacenter_ranges: Self::load_known_datacenter_ranges(),
            tor_exit_nodes: Vec::new(),
        }
    }
    
    pub fn with_databases(city_db_path: &str, asn_db_path: &str) -> Result<Self> {
        let city_reader = Reader::open_readfile(city_db_path)
            .map_err(|e| PiranhaError::Parse(format!("Failed to open city database: {}", e)))?;
        
        let asn_reader = Reader::open_readfile(asn_db_path)
            .map_err(|e| PiranhaError::Parse(format!("Failed to open ASN database: {}", e)))?;
        
        Ok(Self {
            city_reader: Some(city_reader),
            asn_reader: Some(asn_reader),
            known_vpn_ranges: Self::load_known_vpn_ranges(),
            known_datacenter_ranges: Self::load_known_datacenter_ranges(),
            tor_exit_nodes: Vec::new(),
        })
    }
    
    pub async fn geolocate_ip(&self, ip: IpAddr) -> Result<GeoLocation> {
        let mut location = GeoLocation {
            ip,
            country_code: None,
            country_name: None,
            region: None,
            city: None,
            latitude: None,
            longitude: None,
            timezone: None,
            asn: None,
            asn_org: None,
            isp: None,
            accuracy_radius: None,
            is_satellite: None,
            is_anonymous_proxy: None,
        };
        
        // Try MaxMind database first
        if let Some(ref reader) = self.city_reader {
            if let Ok(city_data) = reader.lookup::<maxminddb::geoip2::City>(ip) {
                if let Some(country) = city_data.country {
                    location.country_code = country.iso_code.map(|s| s.to_string());
                    if let Some(names) = country.names {
                        location.country_name = names.get("en").map(|s| s.to_string());
                    }
                }
                
                if let Some(subdivisions) = city_data.subdivisions {
                    if let Some(subdivision) = subdivisions.first() {
                        if let Some(names) = &subdivision.names {
                            location.region = names.get("en").map(|s| s.to_string());
                        }
                    }
                }
                
                if let Some(city) = city_data.city {
                    if let Some(names) = city.names {
                        location.city = names.get("en").map(|s| s.to_string());
                    }
                }
                
                if let Some(geo_location) = city_data.location {
                    location.latitude = geo_location.latitude;
                    location.longitude = geo_location.longitude;
                    location.accuracy_radius = geo_location.accuracy_radius;
                    location.timezone = geo_location.time_zone.map(|s| s.to_string());
                }
                
                if let Some(traits) = city_data.traits {
                    location.is_satellite = Some(traits.is_satellite_provider.unwrap_or(false));
                    location.is_anonymous_proxy = Some(traits.is_anonymous_proxy.unwrap_or(false));
                }
            }
        }
        
        // Try ASN database
        if let Some(ref reader) = self.asn_reader {
            if let Ok(asn_data) = reader.lookup::<maxminddb::geoip2::Asn>(ip) {
                location.asn = asn_data.autonomous_system_number;
                location.asn_org = asn_data.autonomous_system_organization.map(|s| s.to_string());
            }
        }
        
        // Fallback to basic IP range analysis
        if location.country_code.is_none() {
            location = self.analyze_ip_ranges(location).await?;
        }
        
        Ok(location)
    }
    
    pub async fn analyze_locations(&self, ips: Vec<IpAddr>) -> Result<GeoAnalysis> {
        let mut locations = Vec::new();
        let mut country_distribution = HashMap::new();
        let mut asn_distribution = HashMap::new();
        
        // Geolocate all IPs
        for ip in &ips {
            let location = self.geolocate_ip(*ip).await?;
            
            // Update distributions
            if let Some(ref country) = location.country_code {
                *country_distribution.entry(country.clone()).or_insert(0) += 1;
            }
            
            if let Some(asn) = location.asn {
                *asn_distribution.entry(asn).or_insert(0) += 1;
            }
            
            locations.push(location);
        }
        
        // Calculate distances
        let distance_analysis = self.calculate_distances(&locations).await?;
        
        // Detect anomalies
        let anomaly_detection = self.detect_geo_anomalies(&locations).await?;
        
        Ok(GeoAnalysis {
            target_ips: ips,
            locations,
            country_distribution,
            asn_distribution,
            distance_analysis,
            anomaly_detection,
        })
    }
    
    async fn analyze_ip_ranges(&self, mut location: GeoLocation) -> Result<GeoLocation> {
        let ip = location.ip;
        
        // Check if IP is in known VPN ranges
        if self.is_in_vpn_range(ip) {
            location.is_anonymous_proxy = Some(true);
            location.asn_org = Some("VPN Service".to_string());
        }
        
        // Check if IP is in known datacenter ranges
        if self.is_in_datacenter_range(ip) {
            location.isp = Some("Datacenter".to_string());
        }
        
        // Check if IP is a known Tor exit node
        if self.tor_exit_nodes.contains(&ip) {
            location.is_anonymous_proxy = Some(true);
            location.asn_org = Some("Tor Exit Node".to_string());
        }
        
        // Basic country detection based on IP ranges
        if location.country_code.is_none() {
            location.country_code = self.estimate_country_from_ip(ip);
        }
        
        Ok(location)
    }
    
    fn is_in_vpn_range(&self, ip: IpAddr) -> bool {
        for range in &self.known_vpn_ranges {
            if self.ip_in_range(ip, range) {
                return true;
            }
        }
        false
    }
    
    fn is_in_datacenter_range(&self, ip: IpAddr) -> bool {
        for range in &self.known_datacenter_ranges {
            if self.ip_in_range(ip, range) {
                return true;
            }
        }
        false
    }
    
    fn ip_in_range(&self, ip: IpAddr, range: &IpRange) -> bool {
        // Simplified range checking - in practice, this would use proper CIDR matching
        match (ip, range.start, range.end) {
            (IpAddr::V4(ip), IpAddr::V4(start), IpAddr::V4(end)) => {
                u32::from(ip) >= u32::from(start) && u32::from(ip) <= u32::from(end)
            }
            _ => false,
        }
    }
    
    fn estimate_country_from_ip(&self, ip: IpAddr) -> Option<String> {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // Very basic country estimation - in practice, use proper IP allocation databases
                match octets[0] {
                    1..=2 => Some("US".to_string()),
                    3..=15 => Some("US".to_string()),
                    16..=31 => Some("US".to_string()),
                    32..=63 => Some("US".to_string()),
                    64..=127 => Some("US".to_string()),
                    128..=191 => Some("US".to_string()),
                    192 => Some("Private".to_string()),
                    _ => Some("Unknown".to_string()),
                }
            }
            IpAddr::V6(_) => Some("IPv6".to_string()),
        }
    }
    
    async fn calculate_distances(&self, locations: &[GeoLocation]) -> Result<Vec<DistanceInfo>> {
        let mut distances = Vec::new();
        
        for (i, loc1) in locations.iter().enumerate() {
            for (j, loc2) in locations.iter().enumerate() {
                if i >= j {
                    continue;
                }
                
                if let (Some(lat1), Some(lon1), Some(lat2), Some(lon2)) = 
                    (loc1.latitude, loc1.longitude, loc2.latitude, loc2.longitude) {
                    
                    let distance = self.haversine_distance(lat1, lon1, lat2, lon2);
                    let is_suspicious = distance > 10000.0; // More than 10,000 km apart
                    
                    distances.push(DistanceInfo {
                        from_ip: loc1.ip,
                        to_ip: loc2.ip,
                        distance_km: distance,
                        is_suspicious,
                    });
                }
            }
        }
        
        Ok(distances)
    }
    
    fn haversine_distance(&self, lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
        let r = 6371.0; // Earth's radius in kilometers
        
        let dlat = (lat2 - lat1).to_radians();
        let dlon = (lon2 - lon1).to_radians();
        
        let a = (dlat / 2.0).sin().powi(2)
            + lat1.to_radians().cos() * lat2.to_radians().cos() * (dlon / 2.0).sin().powi(2);
        
        let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
        
        r * c
    }
    
    async fn detect_geo_anomalies(&self, locations: &[GeoLocation]) -> Result<GeoAnomalyReport> {
        let mut unusual_locations = Vec::new();
        let mut vpn_indicators = Vec::new();
        let mut proxy_indicators = Vec::new();
        let mut tor_indicators = Vec::new();
        let mut datacenter_ips = Vec::new();
        let rapid_location_changes = Vec::new(); // Would be populated with historical data
        
        for location in locations {
            // Check for VPN/Proxy indicators
            if location.is_anonymous_proxy.unwrap_or(false) {
                proxy_indicators.push(location.ip);
            }
            
            // Check for Tor exit nodes
            if self.tor_exit_nodes.contains(&location.ip) {
                tor_indicators.push(location.ip);
            }
            
            // Check for datacenter IPs
            if self.is_in_datacenter_range(location.ip) {
                datacenter_ips.push(location.ip);
            }
            
            // Check for VPN services
            if self.is_in_vpn_range(location.ip) {
                vpn_indicators.push(location.ip);
            }
            
            // Check for unusual locations (e.g., sanctioned countries, high-risk regions)
            if let Some(ref country) = location.country_code {
                if self.is_high_risk_country(country) {
                    unusual_locations.push(location.ip);
                }
            }
        }
        
        Ok(GeoAnomalyReport {
            unusual_locations,
            vpn_indicators,
            proxy_indicators,
            tor_indicators,
            datacenter_ips,
            rapid_location_changes,
        })
    }
    
    fn is_high_risk_country(&self, country_code: &str) -> bool {
        // List of countries that might be considered high-risk for certain analyses
        let high_risk_countries = vec![
            "IR", "KP", "SY", "CU", "SD", // Sanctioned countries
            "CN", "RU", "BY", // Countries with high cyber activity
        ];
        
        high_risk_countries.contains(&country_code)
    }
    
    fn load_known_vpn_ranges() -> Vec<IpRange> {
        // In practice, this would load from a database or file
        vec![
            // Example VPN ranges - these would be more comprehensive
            IpRange {
                start: "5.8.0.0".parse().unwrap(),
                end: "5.8.255.255".parse().unwrap(),
                description: "ExpressVPN".to_string(),
            },
            IpRange {
                start: "31.171.0.0".parse().unwrap(),
                end: "31.171.255.255".parse().unwrap(),
                description: "NordVPN".to_string(),
            },
        ]
    }
    
    fn load_known_datacenter_ranges() -> Vec<IpRange> {
        // In practice, this would load from a database or file
        vec![
            // Example datacenter ranges
            IpRange {
                start: "52.0.0.0".parse().unwrap(),
                end: "54.255.255.255".parse().unwrap(),
                description: "Amazon AWS".to_string(),
            },
            IpRange {
                start: "104.16.0.0".parse().unwrap(),
                end: "104.31.255.255".parse().unwrap(),
                description: "Cloudflare".to_string(),
            },
        ]
    }
    
    pub async fn update_tor_exit_nodes(&mut self) -> Result<()> {
        // In practice, this would fetch from the Tor Project's exit node list
        // For now, we'll simulate with some example IPs
        self.tor_exit_nodes = vec![
            "185.220.101.1".parse().unwrap(),
            "185.220.101.2".parse().unwrap(),
            "185.220.101.3".parse().unwrap(),
        ];
        
        Ok(())
    }
    
    pub fn get_location_summary(&self, location: &GeoLocation) -> String {
        let mut parts = Vec::new();
        
        if let Some(ref city) = location.city {
            parts.push(city.clone());
        }
        
        if let Some(ref region) = location.region {
            parts.push(region.clone());
        }
        
        if let Some(ref country) = location.country_name {
            parts.push(country.clone());
        }
        
        if parts.is_empty() {
            format!("Unknown location ({})", location.ip)
        } else {
            format!("{} ({})", parts.join(", "), location.ip)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    
    #[test]
    fn test_geolocator_creation() {
        let geolocator = GeoLocator::new();
        assert!(geolocator.city_reader.is_none());
        assert!(geolocator.asn_reader.is_none());
    }
    
    #[test]
    fn test_haversine_distance() {
        let geolocator = GeoLocator::new();
        
        // Distance between New York and London
        let distance = geolocator.haversine_distance(40.7128, -74.0060, 51.5074, -0.1278);
        assert!((distance - 5585.0).abs() < 100.0); // Should be approximately 5585 km
    }
    
    #[test]
    fn test_ip_range_checking() {
        let geolocator = GeoLocator::new();
        
        let range = IpRange {
            start: "192.168.1.1".parse().unwrap(),
            end: "192.168.1.255".parse().unwrap(),
            description: "Test range".to_string(),
        };
        
        let ip_in_range = "192.168.1.100".parse().unwrap();
        let ip_out_of_range = "192.168.2.100".parse().unwrap();
        
        assert!(geolocator.ip_in_range(ip_in_range, &range));
        assert!(!geolocator.ip_in_range(ip_out_of_range, &range));
    }
    
    #[test]
    fn test_high_risk_country_detection() {
        let geolocator = GeoLocator::new();
        
        assert!(geolocator.is_high_risk_country("IR"));
        assert!(geolocator.is_high_risk_country("KP"));
        assert!(!geolocator.is_high_risk_country("US"));
        assert!(!geolocator.is_high_risk_country("GB"));
    }
    
    #[test]
    fn test_location_summary() {
        let geolocator = GeoLocator::new();
        
        let location = GeoLocation {
            ip: "8.8.8.8".parse().unwrap(),
            country_code: Some("US".to_string()),
            country_name: Some("United States".to_string()),
            region: Some("California".to_string()),
            city: Some("Mountain View".to_string()),
            latitude: Some(37.4056),
            longitude: Some(-122.0775),
            timezone: Some("America/Los_Angeles".to_string()),
            asn: Some(15169),
            asn_org: Some("Google LLC".to_string()),
            isp: Some("Google".to_string()),
            accuracy_radius: Some(1000),
            is_satellite: Some(false),
            is_anonymous_proxy: Some(false),
        };
        
        let summary = geolocator.get_location_summary(&location);
        assert_eq!(summary, "Mountain View, California, United States (8.8.8.8)");
    }
    
    #[tokio::test]
    async fn test_anomaly_detection() {
        let geolocator = GeoLocator::new();
        
        let locations = vec![
            GeoLocation {
                ip: "8.8.8.8".parse().unwrap(),
                country_code: Some("US".to_string()),
                country_name: Some("United States".to_string()),
                region: None,
                city: None,
                latitude: None,
                longitude: None,
                timezone: None,
                asn: None,
                asn_org: None,
                isp: None,
                accuracy_radius: None,
                is_satellite: None,
                is_anonymous_proxy: Some(false),
            },
            GeoLocation {
                ip: "1.1.1.1".parse().unwrap(),
                country_code: Some("IR".to_string()),
                country_name: Some("Iran".to_string()),
                region: None,
                city: None,
                latitude: None,
                longitude: None,
                timezone: None,
                asn: None,
                asn_org: None,
                isp: None,
                accuracy_radius: None,
                is_satellite: None,
                is_anonymous_proxy: Some(true),
            },
        ];
        
        let anomaly_report = geolocator.detect_geo_anomalies(&locations).await.unwrap();
        
        assert_eq!(anomaly_report.unusual_locations.len(), 1);
        assert_eq!(anomaly_report.proxy_indicators.len(), 1);
    }
}