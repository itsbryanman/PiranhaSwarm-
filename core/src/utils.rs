use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use crate::Result;

pub fn generate_session_id() -> String {
    Uuid::new_v4().to_string()
}

pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn format_timestamp(timestamp: u64) -> String {
    let dt = DateTime::from_timestamp(timestamp as i64, 0)
        .unwrap_or_else(|| Utc::now());
    dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local()
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback() || ipv6.is_unicast_link_local()
        }
    }
}

pub fn calculate_jitter(rtts: &[Duration]) -> f64 {
    if rtts.len() < 2 {
        return 0.0;
    }
    
    let mut deviations = Vec::new();
    for i in 1..rtts.len() {
        let diff = if rtts[i] > rtts[i-1] {
            rtts[i] - rtts[i-1]
        } else {
            rtts[i-1] - rtts[i]
        };
        deviations.push(diff.as_nanos() as f64);
    }
    
    let mean = deviations.iter().sum::<f64>() / deviations.len() as f64;
    mean / 1_000_000.0 // Convert to milliseconds
}

pub fn calculate_average_rtt(rtts: &[Duration]) -> f64 {
    if rtts.is_empty() {
        return 0.0;
    }
    
    let total_nanos: u128 = rtts.iter().map(|d| d.as_nanos()).sum();
    (total_nanos as f64) / (rtts.len() as f64) / 1_000_000.0 // Convert to milliseconds
}

pub fn hex_encode(data: &[u8]) -> String {
    hex::encode(data)
}

pub fn hex_decode(hex_str: &str) -> Result<Vec<u8>> {
    hex::decode(hex_str).map_err(|e| crate::PiranhaError::Parse(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_session_id_generation() {
        let id1 = generate_session_id();
        let id2 = generate_session_id();
        assert_ne!(id1, id2);
        assert_eq!(id1.len(), 36); // UUID length
    }
    
    #[test]
    fn test_private_ip_detection() {
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }
    
    #[test]
    fn test_jitter_calculation() {
        let rtts = vec![
            Duration::from_millis(10),
            Duration::from_millis(12),
            Duration::from_millis(8),
            Duration::from_millis(15),
        ];
        let jitter = calculate_jitter(&rtts);
        assert!(jitter > 0.0);
    }
}