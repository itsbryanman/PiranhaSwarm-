use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};
use crate::{Result, PiranhaError};
use super::packet_capture::PacketInfo;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetadata {
    pub session_id: String,
    pub target_ip: IpAddr,
    pub timestamp: u64,
    pub ttl_analysis: TtlAnalysis,
    pub tcp_window_analysis: TcpWindowAnalysis,
    pub packet_timing: PacketTimingAnalysis,
    pub protocol_distribution: HashMap<String, usize>,
    pub port_analysis: PortAnalysis,
    pub bandwidth_estimation: BandwidthEstimation,
    pub anomaly_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtlAnalysis {
    pub observed_ttls: Vec<u8>,
    pub most_common_ttl: u8,
    pub ttl_variance: f64,
    pub estimated_hops: u8,
    pub os_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpWindowAnalysis {
    pub window_sizes: Vec<u16>,
    pub average_window: f64,
    pub window_scaling: bool,
    pub max_window: u16,
    pub min_window: u16,
    pub window_pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketTimingAnalysis {
    pub inter_packet_delays: Vec<u64>,
    pub average_delay: f64,
    pub jitter: f64,
    pub timing_pattern: String,
    pub burst_detection: Vec<BurstInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurstInfo {
    pub start_time: u64,
    pub end_time: u64,
    pub packet_count: usize,
    pub burst_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortAnalysis {
    pub source_ports: HashMap<u16, usize>,
    pub dest_ports: HashMap<u16, usize>,
    pub ephemeral_port_range: Option<(u16, u16)>,
    pub sequential_ports: bool,
    pub common_services: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthEstimation {
    pub bytes_per_second: f64,
    pub packets_per_second: f64,
    pub peak_bandwidth: f64,
    pub utilization_pattern: String,
}

pub struct NetworkAnalyzer {
    session_id: String,
    packets: Vec<PacketInfo>,
    analysis_window: Duration,
}

impl NetworkAnalyzer {
    pub fn new(session_id: String) -> Self {
        Self {
            session_id,
            packets: Vec::new(),
            analysis_window: Duration::from_secs(60),
        }
    }
    
    pub fn add_packet(&mut self, packet: PacketInfo) {
        self.packets.push(packet);
        
        // Keep only packets within the analysis window
        let cutoff_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() - self.analysis_window.as_secs();
        
        self.packets.retain(|p| p.timestamp >= cutoff_time);
    }
    
    pub fn analyze(&self, target_ip: IpAddr) -> Result<NetworkMetadata> {
        let target_packets: Vec<&PacketInfo> = self.packets
            .iter()
            .filter(|p| p.source_ip == target_ip || p.dest_ip == target_ip)
            .collect();
        
        if target_packets.is_empty() {
            return Err(PiranhaError::Parse("No packets found for target IP".to_string()));
        }
        
        let ttl_analysis = self.analyze_ttl(&target_packets);
        let tcp_window_analysis = self.analyze_tcp_windows(&target_packets);
        let packet_timing = self.analyze_packet_timing(&target_packets);
        let protocol_distribution = self.analyze_protocol_distribution(&target_packets);
        let port_analysis = self.analyze_ports(&target_packets);
        let bandwidth_estimation = self.estimate_bandwidth(&target_packets);
        let anomaly_score = self.calculate_anomaly_score(&target_packets);
        
        Ok(NetworkMetadata {
            session_id: self.session_id.clone(),
            target_ip,
            timestamp: crate::utils::current_timestamp(),
            ttl_analysis,
            tcp_window_analysis,
            packet_timing,
            protocol_distribution,
            port_analysis,
            bandwidth_estimation,
            anomaly_score,
        })
    }
    
    fn analyze_ttl(&self, packets: &[&PacketInfo]) -> TtlAnalysis {
        let mut ttl_counts: HashMap<u8, usize> = HashMap::new();
        let mut ttls = Vec::new();
        
        for packet in packets {
            if let Some(ttl) = packet.ttl {
                ttls.push(ttl);
                *ttl_counts.entry(ttl).or_insert(0) += 1;
            }
        }
        
        let most_common_ttl = ttl_counts
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(ttl, _)| *ttl)
            .unwrap_or(64);
        
        let ttl_variance = if ttls.len() > 1 {
            let mean = ttls.iter().sum::<u8>() as f64 / ttls.len() as f64;
            let variance = ttls.iter()
                .map(|&ttl| (ttl as f64 - mean).powi(2))
                .sum::<f64>() / ttls.len() as f64;
            variance
        } else {
            0.0
        };
        
        let estimated_hops = Self::estimate_hops(most_common_ttl);
        let os_fingerprint = Self::fingerprint_os_from_ttl(most_common_ttl);
        
        TtlAnalysis {
            observed_ttls: ttls,
            most_common_ttl,
            ttl_variance,
            estimated_hops,
            os_fingerprint,
        }
    }
    
    fn analyze_tcp_windows(&self, packets: &[&PacketInfo]) -> TcpWindowAnalysis {
        let mut window_sizes = Vec::new();
        
        for packet in packets {
            if packet.protocol == "TCP" {
                if let Some(window) = packet.window_size {
                    window_sizes.push(window);
                }
            }
        }
        
        if window_sizes.is_empty() {
            return TcpWindowAnalysis {
                window_sizes: vec![],
                average_window: 0.0,
                window_scaling: false,
                max_window: 0,
                min_window: 0,
                window_pattern: "No TCP packets".to_string(),
            };
        }
        
        let average_window = window_sizes.iter().sum::<u16>() as f64 / window_sizes.len() as f64;
        let max_window = *window_sizes.iter().max().unwrap_or(&0);
        let min_window = *window_sizes.iter().min().unwrap_or(&0);
        let window_scaling = max_window > 65535;
        let window_pattern = Self::analyze_window_pattern(&window_sizes);
        
        TcpWindowAnalysis {
            window_sizes,
            average_window,
            window_scaling,
            max_window,
            min_window,
            window_pattern,
        }
    }
    
    fn analyze_packet_timing(&self, packets: &[&PacketInfo]) -> PacketTimingAnalysis {
        let mut timestamps: Vec<u64> = packets.iter().map(|p| p.timestamp).collect();
        timestamps.sort_unstable();
        
        let mut inter_packet_delays = Vec::new();
        for i in 1..timestamps.len() {
            let delay = timestamps[i] - timestamps[i-1];
            inter_packet_delays.push(delay);
        }
        
        let average_delay = if !inter_packet_delays.is_empty() {
            inter_packet_delays.iter().sum::<u64>() as f64 / inter_packet_delays.len() as f64
        } else {
            0.0
        };
        
        let jitter = if inter_packet_delays.len() > 1 {
            let mean = average_delay;
            let variance = inter_packet_delays.iter()
                .map(|&delay| (delay as f64 - mean).powi(2))
                .sum::<f64>() / inter_packet_delays.len() as f64;
            variance.sqrt()
        } else {
            0.0
        };
        
        let timing_pattern = Self::analyze_timing_pattern(&inter_packet_delays);
        let burst_detection = Self::detect_bursts(&timestamps);
        
        PacketTimingAnalysis {
            inter_packet_delays,
            average_delay,
            jitter,
            timing_pattern,
            burst_detection,
        }
    }
    
    fn analyze_protocol_distribution(&self, packets: &[&PacketInfo]) -> HashMap<String, usize> {
        let mut distribution = HashMap::new();
        
        for packet in packets {
            *distribution.entry(packet.protocol.clone()).or_insert(0) += 1;
        }
        
        distribution
    }
    
    fn analyze_ports(&self, packets: &[&PacketInfo]) -> PortAnalysis {
        let mut source_ports = HashMap::new();
        let mut dest_ports = HashMap::new();
        let mut ephemeral_ports = Vec::new();
        let mut common_services = Vec::new();
        
        for packet in packets {
            if let Some(sport) = packet.source_port {
                *source_ports.entry(sport).or_insert(0) += 1;
                if sport >= 32768 {
                    ephemeral_ports.push(sport);
                }
            }
            
            if let Some(dport) = packet.dest_port {
                *dest_ports.entry(dport).or_insert(0) += 1;
                if let Some(service) = Self::port_to_service(dport) {
                    if !common_services.contains(&service) {
                        common_services.push(service);
                    }
                }
            }
        }
        
        let ephemeral_port_range = if ephemeral_ports.len() > 1 {
            ephemeral_ports.sort_unstable();
            Some((ephemeral_ports[0], ephemeral_ports[ephemeral_ports.len() - 1]))
        } else {
            None
        };
        
        let sequential_ports = Self::detect_sequential_ports(&source_ports);
        
        PortAnalysis {
            source_ports,
            dest_ports,
            ephemeral_port_range,
            sequential_ports,
            common_services,
        }
    }
    
    fn estimate_bandwidth(&self, packets: &[&PacketInfo]) -> BandwidthEstimation {
        if packets.is_empty() {
            return BandwidthEstimation {
                bytes_per_second: 0.0,
                packets_per_second: 0.0,
                peak_bandwidth: 0.0,
                utilization_pattern: "No data".to_string(),
            };
        }
        
        let mut timestamps: Vec<u64> = packets.iter().map(|p| p.timestamp).collect();
        timestamps.sort_unstable();
        
        let duration = timestamps.last().unwrap() - timestamps.first().unwrap();
        if duration == 0 {
            return BandwidthEstimation {
                bytes_per_second: 0.0,
                packets_per_second: 0.0,
                peak_bandwidth: 0.0,
                utilization_pattern: "Instantaneous".to_string(),
            };
        }
        
        let total_bytes: usize = packets.iter().map(|p| p.packet_size).sum();
        let bytes_per_second = total_bytes as f64 / duration as f64;
        let packets_per_second = packets.len() as f64 / duration as f64;
        
        // Calculate peak bandwidth in 1-second windows
        let mut peak_bandwidth = 0.0;
        for window_start in timestamps.first().unwrap()..=timestamps.last().unwrap() {
            let window_end = window_start + 1;
            let window_bytes: usize = packets.iter()
                .filter(|p| p.timestamp >= window_start && p.timestamp < window_end)
                .map(|p| p.packet_size)
                .sum();
            peak_bandwidth = peak_bandwidth.max(window_bytes as f64);
        }
        
        let utilization_pattern = Self::analyze_utilization_pattern(&timestamps, &packets);
        
        BandwidthEstimation {
            bytes_per_second,
            packets_per_second,
            peak_bandwidth,
            utilization_pattern,
        }
    }
    
    fn calculate_anomaly_score(&self, packets: &[&PacketInfo]) -> f64 {
        let mut score = 0.0;
        
        // Check for unusual TTL values
        let ttl_analysis = self.analyze_ttl(packets);
        if ttl_analysis.ttl_variance > 10.0 {
            score += 0.2;
        }
        
        // Check for unusual port patterns
        let port_analysis = self.analyze_ports(packets);
        if port_analysis.sequential_ports {
            score += 0.3;
        }
        
        // Check for timing anomalies
        let timing_analysis = self.analyze_packet_timing(packets);
        if timing_analysis.jitter > 100.0 {
            score += 0.2;
        }
        
        // Check for bandwidth spikes
        let bandwidth_analysis = self.estimate_bandwidth(packets);
        if bandwidth_analysis.peak_bandwidth > bandwidth_analysis.bytes_per_second * 10.0 {
            score += 0.3;
        }
        
        score.min(1.0)
    }
    
    fn estimate_hops(ttl: u8) -> u8 {
        match ttl {
            253..=255 => 255 - ttl,
            125..=128 => 128 - ttl,
            61..=64 => 64 - ttl,
            29..=32 => 32 - ttl,
            _ => 0,
        }
    }
    
    fn fingerprint_os_from_ttl(ttl: u8) -> Option<String> {
        match ttl {
            64 => Some("Linux/Unix".to_string()),
            128 => Some("Windows".to_string()),
            255 => Some("Cisco/Network Device".to_string()),
            _ => None,
        }
    }
    
    fn analyze_window_pattern(windows: &[u16]) -> String {
        if windows.is_empty() {
            return "No data".to_string();
        }
        
        let mut increasing = 0;
        let mut decreasing = 0;
        let mut constant = 0;
        
        for i in 1..windows.len() {
            match windows[i].cmp(&windows[i-1]) {
                std::cmp::Ordering::Greater => increasing += 1,
                std::cmp::Ordering::Less => decreasing += 1,
                std::cmp::Ordering::Equal => constant += 1,
            }
        }
        
        if increasing > decreasing && increasing > constant {
            "Increasing".to_string()
        } else if decreasing > increasing && decreasing > constant {
            "Decreasing".to_string()
        } else if constant > increasing && constant > decreasing {
            "Constant".to_string()
        } else {
            "Variable".to_string()
        }
    }
    
    fn analyze_timing_pattern(delays: &[u64]) -> String {
        if delays.is_empty() {
            return "No data".to_string();
        }
        
        let mean = delays.iter().sum::<u64>() as f64 / delays.len() as f64;
        let variance = delays.iter()
            .map(|&d| (d as f64 - mean).powi(2))
            .sum::<f64>() / delays.len() as f64;
        
        if variance < mean * 0.1 {
            "Regular".to_string()
        } else if variance > mean * 2.0 {
            "Highly Variable".to_string()
        } else {
            "Moderately Variable".to_string()
        }
    }
    
    fn detect_bursts(timestamps: &[u64]) -> Vec<BurstInfo> {
        let mut bursts = Vec::new();
        let mut current_burst_start = None;
        let mut current_burst_packets = 0;
        
        for i in 1..timestamps.len() {
            let delay = timestamps[i] - timestamps[i-1];
            
            if delay < 100 { // Less than 100ms between packets
                if current_burst_start.is_none() {
                    current_burst_start = Some(timestamps[i-1]);
                    current_burst_packets = 2;
                } else {
                    current_burst_packets += 1;
                }
            } else {
                if let Some(start) = current_burst_start {
                    if current_burst_packets >= 3 {
                        let duration = timestamps[i-1] - start;
                        bursts.push(BurstInfo {
                            start_time: start,
                            end_time: timestamps[i-1],
                            packet_count: current_burst_packets,
                            burst_rate: current_burst_packets as f64 / duration as f64,
                        });
                    }
                    current_burst_start = None;
                    current_burst_packets = 0;
                }
            }
        }
        
        bursts
    }
    
    fn port_to_service(port: u16) -> Option<String> {
        match port {
            80 => Some("HTTP".to_string()),
            443 => Some("HTTPS".to_string()),
            22 => Some("SSH".to_string()),
            21 => Some("FTP".to_string()),
            25 => Some("SMTP".to_string()),
            53 => Some("DNS".to_string()),
            110 => Some("POP3".to_string()),
            143 => Some("IMAP".to_string()),
            993 => Some("IMAPS".to_string()),
            995 => Some("POP3S".to_string()),
            3389 => Some("RDP".to_string()),
            _ => None,
        }
    }
    
    fn detect_sequential_ports(ports: &HashMap<u16, usize>) -> bool {
        let mut port_list: Vec<u16> = ports.keys().cloned().collect();
        port_list.sort_unstable();
        
        if port_list.len() < 3 {
            return false;
        }
        
        let mut sequential_count = 0;
        for i in 1..port_list.len() {
            if port_list[i] == port_list[i-1] + 1 {
                sequential_count += 1;
            }
        }
        
        sequential_count >= 3
    }
    
    fn analyze_utilization_pattern(timestamps: &[u64], packets: &[&PacketInfo]) -> String {
        let mut hourly_bytes = HashMap::new();
        
        for packet in packets {
            let hour = packet.timestamp / 3600;
            *hourly_bytes.entry(hour).or_insert(0) += packet.packet_size;
        }
        
        if hourly_bytes.is_empty() {
            return "No data".to_string();
        }
        
        let values: Vec<usize> = hourly_bytes.values().cloned().collect();
        let mean = values.iter().sum::<usize>() as f64 / values.len() as f64;
        let variance = values.iter()
            .map(|&v| (v as f64 - mean).powi(2))
            .sum::<f64>() / values.len() as f64;
        
        if variance < mean * 0.5 {
            "Steady".to_string()
        } else if variance > mean * 2.0 {
            "Bursty".to_string()
        } else {
            "Variable".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    
    #[test]
    fn test_ttl_analysis() {
        let mut analyzer = NetworkAnalyzer::new("test-session".to_string());
        
        let packets = vec![
            PacketInfo {
                timestamp: 1000,
                source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                dest_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                source_port: Some(12345),
                dest_port: Some(80),
                protocol: "TCP".to_string(),
                packet_size: 100,
                ttl: Some(64),
                window_size: Some(65535),
                flags: None,
                payload_size: 60,
            },
        ];
        
        let packet_refs: Vec<&PacketInfo> = packets.iter().collect();
        let ttl_analysis = analyzer.analyze_ttl(&packet_refs);
        
        assert_eq!(ttl_analysis.most_common_ttl, 64);
        assert_eq!(ttl_analysis.os_fingerprint, Some("Linux/Unix".to_string()));
    }
    
    #[test]
    fn test_sequential_port_detection() {
        let mut ports = HashMap::new();
        ports.insert(1000, 1);
        ports.insert(1001, 1);
        ports.insert(1002, 1);
        ports.insert(1003, 1);
        
        assert!(NetworkAnalyzer::detect_sequential_ports(&ports));
        
        let mut scattered_ports = HashMap::new();
        scattered_ports.insert(80, 1);
        scattered_ports.insert(443, 1);
        scattered_ports.insert(8080, 1);
        
        assert!(!NetworkAnalyzer::detect_sequential_ports(&scattered_ports));
    }
}