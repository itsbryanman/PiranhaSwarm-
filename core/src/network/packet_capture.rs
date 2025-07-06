use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;
use serde::{Deserialize, Serialize};
use crate::{Result, PiranhaError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketInfo {
    pub timestamp: u64,
    pub source_ip: IpAddr,
    pub dest_ip: IpAddr,
    pub source_port: Option<u16>,
    pub dest_port: Option<u16>,
    pub protocol: String,
    pub packet_size: usize,
    pub ttl: Option<u8>,
    pub window_size: Option<u16>,
    pub flags: Option<Vec<String>>,
    pub payload_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowStats {
    pub flow_id: String,
    pub packet_count: usize,
    pub byte_count: usize,
    pub first_seen: u64,
    pub last_seen: u64,
    pub avg_packet_size: f64,
    pub packets_per_second: f64,
}

pub struct PacketCapture {
    interface: NetworkInterface,
    filter: Option<String>,
    buffer_size: usize,
    max_packets: Option<usize>,
    timeout: Duration,
}

impl PacketCapture {
    pub fn new(interface_name: &str, config: &crate::config::CaptureConfig) -> Result<Self> {
        let interface = Self::find_interface(interface_name)?;
        
        Ok(Self {
            interface,
            filter: config.packet_filter.clone(),
            buffer_size: config.buffer_size,
            max_packets: config.max_packets,
            timeout: Duration::from_millis(config.capture_timeout),
        })
    }
    
    fn find_interface(name: &str) -> Result<NetworkInterface> {
        let interfaces = datalink::interfaces();
        interfaces
            .into_iter()
            .find(|iface| iface.name == name)
            .ok_or_else(|| PiranhaError::Network(
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Interface {} not found", name)
                )
            ))
    }
    
    pub async fn start_capture(&self) -> Result<mpsc::Receiver<PacketInfo>> {
        let (tx, rx) = mpsc::channel(1000);
        let interface = self.interface.clone();
        let max_packets = self.max_packets;
        let timeout = self.timeout;
        
        tokio::spawn(async move {
            let mut packet_count = 0;
            let start_time = SystemTime::now();
            
            // Create a channel receiver
            let (_, mut datalink_rx) = match datalink::channel(&interface, Default::default()) {
                Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => {
                    log::error!("Unhandled channel type");
                    return;
                }
                Err(e) => {
                    log::error!("Failed to create datalink channel: {}", e);
                    return;
                }
            };
            
            loop {
                match datalink_rx.next() {
                    Ok(packet) => {
                        if let Some(packet_info) = Self::parse_packet(packet) {
                            if tx.send(packet_info).await.is_err() {
                                log::warn!("Receiver dropped, stopping capture");
                                break;
                            }
                            packet_count += 1;
                        }
                        
                        // Check limits
                        if let Some(max) = max_packets {
                            if packet_count >= max {
                                log::info!("Reached maximum packet count: {}", max);
                                break;
                            }
                        }
                        
                        // Check timeout
                        if start_time.elapsed().unwrap_or_default() > timeout {
                            log::info!("Capture timeout reached");
                            break;
                        }
                    }
                    Err(e) => {
                        log::error!("Error receiving packet: {}", e);
                        break;
                    }
                }
            }
        });
        
        Ok(rx)
    }
    
    fn parse_packet(packet: &[u8]) -> Option<PacketInfo> {
        let ethernet_packet = EthernetPacket::new(packet)?;
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        match ethernet_packet.get_ethertype() {
            EtherTypes::Ipv4 => {
                let ipv4_packet = Ipv4Packet::new(ethernet_packet.payload())?;
                let source_ip = IpAddr::V4(ipv4_packet.get_source());
                let dest_ip = IpAddr::V4(ipv4_packet.get_destination());
                let ttl = Some(ipv4_packet.get_ttl());
                let packet_size = packet.len();
                let payload_size = ipv4_packet.payload().len();
                
                match ipv4_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        let tcp_packet = TcpPacket::new(ipv4_packet.payload())?;
                        let flags = Self::parse_tcp_flags(tcp_packet.get_flags());
                        
                        Some(PacketInfo {
                            timestamp,
                            source_ip,
                            dest_ip,
                            source_port: Some(tcp_packet.get_source()),
                            dest_port: Some(tcp_packet.get_destination()),
                            protocol: "TCP".to_string(),
                            packet_size,
                            ttl,
                            window_size: Some(tcp_packet.get_window()),
                            flags: Some(flags),
                            payload_size,
                        })
                    }
                    IpNextHeaderProtocols::Udp => {
                        let udp_packet = UdpPacket::new(ipv4_packet.payload())?;
                        
                        Some(PacketInfo {
                            timestamp,
                            source_ip,
                            dest_ip,
                            source_port: Some(udp_packet.get_source()),
                            dest_port: Some(udp_packet.get_destination()),
                            protocol: "UDP".to_string(),
                            packet_size,
                            ttl,
                            window_size: None,
                            flags: None,
                            payload_size,
                        })
                    }
                    _ => {
                        Some(PacketInfo {
                            timestamp,
                            source_ip,
                            dest_ip,
                            source_port: None,
                            dest_port: None,
                            protocol: format!("{:?}", ipv4_packet.get_next_level_protocol()),
                            packet_size,
                            ttl,
                            window_size: None,
                            flags: None,
                            payload_size,
                        })
                    }
                }
            }
            _ => None,
        }
    }
    
    fn parse_tcp_flags(flags: u8) -> Vec<String> {
        let mut flag_strings = Vec::new();
        
        if flags & 0x01 != 0 { flag_strings.push("FIN".to_string()); }
        if flags & 0x02 != 0 { flag_strings.push("SYN".to_string()); }
        if flags & 0x04 != 0 { flag_strings.push("RST".to_string()); }
        if flags & 0x08 != 0 { flag_strings.push("PSH".to_string()); }
        if flags & 0x10 != 0 { flag_strings.push("ACK".to_string()); }
        if flags & 0x20 != 0 { flag_strings.push("URG".to_string()); }
        if flags & 0x40 != 0 { flag_strings.push("ECE".to_string()); }
        if flags & 0x80 != 0 { flag_strings.push("CWR".to_string()); }
        
        flag_strings
    }
    
    pub fn analyze_flows(&self, packets: &[PacketInfo]) -> Vec<FlowStats> {
        let mut flows: HashMap<String, FlowStats> = HashMap::new();
        
        for packet in packets {
            let flow_id = format!("{}:{}-{}:{}", 
                packet.source_ip,
                packet.source_port.unwrap_or(0),
                packet.dest_ip,
                packet.dest_port.unwrap_or(0)
            );
            
            let flow = flows.entry(flow_id.clone()).or_insert_with(|| FlowStats {
                flow_id: flow_id.clone(),
                packet_count: 0,
                byte_count: 0,
                first_seen: packet.timestamp,
                last_seen: packet.timestamp,
                avg_packet_size: 0.0,
                packets_per_second: 0.0,
            });
            
            flow.packet_count += 1;
            flow.byte_count += packet.packet_size;
            flow.last_seen = packet.timestamp.max(flow.last_seen);
            flow.first_seen = packet.timestamp.min(flow.first_seen);
            
            // Calculate averages
            flow.avg_packet_size = flow.byte_count as f64 / flow.packet_count as f64;
            let duration = (flow.last_seen - flow.first_seen).max(1);
            flow.packets_per_second = flow.packet_count as f64 / duration as f64;
        }
        
        flows.into_values().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_tcp_flags_parsing() {
        let flags = PacketCapture::parse_tcp_flags(0x18); // PSH + ACK
        assert!(flags.contains(&"PSH".to_string()));
        assert!(flags.contains(&"ACK".to_string()));
        assert_eq!(flags.len(), 2);
    }
    
    #[test]
    fn test_flow_analysis() {
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
                flags: Some(vec!["SYN".to_string()]),
                payload_size: 0,
            },
            PacketInfo {
                timestamp: 1001,
                source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                dest_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                source_port: Some(12345),
                dest_port: Some(80),
                protocol: "TCP".to_string(),
                packet_size: 200,
                ttl: Some(64),
                window_size: Some(65535),
                flags: Some(vec!["ACK".to_string()]),
                payload_size: 160,
            },
        ];
        
        let capture = PacketCapture {
            interface: NetworkInterface {
                name: "test".to_string(),
                description: "Test interface".to_string(),
                index: 0,
                mac: None,
                ips: vec![],
                flags: 0,
            },
            filter: None,
            buffer_size: 1024,
            max_packets: None,
            timeout: Duration::from_secs(10),
        };
        
        let flows = capture.analyze_flows(&packets);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].packet_count, 2);
        assert_eq!(flows[0].byte_count, 300);
        assert_eq!(flows[0].avg_packet_size, 150.0);
    }
}