use clap::{Arg, Command};
use env_logger;
use log::{info, error};
use std::net::IpAddr;
use std::time::Duration;
use tokio;

use piranha_swarm_core::{
    Config, Result,
    network::{PacketCapture, NetworkAnalyzer, DnsResolver, TcpFingerprinter, GeoLocator},
    utils::generate_session_id,
};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    
    let matches = Command::new("piranha-swarm")
        .version("0.1.0")
        .author("itsbryanman <dev@piranhaswarm.com>")
        .about("Advanced network metadata harvesting and deanonymization engine")
        .subcommand(
            Command::new("capture")
                .about("Start packet capture and analysis")
                .arg(
                    Arg::new("interface")
                        .short('i')
                        .long("interface")
                        .value_name("INTERFACE")
                        .help("Network interface to capture from")
                        .default_value("eth0")
                )
                .arg(
                    Arg::new("target")
                        .short('t')
                        .long("target")
                        .value_name("IP")
                        .help("Target IP address to analyze")
                        .required(true)
                )
                .arg(
                    Arg::new("duration")
                        .short('d')
                        .long("duration")
                        .value_name("SECONDS")
                        .help("Capture duration in seconds")
                        .default_value("60")
                )
                .arg(
                    Arg::new("config")
                        .short('c')
                        .long("config")
                        .value_name("FILE")
                        .help("Configuration file path")
                        .default_value("config/default.json")
                )
        )
        .subcommand(
            Command::new("fingerprint")
                .about("Perform TCP fingerprinting")
                .arg(
                    Arg::new("target")
                        .short('t')
                        .long("target")
                        .value_name("IP")
                        .help("Target IP address to fingerprint")
                        .required(true)
                )
                .arg(
                    Arg::new("timeout")
                        .long("timeout")
                        .value_name("SECONDS")
                        .help("Connection timeout in seconds")
                        .default_value("5")
                )
        )
        .subcommand(
            Command::new("dns")
                .about("Perform comprehensive DNS analysis")
                .arg(
                    Arg::new("domain")
                        .short('d')
                        .long("domain")
                        .value_name("DOMAIN")
                        .help("Domain to analyze")
                        .required(true)
                )
        )
        .subcommand(
            Command::new("geo")
                .about("Perform geolocation analysis")
                .arg(
                    Arg::new("ips")
                        .short('i')
                        .long("ips")
                        .value_name("IP_LIST")
                        .help("Comma-separated list of IP addresses")
                        .required(true)
                )
                .arg(
                    Arg::new("geoip-db")
                        .long("geoip-db")
                        .value_name("PATH")
                        .help("Path to GeoIP database file")
                )
        )
        .get_matches();
    
    match matches.subcommand() {
        Some(("capture", sub_matches)) => {
            let interface = sub_matches.get_one::<String>("interface").unwrap();
            let target: IpAddr = sub_matches.get_one::<String>("target").unwrap()
                .parse()
                .map_err(|_| piranha_swarm_core::PiranhaError::Parse("Invalid IP address".to_string()))?;
            let duration: u64 = sub_matches.get_one::<String>("duration").unwrap()
                .parse()
                .map_err(|_| piranha_swarm_core::PiranhaError::Parse("Invalid duration".to_string()))?;
            let config_path = sub_matches.get_one::<String>("config").unwrap();
            
            run_capture_mode(interface, target, duration, config_path).await?;
        }
        Some(("fingerprint", sub_matches)) => {
            let target: IpAddr = sub_matches.get_one::<String>("target").unwrap()
                .parse()
                .map_err(|_| piranha_swarm_core::PiranhaError::Parse("Invalid IP address".to_string()))?;
            let timeout: u64 = sub_matches.get_one::<String>("timeout").unwrap()
                .parse()
                .map_err(|_| piranha_swarm_core::PiranhaError::Parse("Invalid timeout".to_string()))?;
            
            run_fingerprint_mode(target, timeout).await?;
        }
        Some(("dns", sub_matches)) => {
            let domain = sub_matches.get_one::<String>("domain").unwrap();
            
            run_dns_mode(domain).await?;
        }
        Some(("geo", sub_matches)) => {
            let ip_list = sub_matches.get_one::<String>("ips").unwrap();
            let geoip_db = sub_matches.get_one::<String>("geoip-db");
            
            run_geo_mode(ip_list, geoip_db).await?;
        }
        _ => {
            eprintln!("No subcommand provided. Use --help for usage information.");
            std::process::exit(1);
        }
    }
    
    Ok(())
}

async fn run_capture_mode(interface: &str, target_ip: IpAddr, duration: u64, config_path: &str) -> Result<()> {
    info!("Starting capture mode on interface {} for target {}", interface, target_ip);
    
    // Load configuration
    let config = if std::path::Path::new(config_path).exists() {
        Config::from_file(config_path)?
    } else {
        info!("Config file not found, using defaults");
        Config::default()
    };
    
    // Initialize components
    let session_id = generate_session_id();
    let mut analyzer = NetworkAnalyzer::new(session_id.clone());
    
    // Start packet capture
    let capture = PacketCapture::new(interface, &config.capture)?;
    let mut packet_rx = capture.start_capture().await?;
    
    info!("Capture started. Session ID: {}", session_id);
    info!("Analyzing traffic for {} seconds...", duration);
    
    let start_time = std::time::Instant::now();
    let capture_duration = Duration::from_secs(duration);
    
    // Collect packets
    while start_time.elapsed() < capture_duration {
        tokio::select! {
            packet = packet_rx.recv() => {
                if let Some(packet) = packet {
                    analyzer.add_packet(packet);
                } else {
                    break;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                // Continue processing
            }
        }
    }
    
    // Analyze collected data
    info!("Capture complete. Analyzing metadata...");
    let metadata = analyzer.analyze(target_ip)?;
    
    // Output results
    println!("\n=== NETWORK METADATA ANALYSIS ===");
    println!("Session ID: {}", metadata.session_id);
    println!("Target IP: {}", metadata.target_ip);
    println!("Timestamp: {}", crate::utils::format_timestamp(metadata.timestamp));
    
    println!("\n--- TTL Analysis ---");
    println!("Most common TTL: {}", metadata.ttl_analysis.most_common_ttl);
    println!("Estimated hops: {}", metadata.ttl_analysis.estimated_hops);
    if let Some(ref os) = metadata.ttl_analysis.os_fingerprint {
        println!("OS fingerprint: {}", os);
    }
    
    println!("\n--- TCP Window Analysis ---");
    println!("Average window size: {:.2}", metadata.tcp_window_analysis.average_window);
    println!("Window scaling: {}", metadata.tcp_window_analysis.window_scaling);
    println!("Window pattern: {}", metadata.tcp_window_analysis.window_pattern);
    
    println!("\n--- Packet Timing ---");
    println!("Average delay: {:.2} ms", metadata.packet_timing.average_delay);
    println!("Jitter: {:.2} ms", metadata.packet_timing.jitter);
    println!("Timing pattern: {}", metadata.packet_timing.timing_pattern);
    println!("Burst count: {}", metadata.packet_timing.burst_detection.len());
    
    println!("\n--- Protocol Distribution ---");
    for (protocol, count) in &metadata.protocol_distribution {
        println!("{}: {}", protocol, count);
    }
    
    println!("\n--- Bandwidth Analysis ---");
    println!("Bytes per second: {:.2}", metadata.bandwidth_estimation.bytes_per_second);
    println!("Packets per second: {:.2}", metadata.bandwidth_estimation.packets_per_second);
    println!("Peak bandwidth: {:.2}", metadata.bandwidth_estimation.peak_bandwidth);
    
    println!("\n--- Anomaly Score ---");
    println!("Score: {:.2}/1.0", metadata.anomaly_score);
    
    // Save results to JSON
    let output_file = format!("results/metadata_{}.json", session_id);
    std::fs::create_dir_all("results").ok();
    let json_output = serde_json::to_string_pretty(&metadata)?;
    std::fs::write(&output_file, json_output)?;
    
    info!("Results saved to: {}", output_file);
    
    Ok(())
}

async fn run_fingerprint_mode(target_ip: IpAddr, timeout: u64) -> Result<()> {
    info!("Starting fingerprint mode for target: {}", target_ip);
    
    let fingerprinter = TcpFingerprinter::new(Duration::from_secs(timeout), 1000);
    let fingerprint = fingerprinter.fingerprint_target(target_ip).await?;
    
    println!("\n=== TCP FINGERPRINT RESULTS ===");
    println!("Target IP: {}", fingerprint.target_ip);
    println!("Timestamp: {}", crate::utils::format_timestamp(fingerprint.timestamp));
    
    println!("\n--- Open Ports ---");
    for port in &fingerprint.open_ports {
        println!("Port {}: Open", port);
        
        if let Some(banner) = fingerprint.service_banners.get(port) {
            if !banner.trim().is_empty() {
                println!("  Banner: {}", banner.trim());
            }
        }
        
        if let Some(version) = fingerprint.service_versions.get(port) {
            println!("  Service: {}", version.service);
            if let Some(ref product) = version.product {
                println!("  Product: {}", product);
            }
            if let Some(ref ver) = version.version {
                println!("  Version: {}", ver);
            }
        }
        
        if let Some(response_time) = fingerprint.response_times.get(port) {
            println!("  Response time: {:?}", response_time);
        }
        
        println!();
    }
    
    println!("--- TCP Stack Fingerprint ---");
    println!("Window size: {}", fingerprint.tcp_stack_fingerprint.window_size);
    println!("TTL: {}", fingerprint.tcp_stack_fingerprint.ttl);
    if let Some(mss) = fingerprint.tcp_stack_fingerprint.mss {
        println!("MSS: {}", mss);
    }
    println!("SACK permitted: {}", fingerprint.tcp_stack_fingerprint.sack_permitted);
    
    if let Some(ref os_guess) = fingerprint.os_guess {
        println!("\n--- OS Detection ---");
        println!("Estimated OS: {}", os_guess);
    }
    
    // Save results
    let output_file = format!("results/fingerprint_{}.json", target_ip);
    std::fs::create_dir_all("results").ok();
    let json_output = serde_json::to_string_pretty(&fingerprint)?;
    std::fs::write(&output_file, json_output)?;
    
    info!("Fingerprint results saved to: {}", output_file);
    
    Ok(())
}

async fn run_dns_mode(domain: &str) -> Result<()> {
    info!("Starting DNS analysis for domain: {}", domain);
    
    let resolver = DnsResolver::default()?;
    let analysis = resolver.resolve_comprehensive(domain).await?;
    
    println!("\n=== DNS ANALYSIS RESULTS ===");
    println!("Domain: {}", analysis.domain);
    
    println!("\n--- IP Addresses ---");
    for ip in &analysis.ip_addresses {
        println!("{}", ip);
    }
    
    println!("\n--- Reverse DNS ---");
    for (ip, hostname) in &analysis.reverse_dns {
        println!("{} -> {}", ip, hostname);
    }
    
    if !analysis.mx_records.is_empty() {
        println!("\n--- MX Records ---");
        for mx in &analysis.mx_records {
            println!("{}", mx);
        }
    }
    
    if !analysis.ns_records.is_empty() {
        println!("\n--- NS Records ---");
        for ns in &analysis.ns_records {
            println!("{}", ns);
        }
    }
    
    if !analysis.txt_records.is_empty() {
        println!("\n--- TXT Records ---");
        for txt in &analysis.txt_records {
            println!("{}", txt);
        }
    }
    
    if !analysis.subdomains.is_empty() {
        println!("\n--- Discovered Subdomains ---");
        for subdomain in &analysis.subdomains {
            println!("{}", subdomain);
        }
    }
    
    if !analysis.authoritative_servers.is_empty() {
        println!("\n--- Authoritative Servers ---");
        for server in &analysis.authoritative_servers {
            println!("{}", server);
        }
    }
    
    // Save results
    let output_file = format!("results/dns_{}.json", domain.replace(".", "_"));
    std::fs::create_dir_all("results").ok();
    let json_output = serde_json::to_string_pretty(&analysis)?;
    std::fs::write(&output_file, json_output)?;
    
    info!("DNS analysis results saved to: {}", output_file);
    
    Ok(())
}

async fn run_geo_mode(ip_list: &str, geoip_db_path: Option<&String>) -> Result<()> {
    info!("Starting geolocation analysis");
    
    // Parse IP addresses
    let ips: Result<Vec<IpAddr>> = ip_list
        .split(',')
        .map(|ip_str| ip_str.trim().parse()
            .map_err(|_| piranha_swarm_core::PiranhaError::Parse(format!("Invalid IP: {}", ip_str))))
        .collect();
    let ips = ips?;
    
    // Initialize geolocator
    let geolocator = if let Some(db_path) = geoip_db_path {
        // Assume ASN database is in the same directory
        let asn_db_path = db_path.replace("City", "ASN");
        GeoLocator::with_databases(db_path, &asn_db_path)?
    } else {
        GeoLocator::new()
    };
    
    let analysis = geolocator.analyze_locations(ips).await?;
    
    println!("\n=== GEOLOCATION ANALYSIS ===");
    
    println!("\n--- Individual Locations ---");
    for location in &analysis.locations {
        println!("IP: {}", location.ip);
        if let Some(ref country) = location.country_name {
            println!("  Country: {}", country);
        }
        if let Some(ref region) = location.region {
            println!("  Region: {}", region);
        }
        if let Some(ref city) = location.city {
            println!("  City: {}", city);
        }
        if let (Some(lat), Some(lon)) = (location.latitude, location.longitude) {
            println!("  Coordinates: {:.4}, {:.4}", lat, lon);
        }
        if let Some(asn) = location.asn {
            println!("  ASN: {}", asn);
        }
        if let Some(ref org) = location.asn_org {
            println!("  Organization: {}", org);
        }
        if location.is_anonymous_proxy.unwrap_or(false) {
            println!("  ⚠️  Anonymous proxy detected");
        }
        println!();
    }
    
    println!("--- Country Distribution ---");
    for (country, count) in &analysis.country_distribution {
        println!("{}: {}", country, count);
    }
    
    if !analysis.distance_analysis.is_empty() {
        println!("\n--- Distance Analysis ---");
        for distance in &analysis.distance_analysis {
            println!("{} <-> {}: {:.2} km", 
                distance.from_ip, distance.to_ip, distance.distance_km);
            if distance.is_suspicious {
                println!("  ⚠️  Suspicious distance");
            }
        }
    }
    
    println!("\n--- Anomaly Detection ---");
    if !analysis.anomaly_detection.unusual_locations.is_empty() {
        println!("Unusual locations: {:?}", analysis.anomaly_detection.unusual_locations);
    }
    if !analysis.anomaly_detection.vpn_indicators.is_empty() {
        println!("VPN indicators: {:?}", analysis.anomaly_detection.vpn_indicators);
    }
    if !analysis.anomaly_detection.proxy_indicators.is_empty() {
        println!("Proxy indicators: {:?}", analysis.anomaly_detection.proxy_indicators);
    }
    if !analysis.anomaly_detection.datacenter_ips.is_empty() {
        println!("Datacenter IPs: {:?}", analysis.anomaly_detection.datacenter_ips);
    }
    
    // Save results
    let output_file = "results/geolocation_analysis.json";
    std::fs::create_dir_all("results").ok();
    let json_output = serde_json::to_string_pretty(&analysis)?;
    std::fs::write(output_file, json_output)?;
    
    info!("Geolocation analysis saved to: {}", output_file);
    
    Ok(())
}