# Piranha Swarm

**Advanced Network Metadata Harvesting and Deanonymization Engine**

⚠️ **DISCLAIMER**: This tool is designed for legitimate security research, corporate intelligence, and investigative purposes only. Use only on networks and systems you own or have explicit permission to test.

## Overview

Piranha Swarm is a sophisticated network analysis and deanonymization platform built with Rust and Go. It implements advanced techniques for harvesting network metadata, analyzing traffic patterns, and correlating digital footprints to reveal the true identity and location of network actors.

## Architecture

The platform consists of several components:

### Core Engine (Rust)
- **Network Metadata Harvesting**: Raw packet capture and analysis
- **TCP/IP Fingerprinting**: OS detection and stack analysis  
- **DNS Analysis**: Comprehensive domain resolution and monitoring
- **Geolocation Engine**: IP address location analysis with anomaly detection

### Auxiliary Services (Go)
- **DNS Trap Server**: Generates per-session subdomains and logs queries
- **HTTP Bait Server**: Serves malicious payloads and tracks callbacks

## Features

### Network Analysis
- Multi-interface packet capture with TTL/TCP window analysis
- Real-time protocol distribution and bandwidth estimation
- Advanced timing analysis with jitter calculation and burst detection
- Reverse DNS lookups and BGP/ASN queries

### Fingerprinting
- TCP stack fingerprinting for OS identification
- HTTP service detection and banner grabbing
- Application-level protocol analysis
- Browser and client fingerprinting

### DNS Intelligence
- Comprehensive subdomain enumeration
- DNS history tracking and change monitoring
- Authoritative server identification
- Geo-distributed DNS analysis

### Geolocation & Privacy Detection
- MaxMind GeoIP database integration
- VPN/Proxy/Tor detection with known IP ranges
- Datacenter IP identification
- Impossible travel detection

### Entrapment Systems
- Dynamic DNS trap generation
- HTTP bait services with callback payloads
- Cross-platform payload generation
- Session tracking and correlation

## Quick Start

### Prerequisites
- Rust 1.70+ with Cargo
- Go 1.21+
- Root privileges (for packet capture)
- Optional: MaxMind GeoIP databases

### Installation

```bash
# Clone the repository
git clone https://github.com/itsbryanman/piranha-swarm.git
cd piranha-swarm

# Install dependencies
make deps

# Build all components
make build

# Install binaries (optional)
sudo make install
```

### Basic Usage

#### Network Metadata Harvesting
```bash
# Capture and analyze traffic for a target IP
./bin/piranha-swarm capture -i eth0 -t 192.168.1.100 -d 60

# Perform TCP fingerprinting
./bin/piranha-swarm fingerprint -t 192.168.1.100

# DNS analysis
./bin/piranha-swarm dns -d example.com

# Geolocation analysis
./bin/piranha-swarm geo -i "8.8.8.8,1.1.1.1,192.168.1.1"
```

#### Service Deployment
```bash
# Start DNS trap server
./bin/dns-trap -c config/dns-trap.yaml

# Start HTTP bait server  
./bin/http-bait -c config/http-bait.yaml
```

## Configuration

Configuration files are located in the `config/` directory:

- `default.json` - Core engine configuration
- `dns-trap.yaml` - DNS trap server settings
- `http-bait.yaml` - HTTP bait server settings

## Development

### Building from Source
```bash
# Build Rust core
make build-rust

# Build Go services
make build-go

# Run tests
make test

# Format code
make fmt

# Lint code
make lint
```

### Development Mode
```bash
# Run core engine in development
make dev-rust

# Run DNS trap in development
make dev-dns

# Run HTTP bait in development
make dev-http
```

## Security Considerations

### Legal Compliance
- Only use on networks you own or have permission to test
- Comply with all applicable laws and regulations
- Implement proper data protection and retention policies
- Honor robots.txt and rate limiting

### Ethical Guidelines
- Respect privacy and data protection laws
- Use defensive security practices only
- Implement access controls and audit logging
- Secure all collected data with encryption

## Output and Results

### Metadata Analysis
Results are saved in JSON format to the `results/` directory:
- Network metadata with timing analysis
- TCP fingerprints with OS detection
- DNS analysis with subdomain enumeration  
- Geolocation data with anomaly detection

### Session Tracking
All trap activations and payload deliveries are logged with:
- Session correlation across services
- Detailed request/response logging
- Browser and client fingerprinting
- Callback payload tracking

## Advanced Features

### Custom Payloads
The HTTP bait server generates dynamic payloads based on:
- User-Agent detection (Windows/Linux/Web)
- Request patterns and timing
- Session correlation data
- Callback mechanism integration

### Anomaly Detection
The system includes detection for:
- Unusual TTL patterns
- Sequential port scanning
- Rapid location changes
- VPN/Proxy usage indicators

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Ensure all tests pass (`make test`)
5. Format code (`make fmt`)
6. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This software is provided for educational and security research purposes only. The authors are not responsible for any misuse or damage caused by this software. Users are responsible for ensuring compliance with all applicable laws and regulations in their jurisdiction.

## Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Review the documentation in `docs/`
- Check the example configurations in `config/`

---

**Remember**: With great power comes great responsibility. Use this tool ethically and legally.