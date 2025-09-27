# 🛡️ PANDABOX Cybersecurity Configuration - WSL Kali

A comprehensive Zsh configuration designed for cybersecurity professionals, penetration testers, and security researchers. This configuration provides an organized, efficient environment with automated tools and workflows for security testing.

## 🚀 Features

### Core Functionality
- **Automated Reconnaissance**: Network discovery, port scanning, service enumeration
- **Web Application Testing**: Comprehensive web security assessment tools
- **Payload Generation**: Multiple reverse shell and exploit payload generators
- **File Management**: Enhanced file viewing and copying utilities
- **Environment Setup**: Organized workspace for security testing projects

### Advanced Tools Integration
- **Network Scanning**: Nmap integration with custom profiles
- **Web Testing**: Gobuster, Nikto, whatweb automation
- **Subdomain Enumeration**: Multiple tool integration (subfinder, assetfinder)
- **Vulnerability Assessment**: Automated vulnerability scanning workflows
- **Encoding/Decoding**: Built-in utilities for common encoding schemes

### Quality of Life Improvements
- **Enhanced History**: Advanced command history with deduplication
- **Smart Completion**: Intelligent auto-completion for security tools
- **Quick Navigation**: Fast workspace and directory switching
- **Copy/Paste Optimization**: Better terminal text handling
- **Colour-coded Output**: Enhanced readability for scan results

## 📦 Installation

### Prerequisites
- Linux-based system (Kali, Ubuntu, Debian recommended)
- Zsh shell
- Oh-My-Zsh (will be prompted to install if missing)

### Quick Install
```bash
# Backup your current configuration
cp ~/.zshrc ~/.zshrc.backup

# Download and install
curl -fsSL https://github.com/cyb0rgdoll/wslsetupscript/blob/88d55508962eeab3de96dc2b1fa1d08ec1945577/wslscript.sh | bash

wget https://github.com/cyb0rgdoll/wslsetupscript
```

### First-time Setup
```bash
# Initialize the cybersecurity environment
setup-cybersec

# Install common penetration testing tools
install-pentest-tools

# Install Go-based security tools (optional)
install-go-tools

# Install Python security tools (optional)
install-python-tools

# Setup API keys (optional)
setup_api_keys
```

## 🛠️ Usage

### Quick Start Commands

#### Network Reconnaissance
```bash
# Discover live hosts on a network
discover 192.168.1.0/24

# Quick target scan
quickscan 192.168.1.100

# Detailed port scanning
portscan 192.168.1.100 1-10000

# Vulnerability enumeration
enum 192.168.1.100
```

#### Web Application Testing
```bash
# Comprehensive web testing
webtest https://example.com

# Domain reconnaissance
recon-domain example.com

# Start local HTTP server
serve 8080
```

#### Payload Generation
```bash
# Generate reverse shells
payload bash 4444
payload python 4444
payload powershell 4444

# Start listener with payloads
revshell 4444
```

#### File Operations
```bash
# View file with line numbers
viewfile script.sh

# Copy file content (plain text)
copytext config.txt

# Extract specific lines
copylines logfile.txt 100 200

# Copy to clipboard
toclip important.txt
```

### Advanced Features

#### Automated Reconnaissance
```bash
# Full automated recon pipeline
autorecon target.com

# SMB enumeration
smbenum 192.168.1.100

# Monitor network traffic
monitor eth0
```

#### Encoding/Decoding
```bash
# Encode data
encode base64 "hello world"
encode url "special chars &"
encode hex "binary data"

# Decode data
decode base64 "aGVsbG8gd29ybGQ="
decode url "special%20chars%20%26"
```

#### Utilities
```bash
# Network information
myip

# Generate passwords
genpass 16 5

# Quick port check
ports 192.168.1.1

# Vulnerability check
vulncheck 192.168.1.100
```

## 📁 Directory Structure

After running `setup-cybersec`, your workspace will be organized as:

```
~/cybersec/
├── scans/               # Scan results
│   ├── nmap/           # Nmap scans
│   ├── web/            # Web scans
│   └── vuln/           # Vulnerability scans
├── exploits/           # Exploit code and payloads
├── loot/               # Extracted data and credentials
├── notes/              # Documentation and findings
│   ├── targets/        # Target-specific notes
│   ├── methodology/    # Testing methodologies
│   └── findings/       # Vulnerability findings
├── scripts/            # Custom scripts
├── tools/              # Additional tools
├── wordlists/          # Custom wordlists
└── reports/            # Final reports
    ├── daily/          # Daily progress reports
    └── final/          # Final assessment reports
```

## ⚙️ Configuration

### API Keys Setup
```bash
# Create API keys configuration
setup_api_keys

# Edit the configuration file
nano ~/.config/cybersec/api_keys.env
```

### Customization
The configuration is modular and can be customized by editing `~/.zshrc`. Key sections:

- **Core Functions**: Main security testing functions
- **File Operations**: Enhanced file handling
- **Network Tools**: Scanning and enumeration
- **Payload Generation**: Exploit and shell generation
- **Utilities**: Helper functions and tools

### Environment Variables
```bash
# Customize your attack IP (default: auto-detected)
export ATTACK_IP="10.10.10.100"

# Set default ports
export DEFAULT_LISTENER_PORT="4444"

# Custom wordlist paths
export CUSTOM_WORDLIST="/path/to/wordlist.txt"
```

## 🔧 Tool Integration

### Supported Tools
- **Network**: nmap, masscan, zmap
- **Web**: gobuster, dirb, nikto, whatweb, sqlmap
- **Enumeration**: enum4linux, smbclient, ldapsearch
- **Exploitation**: metasploit, john, hashcat, hydra
- **Reconnaissance**: subfinder, assetfinder, amass, httprobe
- **Analysis**: wireshark, tcpdump, burp suite

### Installation Scripts
The configuration includes automated installation for:
- Core penetration testing tools (APT packages)
- Go-based security tools (subfinder, httpx, nuclei)
- Python security libraries (impacket, crackmapexec)

## 📚 Examples

### Penetration Testing Workflow
```bash
# 1. Setup environment
setup-cybersec
cd ~/cybersec

# 2. Network discovery
discover 192.168.1.0/24

# 3. Target scanning
quickscan 192.168.1.100

# 4. Web application testing
webtest http://192.168.1.100

# 5. Generate payloads if needed
payload bash 4444

# 6. Document findings
cd notes/targets
nano 192.168.1.100.md
```

### Bug Bounty Workflow
```bash
# 1. Domain reconnaissance
recon-domain target.com

# 2. Subdomain enumeration
subfinder -d target.com | httpx -silent

# 3. Web technology detection
webtest https://target.com

# 4. Automated vulnerability scanning
autorecon target.com
```

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting pull requests.

### How to Contribute
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-tool`)
3. Commit your changes (`git commit -am 'Add new tool integration'`)
4. Push to the branch (`git push origin feature/new-tool`)
5. Create a Pull Request

### Areas for Contribution
- New tool integrations
- Performance improvements
- Documentation enhancements
- Bug fixes and optimizations
- Platform support (macOS, other Linux distributions)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This configuration is designed for authorized security testing only. Users are responsible for ensuring they have proper authorization before using these tools against any systems. The authors are not responsible for any misuse or damage caused by this software.

## 🔗 Related Projects

- [Oh My Zsh](https://github.com/ohmyzsh/ohmyzsh) - Framework for managing Zsh configuration
- [ProjectDiscovery Tools](https://github.com/projectdiscovery) - Modern security tools
- [SecLists](https://github.com/danielmiessler/SecLists) - Security testing wordlists


## Acknowledgments

- The cybersecurity community for tool development and testing methodologies
- Oh My Zsh team for the excellent framework
- ProjectDiscovery for modern security tools
- All contributors and users providing feedback
