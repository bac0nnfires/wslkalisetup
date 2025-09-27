🛡️ WSL Kali Setup - Cybersecurity Configuration 

<img width="450" height="400" alt="image" src="https://github.com/user-attachments/assets/610cc583-a541-49d7-8a65-1196b76f9047" />
<img width="380" height="400" alt="image" src="https://github.com/user-attachments/assets/8b3651c0-90f8-4472-88de-c203cc6b0bc0" />


## 🚀 Features 🚀
Functionality and Advanced Tools Integration
- **Automated Reconnaissance**: Network discovery, port scanning, service enumeration
- **Web Application Testing**: Comprehensive web security assessment tools
- **Payload Generation**: Multiple reverse shell and exploit payload generators
- **File Management**: Enhanced file viewing and copying utilities
- **Environment Setup**: Organized workspace for security testing projects
- **Network Scanning**: Nmap integration with custom profiles
- **Web testing and modern Tools**: Gobuster, Nikto, whatweb automation, ffuf, feroxbuster, masscan, metasploit integration
- **Subdomain Enumeration**: Multiple tool integration (subfinder, assetfinder)
- **Vulnerability Assessment**: Automated vulnerability scanning workflows
- **Encoding/Decoding**: Built-in utilities for common encoding schemes
- **Enhanced History**: Advanced command history with deduplication
- **Smart Completion**: Intelligent auto-completion for security tools
- **Quick Navigation**: Fast workspace and directory switching
- **Automated Workflows**: `full_recon <target>` for complete reconnaissance
- **CVE Database**: `cve_lookup CVE-2021-44228` and exploit search
- **Smart Aliases**: 40+ shortcuts for common tasks
- **Organized Workspace**: Structured directories for scans, loot, reports
- **Enhanced Terminal**: Better history, completion, file operations

## 📦 Installation 📦

## Requirements
- Linux system (WSL, Kali, Ubuntu, Debian)
- Zsh shell (auto-installed)

### Quick Install
```bash
curl -fsSL https://raw.githubusercontent.com/cyb0rgdoll/wslkalisetup/main/install.sh | bash
```

### Options
```bash
./install.sh --unattended    # No prompts
./install.sh --no-tools      # Config only
./install.sh --help          # Show options
```

## Quick Usage

```bash
# Network reconnaissance
discover 192.168.1.0/24
quickscan 192.168.1.100
full_recon example.com

# Web testing
webtest https://example.com
ff -u https://example.com/FUZZ -w wordlist.txt

# Payload generation
payload bash 4444
msf_payload linux 4444
revshell 4444

# Vulnerability research
cve_lookup CVE-2021-44228
exploit_search "apache struts"

# View all shortcuts
show_aliases
cybersec-help
```

## Tools Installed

**Core**: nmap, gobuster, nikto, whatweb, enum4linux, metasploit-framework  
**Modern**: ffuf, feroxbuster, masscan, amass  
**Go Tools**: subfinder, httpx, nuclei (optional)  
**Utilities**: neofetch, searchsploit, custom wordlist management

## Directory Structure

```
~/cybersec/
├── scans/      # Scan results
├── loot/       # Extracted data
├── reports/    # Assessment reports
├── scripts/    # Custom tools
└── wordlists/  # Custom wordlists
```

## Configuration

**API Keys**: Edit `~/.config/cybersec/api_keys.env`  
**Customization**: Modify `~/.zshrc` sections as needed  
**Help**: Run `cybersec-help` for detailed usage

## Troubleshooting

```bash
# Test syntax
zsh -n ~/.zshrc

# Reinstall tools
install-pentest-tools

# Restore backup
cp ~/.zshrc.old ~/.zshrc
```

## Uninstall

```bash
~/.wslkali_uninstall.sh
```

## ⚠️ Disclaimer

This configuration is designed for authorized security testing only. Users are responsible for ensuring they have proper authorization before using these tools against any systems. The authors are not responsible for any misuse or damage caused by this software, script or code.

 [GitHub Issues](https://github.com/cyb0rgdoll/wslkalisetup/issues) for support
