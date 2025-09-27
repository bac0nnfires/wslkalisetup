#!/bin/bash

# WSL Kali Setup - Cybersecurity Configuration Installer
# ==============================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO_URL="https://raw.githubusercontent.com/cyb0rgdoll/wslkalisetup/main"
BACKUP_DIR="$HOME/.wslkali_backup_$(date +%Y%m%d_%H%M%S)"

# Print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Create backup
create_backup() {
    print_status "Creating backup of existing configuration..."
    mkdir -p "$BACKUP_DIR"
    
    if [ -f "$HOME/.zshrc" ]; then
        cp "$HOME/.zshrc" "$BACKUP_DIR/zshrc.backup"
        print_success "Backed up .zshrc to $BACKUP_DIR"
    fi
    
    if [ -d "$HOME/.oh-my-zsh" ]; then
        cp -r "$HOME/.oh-my-zsh" "$BACKUP_DIR/oh-my-zsh.backup" 2>/dev/null || true
        print_success "Backed up oh-my-zsh configuration"
    fi
}

# Check system requirements
check_requirements() {
    print_status "Checking system requirements..."
    
    # Check if running on Linux
    if [[ "$OSTYPE" != "linux-gnu"* ]]; then
        print_warning "This installer is designed for Linux systems"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # Check for required commands
    local required_commands=("curl" "git" "zsh" "wget" "unzip")
    local missing_commands=()
    
    for cmd in "${required_commands[@]}"; do
        if ! command_exists "$cmd"; then
            missing_commands+=("$cmd")
        fi
    done
    
    if [ ${#missing_commands[@]} -ne 0 ]; then
        print_error "Missing required commands: ${missing_commands[*]}"
        print_status "Installing missing dependencies..."
        
        # Detect package manager and install
        if command_exists "apt"; then
            sudo apt update
            sudo apt install -y "${missing_commands[@]}"
        elif command_exists "yum"; then
            sudo yum install -y "${missing_commands[@]}"
        elif command_exists "pacman"; then
            sudo pacman -S "${missing_commands[@]}"
        else
            print_error "Could not detect package manager. Please install: ${missing_commands[*]}"
            exit 1
        fi
    fi
    
    print_success "System requirements satisfied"
}

# Install Oh My Zsh
install_oh_my_zsh() {
    if [ ! -d "$HOME/.oh-my-zsh" ]; then
        print_status "Installing Oh My Zsh..."
        
        # Download and run Oh My Zsh installer
        RUNZSH=no CHSH=no sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
        
        print_success "Oh My Zsh installed"
    else
        print_status "Oh My Zsh already installed"
    fi
}

# Install Zsh plugins
install_zsh_plugins() {
    print_status "Installing Zsh plugins..."
    
    local plugin_dir="$HOME/.oh-my-zsh/custom/plugins"
    
    # zsh-autosuggestions
    if [ ! -d "$plugin_dir/zsh-autosuggestions" ]; then
        git clone https://github.com/zsh-users/zsh-autosuggestions "$plugin_dir/zsh-autosuggestions"
        print_success "Installed zsh-autosuggestions"
    fi
    
    # zsh-syntax-highlighting
    if [ ! -d "$plugin_dir/zsh-syntax-highlighting" ]; then
        git clone https://github.com/zsh-users/zsh-syntax-highlighting "$plugin_dir/zsh-syntax-highlighting"
        print_success "Installed zsh-syntax-highlighting"
    fi
    
    # zsh-completions
    if [ ! -d "$plugin_dir/zsh-completions" ]; then
        git clone https://github.com/zsh-users/zsh-completions "$plugin_dir/zsh-completions"
        print_success "Installed zsh-completions"
    fi
}

# Download and install configuration
install_configuration() {
    print_status "Downloading enhanced WSL Kali cybersecurity configuration..."
    
    # Download the main configuration file
    curl -fsSL "$REPO_URL/.zshrc" -o "$HOME/.zshrc.wslkali"
    
    # Backup existing .zshrc if it exists
    if [ -f "$HOME/.zshrc" ]; then
        mv "$HOME/.zshrc" "$HOME/.zshrc.old"
        print_warning "Existing .zshrc moved to .zshrc.old"
    fi
    
    # Install new configuration
    mv "$HOME/.zshrc.wslkali" "$HOME/.zshrc"
    
    print_success "Enhanced WSL Kali cybersecurity configuration installed"
}

# Set Zsh as default shell
set_default_shell() {
    if [ "$SHELL" != "$(which zsh)" ]; then
        print_status "Setting Zsh as default shell..."
        
        # Add zsh to valid shells if not present
        if ! grep -q "$(which zsh)" /etc/shells; then
            echo "$(which zsh)" | sudo tee -a /etc/shells
        fi
        
        # Change default shell
        chsh -s "$(which zsh)"
        print_success "Default shell changed to Zsh"
        print_warning "Please log out and log back in for shell change to take effect"
    else
        print_status "Zsh is already the default shell"
    fi
}

# Install basic penetration testing tools
install_basic_tools() {
    print_status "Installing basic penetration testing tools..."
    
    sudo apt update
    
    local tools=(
        "nmap" "gobuster" "nikto" "whatweb" "curl" "wget" "git"
        "enum4linux" "smbclient" "netcat-openbsd" "xclip" "tree" "jq"
        "make" "unzip" "masscan" "amass" "metasploit-framework"
        "python3-pip" "searchsploit"
    )
    
    for tool in "${tools[@]}"; do
        if ! dpkg -l | grep -q "^ii  $tool "; then
            print_status "Installing $tool..."
            sudo apt install -y "$tool" || print_warning "Failed to install $tool"
        else
            print_status "$tool already installed"
        fi
    done
    
    # Install wordlists
    if [ ! -d "/usr/share/wordlists" ]; then
        print_status "Installing wordlists..."
        sudo apt install -y wordlists || print_warning "Failed to install wordlists"
    fi
    
    print_success "Basic tools installation completed"
}

# Install modern tools
install_modern_tools() {
    print_status "Installing modern security tools..."
    
    # Install ffuf (fast web fuzzer)
    if ! command_exists "ffuf"; then
        print_status "Installing ffuf..."
        local temp_dir=$(mktemp -d)
        cd "$temp_dir"
        wget -q https://github.com/ffuf/ffuf/releases/latest/download/ffuf_2.1.0_linux_amd64.tar.gz
        tar -xzf ffuf_2.1.0_linux_amd64.tar.gz
        sudo mv ffuf /usr/local/bin/
        cd - > /dev/null
        rm -rf "$temp_dir"
        print_success "ffuf installed"
    fi
    
    # Install feroxbuster (recursive directory scanner)
    if ! command_exists "feroxbuster"; then
        print_status "Installing feroxbuster..."
        local temp_dir=$(mktemp -d)
        cd "$temp_dir"
        wget -q https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.zip
        unzip -q x86_64-linux-feroxbuster.zip
        sudo mv feroxbuster /usr/local/bin/
        cd - > /dev/null
        rm -rf "$temp_dir"
        print_success "feroxbuster installed"
    fi
    
    print_success "Modern tools installation completed"
}

# Install neofetch from specific release version
install_neofetch() {
    if ! command_exists "neofetch"; then
        print_status "Installing neofetch v7.1.0..."
        
        # Create temp directory
        local temp_dir=$(mktemp -d)
        cd "$temp_dir"
        
        # Download specific release version 7.1.0
        if curl -sL "https://github.com/dylanaraps/neofetch/archive/refs/tags/7.1.0.zip" -o neofetch.zip && unzip -q neofetch.zip; then
            cd neofetch-7.1.0
            sudo make install
            print_success "Neofetch v7.1.0 installed successfully!"
        else
            print_error "Failed to download neofetch v7.1.0"
        fi
        
        # Clean up
        cd - > /dev/null
        rm -rf "$temp_dir"
    else
        print_success "Neofetch already installed"
    fi
}

# Setup cybersecurity environment
setup_environment() {
    print_status "Setting up enhanced cybersecurity environment..."
    
    # Create directory structure
    mkdir -p "$HOME/cybersec"/{scans,exploits,loot,notes,scripts,tools,wordlists,reports,targets}
    mkdir -p "$HOME/cybersec/scans"/{nmap,web,vuln}
    mkdir -p "$HOME/cybersec/reports"/{daily,final}
    mkdir -p "$HOME/cybersec/notes"/{targets,methodology,findings}
    
    # Create useful scripts
    cat > "$HOME/cybersec/scripts/listener.sh" << 'EOF'
#!/bin/bash
# Simple netcat listener
port=${1:-4444}
echo "Starting listener on port $port..."
nc -lvnp $port
EOF
    chmod +x "$HOME/cybersec/scripts/listener.sh"
    
    # Create quick recon script
    cat > "$HOME/cybersec/scripts/quick-recon.sh" << 'EOF'
#!/bin/bash
# Quick reconnaissance script
target=$1
if [ -z "$target" ]; then
    echo "Usage: $0 <target>"
    exit 1
fi

echo "Quick reconnaissance for $target"
mkdir -p "recon_$target"
cd "recon_$target"

echo "Port scanning..."
nmap -sC -sV $target -oA nmap_scan

echo "Web enumeration..."
if nmap -p 80,443 $target | grep -q "open"; then
    whatweb $target > whatweb.txt 2>/dev/null || true
    if [ -f /usr/share/wordlists/dirb/common.txt ]; then
        gobuster dir -u http://$target -w /usr/share/wordlists/dirb/common.txt -o gobuster.txt -q
    fi
fi

echo "Reconnaissance complete - check recon_$target directory"
EOF
    chmod +x "$HOME/cybersec/scripts/quick-recon.sh"
    
    # Create notes template
    cat > "$HOME/cybersec/notes/template.md" << 'EOF'
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
    
    # Setup API keys directory
    mkdir -p "$HOME/.config/cybersec"
    
    # Create API keys template
    cat > "$HOME/.config/cybersec/api_keys.env" << 'EOF'
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

# Project Discovery (Nuclei, Subfinder, etc.)
# export PROJECT_DISCOVERY_API_KEY="your_pd_api_key_here"

EOF
    chmod 600 "$HOME/.config/cybersec/api_keys.env"
    
    print_success "Enhanced cybersecurity environment setup completed"
}

# Install Go-based security tools
install_go_tools() {
    print_status "Installing Go-based security tools..."
    
    # Check if Go is installed
    if ! command_exists "go"; then
        print_status "Installing Go programming language..."
        local temp_dir=$(mktemp -d)
        cd "$temp_dir"
        wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
        sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
        cd - > /dev/null
        rm -rf "$temp_dir"
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
    )
    
    for tool in "${go_tools[@]}"; do
        print_status "Installing $(basename $tool)..."
        go install "$tool" || print_warning "Failed to install $tool"
    done
    
    print_success "Go tools installation completed"
}

# Create uninstaller
create_uninstaller() {
    cat > "$HOME/.wslkali_uninstall.sh" << 'EOF'
#!/bin/bash
# WSL Kali Setup Uninstaller

echo "WSL Kali Cybersecurity Configuration Uninstaller"
echo "================================================"
echo ""

read -p "Are you sure you want to uninstall WSL Kali configuration? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Uninstall cancelled."
    exit 1
fi

# Find backup directory
BACKUP_DIR=$(find "$HOME" -maxdepth 1 -name ".wslkali_backup_*" -type d | head -1)

if [ -n "$BACKUP_DIR" ] && [ -d "$BACKUP_DIR" ]; then
    echo "Restoring from backup: $BACKUP_DIR"
    
    if [ -f "$BACKUP_DIR/zshrc.backup" ]; then
        cp "$BACKUP_DIR/zshrc.backup" "$HOME/.zshrc"
        echo "Restored .zshrc"
    fi
    
    if [ -d "$BACKUP_DIR/oh-my-zsh.backup" ]; then
        rm -rf "$HOME/.oh-my-zsh"
        cp -r "$BACKUP_DIR/oh-my-zsh.backup" "$HOME/.oh-my-zsh"
        echo "Restored oh-my-zsh"
    fi
else
    echo "No backup found. Removing WSL Kali configuration..."
    rm -f "$HOME/.zshrc"
    
    if [ -f "$HOME/.zshrc.old" ]; then
        mv "$HOME/.zshrc.old" "$HOME/.zshrc"
        echo "Restored previous .zshrc"
    fi
fi

# Remove cybersec directory (with confirmation)
if [ -d "$HOME/cybersec" ]; then
    read -p "Remove cybersec directory? This will delete all your work! (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$HOME/cybersec"
        echo "Removed cybersec directory"
    fi
fi

# Remove API config
rm -rf "$HOME/.config/cybersec"

# Remove this uninstaller
rm -f "$HOME/.wslkali_uninstall.sh"

echo ""
echo "WSL Kali uninstallation completed"
echo "Please restart your terminal or run: source ~/.zshrc"
EOF
    
    chmod +x "$HOME/.wslkali_uninstall.sh"
    print_success "Uninstaller created at ~/.wslkali_uninstall.sh"
}

# Main installation function
main() {
    echo "WSL Kali Setup - Cybersecurity Configuration Installer"
    echo "=============================================================="
    echo ""
    echo "This installer will:"
    echo "• Install Oh My Zsh and required plugins"
    echo "• Install enhanced WSL Kali cybersecurity configuration"
    echo "• Setup comprehensive cybersecurity workspace"
    echo "• Install modern penetration testing tools"
    echo "• Install neofetch with system information display"
    echo "• Create organized directory structure"
    echo "• Setup API key management"
    echo "• Create backup of existing configuration"
    echo ""
    
    read -p "Continue with installation? (Y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        echo "Installation cancelled."
        exit 0
    fi
    
    # Installation steps
    create_backup
    check_requirements
    install_oh_my_zsh
    install_zsh_plugins
    install_configuration
    install_basic_tools
    install_modern_tools
    install_neofetch
    setup_environment
    set_default_shell
    create_uninstaller
    
    # Ask about Go tools
    echo ""
    read -p "Install Go-based security tools? (Y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        install_go_tools
    fi
    
    echo ""
    echo "WSL Kali Setup Installation Completed!"
    echo "============================================="
    echo ""
    echo "Backup created at: $BACKUP_DIR"
    echo "Uninstaller available at: ~/.wslkali_uninstall.sh"
    echo ""
    echo "New Features Available:"
    echo "• Complete workflow automation with 'full_recon <target>'"
    echo "• CVE lookup with 'cve_lookup <CVE-ID>'"
    echo "• Metasploit integration with 'msf' and 'msf_payload'"
    echo "• Custom wordlist management"
    echo "• Modern tools: ffuf, feroxbuster, masscan"
    echo "• Comprehensive aliases - use 'show_aliases' to see all"
    echo ""
    echo "Next steps:"
    echo "1. Restart your terminal or run: source ~/.zshrc"
    echo "2. Run: setup-cybersec (if not auto-completed)"
    echo "3. Run: cybersec-help (for detailed usage information)"
    echo "4. Run: show_aliases (to see all available shortcuts)"
    echo "5. Edit ~/.config/cybersec/api_keys.env (to add your API keys)"
    echo ""
    echo "Documentation: https://github.com/cyb0rgdoll/wslkalisetup"
    echo "Issues: https://github.com/cyb0rgdoll/wslkalisetup/issues"
    echo ""
    
    # Ask if user wants to restart shell now
    read -p "Restart shell now? (Y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        exec zsh
    fi
}

# Handle script arguments
case "${1:-}" in
    "--help"|"-h")
        echo "WSL Kali Setup - Enhanced Cybersecurity Configuration Installer"
        echo ""
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --unattended   Run installation without prompts"
        echo "  --no-tools     Skip tool installation"
        echo "  --no-go        Skip Go tools installation"
        echo ""
        echo "Examples:"
        echo "  $0                    # Interactive installation"
        echo "  $0 --unattended      # Automated installation"
        echo "  $0 --no-tools        # Install config only, no tools"
        echo ""
        exit 0
        ;;
    "--unattended")
        # Set unattended mode
        export DEBIAN_FRONTEND=noninteractive
        UNATTENDED=true
        ;;
    "--no-tools")
        NO_TOOLS=true
        ;;
    "--no-go")
        NO_GO=true
        ;;
esac

# Unattended installation function
unattended_install() {
    echo "Running unattended installation..."
    
    create_backup
    check_requirements
    install_oh_my_zsh
    install_zsh_plugins
    install_configuration
    
    if [[ "$NO_TOOLS" != "true" ]]; then
        install_basic_tools
        install_modern_tools
        install_neofetch
    fi
    
    setup_environment
    set_default_shell
    create_uninstaller
    
    if [[ "$NO_GO" != "true" && "$NO_TOOLS" != "true" ]]; then
        install_go_tools
    fi
    
    echo "Unattended installation completed successfully!"
}

# Run appropriate installation
if [[ "$UNATTENDED" == "true" ]]; then
    unattended_install
else
    main "$@"
fi
