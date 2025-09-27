#!/bin/bash

# Cybersecurity Configuration Installer
# ==============================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO_URL="https://github.com/cyb0rgdoll/wslkalisetup/"
BACKUP_DIR="$HOME/.pandabox_backup_$(date +%Y%m%d_%H%M%S)"

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
    local required_commands=("curl" "git" "zsh")
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
    print_status "Downloading PANDABOX configuration..."
    
    # Download the main configuration file
    curl -fsSL "$REPO_URL/.zshrc" -o "$HOME/.zshrc.pandabox"
    
    # Backup existing .zshrc if it exists
    if [ -f "$HOME/.zshrc" ]; then
        mv "$HOME/.zshrc" "$HOME/.zshrc.old"
        print_warning "Existing .zshrc moved to .zshrc.old"
    fi
    
    # Install new configuration
    mv "$HOME/.zshrc.pandabox" "$HOME/.zshrc"
    
    print_success "PANDABOX configuration installed"
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
    
    local tools=(
        "nmap"
        "gobuster" 
        "nikto"
        "whatweb"
        "curl"
        "wget"
        "git"
        "netcat-openbsd"
        "xclip"
    )
    
    if command_exists "apt"; then
        sudo apt update
        for tool in "${tools[@]}"; do
            if ! command_exists "$tool"; then
                print_status "Installing $tool..."
                sudo apt install -y "$tool" || print_warning "Failed to install $tool"
            fi
        done
    elif command_exists "yum"; then
        for tool in "${tools[@]}"; do
            if ! command_exists "$tool"; then
                print_status "Installing $tool..."
                sudo yum install -y "$tool" || print_warning "Failed to install $tool"
            fi
        done
    else
        print_warning "Could not auto-install tools. Please install manually: ${tools[*]}"
    fi
    
    print_success "Basic tools installation completed"
}

# Setup cybersecurity environment
setup_environment() {
    print_status "Setting up cybersecurity environment..."
    
    # Create directory structure
    mkdir -p "$HOME/cybersec"/{scans,exploits,loot,notes,scripts,tools,wordlists,reports}
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
    
    print_success "Cybersecurity environment setup completed"
}

# Create uninstaller
create_uninstaller() {
    cat > "$HOME/.pandabox_uninstall.sh" << 'EOF'
#!/bin/bash
# PANDABOX Uninstaller

echo "🗑️ Cybersecurity Configuration Uninstaller"
echo "=================================================="
echo ""

read -p "Are you sure you want to uninstall configuration? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Uninstall cancelled."
    exit 1
fi

# Find backup directory
BACKUP_DIR=$(find "$HOME" -maxdepth 1 -name ".pandabox_backup_*" -type d | head -1)

if [ -n "$BACKUP_DIR" ] && [ -d "$BACKUP_DIR" ]; then
    echo "Restoring from backup: $BACKUP_DIR"
    
    if [ -f "$BACKUP_DIR/zshrc.backup" ]; then
        cp "$BACKUP_DIR/zshrc.backup" "$HOME/.zshrc"
        echo "✅ Restored .zshrc"
    fi
    
    if [ -d "$BACKUP_DIR/oh-my-zsh.backup" ]; then
        rm -rf "$HOME/.oh-my-zsh"
        cp -r "$BACKUP_DIR/oh-my-zsh.backup" "$HOME/.oh-my-zsh"
        echo "✅ Restored oh-my-zsh"
    fi
else
    echo "⚠️ No backup found. Removing configuration..."
    rm -f "$HOME/.zshrc"
    
    if [ -f "$HOME/.zshrc.old" ]; then
        mv "$HOME/.zshrc.old" "$HOME/.zshrc"
        echo "✅ Restored previous .zshrc"
    fi
fi

# Remove cybersec directory (with confirmation)
if [ -d "$HOME/cybersec" ]; then
    read -p "Remove cybersec directory? This will delete all your work! (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$HOME/cybersec"
        echo "✅ Removed cybersec directory"
    fi
fi

# Remove API config
rm -rf "$HOME/.config/cybersec"

# Remove this uninstaller
rm -f "$HOME/.uninstall.sh"

echo ""
echo "🗑️ uninstallation completed"
echo "Please restart your terminal or run: source ~/.zshrc"
EOF
    
    chmod +x "$HOME/.uninstall.sh"
    print_success "Uninstaller created at ~/.uninstall.sh"
}

# Main installation function
main() {
    echo "🛡️Cybersecurity Configuration Installer"
    echo "================================================"
    echo ""
    echo "This installer will:"
    echo "• Install Oh My Zsh and required plugins"
    echo "• Install cybersecurity configuration"
    echo "• Setup cybersecurity workspace"
    echo "• Install basic penetration testing tools"
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
    setup_environment
    set_default_shell
    create_uninstaller
    
    echo ""
    echo "🎉 Installation Completed!"
    echo "=================================="
    echo ""
    echo "📁 Backup created at: $BACKUP_DIR"
    echo "🗑️ Uninstaller available at: ~/.pandabox_uninstall.sh"
    echo ""
    echo "🚀 Next steps:"
    echo "1. Restart your terminal or run: source ~/.zshrc"
    echo "2. Run: setup-cybersec (if not auto-completed)"
    echo "3. Run: install-pentest-tools (for additional tools)"
    echo "4. Run: cybersec-help (for usage information)"
    echo ""
    echo "📖 Documentation: https://github.com/cyb0rgdoll/wslkalisetup"
    echo ""
    
    # Ask if user wants to restart shell now
    read -p "Restart shell now? (Y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        exec zsh
    fi
}

# Run main function
main "$@"
