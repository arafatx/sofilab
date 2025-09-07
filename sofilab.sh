#!/usr/bin/env bash
#
# sofilab.sh - Server Management and Administration Tool
# Provides SSH connections, server monitoring, and installation management
#
# Author: Arafat Ali <arafat@sofibox.com>
# Repository: https://github.com/arafatx/sofilab
#

set -Eeuo pipefail

# Version information
VERSION="1.0.0"
BUILD_DATE="2025-09-05"

# Global variables
# Resolve symlink to get the real script directory
if [[ -L "${BASH_SOURCE[0]}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "$(readlink "${BASH_SOURCE[0]}")")" && pwd)"
else
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi
SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
CONFIG_FILE="$SCRIPT_DIR/sofilab.conf"

# Logging functions
info() { echo "[INFO] $*" >&2; }
error() { echo "[ERROR] $*" >&2; }
warn() { echo "[WARN] $*" >&2; }

# Show usage
usage() {
    cat << EOF
Usage: $SCRIPT_NAME <command> [alias]

Commands:
  login <alias>       Connect to configured host using SSH alias
  install             Install sofilab command globally (requires sudo)
  uninstall           Uninstall sofilab command (requires sudo)
  --version, -V       Show version information
  --help, -h          Show this help message

Examples:
  $SCRIPT_NAME login pmx
  $SCRIPT_NAME install

Configuration format in sofilab.conf:
  [alias1,alias2]
  host="IP_ADDRESS"
  user="USERNAME"
  password="PASSWORD"
  port="SSH_PORT" (optional, default 22)
  keyfile="ssh/alias_key" (optional)
  scripts="script1.sh,script2.sh" (optional)

EOF
}

# Load and parse server configuration for given alias
get_server_config() {
    local alias="$1"
    local in_section=false
    local host="" user="" password="" port="" keyfile=""
    
    [[ ! -f "$CONFIG_FILE" ]] && { error "Config file not found: $CONFIG_FILE"; exit 1; }
    
    while IFS= read -r line; do
        line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        [[ -z "$line" || "$line" =~ ^# ]] && continue
        
        # Check for section header [alias1,alias2,...]
        if [[ "$line" =~ ^\[([^]]+)\]$ ]]; then
            in_section=false
            IFS=',' read -ra aliases <<< "${BASH_REMATCH[1]}"
            for a in "${aliases[@]}"; do
                a=$(echo "$a" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
                [[ "$a" == "$alias" ]] && { in_section=true; break; }
            done
            continue
        fi
        
        # Parse key=value pairs in current section
        if [[ "$in_section" == true && "$line" =~ ^([^=]+)=(.*)$ ]]; then
            local key="${BASH_REMATCH[1]}"
            local value="${BASH_REMATCH[2]}"
            value="${value#\"}"  # Remove quotes
            value="${value%\"}"
            
            case "$key" in
                host) host="$value" ;;
                user) user="$value" ;;
                password) password="$value" ;;
                port) port="$value" ;;
                keyfile) keyfile="$value" ;;
            esac
        fi
    done < "$CONFIG_FILE"
    
    # Export parsed values
    SERVER_HOST="$host"
    SERVER_USER="$user"
    SERVER_PASSWORD="$password"
    SERVER_PORT="${port:-22}"
    SERVER_KEYFILE="$keyfile"
}

# Check if a port is open without authentication (won't trigger firewall rules)
check_port_open() {
    local host="$1"
    local port="$2"
    local timeout=3
    
    # Try using nc (netcat) if available
    if command -v nc >/dev/null 2>&1; then
        # Different nc versions have different syntax
        if nc -h 2>&1 | grep -q "GNU netcat"; then
            # GNU netcat
            nc -z -w "$timeout" "$host" "$port" >/dev/null 2>&1
        else
            # BSD/macOS netcat
            nc -z -w "$timeout" "$host" "$port" >/dev/null 2>&1
        fi
        return $?
    fi
    
    # Fallback to bash's /dev/tcp if nc not available
    if [[ -n "$BASH_VERSION" ]]; then
        timeout "$timeout" bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null
        return $?
    fi
    
    # Last resort: use telnet if available
    if command -v telnet >/dev/null 2>&1; then
        (echo quit | timeout "$timeout" telnet "$host" "$port" 2>/dev/null | grep -q "Connected") 2>/dev/null
        return $?
    fi
    
    # If no tools available, return success to proceed with SSH attempt
    return 0
}

# Test SSH connectivity quickly
test_ssh_connection() {
    local port="$1"
    local keyfile="$2"
    
    # Try SSH key first if available
    if [[ -n "$keyfile" && -f "$keyfile" ]]; then
        if ssh -i "$keyfile" -p "$port" -o StrictHostKeyChecking=no -o PasswordAuthentication=no -o ConnectTimeout=5 "$SERVER_USER@$SERVER_HOST" "echo connected" >/dev/null 2>&1; then
            return 0  # SSH key worked
        fi
    fi
    
    # Try password if SSH key failed or not available
    if [[ -n "$SERVER_PASSWORD" ]] && command -v sshpass >/dev/null 2>&1; then
        if sshpass -p "$SERVER_PASSWORD" ssh -p "$port" -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$SERVER_USER@$SERVER_HOST" "echo connected" >/dev/null 2>&1; then
            return 0  # Password worked
        fi
    fi
    
    # Try direct SSH as last resort
    ssh -p "$port" -o ConnectTimeout=5 "$SERVER_USER@$SERVER_HOST" "echo connected" >/dev/null 2>&1
}

# Connect to server interactively
connect_ssh() {
    local port="$1"
    local keyfile="$2"
    
    # Try SSH key first if available
    if [[ -n "$keyfile" && -f "$keyfile" ]]; then
        if ssh -i "$keyfile" -p "$port" -o StrictHostKeyChecking=no -o PasswordAuthentication=no -o ConnectTimeout=5 "$SERVER_USER@$SERVER_HOST" "echo connected" >/dev/null 2>&1; then
            ssh -i "$keyfile" -p "$port" -o StrictHostKeyChecking=no "$SERVER_USER@$SERVER_HOST"
            return
        fi
    fi
    
    # Try password if SSH key failed or not available
    if [[ -n "$SERVER_PASSWORD" ]] && command -v sshpass >/dev/null 2>&1; then
        sshpass -p "$SERVER_PASSWORD" ssh -p "$port" -o StrictHostKeyChecking=no "$SERVER_USER@$SERVER_HOST"
        return
    fi
    
    # Direct SSH as last resort
    ssh -p "$port" "$SERVER_USER@$SERVER_HOST"
}

# Main SSH login function
ssh_login() {
    local alias="$1"
    
    info "Loading configuration: $CONFIG_FILE"
    get_server_config "$alias"
    
    [[ -z "$SERVER_HOST" ]] && { error "Unknown alias: $alias"; exit 1; }
    
    info "Connecting to $SERVER_HOST as $SERVER_USER"
    
    # Determine SSH key
    local keyfile=""
    if [[ -n "$SERVER_KEYFILE" ]]; then
        keyfile="$SCRIPT_DIR/$SERVER_KEYFILE"
        [[ -f "$keyfile" ]] && info "Using SSH key: $keyfile" || keyfile=""
    fi
    
    # Auto-detect key if not specified
    if [[ -z "$keyfile" ]]; then
        local auto_key="$SCRIPT_DIR/ssh/${alias}_key"
        [[ -f "$auto_key" ]] && { keyfile="$auto_key"; info "Using auto-detected SSH key: $keyfile"; }
    fi
    
    # Determine which port to use by checking port availability first
    local use_port=""
    
    # Check configured port first (without authentication to avoid firewall triggers)
    info "Checking port availability on $SERVER_PORT..."
    if check_port_open "$SERVER_HOST" "$SERVER_PORT"; then
        info "Port $SERVER_PORT is open $([ "$SERVER_PORT" == "22" ] && echo "(default SSH port)" || echo "(custom SSH port)")"
        use_port="$SERVER_PORT"
    elif [[ "$SERVER_PORT" != "22" ]]; then
        # Only try port 22 as fallback if configured port is different
        info "Port $SERVER_PORT is not accessible, checking fallback port 22..."
        if check_port_open "$SERVER_HOST" "22"; then
            info "Port 22 is open (fallback to default SSH port)"
            use_port="22"
        else
            error "Neither port $SERVER_PORT nor port 22 are accessible"
            error "Please check your network connection and firewall settings"
            exit 1
        fi
    else
        error "Port $SERVER_PORT is not accessible"
        error "Please check your network connection and firewall settings"
        exit 1
    fi
    
    # Now attempt SSH connection on the verified open port
    info "Attempting SSH connection on port $use_port..."
    if test_ssh_connection "$use_port" "$keyfile"; then
        info "Authentication successful"
        connect_ssh "$use_port" "$keyfile"
        info "Disconnected from $SERVER_HOST"
        return 0
    else
        error "Authentication failed on port $use_port"
        error "Please check your credentials or SSH key"
        exit 1
    fi
}

# Show version information
show_version() {
    echo "SofiLab Server Management Tool"
    echo "Version: $VERSION"
    echo "Build Date: $BUILD_DATE"
    echo "Author: Arafat Ali <arafat@sofibox.com>"
    echo "Repository: https://github.com/arafatx/sofilab"
    echo ""
    echo "Features: SSH connections, server monitoring, installation management"
}

# Install sofilab command globally
install_sofilab() {
    local install_dir="/usr/local/bin"
    local install_name="sofilab"
    local script_path="$SCRIPT_DIR/$SCRIPT_NAME"
    local symlink_path="$install_dir/$install_name"
    
    info "Installing sofilab command globally..."
    
    # Check if script exists
    if [[ ! -f "$script_path" ]]; then
        error "Script not found: $script_path"
        exit 1
    fi
    
    # Make script executable
    chmod +x "$script_path" || { error "Failed to make script executable"; exit 1; }
    info "Made script executable: $script_path"
    
    # Check if /usr/local/bin exists, create if needed
    if [[ ! -d "$install_dir" ]]; then
        info "Creating $install_dir directory..."
        sudo mkdir -p "$install_dir" || { error "Failed to create $install_dir"; exit 1; }
    fi
    
    # Remove existing symlink if it exists
    if [[ -L "$symlink_path" ]]; then
        info "Removing existing symlink..."
        sudo rm "$symlink_path" || { error "Failed to remove existing symlink"; exit 1; }
    elif [[ -f "$symlink_path" ]]; then
        error "File already exists at $symlink_path and is not a symlink"
        error "Please remove it manually or choose a different installation method"
        exit 1
    fi
    
    # Create symlink
    info "Creating symlink: $symlink_path -> $script_path"
    sudo ln -s "$script_path" "$symlink_path" || { error "Failed to create symlink"; exit 1; }
    
    # Verify installation
    if command -v "$install_name" >/dev/null 2>&1; then
        info "✓ Installation successful!"
        info "You can now use 'sofilab' command from anywhere"
        info ""
        info "Try: sofilab --help"
    else
        warn "Installation completed but 'sofilab' command not found in PATH"
        warn "You may need to add $install_dir to your PATH"
        warn "Add this line to your ~/.bashrc or ~/.zshrc:"
        warn "  export PATH=\"$install_dir:\$PATH\""
    fi
}

# Uninstall sofilab command
uninstall_sofilab() {
    local install_dir="/usr/local/bin"
    local install_name="sofilab"
    local symlink_path="$install_dir/$install_name"
    
    info "Uninstalling sofilab command..."
    
    if [[ -L "$symlink_path" ]]; then
        # It's a symlink, safe to remove
        sudo rm "$symlink_path" || { error "Failed to remove symlink"; exit 1; }
        info "✓ Removed symlink: $symlink_path"
        info "Uninstallation successful!"
    elif [[ -f "$symlink_path" ]]; then
        # It's a regular file, be cautious
        error "Found regular file at $symlink_path (not a symlink)"
        error "Please verify and remove manually if needed"
        exit 1
    else
        warn "No installation found at $symlink_path"
        info "Nothing to uninstall"
    fi
}

# Main function
main() {
    case "${1:-}" in
        login)
            [[ -z "${2:-}" ]] && { error "Alias required for login command"; usage; exit 1; }
            ssh_login "$2"
            ;;
        install)
            install_sofilab
            ;;
        uninstall)
            uninstall_sofilab
            ;;
        --version|-V|version)
            show_version
            ;;
        --help|-h|help)
            usage
            ;;
        "")
            usage
            ;;
        *)
            error "Unknown command: ${1:-}"
            usage
            exit 1
            ;;
    esac
}

# Run main function if script is executed directly
[[ "${BASH_SOURCE[0]}" == "${0}" ]] && main "$@"
