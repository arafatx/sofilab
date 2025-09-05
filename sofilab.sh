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
  --version, -v       Show version information
  --help, -h          Show this help message

Examples:
  $SCRIPT_NAME login pmx
  $SCRIPT_NAME login pmx-home
  $SCRIPT_NAME login router

Configuration format in sofilab.conf:
  [alias1,alias2]
  host="IP_ADDRESS"
  user="USERNAME"
  password="PASSWORD"
  port="SSH_PORT" (optional, default 22)
  keyfile="ssh/alias_key" (optional)

Note: Script tries configured port first, falls back to port 22 if connection refused

Authentication priority:
  1. SSH key (if keyfile specified or ssh/<alias>_key exists)
  2. Password (if specified)
  3. Direct SSH (relies on SSH agent or default keys)

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
    info "Using port $SERVER_PORT $([ "$SERVER_PORT" == "22" ] && echo "(default SSH port)" || echo "(custom SSH port)")"
    
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
    
    # Try configured port first
    if test_ssh_connection "$SERVER_PORT" "$keyfile"; then
        info "Authentication successful"
        connect_ssh "$SERVER_PORT" "$keyfile"
        info "Disconnected from $SERVER_HOST"
        return 0
    fi
    
    # Fallback to port 22 if configured port != 22
    if [[ "$SERVER_PORT" != "22" ]]; then
        warn "Connection failed on port $SERVER_PORT, trying fallback port 22"
        if test_ssh_connection "22" "$keyfile"; then
            info "Authentication successful"
            connect_ssh "22" "$keyfile"
            info "Disconnected from $SERVER_HOST"
            return 0
        fi
    fi
    
    error "Could not establish SSH connection on any port"
    exit 1
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

# Main function
main() {
    case "${1:-}" in
        login)
            [[ -z "${2:-}" ]] && { error "Alias required for login command"; usage; exit 1; }
            ssh_login "$2"
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
