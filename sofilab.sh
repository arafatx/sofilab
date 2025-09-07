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
Usage: $SCRIPT_NAME <command> [alias] [options]

Commands:
  login <alias>               Connect to configured host using SSH alias
  reset-hostkey <alias>       Remove stored SSH host key (for reinstalled servers)
  run-scripts <alias>         Run all scripts defined for alias in order
  run-script <alias> <script> Run a specific script on remote server
  list-scripts <alias>        List available scripts for an alias
  install                     Install sofilab command globally (requires sudo)
  uninstall                   Uninstall sofilab command (requires sudo)
  --version, -V               Show version information
  --help, -h                  Show this help message

Examples:
  $SCRIPT_NAME login pmx
  $SCRIPT_NAME reset-hostkey pmx    # Use after server reinstall
  $SCRIPT_NAME run-scripts pmx
  $SCRIPT_NAME run-script pmx pmx-update-server.sh
  $SCRIPT_NAME list-scripts pmx
  $SCRIPT_NAME install

Configuration format in sofilab.conf:
  [alias1,alias2]
  host="IP_ADDRESS"
  user="USERNAME"
  password="PASSWORD"
  port="SSH_PORT" (optional, default 22)
  keyfile="ssh/alias_key" (optional)
  scripts="script1.sh,script2.sh" (optional, comma-separated)

EOF
}

# Load and parse server configuration for given alias
get_server_config() {
    local alias="$1"
    local in_section=false
    local host="" user="" password="" port="" keyfile="" scripts=""
    
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
                scripts) scripts="$value" ;;
            esac
        fi
    done < "$CONFIG_FILE"
    
    # Export parsed values
    SERVER_HOST="$host"
    SERVER_USER="$user"
    SERVER_PASSWORD="$password"
    SERVER_PORT="${port:-22}"
    SERVER_KEYFILE="$keyfile"
    SERVER_SCRIPTS="$scripts"
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
    
    # First check if there's a host key mismatch issue
    local ssh_output
    ssh_output=$(ssh -p "$port" -o ConnectTimeout=5 -o BatchMode=yes "$SERVER_USER@$SERVER_HOST" "echo connected" 2>&1)
    
    if echo "$ssh_output" | grep -q "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED\|Host key verification failed"; then
        # Host key has changed - likely a fresh install
        warn "Host key has changed - this is expected for a fresh installation"
        info "Automatically removing old host key..."
        
        # Remove old host keys
        ssh-keygen -R "$SERVER_HOST" 2>/dev/null
        ssh-keygen -R "[$SERVER_HOST]:$port" 2>/dev/null
        
        info "Old host key removed. Retrying connection..."
    fi
    
    # Try SSH key first if available
    if [[ -n "$keyfile" && -f "$keyfile" ]]; then
        if ssh -i "$keyfile" -p "$port" -o StrictHostKeyChecking=accept-new -o PasswordAuthentication=no -o ConnectTimeout=5 "$SERVER_USER@$SERVER_HOST" "echo connected" >/dev/null 2>&1; then
            return 0  # SSH key worked
        fi
    fi
    
    # Try password if SSH key failed or not available
    if [[ -n "$SERVER_PASSWORD" ]] && command -v sshpass >/dev/null 2>&1; then
        if sshpass -p "$SERVER_PASSWORD" ssh -p "$port" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 "$SERVER_USER@$SERVER_HOST" "echo connected" >/dev/null 2>&1; then
            return 0  # Password worked
        fi
    fi
    
    # Try direct SSH as last resort
    ssh -p "$port" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 "$SERVER_USER@$SERVER_HOST" "echo connected" >/dev/null 2>&1
}

# Connect to server interactively
connect_ssh() {
    local port="$1"
    local keyfile="$2"
    
    # Try SSH key first if available
    if [[ -n "$keyfile" && -f "$keyfile" ]]; then
        if ssh -i "$keyfile" -p "$port" -o StrictHostKeyChecking=accept-new -o PasswordAuthentication=no -o ConnectTimeout=5 "$SERVER_USER@$SERVER_HOST" "echo connected" >/dev/null 2>&1; then
            ssh -i "$keyfile" -p "$port" -o StrictHostKeyChecking=accept-new "$SERVER_USER@$SERVER_HOST"
            return
        fi
    fi
    
    # Try password if SSH key failed or not available
    if [[ -n "$SERVER_PASSWORD" ]] && command -v sshpass >/dev/null 2>&1; then
        sshpass -p "$SERVER_PASSWORD" ssh -p "$port" -o StrictHostKeyChecking=accept-new "$SERVER_USER@$SERVER_HOST"
        return
    fi
    
    # Direct SSH as last resort
    ssh -p "$port" -o StrictHostKeyChecking=accept-new "$SERVER_USER@$SERVER_HOST"
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
    local use_port=$(determine_ssh_port "$SERVER_PORT" "$SERVER_HOST")
    [[ -z "$use_port" ]] && exit 1
    
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

# Determine the working SSH port with fallback
determine_ssh_port() {
    local configured_port="$1"
    local host="$2"
    
    # Check configured port first
    info "Checking port availability on $configured_port..."
    if check_port_open "$host" "$configured_port"; then
        info "Port $configured_port is open $([ "$configured_port" == "22" ] && echo "(default SSH port)" || echo "(custom SSH port)")"
        echo "$configured_port"
        return 0
    elif [[ "$configured_port" != "22" ]]; then
        # Only try port 22 as fallback if configured port is different
        info "Port $configured_port is not accessible, checking fallback port 22..."
        if check_port_open "$host" "22"; then
            info "Port 22 is open (fallback to default SSH port)"
            echo "22"
            return 0
        else
            error "Neither port $configured_port nor port 22 are accessible"
            error "Please check your network connection and firewall settings"
            return 1
        fi
    else
        error "Port $configured_port is not accessible"
        error "Please check your network connection and firewall settings"
        return 1
    fi
}

# Get SSH key file for an alias
get_ssh_keyfile() {
    local alias="$1"
    local silent="${2:-false}"  # Optional parameter to suppress info messages
    local keyfile=""
    
    if [[ -n "$SERVER_KEYFILE" ]]; then
        keyfile="$SCRIPT_DIR/$SERVER_KEYFILE"
        if [[ -f "$keyfile" ]]; then
            [[ "$silent" != "true" ]] && info "Using SSH key: $keyfile"
            echo "$keyfile"
            return 0
        fi
    fi
    
    # Auto-detect key if not specified
    local auto_key="$SCRIPT_DIR/ssh/${alias}_key"
    if [[ -f "$auto_key" ]]; then
        [[ "$silent" != "true" ]] && info "Using auto-detected SSH key: $auto_key"
        echo "$auto_key"
        return 0
    fi
    
    # No key found
    echo ""
    return 1
}

# Upload a script file to remote server
upload_script() {
    local script_file="$1"
    local alias="$2"
    local use_port="$3"
    # Upload to user's home directory in a .sofilab_scripts folder
    local remote_dir=".sofilab_scripts"
    local remote_path="$remote_dir/$(basename "$script_file")"
    
    info "Uploading script: $script_file to ~/$remote_path"
    
    # Check if script exists locally
    if [[ ! -f "$SCRIPT_DIR/scripts/$script_file" ]]; then
        error "Script not found: $SCRIPT_DIR/scripts/$script_file"
        return 1
    fi
    
    # Get SSH key (show info message)
    local keyfile=$(get_ssh_keyfile "$alias" "false")
    
    # Create remote directory first - try key, then password
    local mkdir_cmd="mkdir -p ~/$remote_dir"
    local mkdir_success=false
    
    if [[ -n "$keyfile" ]]; then
        # Try SSH key first
        if ssh -i "$keyfile" -p "$use_port" -o StrictHostKeyChecking=accept-new -o PasswordAuthentication=no -o ConnectTimeout=5 "$SERVER_USER@$SERVER_HOST" "$mkdir_cmd" 2>/dev/null; then
            mkdir_success=true
        elif [[ -n "$SERVER_PASSWORD" ]] && command -v sshpass >/dev/null 2>&1; then
            # SSH key failed, add small delay to avoid triggering fail2ban
            sleep 2
            info "SSH key authentication failed, trying password authentication..."
            sshpass -p "$SERVER_PASSWORD" ssh -p "$use_port" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 "$SERVER_USER@$SERVER_HOST" "$mkdir_cmd" 2>/dev/null && mkdir_success=true
        fi
    elif [[ -n "$SERVER_PASSWORD" ]] && command -v sshpass >/dev/null 2>&1; then
        # No SSH key, use password directly
        sshpass -p "$SERVER_PASSWORD" ssh -p "$use_port" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 "$SERVER_USER@$SERVER_HOST" "$mkdir_cmd" 2>/dev/null && mkdir_success=true
    else
        # Try without any authentication method (will prompt for password)
        ssh -p "$use_port" -o ConnectTimeout=5 "$SERVER_USER@$SERVER_HOST" "$mkdir_cmd" 2>/dev/null && mkdir_success=true
    fi
    
    # Upload using scp - try key first, then password
    local upload_success=false
    
    if [[ -n "$keyfile" ]]; then
        # Try SSH key first
        if scp -i "$keyfile" -P "$use_port" -o StrictHostKeyChecking=accept-new -o PasswordAuthentication=no -o ConnectTimeout=5 "$SCRIPT_DIR/scripts/$script_file" "$SERVER_USER@$SERVER_HOST:$remote_path" 2>/dev/null; then
            upload_success=true
        elif [[ -n "$SERVER_PASSWORD" ]] && command -v sshpass >/dev/null 2>&1; then
            # SSH key failed, add small delay to avoid triggering fail2ban
            sleep 2
            info "SSH key authentication failed, using password authentication..."
            sshpass -p "$SERVER_PASSWORD" scp -P "$use_port" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 "$SCRIPT_DIR/scripts/$script_file" "$SERVER_USER@$SERVER_HOST:$remote_path" && upload_success=true
        fi
    elif [[ -n "$SERVER_PASSWORD" ]] && command -v sshpass >/dev/null 2>&1; then
        # No SSH key, use password directly
        sshpass -p "$SERVER_PASSWORD" scp -P "$use_port" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 "$SCRIPT_DIR/scripts/$script_file" "$SERVER_USER@$SERVER_HOST:$remote_path" && upload_success=true
    else
        # Try without any authentication method (will prompt for password)
        scp -P "$use_port" -o ConnectTimeout=5 "$SCRIPT_DIR/scripts/$script_file" "$SERVER_USER@$SERVER_HOST:$remote_path" && upload_success=true
    fi
    
    [[ "$upload_success" == true ]] && return 0 || return 1
}

# Execute a script on remote server
execute_remote_script() {
    local script_file="$1"
    local alias="$2"
    local use_port="$3"
    # Script is in user's home directory
    local remote_dir=".sofilab_scripts"
    local remote_path="$remote_dir/$(basename "$script_file")"
    
    info "Executing script: $script_file on $SERVER_HOST"
    
    # Get SSH key (silent mode to avoid duplicate messages)
    local keyfile=$(get_ssh_keyfile "$alias" "true")
    
    # Prepare environment variables for the script
    # Pass both configured port and actual connection port, plus SSH key content
    local ssh_key_path=""
    local ssh_public_key=""
    if [[ -n "$keyfile" ]]; then
        # Remove .pub extension if present to get base key path
        ssh_key_path="${keyfile%.pub}"
        # Read the actual public key content if it exists
        if [[ -f "${ssh_key_path}.pub" ]]; then
            ssh_public_key="$(cat "${ssh_key_path}.pub")"
            info "Including SSH public key for automatic setup"
        fi
    fi
    local env_vars="SSH_PORT='$SERVER_PORT' ACTUAL_PORT='$use_port' ADMIN_USER='$SERVER_USER' SSH_KEY_PATH='$ssh_key_path' SSH_PUBLIC_KEY='$ssh_public_key'"
    
    # Execute script remotely (using full path from home directory)
    local ssh_cmd="cd ~ && chmod +x $remote_path && $env_vars bash $remote_path; rm -f $remote_path"
    
    local exec_success=false
    
    if [[ -n "$keyfile" ]]; then
        # Try SSH key first
        if ssh -i "$keyfile" -p "$use_port" -o StrictHostKeyChecking=accept-new -o PasswordAuthentication=no -o ConnectTimeout=5 "$SERVER_USER@$SERVER_HOST" "$ssh_cmd" 2>/dev/null; then
            exec_success=true
        elif [[ -n "$SERVER_PASSWORD" ]] && command -v sshpass >/dev/null 2>&1; then
            # SSH key failed, add small delay to avoid triggering fail2ban
            sleep 2
            info "SSH key authentication failed, using password authentication..."
            sshpass -p "$SERVER_PASSWORD" ssh -p "$use_port" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 "$SERVER_USER@$SERVER_HOST" "$ssh_cmd" && exec_success=true
        fi
    elif [[ -n "$SERVER_PASSWORD" ]] && command -v sshpass >/dev/null 2>&1; then
        # No SSH key, use password directly
        sshpass -p "$SERVER_PASSWORD" ssh -p "$use_port" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 "$SERVER_USER@$SERVER_HOST" "$ssh_cmd" && exec_success=true
    else
        # Try without any authentication method (will prompt for password)
        ssh -p "$use_port" -o ConnectTimeout=5 "$SERVER_USER@$SERVER_HOST" "$ssh_cmd" && exec_success=true
    fi
    
    [[ "$exec_success" == true ]] && return 0 || return 1
}

# Run all scripts defined for an alias in order
run_scripts() {
    local alias="$1"
    
    info "Loading configuration for alias: $alias"
    get_server_config "$alias"
    
    [[ -z "$SERVER_HOST" ]] && { error "Unknown alias: $alias"; exit 1; }
    [[ -z "$SERVER_SCRIPTS" ]] && { warn "No scripts defined for alias: $alias"; exit 0; }
    
    info "Server: $SERVER_HOST:$SERVER_PORT"
    info "User: $SERVER_USER"
    info "Scripts to run: $SERVER_SCRIPTS"
    echo ""
    
    # Determine working port with fallback
    local use_port=$(determine_ssh_port "$SERVER_PORT" "$SERVER_HOST")
    [[ -z "$use_port" ]] && exit 1
    
    # Split scripts by comma and run each
    IFS=',' read -ra script_array <<< "$SERVER_SCRIPTS"
    local total=${#script_array[@]}
    local count=0
    
    for script in "${script_array[@]}"; do
        script=$(echo "$script" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')  # Trim whitespace
        count=$((count + 1))
        
        echo "[$count/$total] Processing script: $script"
        echo "========================================="
        
        # Upload script
        if upload_script "$script" "$alias" "$use_port"; then
            info "✓ Script uploaded successfully"
        else
            error "✗ Failed to upload script: $script"
            exit 1
        fi
        
        # Execute script
        if execute_remote_script "$script" "$alias" "$use_port"; then
            info "✓ Script executed successfully: $script"
        else
            error "✗ Script execution failed: $script"
            exit 1
        fi
        
        # Add delay between scripts to avoid triggering fail2ban
        if [[ $count -lt $total ]]; then
            info "Waiting 3 seconds before next script to avoid rate limiting..."
            sleep 3
        fi
        
        echo ""
    done
    
    info "All scripts executed successfully!"
}

# Run a specific script on remote server
run_single_script() {
    local alias="$1"
    local script_name="$2"
    
    info "Loading configuration for alias: $alias"
    get_server_config "$alias"
    
    [[ -z "$SERVER_HOST" ]] && { error "Unknown alias: $alias"; exit 1; }
    
    info "Server: $SERVER_HOST:$SERVER_PORT"
    info "User: $SERVER_USER"
    info "Script to run: $script_name"
    echo ""
    
    # Check if script exists
    if [[ ! -f "$SCRIPT_DIR/scripts/$script_name" ]]; then
        error "Script not found: $SCRIPT_DIR/scripts/$script_name"
        echo ""
        echo "Available scripts in $SCRIPT_DIR/scripts/:"
        ls -1 "$SCRIPT_DIR/scripts/" 2>/dev/null | grep -E '\.sh$' | sed 's/^/  - /'
        exit 1
    fi
    
    # Determine working port with fallback
    local use_port=$(determine_ssh_port "$SERVER_PORT" "$SERVER_HOST")
    [[ -z "$use_port" ]] && exit 1
    
    # Upload script
    if upload_script "$script_name" "$alias" "$use_port"; then
        info "✓ Script uploaded successfully"
    else
        error "✗ Failed to upload script: $script_name"
        exit 1
    fi
    
    # Execute script
    if execute_remote_script "$script_name" "$alias" "$use_port"; then
        info "✓ Script executed successfully: $script_name"
    else
        error "✗ Script execution failed: $script_name"
        exit 1
    fi
}

# List available scripts for an alias
list_scripts() {
    local alias="$1"
    
    info "Loading configuration for alias: $alias"
    get_server_config "$alias"
    
    [[ -z "$SERVER_HOST" ]] && { error "Unknown alias: $alias"; exit 1; }
    
    echo ""
    echo "Server: $SERVER_HOST"
    echo "Alias: $alias"
    echo ""
    
    if [[ -n "$SERVER_SCRIPTS" ]]; then
        echo "Configured scripts (will run in this order):"
        IFS=',' read -ra script_array <<< "$SERVER_SCRIPTS"
        local count=0
        for script in "${script_array[@]}"; do
            script=$(echo "$script" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            count=$((count + 1))
            echo "  $count. $script"
        done
    else
        echo "No scripts configured for this alias."
    fi
    
    echo ""
    echo "All available scripts in $SCRIPT_DIR/scripts/:"
    if [[ -d "$SCRIPT_DIR/scripts" ]]; then
        ls -1 "$SCRIPT_DIR/scripts/" 2>/dev/null | grep -E '\.sh$' | sed 's/^/  - /' || echo "  (no scripts found)"
    else
        echo "  (scripts directory not found)"
    fi
    
    echo ""
    echo "To run all configured scripts in order:"
    echo "  $SCRIPT_NAME run-scripts $alias"
    echo ""
    echo "To run a specific script:"
    echo "  $SCRIPT_NAME run-script $alias <script-name>"
}

# Reset SSH host key for a server (useful after reinstall)
reset_hostkey() {
    local alias="$1"
    
    info "Loading configuration for alias: $alias"
    get_server_config "$alias"
    
    [[ -z "$SERVER_HOST" ]] && { error "Unknown alias: $alias"; exit 1; }
    
    echo ""
    echo "Removing SSH host keys for: $SERVER_HOST"
    echo "This is useful when a server has been reinstalled."
    echo ""
    
    # Remove from known_hosts
    local removed=false
    
    # Try to remove by hostname
    if ssh-keygen -R "$SERVER_HOST" 2>/dev/null; then
        info "Removed host key for: $SERVER_HOST"
        removed=true
    fi
    
    # Also try to remove entries for different ports
    for port in 22 896 "$SERVER_PORT"; do
        if ssh-keygen -R "[$SERVER_HOST]:$port" 2>/dev/null; then
            info "Removed host key for: [$SERVER_HOST]:$port"
            removed=true
        fi
    done
    
    if [[ "$removed" == true ]]; then
        echo ""
        info "✓ Host keys removed successfully"
        echo ""
        echo "You can now connect to the server without host key warnings:"
        echo "  $SCRIPT_NAME login $alias"
    else
        warn "No host keys found for $SERVER_HOST"
        echo "The server might not be in your known_hosts file."
    fi
}

# Main function
main() {
    case "${1:-}" in
        login)
            [[ -z "${2:-}" ]] && { error "Alias required for login command"; usage; exit 1; }
            ssh_login "$2"
            ;;
        reset-hostkey)
            [[ -z "${2:-}" ]] && { error "Alias required for reset-hostkey command"; usage; exit 1; }
            reset_hostkey "$2"
            ;;
        run-scripts)
            [[ -z "${2:-}" ]] && { error "Alias required for run-scripts command"; usage; exit 1; }
            run_scripts "$2"
            ;;
        run-script)
            [[ -z "${2:-}" ]] && { error "Alias required for run-script command"; usage; exit 1; }
            [[ -z "${3:-}" ]] && { error "Script name required for run-script command"; usage; exit 1; }
            run_single_script "$2" "$3"
            ;;
        list-scripts)
            [[ -z "${2:-}" ]] && { error "Alias required for list-scripts command"; usage; exit 1; }
            list_scripts "$2"
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
