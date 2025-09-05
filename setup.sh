#!/usr/bin/env bash
#
# setup.sh - Simple installation script for SofiLab
#

set -euo pipefail

# Configuration
INSTALL_DIR="$HOME/.local/bin"
SCRIPT_NAME="sofilab"
SOURCE_FILE="$(pwd)/sofilab.sh"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Simple logging
info() { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Show usage
usage() {
    cat << EOF
SofiLab Setup Script

Usage: ./setup.sh [command]

Commands:
  install    Install sofilab command globally
  remove     Remove sofilab command
  status     Check installation status

Examples:
  ./setup.sh install
  ./setup.sh status
  ./setup.sh remove

EOF
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Add to PATH if needed
setup_path() {
    local shell_rc="$HOME/.zshrc"
    [[ "$SHELL" == *bash* ]] && shell_rc="$HOME/.bashrc"
    
    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
        echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> "$shell_rc"
        info "Added $INSTALL_DIR to PATH in $shell_rc"
        warn "Please restart your terminal or run: source $shell_rc"
    fi
}

# Install sofilab
install() {
    info "Installing SofiLab..."
    
    # Create install directory
    mkdir -p "$INSTALL_DIR"
    
    # Create symlink
    ln -sf "$SOURCE_FILE" "$INSTALL_DIR/$SCRIPT_NAME"
    chmod +x "$SOURCE_FILE"
    
    # Setup PATH
    setup_path
    
    info "SofiLab installed successfully!"
    info "Run 'sofilab --help' to get started"
}

# Remove sofilab
remove() {
    if [[ -f "$INSTALL_DIR/$SCRIPT_NAME" ]]; then
        rm "$INSTALL_DIR/$SCRIPT_NAME"
        info "SofiLab removed successfully"
    else
        warn "SofiLab is not installed"
    fi
}

# Check status
status() {
    if [[ -f "$INSTALL_DIR/$SCRIPT_NAME" ]]; then
        info "SofiLab is installed at $INSTALL_DIR/$SCRIPT_NAME"
        if command_exists "$SCRIPT_NAME"; then
            info "Command 'sofilab' is available in PATH"
        else
            warn "Command 'sofilab' not found in PATH"
        fi
    else
        warn "SofiLab is not installed"
    fi
}

# Main
case "${1:-}" in
    install) install ;;
    remove) remove ;;
    status) status ;;
    *) usage ;;
esac
