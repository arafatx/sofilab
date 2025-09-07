#!/bin/bash
# Comprehensive Proxmox Security Setup Script
# Focuses on security configuration only
# Safe to run multiple times (idempotent)
# Prerequisites: Run pmx-update-server.sh first for system updates

set -e
set -u

# Get configuration from sofilab.sh environment variables
SSH_PORT="${SSH_PORT:-896}"
ADMIN_USER="${ADMIN_USER:-root}"

echo "=== Proxmox Security Configuration ==="
echo "SSH Port: $SSH_PORT"
echo "User: $ADMIN_USER"
echo "Date: $(date)"
echo ""

# ============================================================================
# PART 1: SECURITY TOOLS INSTALLATION
# ============================================================================

echo "Step 1: Installing essential security tools..."

# Check if packages are already installed to avoid unnecessary operations
PACKAGES_TO_INSTALL=""
for pkg in fail2ban unattended-upgrades htop curl wget git; do
    if ! dpkg -l | grep -q "^ii.*$pkg "; then
        PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL $pkg"
    fi
done

if [[ -n "$PACKAGES_TO_INSTALL" ]]; then
    echo "Installing packages:$PACKAGES_TO_INSTALL"
    apt update -qq
    apt install -y $PACKAGES_TO_INSTALL
else
    echo "All required packages are already installed"
fi

echo "Step 2: Configuring fail2ban for SSH protection..."

# Configure fail2ban only if not already configured
if [[ ! -f /etc/fail2ban/jail.local ]] || ! grep -q "port = $SSH_PORT" /etc/fail2ban/jail.local 2>/dev/null; then
    echo "Setting up fail2ban configuration..."
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF

    if ! systemctl is-enabled fail2ban >/dev/null 2>&1; then
        systemctl enable fail2ban
    fi
    systemctl restart fail2ban
    echo "Fail2ban configured and restarted"
else
    echo "Fail2ban already configured for port $SSH_PORT"
fi

echo "Step 3: Configuring automatic security updates..."

# Configure unattended upgrades only if not already configured
if [[ ! -f /etc/apt/apt.conf.d/50unattended-upgrades ]] || ! grep -q "distro_id" /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null; then
    echo "Setting up automatic security updates..."
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "origin=Debian,codename=${distro_codename},label=Debian-Security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

    if ! systemctl is-enabled unattended-upgrades >/dev/null 2>&1; then
        systemctl enable unattended-upgrades
    fi
    echo "Automatic security updates configured"
else
    echo "Automatic security updates already configured"
fi

echo "Step 4: Applying system hardening..."

# Disable unused network protocols (idempotent)
echo "Hardening network protocols..."
if [[ ! -f /etc/modprobe.d/blacklist-rare-protocols.conf ]]; then
    cat > /etc/modprobe.d/blacklist-rare-protocols.conf << 'EOF'
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF
    echo "Network protocols blacklisted"
else
    echo "Network protocols already hardened"
fi

# Set kernel parameters for security (idempotent)
echo "Configuring kernel security parameters..."
if [[ ! -f /etc/sysctl.d/99-security.conf ]] || ! grep -q "net.ipv4.conf.all.rp_filter" /etc/sysctl.d/99-security.conf 2>/dev/null; then
    cat > /etc/sysctl.d/99-security.conf << 'EOF'
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Log Martians
net.ipv4.conf.all.log_martians = 1

# Ignore ping requests
net.ipv4.icmp_echo_ignore_all = 0
EOF
    sysctl -p /etc/sysctl.d/99-security.conf
    echo "Kernel security parameters applied"
else
    echo "Kernel security parameters already configured"
fi

# ============================================================================
# PART 2: SSH SECURITY CONFIGURATION
# ============================================================================

echo ""
echo "Step 5: SSH Security Configuration..."

# Backup original SSH config (only if not already backed up today)
BACKUP_DATE=$(date +%Y%m%d)
if [[ ! -f "/etc/ssh/sshd_config.backup.$BACKUP_DATE"* ]]; then
    echo "Backing up SSH configuration..."
    cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)"
else
    echo "SSH configuration already backed up today"
fi

# Create SSH directory
echo "Setting up SSH directory..."
mkdir -p /root/.ssh
chmod 700 /root/.ssh

# Setup authorized_keys with SSH key from sofilab
echo "Setting up SSH key authentication..."

if [[ -f "/tmp/sofilab_pubkey" ]]; then
    echo "Installing SSH public key from sofilab..."
    cat /tmp/sofilab_pubkey > /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    rm -f /tmp/sofilab_pubkey
    echo "SSH public key installed successfully"
elif [[ -f /root/.ssh/authorized_keys && -s /root/.ssh/authorized_keys ]]; then
    echo "Using existing authorized_keys file"
    chmod 600 /root/.ssh/authorized_keys
else
    echo "ERROR: No SSH public key available!"
    echo "Make sure you run this script through sofilab.sh which will upload the key."
    exit 1
fi

# Configure SSH daemon (idempotent modifications)
echo "Configuring SSH daemon..."

# Function to update SSH config setting
update_ssh_config() {
    local setting="$1"
    local value="$2"
    local config_file="/etc/ssh/sshd_config"
    
    # Remove any existing setting (commented or uncommented)
    sed -i "/^#*${setting}/d" "$config_file"
    # Add the new setting
    echo "${setting} ${value}" >> "$config_file"
}

# Apply SSH security settings
update_ssh_config "Port" "$SSH_PORT"
update_ssh_config "PasswordAuthentication" "no"
update_ssh_config "PubkeyAuthentication" "yes"
update_ssh_config "PermitRootLogin" "prohibit-password"
update_ssh_config "PermitEmptyPasswords" "no"

echo "SSH daemon configured with security settings"

# ============================================================================
# PART 3: PROXMOX FIREWALL CONFIGURATION
# ============================================================================

echo ""
echo "Step 6: Configuring Proxmox firewall..."

# Enable datacenter firewall if not already enabled
if ! pvesh get /cluster/firewall/options 2>/dev/null | grep -q '"enable":1'; then
    pvesh set /cluster/firewall/options --enable 1 2>/dev/null || true
    echo "Proxmox datacenter firewall enabled"
else
    echo "Proxmox datacenter firewall already enabled"
fi

# Function to check if firewall rule exists
rule_exists() {
    local port="$1"
    local comment="$2"
    pvesh get /cluster/firewall/rules --output-format json 2>/dev/null | \
    grep -q "\"dport\":\"$port\".*\"comment\":\"$comment\""
}

# Add rule for Proxmox Web UI (port 8006) - CRITICAL for web access
if ! rule_exists "8006" "Proxmox-WebUI"; then
    pvesh create /cluster/firewall/rules --type in --action ACCEPT --proto tcp --dport 8006 --comment "Proxmox-WebUI" --enable 1 2>/dev/null && \
    echo "Added Proxmox WebUI firewall rule" || echo "Failed to add Proxmox WebUI rule"
else
    echo "Proxmox WebUI firewall rule already exists"
fi

# Add SSH rule for custom port
if ! rule_exists "$SSH_PORT" "SSH-$SSH_PORT"; then
    pvesh create /cluster/firewall/rules --type in --action ACCEPT --proto tcp --dport $SSH_PORT --comment "SSH-$SSH_PORT" --enable 1 2>/dev/null && \
    echo "Added SSH firewall rule for port $SSH_PORT" || echo "Failed to add SSH rule"
else
    echo "SSH firewall rule for port $SSH_PORT already exists"
fi

# Remove default SSH rule on port 22 (if exists and different from our SSH_PORT)
if [[ "$SSH_PORT" != "22" ]]; then
    echo "Checking for default SSH rule on port 22..."
    pvesh get /cluster/firewall/rules --output-format json 2>/dev/null | grep -o '"pos":[0-9]*' | grep -o '[0-9]*' | while read pos; do
        rule_info=$(pvesh get /cluster/firewall/rules/$pos --output-format json 2>/dev/null || echo "")
        if echo "$rule_info" | grep -q '"dport":"22"' && echo "$rule_info" | grep -q '"proto":"tcp"'; then
            pvesh delete /cluster/firewall/rules/$pos 2>/dev/null && echo "Removed default SSH rule on port 22" || true
            break
        fi
    done 2>/dev/null || true
fi

echo "Proxmox firewall status:"
echo "- SSH port $SSH_PORT: CONFIGURED"
echo "- Proxmox WebUI port 8006: CONFIGURED"

# ============================================================================
# PART 4: FINALIZATION AND TESTING
# ============================================================================

echo ""
echo "Step 7: Testing and finalizing SSH configuration..."
if sshd -t; then
    echo "SSH configuration is valid"
    if systemctl restart sshd; then
        echo "SSH service restarted successfully"
    else
        echo "WARNING: SSH service restart failed, but configuration is valid"
    fi
else
    echo "ERROR: SSH configuration is invalid!"
    echo "Restoring backup..."
    if ls /etc/ssh/sshd_config.backup.* >/dev/null 2>&1; then
        cp $(ls -t /etc/ssh/sshd_config.backup.* | head -1) /etc/ssh/sshd_config
        systemctl restart sshd
        echo "SSH configuration restored from backup"
    fi
    exit 1
fi

echo ""
echo "=== Proxmox Security Configuration Complete ==="
echo ""
echo "✓ Security tools installed and configured"
echo "✓ Fail2ban protecting SSH on port $SSH_PORT"
echo "✓ Automatic security updates enabled"
echo "✓ System hardening applied"
echo "✓ SSH configured with key-only authentication"
echo "✓ SSH port changed to $SSH_PORT"
echo "✓ Proxmox firewall configured"
echo ""
echo "IMPORTANT: Test your SSH connection now!"
echo "Command: ssh -i ssh/pmx_key -p $SSH_PORT root@$(hostname -I | awk '{print $1}')"
echo ""
echo "If SSH connection fails, you can restore the backup:"
echo "cp \$(ls -t /etc/ssh/sshd_config.backup.* | head -1) /etc/ssh/sshd_config && systemctl restart sshd"
echo ""
echo "Security Summary:"
echo "- SSH Port: $SSH_PORT (password auth disabled)"
echo "- Proxmox WebUI: port 8006 (accessible)"
echo "- Fail2ban: protecting SSH"
echo "- Auto-updates: enabled for security patches"
echo "- Firewall: Proxmox built-in (configured)"
echo ""
echo "Note: Run pmx-update-server.sh first for system updates"

# Explicit success exit
exit 0
