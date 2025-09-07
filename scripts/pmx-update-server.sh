#!/bin/bash
# Proxmox Repository Setup and System Update Script
# Automatically detects Debian codename and Proxmox version
# Safe to run multiple times (idempotent)

set -euo pipefail

echo "=== Proxmox Repository Setup and System Update ==="
echo "Date: $(date)"
echo

# Detect Debian codename
. /etc/os-release
DEB_CODENAME="${VERSION_CODENAME:-unknown}"

# Detect PVE version (if installed)
PVE_MANAGER_VER="$(pveversion -v 2>/dev/null | awk -F'[/ ]' '/^pve-manager/ {print $2}' || true)"
PVE_MAJOR="${PVE_MANAGER_VER%%.*}"

# Decide suite (only allow known combinations)
case "$DEB_CODENAME" in
  trixie)
    EXPECTED_PVE="9"
    SUITE="trixie"
    ;;
  bookworm)
    EXPECTED_PVE="8"
    SUITE="bookworm"
    ;;
  *)
    echo "Unsupported Debian codename: $DEB_CODENAME"
    exit 1
    ;;
esac

if [ -n "$PVE_MAJOR" ] && [ "$PVE_MAJOR" != "$EXPECTED_PVE" ]; then
  echo "Mismatch: Detected PVE $PVE_MAJOR.x on Debian $DEB_CODENAME. Aborting."
  exit 1
fi

echo "Detected Debian: $DEB_CODENAME ${PVE_MANAGER_VER:+, PVE $PVE_MANAGER_VER}"
echo

echo "Step 1: Configuring repositories..."

# Remove enterprise/ceph repos
rm -f /etc/apt/sources.list.d/pve-enterprise.list \
      /etc/apt/sources.list.d/pve-enterprise.sources \
      /etc/apt/sources.list.d/ceph.list \
      /etc/apt/sources.list.d/ceph.sources

# Remove legacy Debian sources (we'll use deb822 instead)
rm -f /etc/apt/sources.list /etc/apt/sources.list.d/debian.sources

# Write Debian deb822 sources
cat >/etc/apt/sources.list.d/debian.sources <<EOF
Types: deb
URIs: http://deb.debian.org/debian
Suites: ${DEB_CODENAME} ${DEB_CODENAME}-updates
Components: main contrib non-free-firmware

Types: deb
URIs: http://security.debian.org/debian-security
Suites: ${DEB_CODENAME}-security
Components: main contrib non-free-firmware
EOF

# Write Proxmox no-subscription repo
cat >/etc/apt/sources.list.d/pve-no-subscription.list <<EOF
deb http://download.proxmox.com/debian/pve ${SUITE} pve-no-subscription
EOF

echo "Repositories configured."
echo

echo "Step 2: Updating system packages..."
apt clean
rm -rf /var/lib/apt/lists/*
apt update
DEBIAN_FRONTEND=noninteractive apt -y full-upgrade

echo
echo "=== Complete ==="
echo "Debian codename : $DEB_CODENAME"
[ -n "$PVE_MANAGER_VER" ] && echo "Proxmox version : $PVE_MANAGER_VER"
echo "Repos set to    : Debian ($SUITE) + Proxmox no-subscription"
