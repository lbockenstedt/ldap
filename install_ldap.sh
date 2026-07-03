#!/bin/bash
set -e

# Default Configuration
# HUB_URL defaults to "auto": the spoke auto-discovers the hub (DNS
# lm-hub.<suffix> then mDNS) on each connect via BaseControlPlane. The old
# "ws://localhost:8765" default is BROKEN now that the hub's bare 8765 listener
# was retired by the unified-:443 merge (the hub serves only on :443); a
# co-located spoke dialed a dead port and a remote one dialed its own localhost.
# Pass --hub <url> to pin.
HUB_URL="${HUB_URL:-auto}"
SPOKE_ID="${SPOKE_ID:-ldap-$(hostname -s)}"
SPOKE_SECRET="lm-secret"

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --hub) HUB_URL="$2"; shift ;;
        --id|--name) SPOKE_ID="$2"; shift ;;
        --secret) SPOKE_SECRET="$2"; shift ;;
        --hub-secret) HUB_SECRET="$2"; shift ;;
        --all-prereqs) ;;  # no-op; accepted for LM hub compat
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

if [ -z "$SPOKE_SECRET" ] || [ "$SPOKE_SECRET" == "lm-secret" ]; then
    SPOKE_SECRET=""
    echo "ℹ️  No pre-shared secret — spoke will connect unauthenticated and await admin approval in the LM WebUI."
fi

echo "🚀 Installing LDAP Manager Module (Native)..."

if [ "$(id -u)" -ne 0 ]; then
    echo "⚠️  This script must be run as root."
    exit 1
fi

# 1. System dependencies: slapd (LDAP server) + build deps for python-ldap
# Pre-seed slapd debconf answers so apt never shows an interactive password
# dialog. The admin password set here is overwritten by dpkg-reconfigure
# later, so it's just a placeholder to satisfy the installer.
apt-get update
apt-get install -y debconf-utils
debconf-set-selections <<'DEBCONF'
slapd slapd/internal/generated_adminpw password placeholder
slapd slapd/internal/adminpw password placeholder
slapd slapd/password2 password placeholder
slapd slapd/password1 password placeholder
slapd slapd/domain string lm.local
slapd shared/organization string "Lab Manager"
slapd slapd/backend select MDB
slapd slapd/purge_database boolean true
slapd slapd/move_old_database boolean true
slapd slapd/allow_ldap_v2 boolean false
slapd slapd/no_configuration boolean false
DEBCONF
DEBIAN_FRONTEND=noninteractive apt-get install -y slapd ldap-utils python3-pip python3-venv git curl jq libldap2-dev libsasl2-dev

# Create a dedicated service user
if ! id "svc_lm" &>/dev/null; then
    echo "👤 Creating service user svc_lm..."
    useradd -r -s /bin/false svc_lm
fi

INSTALL_DIR="/opt/lm"
OLD_INSTALL_DIR="/opt/lm-manager"

# Cleanup legacy installation
if [ -d "$OLD_INSTALL_DIR" ]; then
    echo "🗑️  Removing legacy installation at $OLD_INSTALL_DIR..."
    rm -rf "$OLD_INSTALL_DIR"
fi

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

if [ -d "ldap/.git" ]; then
    echo "📂 LDAP repository already exists. Updating..."
    cd ldap && git pull && cd ..
else
    echo "🌐 Cloning LDAP Manager repository..."
    git clone https://github.com/lbockenstedt/ldap.git
fi

echo "🛠️ Setting up LDAP Manager..."
cd ldap

# Always remove existing venv to ensure clean local environment (prevents cross-platform path issues)
echo "♻️ Resetting virtual environment..."
rm -rf venv

python3 -m venv venv
if [ ! -f "venv/bin/python3" ]; then
    echo "❌ Critical Error: venv creation failed."
    exit 1
fi

echo "Installing requirements..."
./venv/bin/python3 -m pip install --upgrade pip -q
if [ -f "requirements.txt" ]; then
    ./venv/bin/python3 -m pip install -r requirements.txt -q
fi

# --- Persistence Configuration ---
echo "⚙️ Configuring Spoke Identity..."
mkdir -p /var/log/lm
cat <<EOF > .env
HUB_URL=$HUB_URL
SPOKE_ID=$SPOKE_ID
SPOKE_SECRET=$SPOKE_SECRET
HUB_SECRET=${HUB_SECRET:-}
LDAP_ADMIN_DN=cn=admin,dc=example,dc=org
LDAP_BASE_DN=dc=example,dc=org
LDAP_SERVER_URL=ldap://localhost:389
# LDAP_ADMIN_PW: REQUIRED. Set to your slapd admin password. Left empty by default;
# the spoke will fail to bind until this is configured (fail-closed).
LDAP_ADMIN_PW=
EOF
chmod 600 .env

# Only pass --secret/--hub-secret when a value is set. Passing --secret with an
# empty value makes argparse abort with "argument --secret: expected one
# argument", crash-looping the service (zero-touch omits it and awaits approval).
SECRET_ARG=""
[ -n "$SPOKE_SECRET" ] && SECRET_ARG="--secret $SPOKE_SECRET"
HUB_SECRET_ARG=""
[ -n "${HUB_SECRET:-}" ] && HUB_SECRET_ARG="--hub-secret ${HUB_SECRET}"

# --- Systemd Service (For Remote/Independent Deployment) ---
echo "⚙️ Creating systemd service for auto-start..."
cat <<EOF > /etc/systemd/system/lm-ldap.service
[Unit]
Description=Lab Manager Spoke - LDAP Manager
After=network.target slapd.service

[Service]
Type=simple
# Runs as root: INSTALL_CERT (hub-brokered Let's Encrypt cert install) writes
# /etc/ldap/tls, runs `ldapmodify -Y EXTERNAL -H ldapi:///` against cn=config
# (root peer-cred → cn=config write), and `systemctl restart slapd` — all need
# root. Mirrors the le cert spoke (User=root because cert ops need root).
User=root
WorkingDirectory=$INSTALL_DIR/ldap
EnvironmentFile=$INSTALL_DIR/ldap/.env
Environment="PYTHONPATH=$INSTALL_DIR:$INSTALL_DIR/core/src:$INSTALL_DIR/ldap/src"
ExecStart=$INSTALL_DIR/ldap/venv/bin/python3 -m src.main --id $SPOKE_ID --hub $HUB_URL $SECRET_ARG $HUB_SECRET_ARG
StandardOutput=append:/var/log/lm/lm-ldap.log
StandardError=append:/var/log/lm/lm-ldap.log
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable lm-ldap
systemctl restart lm-ldap

echo "🎉 LDAP Manager installation complete!"
echo "🌐 Hub Target: $HUB_URL"
echo "🆔 Spoke ID: $SPOKE_ID"
echo "📦 Version: $(cat VERSION 2>/dev/null || echo unknown)"