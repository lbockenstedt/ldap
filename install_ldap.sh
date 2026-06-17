#!/bin/bash
set -e

# Default Configuration
HUB_URL="ws://localhost:8765"
SPOKE_ID="ldap-spoke-1"
SPOKE_SECRET="lm-secret"

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --hub) HUB_URL="$2"; shift ;;
        --id|--name) SPOKE_ID="$2"; shift ;;
        --secret) SPOKE_SECRET="$2"; shift ;;
        --hub-secret) HUB_SECRET="$2"; shift ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

# Auto-fetch secret if not provided
if [ -z "$SPOKE_SECRET" ] || [ "$SPOKE_SECRET" == "lm-secret" ]; then
    echo "🔑 No secret provided. Attempting to fetch first-secret from Hub..."
    HOST=$(echo "$HUB_URL" | sed 's|^ws://||' | cut -d: -f1)
    API_URL="http://$HOST:8000"

    SPOKE_SECRET=$(curl -s -X POST "$API_URL/setup/generate-secret" \
        -H "Content-Type: application/json" \
        -d "{\"spoke_id\": \"$SPOKE_ID\"}" | jq -r '.secret' 2>/dev/null) || true

    if [ "$SPOKE_SECRET" == "null" ] || [ -z "$SPOKE_SECRET" ]; then
        echo "⚠️  Could not fetch secret from Hub. Falling back to default."
        SPOKE_SECRET="lm-secret"
    else
        echo "✅ Successfully fetched first-secret from Hub."
    fi
fi

echo "🚀 Installing LDAP Manager Module (Native)..."

if [ "$(id -u)" -ne 0 ]; then
    echo "⚠️  This script must be run as root."
    exit 1
fi

# 1. System dependencies: slapd (LDAP server) + build deps for python-ldap
apt-get update
apt-get install -y slapd ldap-utils python3-pip python3-venv git curl jq libldap2-dev libsasl2-dev

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
cat <<EOF > .env
HUB_URL=$HUB_URL
SPOKE_ID=$SPOKE_ID
SPOKE_SECRET=$SPOKE_SECRET
HUB_SECRET=$HUB_SECRET
LDAP_ADMIN_DN=cn=admin,dc=example,dc=org
LDAP_ADMIN_PW=admin
LDAP_BASE_DN=dc=example,dc=org
LDAP_SERVER_URL=ldap://localhost:389
EOF

# --- Systemd Service (For Remote/Independent Deployment) ---
echo "⚙️ Creating systemd service for auto-start..."
cat <<EOF > /etc/systemd/system/lm-ldap.service
[Unit]
Description=Lab Manager Spoke - LDAP Manager
After=network.target slapd.service

[Service]
Type=simple
User=svc_lm
WorkingDirectory=$INSTALL_DIR/ldap
Environment="PYTHONPATH=$INSTALL_DIR/core/src:$INSTALL_DIR/ldap/src"
ExecStart=$INSTALL_DIR/ldap/venv/bin/python3 -m src.main --id $SPOKE_ID --secret $SPOKE_SECRET --hub-secret $HUB_SECRET --hub $HUB_URL
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable lm-ldap

echo "🎉 LDAP Manager installation complete!"
echo "🌐 Hub Target: $HUB_URL"
echo "🆔 Spoke ID: $SPOKE_ID"
echo "📦 Version: $(cat VERSION 2>/dev/null || echo unknown)"