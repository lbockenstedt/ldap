#!/bin/bash
set -e

# ------------------------------------------------------------------
# Argument Parsing
# ------------------------------------------------------------------
HUB_WS=""
SPOKE_ID=""
SPOKE_SECRET=""
HUB_SECRET=""

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --hub) HUB_WS="$2"; shift ;;
        --id) SPOKE_ID="$2"; shift ;;
        --secret) SPOKE_SECRET="$2"; shift ;;
        --hub-secret) HUB_SECRET="$2"; shift ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

if [ -z "$HUB_WS" ] || [ -z "$SPOKE_ID" ] || [ -z "$SPOKE_SECRET" ]; then
    echo "❌ Missing required arguments: --hub, --id, and --secret are required."
    exit 1
fi

echo "🚀 Installing LDAP Manager Spoke..."

# 1. Install System Dependencies
apt-get update
apt-get install -y slapd ldap-utils python3-pip python3-venv libldap2-dev libsasl2-dev

# Create a dedicated service user
if ! id "svc_lm" &>/dev/null; then
    echo "👤 Creating service user svc_lm..."
    useradd -r -s /bin/false svc_lm
fi

# 2. Basic OpenLDAP Configuration
# Note: In a real production environment, we'd use a more robust config generation.
# Here we'll ensure a basic structure exists.
echo "⚙️ Configuring OpenLDAP..."
# We'll use the default slapd installation and create a basic setup if it doesn't exist.
# The python-ldap lib will handle most of the structure creation via the API.

# 3. Python Environment Setup
INSTALL_DIR="/opt/lm/ldap"
mkdir -p "$INSTALL_DIR"
cp -r . "$INSTALL_DIR/"

cd "$INSTALL_DIR"
python3 -m venv venv
./venv/bin/python3 -m pip install --upgrade pip -q
./venv/bin/python3 -m pip install -r requirements.txt -q

# 4. Env Configuration
cat <<EOF > .env
SPOKE_ID=$SPOKE_ID
SPOKE_SECRET=$SPOKE_SECRET
HUB_SECRET=$HUB_SECRET
HUB_WS=$HUB_WS
LDAP_ADMIN_DN="cn=admin,dc=example,dc=org"
LDAP_ADMIN_PW="admin"
LDAP_BASE_DN="dc=example,dc=org"
EOF

# 5. Systemd Service Setup
cat <<EOF > /etc/systemd/system/lm-ldap.service
[Unit]
Description=Lab Manager LDAP Spoke
After=network.target slapd.service

[Service]
User=svc_lm
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/ldap/src/main.py --id $SPOKE_ID --secret $SPOKE_SECRET --hub-secret $HUB_SECRET --hub $HUB_WS
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable lm-ldap
systemctl restart lm-ldap

echo "🎉 LDAP Spoke installation complete!"
