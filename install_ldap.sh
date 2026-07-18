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

# Accept a bare hub IP/host for --hub (e.g. `--hub 172.16.1.31` == `--hub
# wss://172.16.1.31:443`). A ws://|wss:// scheme or the "auto" sentinel is left
# as-is; host:port gets a scheme; a bare host defaults to the unified :443.
if [ -n "${HUB_URL:-}" ] && [ "$HUB_URL" != "auto" ]; then
    case "$HUB_URL" in
        ws://*|wss://*) : ;;
        *:[0-9]*)       HUB_URL="wss://${HUB_URL}" ;;
        *)              HUB_URL="wss://${HUB_URL}:443" ;;
    esac
fi

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

# ── Retire any legacy lm-generic-agent on this box ───────────────────────────
# Vendored from lm/agent/install_agent.sh:retire_legacy_agent — keep in sync.
# The legacy leaf (lm-generic-agent, /opt/lm/generic-agent/src/agent.py) is
# protocol-incompatible with the session-key-adopting hub: it has no
# SPOKE_UPDATE_SESSION_KEY / LOAD_ROLE handler, connects + passes mTLS but never
# adopts a session key, and the hub refuses to dispatch to it (every role on
# the box times out while the WS stays "online"). Purge it before the clone so
# even an aborted install can't leave the zombie connecting under this box's
# id. Idempotent + non-fatal if absent; never touches this installer's own unit
# ($SERVICE_NAME) — it's (re)written below.
SERVICE_NAME="lm-ldap"
retire_legacy_agent() {
    # Match the legacy leaf by BOTH its historical unit name AND — crucially —
    # by any unit whose definition ExecStarts the legacy path
    # (/opt/lm/generic-agent/src/agent.py). Older template-menu builders named
    # the unit variously (not always lm-generic-agent), so a name-only purge
    # silently misses it and the zombie keeps connecting. Never touch the
    # role-capable unit ($SERVICE_NAME) — the install (re)writes it below.
    local names="lm-generic-agent"
    local f
    # Scan ALL standard systemd unit dirs, not just /etc — older builders dropped
    # the unit under /lib or /usr/lib, so an /etc-only grep misses it entirely.
    for f in /etc/systemd/system/*.service /etc/systemd/system/*/*.service \
             /run/systemd/system/*.service \
             /lib/systemd/system/*.service /usr/lib/systemd/system/*.service; do
        [ -e "$f" ] || continue
        if grep -qE "/opt/lm/generic-agent" "$f" 2>/dev/null; then
            names="$names $(basename "$f" .service)"
        fi
    done
    # Also ask systemd directly which unit (if any) currently has a process whose
    # ExecStart is the legacy path — catches a unit in a non-standard location.
    local u
    for u in $(systemctl list-units --type=service --state=running,failed --no-legend --plain 2>/dev/null | awk '{print $1}'); do
        if systemctl show "$u" -p ExecStart 2>/dev/null | grep -q "/opt/lm/generic-agent"; then
            names="$names ${u%.service}"
        fi
    done
    local svc purged=0
    for svc in $(printf '%s\n' $names | sort -u); do
        [ -n "$svc" ] || continue
        [ "$svc" = "$SERVICE_NAME" ] && continue   # protect the new role-capable unit
        if [ -e "/etc/systemd/system/${svc}.service" ] \
           || systemctl list-unit-files "${svc}.service" 2>/dev/null | grep -qE "^${svc}\.service"; then
            systemctl stop    "$svc" 2>/dev/null || true
            systemctl disable "$svc" 2>/dev/null || true
            rm -f "/etc/systemd/system/${svc}.service"
            systemctl mask    "$svc" 2>/dev/null || true   # after rm → mask sticks (blocks manual restart)
            echo "🧹  Purged legacy leaf unit ${svc}.service."
            purged=1
        fi
    done
    # Also stop any live process still exec'ing the legacy path (belt-and-
    # suspenders if it was launched outside systemd), then remove the dir.
    if [ -d /opt/lm/generic-agent ]; then
        pkill -f "/opt/lm/generic-agent/src/agent.py" 2>/dev/null || true
        rm -rf /opt/lm/generic-agent
        echo "🧹  Removed legacy leaf dir /opt/lm/generic-agent."
        purged=1
    fi
    if [ "$purged" = 1 ]; then
        systemctl daemon-reload 2>/dev/null || true
        echo "    The role-capable ${SERVICE_NAME} now owns this box's spoke connection."
    fi
}
retire_legacy_agent

if [ -d "ldap/.git" ]; then
    echo "📂 LDAP repository already exists. Updating..."
    cd ldap && git fetch origin -q && git reset --hard origin/main && cd ..   # hard-sync (soft `git pull` no-ops on a diverged/detached clone)
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

# Circular logging: cap /var/log/lm/*.log so it can't fill the disk (copytruncate
# keeps the inode → the running spoke's O_APPEND FileHandler + systemd stderr
# keep appending). Belt-and-suspenders alongside logging_setup's RotatingFileHandler.
cat > /etc/logrotate.d/lm <<'LOGROTATE'
/var/log/lm/*.log /var/log/client-sim-*.log {
    su root root
    size 50M
    rotate 5
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
LOGROTATE

# Preserve the minted INSTALL_UUID across a re-run so the hub-side fingerprint
# (install_uuid) stays stable. The cat > below truncates .env, so without this
# the UUID line is wiped and the spoke mints a fresh one on next start → hub
# records a `reimaged` (fingerprint-changed) event for a box that was only
# updated. _ensure_install_uuid mints on first start only when this line is
# absent, so a fresh install is unchanged.
INSTALL_UUID_LINE=""
if [ -f .env ] && grep -q "^INSTALL_UUID=" .env; then
    EXISTING_UUID=$(grep "^INSTALL_UUID=" .env | cut -d= -f2-)
    [ -n "$EXISTING_UUID" ] && INSTALL_UUID_LINE="INSTALL_UUID=$EXISTING_UUID" \
        && echo "Preserving existing install UUID (hub fingerprint)."
fi
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
${INSTALL_UUID_LINE}
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