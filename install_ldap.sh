#!/bin/bash
set -e

# =============================================================================
# LDAP module installer — TWO modes (mirrors netbox/install.sh's split):
#
#   (default)      Install the LM **spoke** (module_type=directory) that MANAGES
#                  an LDAP server. Talks to LDAP_SERVER_URL (local OR remote).
#                  Does NOT provision a server.
#
#   --infra-only   Provision the LDAP **server** (slapd) fully zero-CLI: canonical
#                  base DN, auto-generated admin password, base structure applied,
#                  self-signed TLS, optional 2-node syncrepl mirror-mode, and the
#                  Entra ROPC SASL pass-through bridge. Installs NO spoke unit.
#                  This is the entry point the hub's `ldap-server` deploy role
#                  invokes via curl-pipe-bash:
#                    curl -sSL .../ldap/main/install_ldap.sh | bash -s -- --infra-only [args]
#                  Idempotent + non-interactive (safe to re-run).
#
# A single generic-agent box may run the server (--infra-only) AND the spoke role
# AND other roles co-located, or they can live on separate boxes.
# =============================================================================

# ── Defaults ─────────────────────────────────────────────────────────────────
# HUB_URL "auto": spoke auto-discovers the unified :443 hub (DNS then mDNS).
HUB_URL="${HUB_URL:-auto}"
SPOKE_ID="${SPOKE_ID:-ldap-$(hostname -s)}"
SPOKE_SECRET="lm-secret"
HUB_SECRET=""

INFRA_ONLY=false          # --infra-only: provision the slapd SERVER, no spoke
BASE_DN=""                # --base-dn; derived from host domain if empty
ADMIN_DN=""               # --admin-dn; defaults to cn=admin,<BASE_DN>
ADMIN_PW=""               # --admin-pw; auto-generated (strong) if empty
SERVER_ID=""              # --server-id (1|2) for mirror-mode
PEERS=()                  # --peer (repeatable) → LDAP_MIRROR_PEERS
ENTRA_TENANT=""           # --entra-tenant  → ENTRA_TENANT_ID
ENTRA_CLIENT=""           # --entra-client  → ENTRA_CLIENT_ID
ENTRA_CERT=""             # --entra-cert    → ENTRA_CLIENT_CERT (path)
ENTRA_KEY=""              # --entra-key     → ENTRA_CLIENT_KEY (path)
ENTRA_SCOPE="openid"      # --entra-scope   → ENTRA_ROPC_SCOPE
SERVER_URL="ldap://localhost:389"   # --server-url (spoke → server)

REPO_URL="https://github.com/lbockenstedt/ldap.git"
INSTALL_DIR="/opt/lm"
OLD_INSTALL_DIR="/opt/lm-manager"
TLS_DIR="/etc/ldap/tls"
SASL_SERVICE="slapd"      # slapd's Cyrus SASL app name → /etc/pam.d/<this>

# ── Parse arguments ──────────────────────────────────────────────────────────
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --hub) HUB_URL="$2"; shift ;;
        --id|--name) SPOKE_ID="$2"; shift ;;
        --secret) SPOKE_SECRET="$2"; shift ;;
        --hub-secret) HUB_SECRET="$2"; shift ;;
        --infra-only) INFRA_ONLY=true ;;
        --base-dn) BASE_DN="$2"; shift ;;
        --admin-dn) ADMIN_DN="$2"; shift ;;
        --admin-pw) ADMIN_PW="$2"; shift ;;
        --server-id) SERVER_ID="$2"; shift ;;
        --peer) PEERS+=("$2"); shift ;;
        --entra-tenant) ENTRA_TENANT="$2"; shift ;;
        --entra-client) ENTRA_CLIENT="$2"; shift ;;
        --entra-cert) ENTRA_CERT="$2"; shift ;;
        --entra-key) ENTRA_KEY="$2"; shift ;;
        --entra-scope) ENTRA_SCOPE="$2"; shift ;;
        --server-url) SERVER_URL="$2"; shift ;;
        --all-prereqs) ;;  # no-op; accepted for LM hub compat
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

# Accept a bare hub IP/host for --hub (e.g. `--hub 172.16.1.31`). A ws://|wss://
# scheme or the "auto" sentinel is left as-is; host:port gets a scheme; a bare
# host defaults to the unified :443.
if [ -n "${HUB_URL:-}" ] && [ "$HUB_URL" != "auto" ]; then
    case "$HUB_URL" in
        ws://*|wss://*) : ;;
        *:[0-9]*)       HUB_URL="wss://${HUB_URL}" ;;
        *)              HUB_URL="wss://${HUB_URL}:443" ;;
    esac
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "⚠️  This script must be run as root."
    exit 1
fi

# ── Helpers ──────────────────────────────────────────────────────────────────

# Derive a base DN from the host DNS domain (foo.example.com → dc=example,dc=com).
# Falls back to dc=lm,dc=local when the host has no domain.
derive_base_dn() {
    local dom
    dom="$(dnsdomainname 2>/dev/null || true)"
    [ -z "$dom" ] && dom="$(hostname -d 2>/dev/null || true)"
    if [ -n "$dom" ]; then
        echo "dc=$(echo "$dom" | sed 's/\./,dc=/g')"
    else
        echo "dc=lm,dc=local"
    fi
}

# dc=lm,dc=local → lm.local (for the slapd debconf domain).
domain_from_base_dn() { echo "$1" | sed 's/dc=//g; s/,/./g'; }

# Clone/update this repo into $INSTALL_DIR/ldap and (re)build the venv. Shared by
# both modes — the server needs the venv for the ROPC bridge + the pure LDIF /
# replication renderers; the spoke needs it to run.
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

setup_repo_and_venv() {
    mkdir -p "$INSTALL_DIR"
    cd "$INSTALL_DIR"
    retire_legacy_agent   # purge a legacy lm-generic-agent leaf before (re)cloning
    if [ -d "ldap/.git" ]; then
        echo "📂 LDAP repository already exists. Updating..."
        cd ldap && git fetch origin -q && git reset --hard origin/main && cd ..
    else
        echo "🌐 Cloning LDAP repository..."
        git clone "$REPO_URL"
    fi
    cd ldap
    echo "♻️  Resetting virtual environment..."
    rm -rf venv
    python3 -m venv venv
    if [ ! -f "venv/bin/python3" ]; then
        echo "❌ Critical Error: venv creation failed."
        exit 1
    fi
    ./venv/bin/python3 -m pip install --upgrade pip -q
    if [ -f "requirements.txt" ]; then
        ./venv/bin/python3 -m pip install -r requirements.txt -q
    fi
}

# =============================================================================
# INFRA-ONLY: provision the slapd SERVER (zero-CLI, idempotent)
# =============================================================================
provision_server() {
    [ -z "$BASE_DN" ]  && BASE_DN="$(derive_base_dn)"
    [ -z "$ADMIN_DN" ] && ADMIN_DN="cn=admin,$BASE_DN"
    if [ -z "$ADMIN_PW" ]; then
        ADMIN_PW="$(openssl rand -base64 24 2>/dev/null | tr -dc 'A-Za-z0-9' | cut -c1-24)"
        [ -z "$ADMIN_PW" ] && ADMIN_PW="$(head -c18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-24)"
    fi
    local DOMAIN; DOMAIN="$(domain_from_base_dn "$BASE_DN")"

    echo "🔧 Provisioning LDAP server"
    echo "   Base DN:  $BASE_DN"
    echo "   Admin DN: $ADMIN_DN"
    echo "   Domain:   $DOMAIN"

    # 1. Pre-seed slapd debconf with the CHOSEN domain/password so apt is fully
    #    non-interactive. NOTE: the base DN is fixed at FIRST install (slapd
    #    won't re-suffix an existing DB on a re-run — apt skips reconfigure).
    apt-get update
    apt-get install -y debconf-utils
    debconf-set-selections <<DEBCONF
slapd slapd/internal/generated_adminpw password $ADMIN_PW
slapd slapd/internal/adminpw password $ADMIN_PW
slapd slapd/password1 password $ADMIN_PW
slapd slapd/password2 password $ADMIN_PW
slapd slapd/domain string $DOMAIN
slapd shared/organization string Lab Manager
slapd slapd/backend select MDB
slapd slapd/purge_database boolean true
slapd slapd/move_old_database boolean true
slapd slapd/allow_ldap_v2 boolean false
slapd slapd/no_configuration boolean false
DEBCONF

    # 2. Install slapd + ALL prereqs (sasl2-bin/libsasl2-modules for the Entra
    #    pass-through, openssl for the self-signed TLS cert, python for the
    #    renderers + ROPC bridge, ldap-utils for ldapmodify/ldapadd).
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        slapd ldap-utils sasl2-bin libsasl2-modules libsasl2-modules-ldap \
        openssl git python3-pip python3-venv jq curl \
        libldap2-dev libsasl2-dev
    systemctl enable slapd >/dev/null 2>&1 || true
    systemctl start slapd >/dev/null 2>&1 || true
    sleep 1

    # 3. Repo + venv (needed for the renderers + ROPC bridge).
    setup_repo_and_venv
    cd "$INSTALL_DIR/ldap"

    # 4. Enforce the admin rootDN/rootPW on the mdb DB (idempotent replace) — so
    #    --admin-pw applies even when slapd pre-existed.
    local HASH; HASH="$(slappasswd -s "$ADMIN_PW")"
    ldapmodify -Y EXTERNAL -H ldapi:/// >/dev/null 2>&1 <<LDIF || true
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcRootDN
olcRootDN: $ADMIN_DN
-
replace: olcRootPW
olcRootPW: $HASH
LDIF

    # 5. Apply the templated base structure (ou=users/ou=groups) idempotently.
    local TMPLDIF="/tmp/lm-base-structure.ldif"
    ./venv/bin/python3 -m src.ldif_template "$BASE_DN" base_structure.ldif > "$TMPLDIF"
    local out rc
    out="$(ldapadd -x -D "$ADMIN_DN" -w "$ADMIN_PW" -H ldapi:/// -f "$TMPLDIF" 2>&1)" && rc=0 || rc=$?
    if [ "${rc:-0}" -ne 0 ] && ! echo "$out" | grep -qi "Already exists"; then
        echo "⚠️  base structure apply reported: $out"
    fi
    rm -f "$TMPLDIF"

    # 6. Self-signed TLS so LDAPS works before the hub brokers a real cert
    #    (INSTALL_CERT later overwrites these same paths).
    configure_self_signed_tls

    # 7. Entra ROPC SASL pass-through bridge.
    configure_sasl_passthrough

    # 8. Persist server config to .env (the ROPC bridge reads it; also seeds a
    #    co-located spoke).
    write_server_env

    # 9. 2-node syncrepl mirror-mode (only when --server-id + --peer given).
    if [ -n "$SERVER_ID" ] && [ "${#PEERS[@]}" -gt 0 ]; then
        configure_mirror_mode
    fi

    systemctl restart slapd >/dev/null 2>&1 || true

    echo ""
    echo "🎉 LDAP server provisioned (infra-only)."
    echo "   LDAP:      ldap://$(hostname -f 2>/dev/null || hostname):389"
    echo "   LDAPS:     ldaps://$(hostname -f 2>/dev/null || hostname):636 (self-signed until INSTALL_CERT)"
    echo "   Base DN:   $BASE_DN"
    echo "   Admin DN:  $ADMIN_DN"
    echo "   Admin PW:  $ADMIN_PW"
    echo "   .env:      $INSTALL_DIR/ldap/.env (chmod 600)"
    echo "   Next: point the ldap (directory) spoke's connection at the URL/base/admin above."
    exit 0
}

configure_self_signed_tls() {
    mkdir -p "$TLS_DIR"
    if [ ! -f "$TLS_DIR/slapd-cert.pem" ]; then
        local CN SAN
        CN="$(hostname -f 2>/dev/null || hostname)"
        SAN="DNS:${CN},DNS:localhost,IP:127.0.0.1"
        echo "🔒 Generating self-signed slapd TLS cert ($CN)..."
        openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
            -subj "/CN=${CN}" -addext "subjectAltName=${SAN}" \
            -keyout "$TLS_DIR/slapd-key.pem" -out "$TLS_DIR/slapd-cert.pem" >/dev/null 2>&1 \
            || echo "⚠️  self-signed TLS generation failed; LDAPS unavailable until INSTALL_CERT."
    fi
    if [ -f "$TLS_DIR/slapd-key.pem" ]; then
        chmod 600 "$TLS_DIR/slapd-key.pem"; chmod 644 "$TLS_DIR/slapd-cert.pem"
        chown openldap:openldap "$TLS_DIR"/slapd-*.pem 2>/dev/null || true
        ldapmodify -Y EXTERNAL -H ldapi:/// >/dev/null 2>&1 <<LDIF || true
dn: cn=config
changetype: modify
replace: olcTLSCertificateFile
olcTLSCertificateFile: $TLS_DIR/slapd-cert.pem
-
replace: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: $TLS_DIR/slapd-key.pem
LDIF
        # Enable the ldaps:// listener (idempotent).
        if grep -q '^SLAPD_SERVICES=' /etc/default/slapd 2>/dev/null; then
            sed -i 's|^SLAPD_SERVICES=.*|SLAPD_SERVICES="ldap:/// ldapi:/// ldaps:///"|' /etc/default/slapd
        else
            echo 'SLAPD_SERVICES="ldap:/// ldapi:/// ldaps:///"' >> /etc/default/slapd
        fi
    fi
}

# Wire slapd {SASL} binds → Cyrus SASL → saslauthd(-a pam) → pam_exec → ROPC.
configure_sasl_passthrough() {
    echo "🔗 Configuring Entra ROPC SASL pass-through..."
    # olcPasswordHash advertises {SSHA} + {SASL}; a user's userPassword of
    # {SASL}<upn> routes the bind check to Cyrus SASL.
    ldapmodify -Y EXTERNAL -H ldapi:/// >/dev/null 2>&1 <<'LDIF' || true
dn: cn=config
changetype: modify
replace: olcPasswordHash
olcPasswordHash: {SSHA}
olcPasswordHash: {SASL}
LDIF

    # saslauthd → PAM.
    if [ -f /etc/default/saslauthd ]; then
        sed -i 's/^START=.*/START=yes/' /etc/default/saslauthd
        if grep -q '^MECHANISMS=' /etc/default/saslauthd; then
            sed -i 's/^MECHANISMS=.*/MECHANISMS="pam"/' /etc/default/saslauthd
        else
            echo 'MECHANISMS="pam"' >> /etc/default/saslauthd
        fi
    else
        cat > /etc/default/saslauthd <<'SASLD'
START=yes
DESC="SASL Authentication Daemon"
NAME="saslauthd"
MECHANISMS="pam"
MECH_OPTIONS=""
THREADS=5
OPTIONS="-c -m /var/run/saslauthd"
SASLD
    fi

    # slapd's Cyrus SASL app config: verify passwords via saslauthd.
    mkdir -p /etc/ldap/sasl2
    cat > /etc/ldap/sasl2/slapd.conf <<'SASLCONF'
pwcheck_method: saslauthd
mech_list: plain login
saslauthd_path: /var/run/saslauthd/mux
SASLCONF

    # PAM service (named after slapd's SASL service) → run the ROPC bridge with
    # the password exposed on stdin (expose_authtok).
    cat > "/etc/pam.d/$SASL_SERVICE" <<PAM
# LM Entra ID ROPC pass-through. slapd {SASL} binds route here via saslauthd.
# The UPN is \$PAM_USER; the bind password is on stdin (expose_authtok).
auth     required   pam_exec.so expose_authtok quiet $INSTALL_DIR/ldap/venv/bin/python3 $INSTALL_DIR/ldap/src/entra_ropc_auth.py
account  required   pam_permit.so
PAM

    # slapd (openldap user) must reach the saslauthd mux socket.
    adduser openldap sasl >/dev/null 2>&1 || true
    systemctl enable saslauthd >/dev/null 2>&1 || true
    systemctl restart saslauthd >/dev/null 2>&1 || true
}

# Configure 2-node syncrepl mirror-mode via the shared pure LDIF builders.
configure_mirror_mode() {
    echo "🔁 Configuring syncrepl mirror-mode (server-id $SERVER_ID, ${#PEERS[@]} peer(s))..."
    # syncprov overlay (PROVIDER role) — tolerate "already exists" for idempotency.
    ./venv/bin/python3 -m src.replication syncprov \
        | ldapmodify -Y EXTERNAL -H ldapi:/// >/dev/null 2>&1 || true
    # serverID + syncrepl(consumer) + mirrormode.
    ./venv/bin/python3 -m src.replication serverid "$SERVER_ID" \
        | ldapmodify -Y EXTERNAL -H ldapi:/// >/dev/null 2>&1 || true
    ./venv/bin/python3 -m src.replication syncrepl "$SERVER_ID" "$BASE_DN" "$ADMIN_DN" "$ADMIN_PW" "${PEERS[@]}" \
        | ldapmodify -Y EXTERNAL -H ldapi:/// >/dev/null 2>&1 || true
    ./venv/bin/python3 -m src.replication mirrormode true \
        | ldapmodify -Y EXTERNAL -H ldapi:/// >/dev/null 2>&1 || true
}

write_server_env() {
    local peers_json="[]"
    if [ "${#PEERS[@]}" -gt 0 ]; then
        peers_json="$(printf '%s\n' "${PEERS[@]}" | jq -R . | jq -s -c .)"
    fi
    cat > "$INSTALL_DIR/ldap/.env" <<EOF
# LDAP SERVER config (infra-only). Read by the Entra ROPC bridge + a co-located spoke.
LDAP_BASE_DN=$BASE_DN
LDAP_ADMIN_DN=$ADMIN_DN
LDAP_ADMIN_PW=$ADMIN_PW
LDAP_SERVER_URL=$SERVER_URL
LDAP_SERVER_ID=$SERVER_ID
LDAP_MIRROR_PEERS=$peers_json
ENTRA_TENANT_ID=$ENTRA_TENANT
ENTRA_CLIENT_ID=$ENTRA_CLIENT
ENTRA_CLIENT_CERT=$ENTRA_CERT
ENTRA_CLIENT_KEY=$ENTRA_KEY
ENTRA_ROPC_SCOPE=$ENTRA_SCOPE
EOF
    chmod 600 "$INSTALL_DIR/ldap/.env"
}

# =============================================================================
# DEFAULT: install the LM directory SPOKE (manages a local OR remote server)
# =============================================================================
install_spoke() {
    echo "🚀 Installing LDAP Manager Spoke (module_type=directory)..."

    if [ -z "$SPOKE_SECRET" ] || [ "$SPOKE_SECRET" == "lm-secret" ]; then
        SPOKE_SECRET=""
        echo "ℹ️  No pre-shared secret — spoke connects unauthenticated and awaits WebUI approval."
    fi

    # Spoke prereqs: python-ldap build deps + ldap-utils (for INSTALL_CERT when
    # co-located). NOT slapd — the server is provisioned separately (--infra-only).
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        ldap-utils python3-pip python3-venv git curl jq libldap2-dev libsasl2-dev

    if ! id "svc_lm" &>/dev/null; then
        echo "👤 Creating service user svc_lm..."
        useradd -r -s /bin/false svc_lm
    fi

    if [ -d "$OLD_INSTALL_DIR" ]; then
        echo "🗑️  Removing legacy installation at $OLD_INSTALL_DIR..."
        rm -rf "$OLD_INSTALL_DIR"
    fi

    setup_repo_and_venv
    cd "$INSTALL_DIR/ldap"

    echo "⚙️  Configuring Spoke Identity..."
    mkdir -p /var/log/lm

    # Circular logging cap (copytruncate keeps the inode for the running spoke).
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

    # Preserve a minted INSTALL_UUID across re-runs (hub fingerprint stability).
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
LDAP_ADMIN_DN=${ADMIN_DN:-cn=admin,dc=example,dc=org}
LDAP_BASE_DN=${BASE_DN:-dc=example,dc=org}
LDAP_SERVER_URL=$SERVER_URL
# LDAP_ADMIN_PW: REQUIRED to bind. Empty by default (fail-closed) — set it here
# OR push it from the WebUI (UPDATE_CONFIG). The hub is the source of truth.
LDAP_ADMIN_PW=${ADMIN_PW:-}
# 2-node mirror-mode + Entra ROPC (normally pushed by the hub via UPDATE_CONFIG).
LDAP_SERVER_ID=$SERVER_ID
LDAP_MIRROR_PEERS=
ENTRA_TENANT_ID=$ENTRA_TENANT
ENTRA_CLIENT_ID=$ENTRA_CLIENT
ENTRA_CLIENT_CERT=$ENTRA_CERT
ENTRA_CLIENT_KEY=$ENTRA_KEY
ENTRA_ROPC_SCOPE=$ENTRA_SCOPE
${INSTALL_UUID_LINE}
EOF
    chmod 600 .env

    # Only pass --secret/--hub-secret when set (empty value aborts argparse).
    SECRET_ARG=""
    [ -n "$SPOKE_SECRET" ] && SECRET_ARG="--secret $SPOKE_SECRET"
    HUB_SECRET_ARG=""
    [ -n "${HUB_SECRET:-}" ] && HUB_SECRET_ARG="--hub-secret ${HUB_SECRET}"

    echo "⚙️  Creating systemd service for auto-start..."
    cat <<EOF > /etc/systemd/system/lm-ldap.service
[Unit]
Description=Lab Manager Spoke - LDAP Manager
After=network.target slapd.service

[Service]
Type=simple
# root: INSTALL_CERT + mirror-mode UPDATE_CONFIG re-apply write cn=config via
# ldapmodify -Y EXTERNAL and restart slapd — all need root (when co-located).
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

    echo "🎉 LDAP Manager spoke installation complete!"
    echo "🌐 Hub Target: $HUB_URL"
    echo "🆔 Spoke ID: $SPOKE_ID"
    echo "📦 Version: $(cat VERSION 2>/dev/null || echo unknown)"
}

# ── Dispatch ─────────────────────────────────────────────────────────────────
if [ "$INFRA_ONLY" = true ]; then
    provision_server
else
    install_spoke
fi
