# LDAP Spoke — Lab Manager Directory Module

This repository is the **LDAP directory spoke** for the Lab Manager (LM) hub/spoke fleet (`module_type = "directory"`). It wraps an OpenLDAP/389-DS-style LDAP server (`slapd`) and exposes OU/user/group CRUD, group membership, password reset, rename, a unified user/computer search, and a hub-brokered TLS certificate install — all from the LM WebUI's **Directory** view instead of `ldapsearch`/`ldapmodify` on the command line.

See [`docs/ldap.md`](docs/ldap.md) for the full feature reference and [`docs/architecture-topology.md`](docs/architecture-topology.md) for the shared hub/spoke/agent topology.

## Files

- `install_ldap.sh` — Bash installer with **two modes**:
  - **(default)** installs the LM **directory spoke** that MANAGES a server (clones this repo into `/opt/lm/ldap`, builds the venv, writes `.env` + the `lm-ldap.service` systemd unit). Talks to `LDAP_SERVER_URL` (local OR remote); does NOT install `slapd`.
  - **`--infra-only`** provisions the **slapd server** fully zero-CLI: canonical base DN, auto-generated admin password, base structure applied, self-signed TLS (LDAPS), optional 2-node syncrepl mirror-mode, and the Entra ROPC SASL pass-through bridge. Installs no spoke unit. This is what the hub's `ldap-server` deploy role runs via `curl -sSL … | bash -s -- --infra-only <args>`. Idempotent + non-interactive.
  - The `lm-ldap.service` unit runs as `User=root` so `INSTALL_CERT` / mirror-mode re-apply can `ldapmodify -Y EXTERNAL` against `cn=config` and `systemctl restart slapd`.
- `base_structure.ldif` — the base-level `ou=users` / `ou=groups` containers, carrying an `@@BASE_DN@@` placeholder. `--infra-only` renders it (via `src/ldif_template.py`) with the chosen base DN and applies it idempotently. (No seed user — an auto-applied cleartext password would be a credential at rest.)
- `src/main.py` — `LdapControlPlane` (the spoke entrypoint, `python3 -m src.main`).
- `src/ldap_spoke.py` — `LdapSpoke(BaseSpoke)`; the hub-facing command dispatcher + `INSTALL_CERT` + `UPDATE_CONFIG` (Entra `.env` + mirror-mode re-apply).
- `src/ldap_manager.py` — `LdapManager`; the synchronous `python-ldap` CRUD wrapper (incl. tenant-scoped `LDAP_*` operations).
- `src/ldap_dn.py`, `src/ldif_template.py`, `src/replication.py` — dependency-free, unit-tested pure helpers (tenant-scoped DN math + escaping; base-structure LDIF templating; syncrepl mirror-mode LDIF builders). Shared by the installer (`python3 -m src.<mod>`) and the spoke.
- `src/entra_ropc_auth.py` — the `pam_exec` Entra ID ROPC pass-through authenticator (validates `{SASL}` binds against Entra).
- `tests/` — `test_install_cert.py` (INSTALL_CERT), `test_ldap_dn.py`, `test_ldif_template.py`, `test_replication.py`, `test_entra_ropc.py` (all stub/avoid `python-ldap`).

## How it runs

LDAP runs **primarily as the `ldap` role** hosted by the generic agent (`agent-<hostname>`, unit `lm-agent`): the agent opens a sub-spoke `{agent}-ldap` (module_type `directory`, parent-auto-approved) and self-installs this repo. The `install_ldap.sh` / `lm-ldap.service` standalone path is the **legacy** alternative for a dedicated single-purpose box. In either mode, connection settings (`LDAP_SERVER_URL`, `LDAP_ADMIN_DN`, `LDAP_ADMIN_PW`, `LDAP_BASE_DN`) are **pushed by the hub** via `UPDATE_CONFIG` from the WebUI Directory setup form — not read from a per-module `.env`.

## Install

**Provision the server (zero-CLI):**

```bash
sudo ./install_ldap.sh --infra-only \
  --base-dn dc=lm,dc=local --server-id 1 \
  --peer ldaps://ldap2.lm.local:636 \
  --entra-tenant <tenant-guid> --entra-client <client-guid> \
  --entra-cert /etc/lm/entra/client-cert.pem --entra-key /etc/lm/entra/client-key.pem
```

Post-`--infra-only` args (all optional; the hub's `ldap-server` role passes exactly these): `--base-dn <dn>` (derived from the host DNS domain if omitted, fallback `dc=lm,dc=local`), `--admin-dn <dn>` (default `cn=admin,<base-dn>`), `--admin-pw <pw>` (auto-generated strong password if omitted — printed once at the end), `--server-id <1|2>` + `--peer <ldap-url>` (repeatable) for mirror-mode, `--entra-tenant/--entra-client/--entra-cert/--entra-key/--entra-scope`, `--server-url`. Re-runnable/idempotent. **The base DN is fixed at first install** (slapd won't re-suffix an existing DB).

**Install the managing spoke:**

```bash
sudo ./install_ldap.sh --hub wss://172.16.1.31:443 --id ldap-spoke-1
```

`--hub` accepts a bare IP/host (normalized to `wss://<host>:443`); omit it (or pass `auto`) to auto-discover the hub via mDNS/DNS. Other flags: `--id`/`--name`, `--secret` (PSK; omit to connect unauthenticated and await WebUI approval), `--hub-secret`, `--server-url` (local or remote server), `--all-prereqs` (no-op). The spoke's `.env` defaults `LDAP_ADMIN_PW=` (empty — set it, or push config from the WebUI, before the spoke can bind). A single box can run both modes (server + spoke) co-located.

## Verification

Once installed and the spoke has bound (green status in the WebUI), verify the server directly:

```bash
# List all entries under your base DN:
ldapsearch -x -b "dc=example,dc=org" -H ldap://localhost

# Test admin bind (use the password you set in the WebUI or .env):
ldapsearch -x -D "cn=admin,dc=example,dc=org" -w "yourpassword" -b "dc=example,dc=org"
```

Replace `dc=example,dc=org` with your actual base DN.

## Prerequisites

- A fresh installation of Ubuntu or Debian.
- Root or sudo access (the installer and `INSTALL_CERT` require root).
- An LM hub reachable at `wss://<hub>:443` (or auto-discovered via mDNS/DNS).