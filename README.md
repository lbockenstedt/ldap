# LDAP Spoke — Lab Manager Directory Module

This repository is the **LDAP directory spoke** for the Lab Manager (LM) hub/spoke fleet (`module_type = "directory"`). It wraps an OpenLDAP/389-DS-style LDAP server (`slapd`) and exposes OU/user/group CRUD, group membership, password reset, rename, a unified user/computer search, and a hub-brokered TLS certificate install — all from the LM WebUI's **Directory** view instead of `ldapsearch`/`ldapmodify` on the command line.

See [`docs/ldap.md`](docs/ldap.md) for the full feature reference and [`docs/architecture-topology.md`](docs/architecture-topology.md) for the shared hub/spoke/agent topology.

## Files

- `install_ldap.sh` — Bash installer for the **standalone** spoke path (installs `slapd` non-interactively via debconf pre-seeding, clones this repo into `/opt/lm/ldap`, builds the venv, writes `.env` + the `lm-ldap.service` systemd unit). The unit runs as `User=root` so `INSTALL_CERT` can `ldapmodify -Y EXTERNAL` against `cn=config` and `systemctl restart slapd`.
- `base_structure.ldif` — a **reference template** defining the base Organizational Units (`People`, `Groups`) plus an example `admin_user`. It is **not** auto-applied by the installer; load it manually with `ldapadd -Y EXTERNAL -H ldapi:/// -f base_structure.ldif` (adjust the `dc=EXAMPLE,dc=COM` suffix to your real base DN first).
- `src/main.py` — `LdapControlPlane` (the spoke entrypoint, `python3 -m src.main`).
- `src/ldap_spoke.py` — `LdapSpoke(BaseSpoke)`; the hub-facing command dispatcher + `INSTALL_CERT` logic.
- `src/ldap_manager.py` — `LdapManager`; the synchronous `python-ldap` CRUD wrapper.
- `tests/test_install_cert.py` — unit tests for the `INSTALL_CERT` flow (stubs `python-ldap`).

## How it runs

LDAP runs **primarily as the `ldap` role** hosted by the generic agent (`agent-<hostname>`, unit `lm-agent`): the agent opens a sub-spoke `{agent}-ldap` (module_type `directory`, parent-auto-approved) and self-installs this repo. The `install_ldap.sh` / `lm-ldap.service` standalone path is the **legacy** alternative for a dedicated single-purpose box. In either mode, connection settings (`LDAP_SERVER_URL`, `LDAP_ADMIN_DN`, `LDAP_ADMIN_PW`, `LDAP_BASE_DN`) are **pushed by the hub** via `UPDATE_CONFIG` from the WebUI Directory setup form — not read from a per-module `.env`.

## Standalone install

```bash
chmod +x install_ldap.sh
sudo ./install_ldap.sh --hub wss://172.16.1.31:443 --id ldap-spoke-1
```

`--hub` accepts a bare IP/host (normalized to `wss://<host>:443`); omit it (or pass `auto`) to auto-discover the hub via mDNS/DNS. Other flags: `--id`/`--name`, `--secret` (PSK; omit to connect unauthenticated and await WebUI approval), `--hub-secret`, `--all-prereqs` (no-op). The installer pre-seeds slapd debconf with domain `lm.local` and backend MDB; the `.env` defaults `LDAP_BASE_DN=dc=example,dc=org` and `LDAP_ADMIN_PW=` (empty — set it, or push config from the WebUI, before the spoke can bind).

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