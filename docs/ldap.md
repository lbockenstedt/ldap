# ldap — Directory

LDAP directory spoke. Repo: `ldap`. `module_type = "directory"`. See [architecture-topology.md](architecture-topology.md).

## Role & module_type

Directory spoke for an OpenLDAP/389-DS-style server (install targets `slapd`; `ldap_manager.py` uses `python-ldap`). OU/user/group CRUD, group membership, password set, rename (modrdn), and a unified user/computer search. Not a discovery source for IPAM.

## What it does

ldap manages a real LDAP directory server for the lab — organizational units, user accounts, groups, group membership, and passwords — from the WebUI's **Directory** view instead of `ldapsearch`/`ldapmodify` on the command line.

It also feeds the hub's global search bar: any user or computer entry in the directory shows up when you search from anywhere in the WebUI, tagged as an LDAP result.

It is not an IPAM/NetBox discovery source — it doesn't push devices, IPs, or hosts into NetBox; its only outward integration points are the global search feed and (optionally) being a TLS certificate install target for the Certificate Management module.

## Entrypoints

`python3 -m src.main` (`LdapControlPlane`); spoke `LdapSpoke(BaseSpoke)`. systemd `lm-ldap.service` (`After=network.target slapd.service`, `User=root` for `INSTALL_CERT`). Installer `install_ldap.sh` (pre-seeds slapd debconf `slapd/domain string lm.local`, backend MDB, installs `slapd ldap-utils python3-pip python3-venv git curl jq libldap2-dev libsasl2-dev`, writes `.env` + unit; does **not** auto-apply `base_structure.ldif` — that file is a reference template of the People/Groups OUs + an example `admin_user`, apply it manually with `ldapadd` if you want that seed structure).

> **Primarily a role now.** LDAP runs mainly as the **`ldap`** role hosted by the generic agent (`agent-<hostname>`, unit `lm-agent`): the agent opens a sub-spoke `{agent}-ldap` (module_type `directory`, parent-auto-approved) and self-installs it via `agent/src/agent_spoke.py::_install_role` (clones `lbockenstedt/ldap.git` + deps). The dedicated `lm-ldap.service` / `install_ldap.sh` `ldap-spoke-1` path is the **legacy/standalone** alternative. Connection config (`LDAP_SERVER_URL`/admin DN/PW/base DN) comes from the hub push (WebUI), not a per-module `.env`.

## Ports / backends

Talks to the LDAP server via `python-ldap` (`ldap.initialize` + `simple_bind_s`), `src/ldap_manager.py`. Default `LDAP_SERVER_URL=ldap://localhost:389`. No port served.

## Environment variables

`SPOKE_ID`, `SPOKE_SECRET`, `HUB_SECRET`, `HUB_URL` (installer-written; the shipped `.env.template` still carries the legacy `HUB_WS`/`HUB_API` from the retired bare-8765 hub — those are no longer read by `main.py`, which takes `--hub` on the command line), `LDAP_ADMIN_DN` (`cn=admin,dc=example,dc=org`), `LDAP_ADMIN_PW` (required; warned if empty), `LDAP_BASE_DN` (`dc=example,dc=org`), `LDAP_SERVER_URL` (`ldap://localhost:389`). Note: `.env.template` lacks `LDAP_SERVER_URL`; the installer writes it.

## Install flags

`install_ldap.sh`: `--hub` (accepts a bare IP/host, normalized to `wss://<host>:443`; default `auto` = mDNS/DNS discovery), `--id`/`--name`, `--secret`, `--hub-secret`, `--all-prereqs` (no-op). Only passes `--secret`/`--hub-secret` when non-empty (avoid argparse abort); an empty/default secret is dropped so the spoke connects unauthenticated and awaits WebUI approval.

## Key commands / handlers (`ldap_spoke.handle_command`)

`GET_VERSION`, `UPDATE_CONFIG` (re-init `LdapManager`), `LIST_OUS`, `CREATE_OU`, `UPDATE_OU` (modrdn rename), `LIST_USERS`, `CREATE_USER` (`inetOrgPerson`; `secrets.token_urlsafe(16)` random password if none, returned; stored as `{SSHA}` not cleartext), `UPDATE_USER` (modify cn/sn/givenName/mail + optional uid rename), `LIST_GROUPS` (`groupOfNames` or `posixGroup`), `CREATE_GROUP` (`groupOfNames` requires ≥1 member → seeded with base DN), `UPDATE_GROUP` (cn modrdn), `ADD_USER_TO_GROUP`, `REMOVE_USER_FROM_GROUP`, `SET_PASSWORD` (`passwd_s` with `modify_s` userPassword fallback), `DELETE_ENTITY`, `SEARCH_USERS` (filter on uid/cn/mail/sn/givenName/dNSHostName, escapes `\*()`, tags `source="ldap"`, type `user`/`computer`), `INSTALL_CERT` (hub-brokered Let's Encrypt cert → `/etc/ldap/tls` + `ldapmodify -Y EXTERNAL -H ldapi:///` on `cn=config` + `systemctl restart slapd`; root-only).

## Key files

`src/main.py`, `src/ldap_spoke.py`, `src/ldap_manager.py` (~300 lines, whole `LdapManager`), `install_ldap.sh`, `base_structure.ldif` (reference OU/user template, not auto-applied), `tests/test_install_cert.py` (INSTALL_CERT unit tests, stubs python-ldap), `README.md`, `.env.template`, `requirements.txt`, `VERSION`.

## Notable behaviors & gotchas

- **Namespace-package loader (no `__init__.py`)** — `src/` has no `__init__.py`; works as a Python 3 namespace package. `main.py` runs as `-m src.main` and imports `from src.ldap_spoke import LdapSpoke`; `ldap_spoke.py` uses the **relative** import `from .ldap_manager import LdapManager`. `BaseSpoke` import uses the dual-path `try: from base_spoke import BaseSpoke except ImportError: from core.src.base_spoke import BaseSpoke`. Installer sets `PYTHONPATH=$INSTALL_DIR:$INSTALL_DIR/core/src:$INSTALL_DIR/ldap/src`.
- **`LdapControlPlane.register_module` is overridden locally** (assigns `self.modules[name]`) — minor duplication; the only one of this group that does this.
- **Password generation** — `create_user` never hardcodes a password (`secrets.token_urlsafe(16)` default; returns it). The password is stored `{SSHA}`-hashed (`LdapManager._ssha`) because slapd does **not** hash a plain `add`/`modify` of `userPassword` (only the Password-Modify ext-op does) — so hashing before store avoids cleartext passwords at rest.
- **`search`** is the cross-cutting directory query the hub uses for global search (returns `source="ldap"` records compatible with the hub's unified results).
- **Generic python-ldap** — works against any RFC-4511 server; nothing FreeIPA-specific. Install path targets OpenLDAP `slapd`; FreeIPA/389-DS work with the same `LDAP_ADMIN_DN`/`LDAP_BASE_DN`/`LDAP_SERVER_URL`.
- **DN/filter injection guards** — DN RDN components are escaped via `ldap.dn.escape_dn_chars` (`_escape_rdn`) and search input is RFC-4515 escaped (`\` → `\5c`, `*` → `\2a`, `(` → `\28`, `)` → `\29`). The spoke binds as admin, so this is security-critical.

## How it works

- **Hub connection.** Like every LM spoke, ldap dials the hub over a WebSocket. In the current unified model this is the sub-spoke `{agent}-ldap` opened by the generic agent (parent-auto-approved); the legacy path is the standalone `ldap-spoke-1` dialing the hub directly. Either way the wire protocol is identical.
- **Config delivery.** Connection settings — `LDAP_SERVER_URL`, `LDAP_ADMIN_DN`, `LDAP_ADMIN_PW`, `LDAP_BASE_DN` — are **not** read from a per-module `.env` when running as a role. The hub pushes them via `UPDATE_CONFIG`, normally right after you fill in the Directory setup form in the WebUI. On `UPDATE_CONFIG` the spoke discards its current config and rebuilds `LdapManager` from scratch with the new values, so a fixed typo (e.g. a wrong admin password) takes effect on the next push without restarting the process.
- **Command flow.** Every WebUI action (list/create/update/delete an OU, user, or group; add/remove group membership; reset a password; rename an entry) becomes one `LdapSpoke.handle_command` call, which runs the matching `LdapManager` method. Because `python-ldap` calls are synchronous/blocking, each one runs in a worker thread via `asyncio.to_thread` — this keeps the spoke's heartbeat to the hub alive even if the directory server is slow or unreachable. Without that, a stalled bind would freeze the spoke's event loop, queue every other command behind it, and get the spoke disconnected as unresponsive. `INSTALL_CERT` is the exception: it is async-native (subprocess + filesystem writes), not `to_thread`-wrapped.
- **Connection hygiene.** Read/list operations (`list_ous`, `list_users`, `list_groups`) and the health check (`check_connection`) use the leak-free `LdapManager._conn()` context manager, which opens a fresh bind and always unbinds in `finally` — even on error. Write operations (`create_*`, `update_*`, `delete_entity`, group membership, `set_password`) still call the older `_get_connection()`, which binds but does **not** explicitly unbind. This is a residual gap (slapd reaps idle sockets, so it hasn't surfaced at lab scale), not a fully-applied fix — worth revisiting before a long-running high-throughput deployment.
- **Global search integration.** `SEARCH_USERS` is the query the hub's cross-system search fans out to every connected directory spoke (alongside NetBox, DHCP, VM, and session searches). It matches on `uid`, `cn`, `mail`, `sn`, `givenName`, or `dNSHostName`, and returns each hit tagged `source="ldap"` with `type` `user` or `computer` (based on `objectClass`) so the WebUI can merge and label results consistently across modules.
- **Certificate installation.** The hub can push an `INSTALL_CERT` command to the ldap spoke — the same command it sends to firewall and hypervisor targets — when a certificate issued by the Certificate Management (le) module is targeted at this directory server. The spoke writes the leaf certificate and private key (plus any CA chain) under `/etc/ldap/tls`, points slapd's `cn=config` `olcTLSCertificateFile`/`olcTLSCertificateKeyFile`/`olcTLSCACertificateFile` at the new files via `ldapmodify -Y EXTERNAL -H ldapi:///`, and restarts `slapd` so the new TLS context takes effect (OpenLDAP ITS#6135: global TLS settings via `cn=config` only reliably apply on restart). The private key is written 0600 and chowned to the slapd user (best-effort) so slapd can read it; it is never logged. This only works when the ldap spoke runs on the OpenLDAP host itself as root (needed to restart the service and read the key file) — `lm-ldap.service` sets `User=root` for this reason.

## How to use it

1. **Connect a directory.** In the Directory view, enter the LDAP server URL, base DN, admin DN, and admin password, and save. This is pushed to the spoke as `UPDATE_CONFIG`; a green/healthy status means the bind succeeded.
2. **Create an OU.** Give it a name (optionally under a parent OU/DN). It's created as an `organizationalUnit` entry.
3. **Create a user.** Provide first name, last name, username, email, and the OU to place them in. Leave the password field blank to have ldap generate a strong random one — it's returned once in the response, so copy it down or hand it to the user immediately; it is not shown again.
4. **Create a group.** Groups are `groupOfNames`, which requires at least one member to exist at all — ldap seeds a new group with the directory's base DN as a placeholder member so creation never fails; add real members afterward and remove the placeholder if you like.
5. **Add / remove a user from a group.** Pick the user and the group; this is a single membership add/remove, not a full group rewrite.
6. **Reset a password.** Set a new password for a user DN directly (no need to know the old one) — this uses LDAP's Password-Modify extended operation, falling back to a direct attribute replace if the server doesn't support it.
7. **Rename an entry.** Renaming an OU, user, or group changes its RDN (`modrdn`) — e.g. changing a username changes the `uid=` component of its DN, which is why the DN in the UI may change after a rename.

## Troubleshooting / common questions

- **"Connect fails / can't bind to the directory."** Double-check the server URL, admin DN, admin password, and base DN in the Directory setup form. An empty admin password is explicitly logged as a warning — the bind will fail with an authentication error until it's set.
- **"The Directory spoke shows offline/red."** The `ldap` role isn't installed on the agent, the agent process (`lm-agent`) is down, or the sub-spoke hasn't been approved yet. Confirm the role is active on the intended host.
- **"Creating a group fails."** `groupOfNames` entries require at least one `member` attribute — if creation still fails after that, check that the target OU exists and the admin account has write access there.
- **"Does this work with FreeIPA or 389-DS, not just OpenLDAP?"** Yes for directory operations — `python-ldap` speaks generic RFC-4511 LDAP, so any compliant server works once you point `LDAP_SERVER_URL`/`LDAP_ADMIN_DN`/`LDAP_BASE_DN` at it. The **installer** (`install_ldap.sh`) is OpenLDAP/`slapd`-specific; a FreeIPA/389-DS server is expected to already exist and just be pointed at.
- **"Why isn't there a config file I can edit for the connection settings?"** In the current agent+role model, config comes from the hub's `UPDATE_CONFIG` push (the WebUI form), not a per-module `.env` — this is deliberate so the hub is the single source of truth and a config change doesn't require touching the host.
- **"A user isn't showing up in the global search bar."** Confirm the Directory spoke is online, and that the search term matches one of the indexed fields (`uid`, `cn`, `mail`, `sn`, `givenName`, `dNSHostName`) — search does not match on arbitrary attributes like OU name or group membership.
- **"INSTALL_CERT reports ldapmodify error 80."** slapd couldn't read the private key — the key file isn't chowned to the slapd user (Debian: `openldap`), or the file mode is too tight. The spoke chowns the key best-effort and logs a warning if the user is missing/non-standard; confirm `LDAP_SLAPD_USER` matches your distro's slapd user.

## Related pages

[architecture-topology.md](architecture-topology.md), [lm-hub.md](lm-hub.md), [install-flags.md](install-flags.md).