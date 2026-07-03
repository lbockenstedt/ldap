# ldap — Directory

LDAP directory spoke. Repo: `ldap`. `module_type = "directory"`. See [architecture-topology.md](architecture-topology.md).

## Role & module_type

Directory spoke for an OpenLDAP/389-DS-style server (install targets `slapd`; `ldap_manager.py` uses `python-ldap`). OU/user/group CRUD, group membership, password set, rename (modrdn), and a unified user/computer search. Not a discovery source for IPAM.

## Entrypoints

`python3 -m src.main` (`LdapControlPlane`); spoke `LdapSpoke(BaseSpoke)`. systemd `lm-ldap.service` (`After=network.target slapd.service`). Installer `install_ldap.sh` (pre-seeds slapd debconf `slapd/domain string lm.local`, backend MDB, installs `slapd ldap-utils python3-pip python3-venv git curl jq libldap2-dev libsasl2-dev`, loads `base_structure.ldif` People/Groups OUs, `.env`, unit).

## Ports / backends

Talks to the LDAP server via `python-ldap` (`ldap.initialize` + `simple_bind_s`), `src/ldap_manager.py`. Default `LDAP_SERVER_URL=ldap://localhost:389`. No port served.

## Environment variables

`SPOKE_ID`, `SPOKE_SECRET`, `HUB_SECRET`, `HUB_WS`, `HUB_API`, `LDAP_ADMIN_DN` (`cn=admin,dc=example,dc=org`), `LDAP_ADMIN_PW` (required; warned if empty), `LDAP_BASE_DN` (`dc=example,dc=org`), `LDAP_SERVER_URL` (`ldap://localhost:389`). Note: `.env.template` lacks `LDAP_SERVER_URL`; the installer writes it.

## Install flags

`install_ldap.sh`: `--hub`, `--id`/`--name`, `--secret`, `--hub-secret`, `--all-prereqs` (no-op). Only passes `--secret`/`--hub-secret` when non-empty (avoid argparse abort).

## Key commands / handlers (`ldap_spoke.handle_command`)

`GET_VERSION`, `UPDATE_CONFIG` (re-init `LdapManager`), `LIST_OUS`, `CREATE_OU`, `UPDATE_OU` (modrdn rename), `LIST_USERS`, `CREATE_USER` (`inetOrgPerson`; `secrets.token_urlsafe(16)` random password if none, returned), `UPDATE_USER` (modify cn/sn/givenName/mail + optional uid rename), `LIST_GROUPS` (`groupOfNames` or `posixGroup`), `CREATE_GROUP` (`groupOfNames` requires ≥1 member → seeded with base DN), `UPDATE_GROUP` (cn modrdn), `ADD_USER_TO_GROUP`, `REMOVE_USER_FROM_GROUP`, `SET_PASSWORD` (`passwd_s` with `modify_s` userPassword fallback), `DELETE_ENTITY`, `SEARCH_USERS` (filter on uid/cn/mail/sn/givenName/dNSHostName, escapes `\*()`, tags `source="ldap"`, type `user`/`computer`).

## Key files

`src/main.py`, `src/ldap_spoke.py`, `src/ldap_manager.py` (~260 lines, whole `LdapManager`), `install_ldap.sh`, `base_structure.ldif`, `README.md`, `.env.template`, `requirements.txt`, `VERSION`.

## Notable behaviors & gotchas

- **Namespace-package loader (no `__init__.py`)** — `src/` has no `__init__.py`; works as a Python 3 namespace package. `main.py` runs as `-m src.main` and imports `from src.ldap_spoke import LdapSpoke`; `ldap_spoke.py` uses the **relative** import `from .ldap_manager import LdapManager`. `BaseSpoke` import uses the dual-path `try: from base_spoke import BaseSpoke except ImportError: from core.src.base_spoke import BaseSpoke`. Installer sets `PYTHONPATH=$INSTALL_DIR:$INSTALL_DIR/core/src:$INSTALL_DIR/ldap/src`.
- **`LdapControlPlane.register_module` is overridden locally** (assigns `self.modules[name]`) — minor duplication; the only one of this group that does this.
- **Password generation** — `create_user` never hardcodes a password (`secrets.token_urlsafe(16)` default; returns it).
- **`search`** is the cross-cutting directory query the hub uses for global search (returns `source="ldap"` records compatible with the hub's unified results).
- **Generic python-ldap** — works against any RFC-4511 server; nothing FreeIPA-specific. Install path targets OpenLDAP `slapd`; FreeIPA/389-DS work with the same `LDAP_ADMIN_DN`/`LDAP_BASE_DN`/`LDAP_SERVER_URL`.

## Related pages

[architecture-topology.md](architecture-topology.md), [lm-hub.md](lm-hub.md), [install-flags.md](install-flags.md).