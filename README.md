# ldap — LDAP Directory Spoke (Lab Manager Module)

LDAP directory spoke for the Lab Manager (LM) hub-and-spoke fleet (`module_type = "directory"`). Manages an OpenLDAP/389-DS directory server (`slapd`), providing OU/user/group lifecycle management, POSIX and LDAP group memberships, password management, cross-tenant isolation, directory replication, and hub-brokered TLS certificate deployment.

---

## Architecture & Overview

The `ldap` spoke bridges Lab Manager to OpenLDAP/389-DS directory servers over a persistent outbound WebSocket connection (port 443).

```
 +-------------------------------------------------------+
 |                     Lab Manager Hub                   |
 +-------------------------------------------------------+
           | (Outbound WebSocket over TLS, port 443)
           v
 +-------------------------------------------------------+
 |                  LdapControlPlane                     |
 |  (Registers module "ldap", dispatches WebSocket cmds) |
 +-------------------------------------------------------+
           |
           v
 +-------------------------------------------------------+
 |                 LDAPSpoke (LdapSpoke)                 |
 |  - Spoke coordinator & command dispatcher             |
 |  - Threaded worker execution (asyncio.to_thread)      |
 |  - Clean error envelopes (LdapBindError / LDAPError)  |
 |  - Hub-brokered TLS cert installer (INSTALL_CERT)     |
 +-------------------------------------------------------+
      |               |                    |
      v               v                    v
+--------------+ +-------------------+ +--------------------+
| LdapManager  | | Entra ROPC Bridge | | Replication Engine |
| - python-ldap| | - pam_exec ROPC   | | - syncrepl mirror  |
| - OU/User/Grp| | - SASL pass-thru  | | - cn=config LDIF   |
| - DN escaping| | - Azure AD auth   | | - Multi-master sync|
+--------------+ +-------------------+ +--------------------+
           \                  |                  /
            v                 v                 v
   +----------------------------------------------------+
   |               slapd (OpenLDAP Daemon)              |
   |           ldap://localhost:389 / ldapi:///         |
   +----------------------------------------------------+
```

- **Spoke Coordinator (`LDAPSpoke` / `LdapSpoke`):** Subclasses `BaseSpoke` to dispatch hub commands to worker threads (`asyncio.to_thread`) so slow directory operations never block the event loop or drop WebSockets.
- **`slapd` Daemon Management:** Manages local or remote OpenLDAP daemons, runtime `cn=config` reconfiguration via `ldapi:///` SASL EXTERNAL, and service control.
- **LDIF Templating & DN Parsing (`ldif_template.py`, `ldap_dn.py`):** Pure-Python helpers handling RFC-4514 DN escaping, canonical slug resolution, and parameterized LDIF template rendering for initial setups.
- **Entra ID ROPC Authentication Fallback (`entra_ropc_auth.py`):** Bridges SASL binds to Azure AD / Entra ID using Resource Owner Password Credentials (ROPC) with client certificate authentication.
- **Directory Replication Engine (`replication.py`):** Configures N-way multi-master syncrepl mirror mode across nodes using dynamic `cn=config` LDIF modifications.
- **TLS Certificate Distribution Target (`INSTALL_CERT`):** Deploys ACME certificates issued by the `le` module directly to `/etc/ldap/tls/`, updates `cn=config` TLS attributes, and restarts `slapd`.

---

## Features

- **Organizational Unit (OU) Lifecycle:** Create, list, rename (`modrdn`), and delete hierarchical directory OUs.
- **User Lifecycle Management:** Create users (`inetOrgPerson`) with auto-generated secure passwords or custom credentials, modify user metadata, delete entries, and reset passwords via LDAP Password-Modify operations.
- **Group Lifecycle Management:** Create and update `groupOfNames` and POSIX groups, manage member DN lists with safe seeding, and add or remove memberships atomically.
- **Search & Unified User/Computer Discovery (`SEARCH_USERS`):** Cross-system user and workstation search that feeds into Lab Manager's global search index with tenant-aware scoping.
- **Tenant Isolation & Multi-Tenancy OU Provisioning (`LDAP_PROVISION_TENANT_OU`):** Provisions isolated OU sub-trees (`ou=<tenant_slug>,<base_dn>`) with partitioned `users` and `groups` containers ensuring strict tenant separation.
- **Automated TLS Certificate Installation:** Ingests issued x509 full chains and private keys, chowns keys to the OpenLDAP process user, and updates directory TLS settings seamlessly.

---

## Spoke Commands Reference

The following commands are handled by `LdapSpoke`:

| Command | Arguments | Description |
| :--- | :--- | :--- |
| `GET_VERSION` | *None* | Retrieves the module semantic version from the `VERSION` file. |
| `UPDATE_CONFIG` | `LDAP_SERVER_URL`, `LDAP_ADMIN_DN`, `LDAP_ADMIN_PW`, `LDAP_BASE_DN`, Entra/Replication settings | Re-initializes `LdapManager`, persists `.env` changes, and re-applies mirror-mode configuration. |
| `LIST_OUS` | *None* | Lists all Organizational Units under the configured directory base DN. |
| `CREATE_OU` | `name`, `parent_dn` | Creates a new Organizational Unit under the base DN or a specified parent DN. |
| `UPDATE_OU` | `dn`, `name` | Renames an existing Organizational Unit via LDAP `modrdn`. |
| `LIST_USERS` | *None* | Returns all users across the directory base tree. |
| `CREATE_USER` | `username`, `first_name`, `last_name`, `email`, `ou_dn`, `password` | Creates an `inetOrgPerson` user; generates and returns a random password if omitted. |
| `UPDATE_USER` | `dn`, `first_name`, `last_name`, `email`, `username` | Updates contact details and attributes on an existing user entry. |
| `LIST_GROUPS` | *None* | Lists all `groupOfNames` directories. |
| `CREATE_GROUP` | `name`, `ou_dn` | Creates a new group populated with a default base placeholder member. |
| `UPDATE_GROUP` | `dn`, `name` | Renames an existing directory group. |
| `ADD_USER_TO_GROUP` | `user_dn`, `group_dn` | Adds a user's distinguished name to the target group's `member` list. |
| `REMOVE_USER_FROM_GROUP` | `user_dn`, `group_dn` | Removes a user's distinguished name from the target group's `member` list. |
| `SET_PASSWORD` | `user_dn`, `password` | Sets a user's password using the Password-Modify extended operation or direct `{SSHA}` hash update. |
| `DELETE_ENTITY` | `dn` | Deletes any leaf directory entity (user, group, or OU) by DN. |
| `SEARCH_USERS` | `q`, `tenant`, `is_admin` | Global search query matching `uid`, `cn`, `mail`, and `dNSHostName` with tenant scoping. |
| `LDAP_MIGRATE_TENANT` | `source_base_dn`, `target_base_dn`, `purge_source` | Re-homes directory entries from an old tenant base DN to a new target base DN. |
| `LDAP_PROVISION_TENANT_OU` | `tenant_slug` | Idempotently provisions a tenant tree (`ou=<slug>`, `ou=users`, `ou=groups`). |
| `INSTALL_CERT` | `fullchain`, `privkey`, `chain` | Installs an ACME TLS certificate into `/etc/ldap/tls/`, updates `cn=config`, and restarts `slapd`. |

---

<!-- INSTALLERS:START -->
## Installation

Every installer in this repo, with every flag and environment variable it accepts.
Installers are idempotent — re-running one updates code and preserves credentials.

### LDAP (directory) spoke — `install_ldap.sh`

```bash
curl -sSL https://raw.githubusercontent.com/lbockenstedt/ldap/main/install_ldap.sh \
  | sudo bash -s -- --hub lm-hub.lrbtechnologies.com
```

Two modes, mirroring `netbox/install.sh`: by default it installs the **spoke** that manages an LDAP server at `--server-url` (local or remote) without provisioning one. `--hub` is required for the spoke runtime.

| Flag | Purpose |
| :--- | :--- |
| `--hub URL` | Hub WebSocket URL. A bare host is fine — `lm-hub.example.com` becomes `wss://lm-hub.example.com:443`, `host:port` gets a `wss://` prefix, and an explicit `ws://`/`wss://` is left alone. Pass `auto` explicitly to use hub auto-discovery (DNS `lm-hub.<suffix>`, then mDNS `_lm-hub._tcp.local.`). |
| `--id`, `--name` | Pin the spoke id. Omitted, the id derives from the hostname, so a renamed clone reconnects under its new name. |
| `--secret` | Pre-shared spoke secret. |
| `--hub-secret` | Hub PSK for auto-approval. Without it the spoke lands in *pending approval* in the WebUI. |
| `--all-prereqs` | Accepted and ignored — kept so the hub's install-module call doesn't abort. |
| `--infra-only` | Host-level infrastructure only — no spoke runtime. |
| `--server-url` | LDAP server this spoke manages (local or remote). |
| `--base-dn` | Directory base DN. Default `dc=example,dc=org`. |
| `--admin-dn` | Admin bind DN. Default `cn=admin,dc=example,dc=org`. |
| `--admin-pw` | Admin bind password. |
| `--server-id` | Node id within a mirror pair. |
| `--peer` | Mirror peer. Repeatable — pass once per peer. |
| `--entra-tenant` | Entra tenant id for the mirror/ROPC path. |
| `--entra-client` | Entra application (client) id. |
| `--entra-cert` | Path to the Entra client certificate. |
| `--entra-key` | Path to its private key. |
| `--entra-scope` | OAuth scope requested from Entra. |

**Environment overrides:** `HUB_URL` (same normalization as `--hub`), `SPOKE_ID`., `BASE_DN`, `ADMIN_DN`, `ADMIN_PW`, `HUB_SECRET`
<!-- INSTALLERS:END -->