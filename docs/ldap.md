---
summary: "LDAP directory spoke. Repo: ldap. moduletype = 'directory'. See architecture-topology.md."
keywords: [backends, behaviors, commands, install_cert, install_ldap, ldap, ldap_server_url, lm, tenant_slug, update_config]
---

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

`SPOKE_ID`, `SPOKE_SECRET`, `HUB_SECRET`, `HUB_URL`, `LDAP_ADMIN_DN`, `LDAP_ADMIN_PW` (required: with none set the spoke never binds, as an empty password would be an anonymous bind, and `UPDATE_CONFIG` returns ERROR), `LDAP_BASE_DN` (canonical everywhere — debconf domain, `.env`, and the templated LDIF), `LDAP_SERVER_URL` (`ldap://localhost:389`). Mirror-mode: `LDAP_SERVER_ID` (int `1`|`2`), `LDAP_MIRROR_PEERS` (JSON list of peer `ldap(s)://` URLs, or of `{server_id, url}` objects as the hub sends them; `[]` = single node, no replication change). Entra ROPC: `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_CERT` (path), `ENTRA_CLIENT_KEY` (path; the hub pushes PEM content, which the spoke writes to `entra-client.crt`/`entra-client.key` (0600) beside `.env` and stores as paths, and a blank push keeps the stored files), `ENTRA_ROPC_SCOPE` (default `openid`) — read by `src/entra_ropc_auth.py` per bind. All are `.env`-written by the installer and re-writable via `UPDATE_CONFIG`.

## Install flags

`install_ldap.sh` has **two modes**:

- **(default) spoke** — `--hub` (accepts a bare IP/host, normalized to `wss://<host>:443`; default `auto` = mDNS/DNS discovery), `--id`/`--name`, `--secret`, `--hub-secret`, `--server-url`, `--all-prereqs` (no-op). Installs the directory spoke that manages a server (local or remote); does NOT install `slapd`. `--secret`/`--hub-secret` are written only to the 0600 `.env` (created under `umask 077`) and reach the service through `EnvironmentFile`, never as `ExecStart` arguments, so they don't show in `ps` and a secret the hub later rotates into `.env` is not overridden; with no secret the spoke connects unauthenticated and awaits WebUI approval.
- **`--infra-only` server** — provisions `slapd` fully zero-CLI (canonical base DN, auto admin password, base structure applied, self-signed TLS/LDAPS, optional mirror-mode, Entra ROPC SASL pass-through). Post-`--infra-only` args (the hub's `ldap-server` deploy role passes exactly these): `--base-dn` (derived from host DNS domain if omitted → `dc=lm,dc=local` fallback), `--admin-dn` (default `cn=admin,<base-dn>`), `--admin-pw` (auto-generated if omitted), `--server-id <1|2>`, `--peer <ldap-url>` (repeatable → `LDAP_MIRROR_PEERS`), `--entra-tenant`/`--entra-client`/`--entra-cert`/`--entra-key`/`--entra-scope`, `--server-url`. Idempotent + non-interactive; base DN is fixed at first install. The admin password never goes on a command line: `slappasswd` and `ldapadd` read it from a 0600 temp file, and the syncrepl builder from `LDAP_ADMIN_PW` in its environment. In each `olcSyncrepl` value the peer URL, base DN, bind DN and password are double-quoted with `\` and `"` escaped, and control characters are refused, so a value can't add syncrepl keywords or `cn=config` changes. A plain `ldap://` peer gets `starttls=critical tls_reqcert=allow`: the bind and the replicated entries always go over TLS, and replication stops rather than fall back to plaintext against a peer with no TLS. The installer gives every node a self-signed cert and fails a mirror-mode deploy if it could not configure slapd TLS. `allow` accepts the self-signed cert, so this stops passive capture but not an active man-in-the-middle. Each replication LDIF is built before it is applied, so a refused value fails the deploy, and `credentials=` (and the password itself) is redacted from ldapmodify errors, in the installer and in the spoke's `UPDATE_CONFIG` reply. `ldaps://` peers are unchanged. Invoked via `curl -sSL … | bash -s -- --infra-only <args>`.

## Key commands / handlers (`ldap_spoke.handle_command`)

**Legacy/base-level:** `GET_VERSION`, `UPDATE_CONFIG` (merges the push into the current config, re-inits `LdapManager`, persists `.env` (Entra PEMs as files) and re-applies mirror-mode `cn=config` when peers are present; applied as one transaction: an empty admin password is refused before anything changes; an unusable mirror section (a non-integer `LDAP_SERVER_ID`, as the hub sends when it derives peers from several directory instances, or malformed peers) skips only replication and the reply is PARTIAL with the rest applied; Entra PEMs are staged under new `entra-client.<random>.crt/.key` names, then `.env` is rewritten, then replication is applied, and only then does the running config switch; a failed step returns ERROR naming it, with `.env` restored byte for byte, the staged PEMs deleted, a changed `olcServerID` put back and the running config untouched (the additive syncprov module/overlay stay); pushes are serialised, and `credentials=` is redacted from replication errors), `LIST_OUS`, `CREATE_OU`, `UPDATE_OU` (modrdn rename), `LIST_USERS`, `CREATE_USER` (`inetOrgPerson`; `secrets.token_urlsafe(16)` random password if none, returned; stored as `{SSHA}` not cleartext), `UPDATE_USER`, `LIST_GROUPS`, `CREATE_GROUP` (`groupOfNames` seeded with base DN member), `UPDATE_GROUP`, `ADD_USER_TO_GROUP` (refuses a member DN that does not exist, so a deleted user can't be re-added as a dangling member), `REMOVE_USER_FROM_GROUP`, `SET_PASSWORD`, `DELETE_ENTITY` (also removes the DN from every group that lists it, so a user recreated with the same DN inherits no groups; the entry's identity (`entryUUID`, or `nsUniqueId` on 389-DS 1.4/FreeIPA) is read first and the delete asserts it (RFC 4528), so only that entry can be deleted, never a same-DN replacement; a server without the assertion control gets an identity re-check at the DN and then a plain delete, and an entry with neither attribute is deleted by DN (both logged); on any error the directory is searched for that identity: still at the DN means nothing was deleted and the memberships are put back (error), gone means it was deleted and they stay removed (success), and moved elsewhere or a failed search leaves them removed with the groups listed in the error; membership adds, removals, moves and deletes are serialised in the spoke, a membership another writer removed mid-sweep is never put back, so an add can't land between the sweep and the delete), `SEARCH_USERS`, `LDAP_MIGRATE_TENANT` (re-home entries from source base DN to target base DN), `INSTALL_CERT` (hub-brokered LE cert → `/etc/ldap/tls` + `ldapmodify -Y EXTERNAL` on `cn=config` + `systemctl restart slapd`; root-only).

**Tenant-scoped (`LDAP_*` contract; TENANT == OU, 1:1, case-insensitive):** `LDAP_PROVISION_TENANT_OU {tenant_slug}` (idempotent, case-insensitive — reuses an existing OU in any case; creates `ou=<slug>,<base>` + child `ou=users`/`ou=groups`; returns OU DN), `LDAP_CREATE_USER {tenant_slug, uid, attrs, auth_mode:"entra"|"local", upn?, password?}` (entra → `userPassword {SASL}<upn>`; local → `{SSHA}`), `LDAP_UPDATE_USER`, `LDAP_DELETE_USER` (removes the user from its groups, as `DELETE_ENTITY`), `LDAP_SET_PASSWORD` (local only — refuses `{SASL}` Entra users), `LDAP_CREATE_GROUP`, `LDAP_ADD_MEMBER`, `LDAP_REMOVE_MEMBER`, `LDAP_LIST_USERS {tenant_slug}`, `LDAP_LIST_GROUPS {tenant_slug}`, `LDAP_GET_USER_GROUPS {uid, tenant_slug}` (memberOf ∪ reverse member search — for hub RBAC). Absent `tenant_slug` = base level (back-compat). Slugs are canonical-lower-cased (`ldap_dn.canonical_slug`) so "LRB" == "lrb" resolve to one OU. DN construction/escaping via the pure `src/ldap_dn.py`.

## OUs inside a tenant

Tenant admins organise users into OUs (folders) below the tenant's
`ou=users` container, for example `ou=Lab,ou=Engineering,ou=users,ou=<tenant>,<base>`.
The WebUI shows an OU as a path such as `Engineering/Lab`.

- **Commands:** `LDAP_LIST_OUS`, `LDAP_CREATE_OU`, `LDAP_RENAME_OU`,
  `LDAP_DELETE_OU` and `LDAP_MOVE_USER`. `LDAP_CREATE_USER` takes an optional
  `ou_path`, and `LDAP_LIST_USERS` returns each user's `ou_path` and `upn`.
  The spoke answers `LDAP_LIST_OUS` from a per-tenant in-memory cache with
  a 5-minute TTL (single-flight, so simultaneous misses make one LDAP call).
  Keys use the manager's canonical slug, including trimming whitespace.
  OU-affecting writes (`LDAP_CREATE_OU`, `LDAP_RENAME_OU`, `LDAP_DELETE_OU`,
  `LDAP_MOVE_USER`, `LDAP_CREATE_USER`, `LDAP_DELETE_USER`) invalidate that
  tenant's entry afterwards unless explicitly refused before mutation.
  Partial and unknown outcomes invalidate too, and an in-flight read cannot
  put the pre-write list back. Legacy DN-based writes (`CREATE_OU`,
  `UPDATE_OU`, `CREATE_USER`, `DELETE_ENTITY`, `LDAP_MIGRATE_TENANT`) clear
  every tenant's entry under the same policy; `UPDATE_CONFIG` always clears
  every entry. This bounds slapd reads only: it does not reduce hub-to-spoke
  command or log volume and does not resolve the command-frequency alert.
  The Directory view still requires a separate change in the hub repository
  to render from its shared persisted cache and refresh in the background,
  rather than polling this command on page renders.
- **Users are found by uid anywhere in the tenant.** A uid is unique across the
  whole tenant, whatever OU it is in. Update, delete, password, group and
  lookup commands search for it instead of assuming `uid=X,ou=users,…`.
- **Moves stay inside the tenant.** A user moves between OUs of its own tenant;
  every path is built from the tenant slug, so a user can never be moved into
  another tenant.
- **Group memberships follow.** Groups are `groupOfNames` and store member DNs,
  so moving a user or renaming an OU rewrites those member values in the
  tenant's groups. The spoke does this itself, so no `refint` overlay is needed
  (it may manage a remote server it can't reconfigure).
- **Delete is safe.** Only an empty OU (no users, no child OUs) can be deleted,
  and the `ou=users` root can't be renamed or deleted.
- **Downstream readers must search the subtree.** Anything that reads users
  (ClearPass, applications) must search `ou=users,ou=<tenant>,…` with subtree
  scope, or it will miss users in OUs. They must bind with a tenant user's DN
  or the admin DN: anonymous search returns nothing (see Directory access control).
- **A failed move is undone, or reported.** If rewriting group members fails,
  the spoke undoes the move. If the undo also fails, the reply has
  `error: PARTIAL_ROLLBACK` and a message listing what is still changed.
- **A tenant that was never provisioned is an error.** With no `ou=users`,
  every OU and user command (list, create, rename, delete, move, password,
  group membership) returns `ERROR` with `error: NOT_PROVISIONED`, never an
  empty list, "user not found" or "OU not found". A provisioned tenant whose
  `ou=groups` is gone gets a plain `ERROR` from `LDAP_LIST_GROUPS`
  ("groups container missing"), and a user deleted while it is being moved
  gets "user not found", not "OU not found". Invalid input (a malformed name
  or path, or renaming or deleting the root `ou=users`) is refused before the
  directory is asked, so it gets its own message in every tenant.
- **A malformed path is an error.** A path must be a list of non-blank names
  or an `A/B` string; `None`, `""` or `[]` mean the top level. Anything else
  (`"/"`, `"A//B"`, a number) is refused, never read as the top level.

## Active Directory (read-only)

`src/ad_directory.py` reads users from an AD domain, so the Directory view can
show LDAP, Entra and AD accounts together. It is read-only for now:
`AD_DISCOVER`, `AD_TEST` and `AD_SEARCH_USERS`.

An AD connection belongs to one tenant. The hub stores it (Setup, the
`ad_connections` list: `domain`, `forest`, `site`, `discover`,
`use_global_catalog`, `use_ssl`, `dns_servers`, `servers`, `bind_user`,
`base_dn`, `timeout`, and the bind password as a Credential Vault reference)
and sends it as the `ad` field of every AD_* command to that tenant's
directory spoke, with `bind_password` filled from the vault at send time. The
spoke never stores the AD password or keeps the connection between commands.
A command with no `ad`, or one without a domain, returns `ERROR` with
`error: NOT_CONFIGURED`. `AD_DISCOVER` returns `ERROR` when no server is
left to try; lookup errors next to a usable server are only warnings. An
account whose `userAccountControl` the bind account cannot read has
`enabled: null` (unknown), not enabled. A connection with no bind user or
password returns `error: NO_CREDENTIALS` (nothing was sent to AD); a rejected
password returns `error: INVALID_CREDENTIALS`.

Which server the spoke uses, in order:

1. **DNS SRV discovery** (`discover`, default on). With `use_global_catalog`
   (the default) it looks up the global catalogs, `_gc._tcp.<site>._sites.<forest>`
   and then `_gc._tcp.<forest>`, on ports 3268/3269. Otherwise it looks up the
   domain controllers, `_ldap._tcp.<site>._sites.dc._msdcs.<domain>` and then
   `_ldap._tcp.dc._msdcs.<domain>`, on ports 389/636. Servers in the spoke's
   own AD site come first; within one answer, lower priority wins, then higher
   weight. The lookup uses a small standard-library DNS client (UDP with EDNS,
   retried over TCP when truncated), so no DNS package is needed.
   `dns_servers` points it at AD's DNS servers when the spoke's own resolver
   can't see the AD zones.
2. **Configured servers** (`servers`): the primary first, then the backup(s).
   They are always tried after the discovered ones, so AD still works when
   discovery fails.

Each server gets a short timeout (`timeout`, default 3 s), and the first one
that binds is used. A down server fails over to the next. A rejected password
is not retried on other servers, because it would fail the same way and could
lock the service account. An empty password is refused, since AD treats it as
an anonymous bind that "succeeds". The password is never sent in clear: LDAPS
(`use_ssl`, the default) or, with `use_ssl` off, StartTLS on 389/3268; a server
that can't do TLS is skipped. Either way the spoke must trust the AD
certificate authority.

## Key files

`src/main.py`, `src/ldap_spoke.py`, `src/ldap_manager.py` (~300 lines, whole `LdapManager`), `install_ldap.sh`, `base_structure.ldif` (reference OU/user template, not auto-applied), `tests/test_install_cert.py` (INSTALL_CERT unit tests, stubs python-ldap), `README.md`, `.env.template`, `requirements.txt`, `VERSION`.

## Notable behaviors & gotchas

- **Namespace-package loader (no `__init__.py`)** — `src/` has no `__init__.py`; works as a Python 3 namespace package. `main.py` runs as `-m src.main` and imports `from src.ldap_spoke import LdapSpoke`; `ldap_spoke.py` uses the **relative** import `from .ldap_manager import LdapManager`. `BaseSpoke` import uses the dual-path `try: from base_spoke import BaseSpoke except ImportError: from core.src.base_spoke import BaseSpoke`. Installer sets `PYTHONPATH=$INSTALL_DIR:$INSTALL_DIR/core/src:$INSTALL_DIR/ldap/src`.
- **`LdapControlPlane.register_module` is overridden locally** (assigns `self.modules[name]`) — minor duplication; the only one of this group that does this.
- **Password generation** — `create_user` never hardcodes a password (`secrets.token_urlsafe(16)` default; returns it). The password is stored `{SSHA}`-hashed (`LdapManager._ssha`) because slapd does **not** hash a plain `add`/`modify` of `userPassword` (only the Password-Modify ext-op does) — so hashing before store avoids cleartext passwords at rest.
- **`search`** is the cross-cutting directory query the hub uses for global search (returns `source="ldap"` records compatible with the hub's unified results).
- **Generic python-ldap** — works against any RFC-4511 server; nothing FreeIPA-specific. Install path targets OpenLDAP `slapd`; FreeIPA/389-DS work with the same `LDAP_ADMIN_DN`/`LDAP_BASE_DN`/`LDAP_SERVER_URL`.
- **Directory access control** — the installer replaces the data database's `olcAccess` (`ldif_template.py --acl`, applied by `configure_directory_acls` on every install run):
  1. `userPassword` is usable only to authenticate (`by anonymous auth`). Nobody can read it, and users cannot change their own password over LDAP, which would bypass the `{SASL}` Entra pass-through.
  2. A user under `ou=<tenant>,<base>` can read only that tenant's subtree. The legacy base-level `ou=users` and `ou=groups` each form their own scope.
  3. Everything else is denied, including anonymous reads.

  The spoke, hub, dot1x JIT provisioning and syncrepl bind as the rootDN, which ACLs do not restrict. An external reader such as a ClearPass auth source must bind with a tenant user's DN (or the admin DN); anonymous search no longer returns anything. An existing server gets these ACLs only when the installer is re-run. If the ACLs can't be applied, the install fails. A new server (slapd was not installed before the run, including one removed but not purged) listens only on its local `ldapi:///` socket until the ACLs are applied: the installer creates `/etc/ldap/.lm-acls-pending`, keeps apt from starting slapd with a `/usr/sbin/policy-rc.d` hook that denies only slapd (an existing `policy-rc.d` that the installer did not write is left alone, with a warning), sets `SLAPD_SERVICES="ldapi:///"` in `/etc/default/slapd` right after installing slapd (or when apt fails), and restores `ldap:///` (and `ldaps:///` with the TLS step) only once the ACLs succeed. This holds if the installer fails at any step, is killed, or the host reboots; re-run the installer to finish. An existing server keeps running on its previous ACLs, because stopping it would take every tenant's logins down.
- **DN/filter injection guards** — DN RDN components are escaped via `ldap.dn.escape_dn_chars` (`_escape_rdn`) and search input is RFC-4515 escaped (`\` → `\5c`, `*` → `\2a`, `(` → `\28`, `)` → `\29`). The spoke binds as admin, so this is security-critical.

## How it works

- **Hub connection.** Like every LM spoke, ldap dials the hub over a WebSocket. In the current unified model this is the sub-spoke `{agent}-ldap` opened by the generic agent (parent-auto-approved); the legacy path is the standalone `ldap-spoke-1` dialing the hub directly. Either way the wire protocol is identical.
- **Config delivery.** Connection settings — `LDAP_SERVER_URL`, `LDAP_ADMIN_DN`, `LDAP_ADMIN_PW`, `LDAP_BASE_DN` — are **not** read from a per-module `.env` when running as a role. The hub pushes them via `UPDATE_CONFIG`, normally right after you fill in the Directory setup form in the WebUI. On `UPDATE_CONFIG` the spoke merges the pushed values into its current config (keys the push leaves out or sends as null are kept) and rebuilds `LdapManager`, so a fixed typo (e.g. a wrong admin password) takes effect on the next push without restarting the process.
- **Command flow.** Every WebUI action (list/create/update/delete an OU, user, or group; add/remove group membership; reset a password; rename an entry) becomes one `LdapSpoke.handle_command` call, which runs the matching `LdapManager` method. Because `python-ldap` calls are synchronous/blocking, each one runs in a worker thread via `asyncio.to_thread` — this keeps the spoke's heartbeat to the hub alive even if the directory server is slow or unreachable. Without that, a stalled bind would freeze the spoke's event loop, queue every other command behind it, and get the spoke disconnected as unresponsive. `INSTALL_CERT` is the exception: its `ldapsearch`/`ldapmodify`/`systemctl` calls are async subprocesses, and only its file reads and writes run via `to_thread`.
- **Connection hygiene.** Read/list operations (`list_ous`, `list_users`, `list_groups`) and the health check (`check_connection`) use the leak-free `LdapManager._conn()` context manager, which opens a fresh bind and always unbinds in `finally` — even on error. Write operations (`create_*`, `update_*`, `delete_entity`, group membership, `set_password`) still call the older `_get_connection()`, which binds but does **not** explicitly unbind. This is a residual gap (slapd reaps idle sockets, so it hasn't surfaced at lab scale), not a fully-applied fix — worth revisiting before a long-running high-throughput deployment.
- **Global search integration.** `SEARCH_USERS` is the query the hub's cross-system search fans out to every connected directory spoke (alongside NetBox, DHCP, VM, and session searches). It matches on `uid`, `cn`, `mail`, `sn`, `givenName`, or `dNSHostName`, and returns each hit tagged `source="ldap"` with `type` `user` or `computer` (based on `objectClass`) so the WebUI can merge and label results consistently across modules.
- **Certificate installation.** The hub can push an `INSTALL_CERT` command to the ldap spoke — the same command it sends to firewall and hypervisor targets — when a certificate issued by the Certificate Management (le) module is targeted at this directory server. The spoke writes the leaf certificate and private key (plus any CA chain) under `/etc/ldap/tls`, points slapd's `cn=config` `olcTLSCertificateFile`/`olcTLSCertificateKeyFile`/`olcTLSCACertificateFile` at the new files via `ldapmodify -Y EXTERNAL -H ldapi:///`, and restarts `slapd` so the new TLS context takes effect (OpenLDAP ITS#6135: global TLS settings via `cn=config` only reliably apply on restart). The private key is written 0600 and chowned to the slapd user (best-effort) so slapd can read it; it is never logged. This only works when the ldap spoke runs on the OpenLDAP host itself as root (needed to restart the service and read the key file) — `lm-ldap.service` sets `User=root` for this reason. A failed install is rolled back: before writing anything the spoke records the current cert/key/CA files (content, mode, owner, or symlink) and the current `olcTLS*` paths (`ldapsearch -Y EXTERNAL`). If a write, the `ldapmodify` or the restart fails, it puts back the files that existed, starts slapd again if a restart was attempted (a failed restart usually leaves it stopped, and the undo goes through its ldapi socket), restores the `olcTLS*` paths when the modify may have applied, removes files the install created once `cn=config` no longer names them, and restarts slapd once more, so slapd keeps serving the previous certificate. A command that times out is killed, so it cannot apply its change after the rollback. Cancelling the command (for example a spoke shutdown) does not stop the install between steps: it finishes or rolls back first. Installs run one at a time on a spoke: a second `INSTALL_CERT` waits until the first has finished or rolled back, so a failed install never restores its old certificate over a newer one that succeeded. The reply is `ERROR` with "previous certificate restored"; if an undo step itself fails, the reply has `error: PARTIAL_ROLLBACK` and lists the failed steps. If the current TLS config can't be read, nothing is changed.

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