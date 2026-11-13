"""LDAP spoke: connects a local OpenLDAP (slapd) server to the hub.

Turns hub commands into LdapManager calls for OUs, users, groups, passwords and
tenant-scoped entries. It also handles config updates (Entra .env and mirror-mode
replication) and installs TLS certificates into slapd.
"""
# asyncio runs blocking LDAP calls off the event loop; json/re/shutil/os help with files.
import asyncio
import json
import logging
import os
import re
import shutil
# Path handles certificate and .env file locations; typing is for hints only.
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
# python-ldap is used here for its exception types.
import ldap
# BaseSpoke lives at the top level when deployed, or under core.src in the monorepo.
try:
    from base_spoke import BaseSpoke
except ImportError:
    from core.src.base_spoke import BaseSpoke

# Directory operations and the bind-failure exception.
from .ldap_manager import LdapManager, LdapBindError, TenantNotProvisionedError
# Read-only Active Directory source (server discovery + failover).
from .ad_directory import AdDirectory
# Replication LDIF builders, imported package-relative or plain.
try:
    from . import replication
except ImportError:  # loaded outside the src package
    import replication

# One named logger for the spoke.
logger = logging.getLogger("LdapSpoke")


def _ou_path(value):
    """Normalise an OU path from a command payload to a list of names.

    Accepts a list of names (``["Engineering", "Lab"]``) or a ``/``-separated
    string (``"Engineering/Lab"``); None, ``""`` or ``[]`` means the
    ``ou=users`` container. Anything else (a blank segment, a non-string)
    returns None, so a malformed path is an error and is never mistaken for
    "the root"."""
    # Absent or empty: the root users container.
    if value is None or value == "":
        return []
    # A string is split on "/"; a list is taken as is.
    if isinstance(value, str):
        value = value.split("/")
    # Every segment must be a non-blank name: "/", " " or "A//B" is malformed,
    # not the root or a guess at what was meant.
    if isinstance(value, (list, tuple)) and all(isinstance(p, str) and p.strip() for p in value):
        return list(value)
    return None


# Commands that take an OU path, and the payload key that holds it.
_OU_PATH_KEYS = {"LDAP_CREATE_USER": "ou_path", "LDAP_CREATE_OU": "parent_path",
                 "LDAP_RENAME_OU": "path", "LDAP_DELETE_OU": "path",
                 "LDAP_MOVE_USER": "target_path"}


class _CertInstallError(Exception):
    """A failed cert-install step (ldapmodify / slapd restart). Raised inside
    install_cert so it maps to a single ERROR result with a clear message."""

class LdapSpoke(BaseSpoke):
    """
    LDAP integration spoke. Hosts the LDAP server and provides a management API.
    """
    def __init__(self, spoke_id: str, config: Dict[str, Any], control_plane=None):
        """Initialize the LDAP spoke instance and instantiate LdapManager."""
        # Base spoke setup, then a manager built from the config (with example defaults).
        super().__init__(spoke_id, config)
        self.manager = LdapManager(
            admin_dn=self.config.get("LDAP_ADMIN_DN", "cn=admin,dc=example,dc=org"),
            admin_pw=self.config.get("LDAP_ADMIN_PW", "admin"),
            base_dn=self.config.get("LDAP_BASE_DN", "dc=example,dc=org"),
            server_url=self.config.get("LDAP_SERVER_URL", "ldap://localhost:389")
        )

    def _ldap_error_envelope(self, exc: Exception) -> Dict[str, Any]:
        """Map an ``ldap.LDAPError`` / :class:`LdapBindError` to a clean ERROR
        envelope.

        The list/read handlers below used to let ``LDAPError`` propagate; the
        control plane catches it (``control_plane.py``) but via
        ``logger.exception``, which dumps a 30-line traceback PER CALL into the
        spoke log — so a stale admin password (bind result 49) spammed the log
        on every LIST_OUS / LDAP_LIST_USERS poll. Returning a clean envelope
        here keeps the log to one line and gives the operator a targeted hint
        for the common bind failure instead of a raw ``INVALID_CREDENTIALS``
        traceback. The write handlers route through :meth:`_ldap_write`, which
        catches a propagating :class:`LdapBindError` (the manager raises it on
        bind failure instead of letting the cryptic dict get logged/returned
        per-method) here too."""
        # Raw wrong-password error from python-ldap: log once and return a helpful hint.
        if isinstance(exc, ldap.INVALID_CREDENTIALS):
            msg = ("LDAP bind failed: invalid credentials — the LDAP_ADMIN_PW "
                   "in this spoke's config does not match slapd's admin "
                   "password. Re-push the correct password via Setup → LDAP "
                   "(UPDATE_CONFIG).")
            logger.warning("LDAP bind failed (invalid credentials): %s", msg)
            return {"status": "ERROR", "error": "INVALID_CREDENTIALS",
                    "message": msg}
        # Bind error already raised by the manager with an actionable message.
        if isinstance(exc, LdapBindError):
            # The manager already formatted the actionable message; surface it
            # verbatim + log one WARNING line (replaces the per-method cryptic
            # ``LdapManager - ERROR - Error creating user … {dict}`` line).
            logger.warning("LDAP bind failed: %s", exc)
            return {"status": "ERROR", "error": "INVALID_CREDENTIALS",
                    "message": str(exc)}
        # Any other LDAP error: return its type and message.
        return {"status": "ERROR", "message": f"{type(exc).__name__}: {exc}"}

    async def _ldap_list(self, fn, *args) -> Dict[str, Any]:
        """Run a list/read manager call in a worker thread; on ``LDAPError`` /
        :class:`LdapBindError` return a clean ERROR envelope instead of raising
        (avoids the per-call traceback dump from the control plane's
        ``logger.exception`` path)."""
        # Run the blocking read in a thread and wrap its result as data.
        try:
            return {"status": "SUCCESS", "data": await asyncio.to_thread(fn, *args)}
        # The tenant's container is missing: say so, never an empty list.
        except TenantNotProvisionedError as exc:
            return {"status": "ERROR", "error": "NOT_PROVISIONED", "message": str(exc)}
        # LDAP or bind failure: return a clean ERROR envelope instead of raising.
        except (ldap.LDAPError, LdapBindError) as exc:
            return self._ldap_error_envelope(exc)

    async def _ldap_write(self, fn, *args) -> Dict[str, Any]:
        """Run a write manager call in a worker thread; on a propagating
        ``LDAPError`` / :class:`LdapBindError` return a clean ERROR envelope.

        The manager's write methods catch ``ldap.LDAPError`` around the
        operation (``add_s`` / ``modify_s`` / …) and return
        ``{status:ERROR, message:str(e)}`` — those are legit per-operation
        errors (e.g. ``ALREADY_EXISTS``) and pass through unchanged. A bind
        failure is different: :meth:`LdapManager._bind` raises
        :class:`LdapBindError` (NOT an ``LDAPError``), which bypasses those
        per-method catches and propagates here — so a stale admin password
        surfaces as the targeted ``INVALID_CREDENTIALS`` envelope (with the
        re-push hint) instead of the raw ``{'result':49,…}`` dict or a
        control-plane traceback. This covers both the ``_conn()``-based scoped
        methods (bind inside the try) and the legacy ``_get_connection()``
        methods (bind outside the try, which used to propagate as a
        traceback)."""
        # Run the blocking write in a thread; the manager returns its own status dict.
        try:
            return await asyncio.to_thread(fn, *args)
        # Bind or uncaught LDAP failure: return a clean ERROR envelope.
        except (ldap.LDAPError, LdapBindError) as exc:
            return self._ldap_error_envelope(exc)

    async def handle_command(self, command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch a hub command to the matching ``LdapManager`` method.

        Command type is matched case-insensitively. The blocking
        ``python-ldap`` calls run via :func:`asyncio.to_thread` so a slow or
        unreachable slapd cannot stall the event loop (which would freeze this
        spoke's heartbeats and get it disconnected). ``GET_VERSION`` and
        ``UPDATE_CONFIG`` are handled inline; ``INSTALL_CERT`` is async-native
        (subprocess + filesystem writes). Returns ``{"status": "SUCCESS"|"ERROR", ...}``."""
        # Normalize command type to uppercase for case-insensitive matching
        normalized_cmd = command_type.upper()

        # GET_VERSION: report the spoke version.
        if normalized_cmd == "GET_VERSION":
            return {"status": "SUCCESS", "version": self.get_version()}

        # UPDATE_CONFIG: take the new settings and rebuild the manager.
        if normalized_cmd == "UPDATE_CONFIG":
            # Redact secrets before logging (admin pw, entra client key/cert path
            # are sensitive-ish; the admin pw certainly).
            logger.info("Updating LDAP configuration (keys: %s)", sorted(data.keys()))
            self.config = data
            # Re-initialize manager with new config
            self.manager = LdapManager(
                admin_dn=self.config.get("LDAP_ADMIN_DN", "cn=admin,dc=example,dc=org"),
                admin_pw=self.config.get("LDAP_ADMIN_PW", "admin"),
                base_dn=self.config.get("LDAP_BASE_DN", "dc=example,dc=org"),
                server_url=self.config.get("LDAP_SERVER_URL", "ldap://localhost:389")
            )
            # Collect notes about the extra side effects below.
            notes = []
            # Entra ROPC config changes: persist to .env so the pam_exec ROPC
            # bridge (src/entra_ropc_auth.py) picks them up on the next bind. No
            # slapd restart needed (the script reads .env live per-bind).
            if any(k.startswith("ENTRA_") for k in data) or "LDAP_BASE_DN" in data:
                try:
                    self._persist_env(data)
                    notes.append("entra .env persisted")
                except Exception as e:  # noqa: BLE001
                    logger.warning("UPDATE_CONFIG: could not persist .env: %s", e)
                    notes.append(f"env persist failed: {str(e)[:120]}")
            # Mirror-mode replication changes: re-apply cn=config idempotently.
            # Best-effort (only works when co-located on the slapd host as root);
            # a failure is logged + surfaced but does not fail the config update.
            if data.get("LDAP_SERVER_ID") and data.get("LDAP_MIRROR_PEERS"):
                repl = await self._apply_replication_config(data)
                notes.append(repl)
            # The config update itself always succeeds.
            return {"status": "SUCCESS", "message": "LDAP configuration updated",
                    "notes": notes}

        # LDAP Management Commands. The python-ldap calls are SYNC + blocking, so
        # run each in a worker thread — a slow/unreachable slapd must not stall the
        # asyncio event loop, which would freeze this spoke's heartbeats and get it
        # disconnected by the hub (and queue every other command behind it).
        # Legacy commands that take explicit DNs.
        if normalized_cmd == "LIST_OUS":
            return await self._ldap_list(self.manager.list_ous)

        if normalized_cmd == "CREATE_OU":
            return await self._ldap_write(self.manager.create_ou, data.get("name"), data.get("parent_dn"))

        if normalized_cmd == "UPDATE_OU":
            return await self._ldap_write(self.manager.update_ou, data.get("dn"), data.get("name"))

        # User listing and create/update by DN.
        if normalized_cmd == "LIST_USERS":
            return await self._ldap_list(self.manager.list_users)

        if normalized_cmd == "CREATE_USER":
            return await self._ldap_write(
                self.manager.create_user,
                data.get("username"), data.get("first_name"), data.get("last_name"),
                data.get("email"), data.get("ou_dn"), data.get("password"))

        if normalized_cmd == "UPDATE_USER":
            return await self._ldap_write(
                self.manager.update_user,
                data.get("dn"), data.get("first_name"), data.get("last_name"),
                data.get("email"), data.get("username"))

        # Group listing, create/rename and membership by DN.
        if normalized_cmd == "LIST_GROUPS":
            return await self._ldap_list(self.manager.list_groups)

        if normalized_cmd == "CREATE_GROUP":
            return await self._ldap_write(self.manager.create_group, data.get("name"), data.get("ou_dn"))

        if normalized_cmd == "UPDATE_GROUP":
            return await self._ldap_write(self.manager.update_group, data.get("dn"), data.get("name"))

        if normalized_cmd == "ADD_USER_TO_GROUP":
            return await self._ldap_write(self.manager.add_user_to_group, data.get("user_dn"), data.get("group_dn"))

        if normalized_cmd == "REMOVE_USER_FROM_GROUP":
            return await self._ldap_write(self.manager.remove_user_from_group, data.get("user_dn"), data.get("group_dn"))

        # SET_PASSWORD: accept either key name for the DN and the password.
        if normalized_cmd == "SET_PASSWORD":
            user_dn = data.get("user_dn") or data.get("dn")
            password = data.get("password") or data.get("new_password")
            if not user_dn or not password:
                return {"status": "ERROR", "message": "Missing user_dn or password"}
            return await self._ldap_write(self.manager.set_password, user_dn, password)

        # DELETE_ENTITY: delete any entry by DN.
        if normalized_cmd == "DELETE_ENTITY":
            return await self._ldap_write(self.manager.delete_entity, data.get("dn"))

        if normalized_cmd == "SEARCH_USERS":
            # Global-search leg (directory users/groups). Now NON-ADMIN ALLOWED
            # but TENANT-OU SCOPED — the hub passes {tenant, is_admin} and the
            # manager enforces the OU scoping (TENANT == OU lowercase). Absent
            # tenant + non-admin → empty (never leak another tenant's users).
            return await self._ldap_write(
                self.manager.search, data.get("q", ""),
                data.get("tenant"), bool(data.get("is_admin")))

        if normalized_cmd == "LDAP_MIGRATE_TENANT":
            # Cross-tenant migration: re-home entries from source_base_dn to
            # target_base_dn (a tenant's ldap_base_dn changed).
            return await self._ldap_write(
                self.manager.migrate_tenant,
                data.get("source_base_dn", ""), data.get("target_base_dn", ""),
                bool(data.get("purge_source", False)))

        # ── Tenant-scoped commands (LDAP_* contract; TENANT == OU 1:1) ─────
        # All accept an optional tenant_slug; absent = base level (back-compat).
        if normalized_cmd == "LDAP_PROVISION_TENANT_OU":
            return await self._ldap_write(
                self.manager.provision_tenant_ou, data.get("tenant_slug"))

        # A malformed OU path is an error, never a silent "move to the root".
        if normalized_cmd in _OU_PATH_KEYS and _ou_path(data.get(_OU_PATH_KEYS[normalized_cmd])) is None:
            return {"status": "ERROR",
                    "message": f"{_OU_PATH_KEYS[normalized_cmd]} must be a list of OU names or an 'A/B' string"}

        if normalized_cmd == "LDAP_CREATE_USER":
            return await self._ldap_write(
                self.manager.create_user_scoped,
                data.get("uid"), data.get("attrs") or {}, data.get("tenant_slug"),
                data.get("auth_mode", "local"), data.get("upn"), data.get("password"),
                _ou_path(data.get("ou_path")))

        if normalized_cmd == "LDAP_UPDATE_USER":
            return await self._ldap_write(
                self.manager.update_user_scoped,
                data.get("uid"), data.get("attrs") or {}, data.get("tenant_slug"))

        if normalized_cmd == "LDAP_DELETE_USER":
            return await self._ldap_write(
                self.manager.delete_user_scoped,
                data.get("uid"), data.get("tenant_slug"))

        if normalized_cmd == "LDAP_SET_PASSWORD":
            return await self._ldap_write(
                self.manager.set_password_scoped,
                data.get("uid"), data.get("password"), data.get("tenant_slug"))

        if normalized_cmd == "LDAP_CREATE_GROUP":
            return await self._ldap_write(
                self.manager.create_group_scoped,
                data.get("cn") or data.get("name"), data.get("tenant_slug"))

        if normalized_cmd == "LDAP_DELETE_GROUP":
            return await self._ldap_write(
                self.manager.delete_group_scoped,
                data.get("cn") or data.get("group") or data.get("name"),
                data.get("tenant_slug"))

        if normalized_cmd == "LDAP_ADD_MEMBER":
            return await self._ldap_write(
                self.manager.add_member_scoped,
                data.get("uid"), data.get("group") or data.get("cn"),
                data.get("tenant_slug"))

        if normalized_cmd == "LDAP_REMOVE_MEMBER":
            return await self._ldap_write(
                self.manager.remove_member_scoped,
                data.get("uid"), data.get("group") or data.get("cn"),
                data.get("tenant_slug"))

        # Tenant-scoped listings return data; the group lookup returns its own status.
        if normalized_cmd == "LDAP_LIST_USERS":
            return await self._ldap_list(self.manager.list_users_scoped, data.get("tenant_slug"))

        if normalized_cmd == "LDAP_LIST_GROUPS":
            return await self._ldap_list(self.manager.list_groups_scoped, data.get("tenant_slug"))

        if normalized_cmd == "LDAP_GET_USER_GROUPS":
            return await self._ldap_write(
                self.manager.get_user_groups,
                data.get("uid"), data.get("tenant_slug"))

        # OUs (folders) inside the tenant's ou=users. Paths are lists of OU
        # names, top down; every path stays inside the given tenant.
        if normalized_cmd == "LDAP_LIST_OUS":
            return await self._ldap_write(self.manager.list_ous_scoped, data.get("tenant_slug"))

        if normalized_cmd == "LDAP_CREATE_OU":
            return await self._ldap_write(
                self.manager.create_ou_scoped, data.get("name"),
                _ou_path(data.get("parent_path")), data.get("tenant_slug"))

        if normalized_cmd == "LDAP_RENAME_OU":
            return await self._ldap_write(
                self.manager.rename_ou_scoped, _ou_path(data.get("path")),
                data.get("new_name"), data.get("tenant_slug"))

        if normalized_cmd == "LDAP_DELETE_OU":
            return await self._ldap_write(
                self.manager.delete_ou_scoped, _ou_path(data.get("path")),
                data.get("tenant_slug"))

        if normalized_cmd == "LDAP_MOVE_USER":
            return await self._ldap_write(
                self.manager.move_user_scoped, data.get("uid"),
                _ou_path(data.get("target_path")), data.get("tenant_slug"))

        # Active Directory (read-only). The hub sends the tenant's AD
        # connection in every command (``ad``), with the bind password taken
        # from the Credential Vault at send time, so the spoke never stores
        # it. Blocking DNS/LDAP work runs in a worker thread.
        if normalized_cmd in ("AD_DISCOVER", "AD_TEST", "AD_SEARCH_USERS"):
            if not isinstance(data.get("ad"), dict):
                return {"status": "ERROR", "error": "NOT_CONFIGURED",
                        "message": "no Active Directory connection in the command"}
            ad = AdDirectory(data["ad"])
            # A connection without a domain (or with discovery off and no
            # servers) is "not configured" for every AD command alike.
            if not ad.configured():
                return {"status": "ERROR", "error": "NOT_CONFIGURED",
                        "message": "the Active Directory connection needs a domain and a server or discovery"}
            if normalized_cmd == "AD_DISCOVER":
                return await asyncio.to_thread(ad.discover)
            if normalized_cmd == "AD_TEST":
                return await asyncio.to_thread(ad.test)
            try:
                limit = int(data.get("limit") or 200)
            except (TypeError, ValueError):
                return {"status": "ERROR", "message": "limit must be a number"}
            return await asyncio.to_thread(ad.search_users, data.get("q") or "", limit)

        if normalized_cmd == "INSTALL_CERT":
            # Hub-brokered Let's Encrypt cert install. The le spoke issued/
            # renewed a cert and the hub pushes the PEM here; we write the
            # leaf/CA/key to /etc/ldap/tls, point slapd's olcTLS* at them via
            # `ldapmodify -Y EXTERNAL -H ldapi:///` on cn=config, and restart
            # slapd so the new SSL context takes effect. The spoke runs as root
            # (install_ldap.sh User=root) — EXTERNAL over ldapi maps root to
            # cn=config write, and the restart needs root. `ca` (the chain) is
            # appended to the CA bundle; intermediates already in fullchain are
            # split out so the leaf goes to olcTLSCertificateFile alone.
            return await self.install_cert(
                data.get("fullchain", ""), data.get("privkey", ""),
                ca_pem=data.get("chain", ""))

        # Unknown command: log it and report an error.
        logger.warning(f"Unknown command received: {command_type}")
        return {"status": "ERROR", "message": f"Unknown command: {command_type}"}

    async def get_status(self) -> Dict[str, Any]:
        """Reports LDAP server status."""
        # The check raises on failure, which is reported as UNHEALTHY.
        try:
            # Leak-free connectivity check (binds + unbinds), off the event loop.
            # NOTE: deliberately asyncio.to_thread (NOT _ldap_write) — a bind
            # failure must RAISE here so this returns UNHEALTHY; _ldap_write would
            # swallow the LdapBindError into an envelope and falsely report HEALTHY.
            await asyncio.to_thread(self.manager.check_connection)
            return {"status": "HEALTHY", "server": "OpenLDAP Online"}
        except Exception as e:
            logger.error(f"LDAP server health check failed: {e}")
            return {"status": "UNHEALTHY", "error": str(e)}

    def get_version(self) -> str:
        """Returns the current version of the LDAP module (from the VERSION file)."""
        # Read VERSION from the module root; fall back to "unknown".
        from pathlib import Path
        try:
            return (Path(__file__).parent.parent / "VERSION").read_text().strip()
        except Exception:
            return "unknown"

    # ── TLS certificate install (hub-brokered, INSTALL_CERT) ───────────────
    # slapd reads its TLS cert/key/CA from FILE PATHS (no inline PEM), so we
    # write the PEM to /etc/ldap/tls and point olcTLSCertificateFile /
    # olcTLSCertificateKeyFile / olcTLSCACertificateFile (global attrs on
    # cn=config) at them via `ldapmodify -Y EXTERNAL -H ldapi:///` with
    # `replace:`, then restart slapd — the new SSL context only reliably takes
    # effect on restart (OpenLDAP ITS#6135). The key must be readable by the
    # slapd user (Debian: openldap) or slapd errors with opaque "error 80".

    @staticmethod
    def _split_chain(fullchain: str) -> Tuple[str, List[str]]:
        """Split a PEM fullchain into (leaf, [intermediate/root blocks]).

        The leaf (first CERTIFICATE block) goes to olcTLSCertificateFile; the
        remaining blocks go to the CA bundle (olcTLSCACertificateFile). Order
        in the CA bundle is not significant per the OpenLDAP admin guide."""
        # Pull every PEM certificate block out of the chain text.
        blocks = re.findall(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            (fullchain or "").strip(), re.DOTALL)
        # No certificates found.
        if not blocks:
            return "", []
        # First block is the leaf; the rest go to the CA bundle.
        return blocks[0] + "\n", [b + "\n" for b in blocks[1:]]

    @staticmethod
    def _build_tls_ldif(cert_path: str, key_path: str,
                        ca_path: Optional[str] = None) -> str:
        """LDIF to replace slapd's olcTLS* file paths on cn=config. Uses
        ``replace:`` (idempotent — works whether or not the attrs already
        exist; ``add:`` would fail with 'Type or value exists' on a renew)."""
        # Replace the certificate and key paths on cn=config.
        blocks = [
            "dn: cn=config",
            "changetype: modify",
            "replace: olcTLSCertificateFile",
            f"olcTLSCertificateFile: {cert_path}",
            "-",
            "replace: olcTLSCertificateKeyFile",
            f"olcTLSCertificateKeyFile: {key_path}",
        ]
        # Also point at the CA bundle when there is one.
        if ca_path:
            blocks += ["-", "replace: olcTLSCACertificateFile",
                       f"olcTLSCACertificateFile: {ca_path}"]
        # Join the lines into LDIF text.
        return "\n".join(blocks) + "\n"

    async def install_cert(self, fullchain: str, privkey: str,
                           ca_pem: str = "") -> Dict[str, Any]:
        """Install a Let's Encrypt cert as slapd's TLS server cert.

        Writes the leaf to the cert file (0644), intermediates (+ any supplied
        ``ca`` chain) to the CA bundle (0644), and the key to the key file
        (0600, chowned to the slapd user), then runs ldapmodify against cn=config
        and restarts slapd. The private key is written to a 0600 file slapd
        reads — it is never logged. Paths/owner/restart are configurable via
        LDAP_TLS_DIR / LDAP_TLS_CERT / LDAP_TLS_KEY / LDAP_TLS_CA /
        LDAP_SLAPD_USER / LDAP_TLS_RESTART."""
        # Reject empty or obviously invalid certificate and key PEMs.
        fullchain = (fullchain or "").strip()
        privkey = (privkey or "").strip()
        if not fullchain or "BEGIN CERTIFICATE" not in fullchain:
            return {"status": "ERROR", "message": "missing or invalid fullchain PEM"}
        if not privkey or "PRIVATE KEY" not in privkey:
            return {"status": "ERROR", "message": "missing or invalid private key PEM"}

        # Resolve file paths, the slapd user and the restart flag from config.
        cfg = self.config or {}
        cert_dir = cfg.get("LDAP_TLS_DIR", "/etc/ldap/tls")
        cert_path = cfg.get("LDAP_TLS_CERT", f"{cert_dir}/slapd-cert.pem")
        key_path = cfg.get("LDAP_TLS_KEY", f"{cert_dir}/slapd-key.pem")
        slapd_user = cfg.get("LDAP_SLAPD_USER", "openldap")
        do_restart = cfg.get("LDAP_TLS_RESTART", True)
        # Split the leaf from intermediates and add any extra CA chain.
        leaf, cas = self._split_chain(fullchain)
        ca_blocks = cas + ([ca_pem.strip()] if ca_pem and ca_pem.strip() else [])
        ca_path = cfg.get("LDAP_TLS_CA", f"{cert_dir}/slapd-ca.pem") if ca_blocks else None

        # Write the files; any failure becomes an ERROR result.
        try:
            os.makedirs(cert_dir, exist_ok=True)
            self._write_pem(cert_path, leaf, 0o644)
            if ca_path:
                self._write_pem(ca_path, "".join(ca_blocks), 0o644)
            self._write_pem(key_path, privkey, 0o600)
            # Key must be readable by the slapd user or slapd errors with the
            # opaque "implementation specific error (80)". Best-effort: a
            # missing/non-standard user logs a warning and proceeds (ldapmodify
            # will then surface the read failure as error 80).
            try:
                shutil.chown(key_path, user=slapd_user)
            except (LookupError, PermissionError, OSError) as e:
                logger.warning("INSTALL_CERT: could not chown key to '%s' (%s); "
                               "slapd may fail to read it (error 80)", slapd_user, e)

            # Point slapd at the files, then restart so it loads them.
            ldif = self._build_tls_ldif(cert_path, key_path, ca_path)
            await self._ldapmodify(ldif)

            if do_restart:
                await self._restart_slapd()
            logger.info("INSTALL_CERT: slapd TLS cert installed (cert=%s)", cert_path)
            return {"status": "SUCCESS",
                    "message": f"slapd TLS cert installed ({cert_path})"}
        # Known install step failure: report its message.
        except _CertInstallError as e:
            return {"status": "ERROR", "message": str(e)}
        # Unexpected failure: report a shortened message.
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "message": f"install_cert failed: {str(e)[:300]}"}

    @staticmethod
    def _write_pem(path: str, content: str, mode: int) -> None:
        """Atomically write PEM certificate content to path with specified file mode."""
        # Atomic + correct-mode-from-creation: create the temp file with `mode` so
        # a 0600 key is never briefly world-readable, then os.replace (a crash
        # mid-write leaves the old file intact, not a truncated cert/key).
        tmp = f"{path}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        # Write the content, set the exact mode, then swap the file into place.
        try:
            with os.fdopen(fd, "w") as f:
                f.write(content)
            os.chmod(tmp, mode)  # os.open honors umask; enforce the exact mode
            os.replace(tmp, path)
        # Remove the partial temp file, then re-raise the error.
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    async def _ldapmodify(self, ldif: str) -> None:
        """Apply an LDIF to cn=config via SASL EXTERNAL over ldapi:/// (root
        peer-cred → cn=config write). Raises _CertInstallError on failure."""
        # Run ldapmodify with root's EXTERNAL identity over the local socket.
        proc = await asyncio.create_subprocess_exec(
            "ldapmodify", "-Y", "EXTERNAL", "-H", "ldapi:///",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        # Feed the LDIF on stdin, waiting up to 30 seconds.
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=ldif.encode()), timeout=30)
        # Non-zero exit: raise with stderr, stdout or the exit code.
        if proc.returncode != 0:
            err = (stderr.decode().strip() or stdout.decode().strip()
                   or f"ldapmodify exited {proc.returncode}")
            raise _CertInstallError(f"ldapmodify failed: {err[:300]}")

    async def _restart_slapd(self) -> None:
        """Restart slapd so the new TLS context takes effect (OpenLDAP ITS#6135:
        global TLS settings via cn=config only reliably apply on restart)."""
        # Restart slapd with systemctl.
        proc = await asyncio.create_subprocess_exec(
            "systemctl", "restart", "slapd",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        # Wait up to 45 seconds.
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=45)
        # Non-zero exit: raise with stderr or the exit code.
        if proc.returncode != 0:
            err = stderr.decode().strip() or f"systemctl exited {proc.returncode}"
            raise _CertInstallError(f"slapd restart failed: {err[:300]}")

    # ── UPDATE_CONFIG re-apply helpers (Entra .env + mirror-mode) ──────────

    # Keys persisted to .env so the standalone pam_exec ROPC bridge (which reads
    # .env, not this process's memory) sees Entra config pushed via UPDATE_CONFIG.
    _ENV_PERSIST_KEYS = (
        "ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "ENTRA_CLIENT_CERT",
        "ENTRA_CLIENT_KEY", "ENTRA_ROPC_SCOPE", "LDAP_BASE_DN",
        "LDAP_ADMIN_DN", "LDAP_SERVER_ID", "LDAP_MIRROR_PEERS",
    )

    def _env_path(self) -> str:
        """Return absolute path to .env file for configuration persistence."""
        # LDAP_ENV_PATH overrides the default .env in the module root.
        return os.environ.get("LDAP_ENV_PATH") or str(Path(__file__).parent.parent / ".env")

    def _persist_env(self, data: Dict[str, Any]) -> None:
        """Merge the persist-worthy keys from ``data`` into the module ``.env``
        (preserving all other lines), then re-chmod 0600. Only keys present in
        ``data`` are updated; ``LDAP_MIRROR_PEERS`` is JSON-serialised if a list."""
        # Pick the persisted keys present in data; peer lists are stored as JSON.
        path = self._env_path()
        updates = {}
        for k in self._ENV_PERSIST_KEYS:
            if k in data and data[k] is not None:
                v = data[k]
                if k == "LDAP_MIRROR_PEERS" and isinstance(v, (list, tuple)):
                    v = json.dumps(list(v))
                updates[k] = str(v)
        # Nothing to persist.
        if not updates:
            return
        # Read the existing .env lines, if any.
        lines = []
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                lines = fh.read().splitlines()
        # Replace matching keys in place and keep every other line as-is.
        seen = set()
        out = []
        for line in lines:
            key = line.split("=", 1)[0].strip() if "=" in line else ""
            if key in updates:
                out.append(f"{key}={updates[key]}")
                seen.add(key)
            else:
                out.append(line)
        # Append keys that were not already in the file.
        for k, v in updates.items():
            if k not in seen:
                out.append(f"{k}={v}")
        # Write a 0600 temp file, then swap it into place.
        tmp = f"{path}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(out) + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)

    async def _ldapmodify_tolerant(self, ldif: str, tolerate: str = "") -> Optional[str]:
        """Like ``_ldapmodify`` but returns an error string instead of raising,
        and treats an error whose text contains ``tolerate`` (e.g. "already
        exists") as success (returns None)."""
        # Apply the LDIF; success returns None.
        try:
            await self._ldapmodify(ldif)
            return None
        # Tolerated errors count as success; others are returned as text.
        except _CertInstallError as e:
            msg = str(e)
            if tolerate and tolerate.lower() in msg.lower():
                return None
            return msg

    async def _apply_replication_config(self, data: Dict[str, Any]) -> str:
        """Re-apply syncrepl mirror-mode to cn=config idempotently (best-effort;
        requires co-location on the slapd host as root via ldapi EXTERNAL).
        Returns a short human-readable note for the UPDATE_CONFIG response."""
        # Parse the server id and peers (JSON list or single URL), then build the LDIF.
        try:
            server_id = int(data.get("LDAP_SERVER_ID"))
            peers = data.get("LDAP_MIRROR_PEERS")
            if isinstance(peers, str):
                peers = json.loads(peers) if peers.strip().startswith("[") else [peers]
            base_dn = data.get("LDAP_BASE_DN", "")
            admin_dn = data.get("LDAP_ADMIN_DN", "")
            admin_pw = data.get("LDAP_ADMIN_PW", "")
            overlay = replication.build_syncprov_overlay_ldif()
            mirror = replication.build_full_mirror_ldif(
                server_id, peers, base_dn, admin_dn, admin_pw)
        # Bad input: report it without touching slapd.
        except (ValueError, TypeError, json.JSONDecodeError) as e:
            return f"replication config invalid: {str(e)[:120]}"
        # syncprov module + overlay: tolerate "exists" so re-runs are idempotent
        # (module load → "value exists", overlay add → "already exists").
        # Load the syncprov module.
        err = await self._ldapmodify_tolerant(
            replication.build_syncprov_module_ldif(), tolerate="exists")
        if err:
            return f"replication syncprov module load failed: {err[:160]}"
        # Add the syncprov overlay.
        err = await self._ldapmodify_tolerant(overlay, tolerate="already exists")
        if err:
            return f"replication syncprov apply failed: {err[:160]}"
        # Apply server id, syncrepl and mirror mode.
        err = await self._ldapmodify_tolerant(mirror)
        if err:
            return f"replication mirror apply failed: {err[:160]}"
        # All steps succeeded.
        logger.info("UPDATE_CONFIG: mirror-mode replication re-applied (serverID=%s)", server_id)
        return "mirror-mode replication re-applied"