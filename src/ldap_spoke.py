"""LDAP spoke: connects a local OpenLDAP (slapd) server to the hub.

Turns hub commands into LdapManager calls for OUs, users, groups, passwords and
tenant-scoped entries. It also handles config updates (Entra .env and mirror-mode
replication) and installs TLS certificates into slapd.
"""
# asyncio runs blocking LDAP calls off the event loop; json/re/shutil/os help with files.
import asyncio
import base64
import json
import logging
import os
import re
import secrets
import shutil
import time
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
from .ldap_dn import canonical_slug
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

class _CertInstallRefusalError(_CertInstallError):
    """slapd cleanly refused ldapmodify with a non-zero exit code (cn=config untouched)."""


class LdapSpoke(BaseSpoke):
    """
    LDAP integration spoke. Hosts the LDAP server and provides a management API.
    """
    def __init__(self, spoke_id: str, config: Dict[str, Any], control_plane=None):
        """Initialize the LDAP spoke instance and instantiate LdapManager."""
        # Base spoke setup, then a manager built from the config (with example defaults).
        super().__init__(spoke_id, config)
        # No default password: an unset one must fail the bind, never guess.
        self.manager = LdapManager(
            admin_dn=self.config.get("LDAP_ADMIN_DN", "cn=admin,dc=example,dc=org"),
            admin_pw=self.config.get("LDAP_ADMIN_PW") or "",
            base_dn=self.config.get("LDAP_BASE_DN", "dc=example,dc=org"),
            server_url=self.config.get("LDAP_SERVER_URL", "ldap://localhost:389")
        )
        # Per-tenant TTL cache bounds slapd reads, not hub command volume.
        # Hub-side background refresh and cached page rendering are still
        # required to bound Directory view commands.
        self._ou_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        # One lock per tenant gives single-flight: concurrent misses make one
        # LDAP call instead of a stampede.
        self._ou_cache_locks: Dict[str, asyncio.Lock] = {}
        # Generation counter per tenant, bumped by every OU-affecting write so
        # a read that was already in flight cannot store pre-write data.
        self._ou_cache_gen: Dict[str, int] = {}
        # One UPDATE_CONFIG at a time: each one snapshots and may roll back
        # .env, the PEM files and cn=config, so two interleaved pushes could
        # restore each other's half-applied state.
        self._update_config_lock = None
        # INSTALL_CERT runs snapshot -> apply -> rollback as one transaction.
        # The control plane runs commands concurrently, so without this lock
        # a failing install could roll back over one that already succeeded.
        self._cert_lock = None

    # Refresh floor for the OU list, in seconds (fleet-rules 4.8: minutes).
    _OU_CACHE_TTL = 300

    def _ou_cache_key(self, tenant_slug: Optional[str]) -> str:
        """Use the manager's canonical identity; an absent slug means base level."""
        return canonical_slug(tenant_slug) if tenant_slug else ""

    def _ou_cache_invalidate(self, tenant_slug: Optional[str]) -> None:
        """Drop a tenant's cached OU list and bump its generation.

        Called AFTER a possibly mutating write: the bump also tells any
        read still in flight that its result is pre-write, so it is returned to
        that caller but never stored."""
        try:
            key = self._ou_cache_key(tenant_slug)
        except ValueError:
            # Invalid slugs cannot have cached entries; preserve the write's
            # error envelope rather than raising during invalidation.
            return
        self._ou_cache_gen[key] = self._ou_cache_gen.get(key, 0) + 1
        self._ou_cache.pop(key, None)

    async def _list_ous_cached(self, tenant_slug: Optional[str]) -> Dict[str, Any]:
        """Serve LDAP_LIST_OUS from the per-tenant TTL cache.

        Steps: take the tenant's lock (single-flight), return a fresh cached
        answer, otherwise ask slapd once; only a SUCCESS whose generation is
        still current is cached, so errors are not cached and a write that
        landed during the read wins."""
        try:
            key = self._ou_cache_key(tenant_slug)
        except ValueError as exc:
            return {"status": "ERROR", "message": str(exc)}
        lock = self._ou_cache_locks.setdefault(key, asyncio.Lock())
        async with lock:
            entry = self._ou_cache.get(key)
            if entry and (time.monotonic() - entry[0]) < self._OU_CACHE_TTL:
                return entry[1]
            gen = self._ou_cache_gen.get(key, 0)
            result = await self._ldap_write(self.manager.list_ous_scoped, tenant_slug)
            if (isinstance(result, dict) and result.get("status") == "SUCCESS"
                    and self._ou_cache_gen.get(key, 0) == gen):
                self._ou_cache[key] = (time.monotonic(), result)
            return result

    def _ou_cache_clear_all(self) -> None:
        """Drop every tenant's cached OU list and bump every generation."""
        for key in set(self._ou_cache) | set(self._ou_cache_gen) | set(self._ou_cache_locks):
            self._ou_cache_invalidate(key)

    @staticmethod
    def _write_may_have_changed(result: Any) -> bool:
        """Invalidate unless an explicit pre-mutation refusal proves no change.

        SUCCESS, PARTIAL, PARTIAL_ROLLBACK and unknown outcomes all invalidate:
        a generic LDAP error may arrive after the server committed a write.
        Never infer a clean refusal from an unstructured error message.
        """
        return not (
            isinstance(result, dict)
            and result.get("status") == "ERROR"
            and result.get("error") in ("NOT_PROVISIONED", "INVALID_CREDENTIALS")
        )

    async def _ldap_write_ou(self, tenant_slug: Optional[str], fn, *args) -> Dict[str, Any]:
        """Run an OU-affecting write, then invalidate the tenant's OU cache.

        Invalidation happens after any write not known to be a clean refusal,
        including partial and unknown outcomes, so the next read refreshes and
        an in-flight read cannot restore the old state."""
        result = await self._ldap_write(fn, *args)
        if self._write_may_have_changed(result):
            self._ou_cache_invalidate(tenant_slug)
        return result

    async def _ldap_write_all_ou(self, fn, *args) -> Dict[str, Any]:
        """Like _ldap_write_ou for DN-based commands that carry no tenant slug:
        invalidates every tenant's cached OU list when the directory changed."""
        result = await self._ldap_write(fn, *args)
        if self._write_may_have_changed(result):
            self._ou_cache_clear_all()
        return result

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
            return await self._update_config(data or {})

        # LDAP Management Commands. The python-ldap calls are SYNC + blocking, so
        # run each in a worker thread — a slow/unreachable slapd must not stall the
        # asyncio event loop, which would freeze this spoke's heartbeats and get it
        # disconnected by the hub (and queue every other command behind it).
        # Legacy commands that take explicit DNs.
        if normalized_cmd == "LIST_OUS":
            return await self._ldap_list(self.manager.list_ous)

        if normalized_cmd == "CREATE_OU":
            return await self._ldap_write_all_ou(self.manager.create_ou, data.get("name"), data.get("parent_dn"))

        if normalized_cmd == "UPDATE_OU":
            return await self._ldap_write_all_ou(self.manager.update_ou, data.get("dn"), data.get("name"))

        # User listing and create/update by DN.
        if normalized_cmd == "LIST_USERS":
            return await self._ldap_list(self.manager.list_users)

        if normalized_cmd == "CREATE_USER":
            return await self._ldap_write_all_ou(
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
            return await self._ldap_write_all_ou(self.manager.delete_entity, data.get("dn"))

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
            return await self._ldap_write_all_ou(
                self.manager.migrate_tenant,
                data.get("source_base_dn", ""), data.get("target_base_dn", ""),
                bool(data.get("purge_source", False)))

        # ── Tenant-scoped commands (LDAP_* contract; TENANT == OU 1:1) ─────
        # All accept an optional tenant_slug; absent = base level (back-compat).
        if normalized_cmd == "LDAP_PROVISION_TENANT_OU":
            return await self._ldap_write_ou(
                data.get("tenant_slug"),
                self.manager.provision_tenant_ou, data.get("tenant_slug"))

        # A malformed OU path is an error, never a silent "move to the root".
        if normalized_cmd in _OU_PATH_KEYS and _ou_path(data.get(_OU_PATH_KEYS[normalized_cmd])) is None:
            return {"status": "ERROR",
                    "message": f"{_OU_PATH_KEYS[normalized_cmd]} must be a list of OU names or an 'A/B' string"}

        if normalized_cmd == "LDAP_CREATE_USER":
            # User counts are part of the OU list, so invalidate it.
            return await self._ldap_write_ou(
                data.get("tenant_slug"),
                self.manager.create_user_scoped,
                data.get("uid"), data.get("attrs") or {}, data.get("tenant_slug"),
                data.get("auth_mode", "local"), data.get("upn"), data.get("password"),
                _ou_path(data.get("ou_path")))

        if normalized_cmd == "LDAP_UPDATE_USER":
            return await self._ldap_write(
                self.manager.update_user_scoped,
                data.get("uid"), data.get("attrs") or {}, data.get("tenant_slug"))

        if normalized_cmd == "LDAP_DELETE_USER":
            return await self._ldap_write_ou(
                data.get("tenant_slug"),
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
            # Polled by the Directory view: served from the per-tenant TTL cache.
            return await self._list_ous_cached(data.get("tenant_slug"))

        if normalized_cmd == "LDAP_CREATE_OU":
            return await self._ldap_write_ou(
                data.get("tenant_slug"),
                self.manager.create_ou_scoped, data.get("name"),
                _ou_path(data.get("parent_path")), data.get("tenant_slug"))

        if normalized_cmd == "LDAP_RENAME_OU":
            return await self._ldap_write_ou(
                data.get("tenant_slug"),
                self.manager.rename_ou_scoped, _ou_path(data.get("path")),
                data.get("new_name"), data.get("tenant_slug"))

        if normalized_cmd == "LDAP_DELETE_OU":
            return await self._ldap_write_ou(
                data.get("tenant_slug"),
                self.manager.delete_ou_scoped, _ou_path(data.get("path")),
                data.get("tenant_slug"))

        if normalized_cmd == "LDAP_MOVE_USER":
            # A move changes the per-OU user counts in the list.
            return await self._ldap_write_ou(
                data.get("tenant_slug"),
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

    @property
    def cert_lock(self) -> asyncio.Lock:
        if self._cert_lock is None:
            self._cert_lock = asyncio.Lock()
        return self._cert_lock

    @property
    def update_config_lock(self) -> asyncio.Lock:
        if self._update_config_lock is None:
            self._update_config_lock = asyncio.Lock()
        return self._update_config_lock

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
        paths = [p for p in (cert_path, key_path, ca_path) if p]
        changed = list(self._TLS_ATTRS[:2]) + ([self._TLS_ATTRS[2]] if ca_path else [])

        async def _serialised() -> Dict[str, Any]:
            """Steps 1-3 under the cert lock, so one install's snapshot and
            rollback never interleave with another's writes."""
            async with self.cert_lock:
                # Step 1: record the live files and olcTLS* paths, so any
                # failure below can put them back. slapd re-reads these files
                # on its next restart: a half-installed or mismatched cert/key
                # left in place would stop LDAPS (or slapd) then, long after
                # this command.
                try:
                    old_attrs = await self._read_tls_attrs()
                    snapshot = await asyncio.to_thread(self._snapshot_files, paths)
                except Exception as e:  # noqa: BLE001
                    return {"status": "ERROR",
                            "message": f"could not read the current TLS config, nothing changed: {str(e)[:300]}"}
                # Steps 2-3: write, modify, restart; roll back on failure.
                return await self._apply_cert(
                    cert_dir, cert_path, leaf, ca_path, "".join(ca_blocks), key_path, privkey,
                    slapd_user, do_restart, snapshot, old_attrs, changed)

        # The transaction runs as its own task, shielded: cancelling this
        # command (e.g. the spoke shutting down) must not stop a half-made
        # change between its steps. It still finishes or rolls back, then the
        # cancellation goes on.
        work = asyncio.ensure_future(_serialised())
        try:
            return await asyncio.shield(work)
        except asyncio.CancelledError:
            while not work.done():
                try:
                    await asyncio.shield(work)
                except asyncio.CancelledError:
                    pass
            raise

    async def _apply_cert(self, cert_dir: str, cert_path: str, leaf: str,
                          ca_path: Optional[str], ca_pem: str, key_path: str, privkey: str,
                          slapd_user: str, do_restart: bool, snapshot: Dict[str, Any],
                          old_attrs: Dict[str, str], changed: List[str]) -> Dict[str, Any]:
        """install_cert steps 2-3: write the files, point cn=config at them
        and restart slapd; on any failure (a cancellation too) roll back to
        the snapshot. A cancellation is re-raised after the rollback."""
        # Step 2. attrs_touched: the modify may have applied (a clean
        # ldapmodify failure means slapd refused it whole; a timeout or a
        # cancellation is unknown). The file write is shielded: a cancelled
        # to_thread keeps writing, so the rollback waits for it first.
        attrs_touched = restarted = False
        write = asyncio.ensure_future(asyncio.to_thread(
            self._write_tls_files, cert_dir, cert_path, leaf, ca_path, ca_pem,
            key_path, privkey, slapd_user))
        try:
            await asyncio.shield(write)
            attrs_touched = True
            try:
                await self._ldapmodify(self._build_tls_ldif(cert_path, key_path, ca_path))
            except _CertInstallRefusalError:
                # slapd cleanly refused the modify whole (non-zero exit): cn=config was not touched
                attrs_touched = False
                raise
            except BaseException:
                # Timeout, cancellation, or unconfirmed state: cn=config may have been modified!
                # attrs_touched remains True so _rollback_cert restores olcTLS* in cn=config.
                raise
            if do_restart:
                restarted = True
                await self._restart_slapd()
        # Step 3: on any failure, put the previous certificate back.
        except BaseException as e:  # noqa: BLE001
            if not write.done():
                await asyncio.wait({write})
            msg = str(e) if isinstance(e, _CertInstallError) else f"install_cert failed: {str(e)[:300] or type(e).__name__}"
            result = await self._rollback_cert(snapshot, old_attrs, changed, attrs_touched, restarted, msg)
            if not isinstance(e, Exception):
                raise
            return result
        logger.info("INSTALL_CERT: slapd TLS cert installed (cert=%s)", cert_path)
        return {"status": "SUCCESS", "message": f"slapd TLS cert installed ({cert_path})"}

    # The cn=config attributes INSTALL_CERT sets: cert, key, then CA bundle.
    _TLS_ATTRS = ("olcTLSCertificateFile", "olcTLSCertificateKeyFile", "olcTLSCACertificateFile")

    def _write_tls_files(self, cert_dir: str, cert_path: str, leaf: str,
                         ca_path: Optional[str], ca_pem: str, key_path: str,
                         privkey: str, slapd_user: str) -> None:
        """Write the leaf (0644), CA bundle (0644, when there is one) and key
        (0600, chowned to the slapd user). Blocking; run via to_thread."""
        os.makedirs(cert_dir, exist_ok=True)
        self._write_pem(cert_path, leaf, 0o644)
        if ca_path:
            self._write_pem(ca_path, ca_pem, 0o644)
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

    async def _read_tls_attrs(self) -> Dict[str, str]:
        """The olcTLS* file paths cn=config holds now (an unset one is absent).
        Raises _CertInstallError when slapd can't be asked."""
        proc = await asyncio.create_subprocess_exec(
            "ldapsearch", "-LLL", "-Q", "-Y", "EXTERNAL", "-H", "ldapi:///",
            # ldapsearch reads the first operand as the filter, the rest as
            # the attributes to return.
            "-b", "cn=config", "-s", "base", "(objectClass=*)", *self._TLS_ATTRS,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await self._communicate(proc, None, 30)
        if proc.returncode != 0:
            err = stderr.decode().strip() or f"ldapsearch exited {proc.returncode}"
            raise _CertInstallError(f"ldapsearch failed: {err[:300]}")
        # Unfold continuation lines (RFC 2849), then read "attr: v" and
        # base64 "attr:: v" values.
        text = re.sub(r"\r?\n ", "", stdout.decode("utf-8", errors="replace"))
        names = {a.lower(): a for a in self._TLS_ATTRS}
        found = {}
        for line in text.splitlines():
            name, sep, value = line.partition(":")
            if sep and name.lower() in names:
                found[names[name.lower()]] = (
                    base64.b64decode(value[1:].strip()).decode("utf-8") if value.startswith(":")
                    else value.strip())
        return found

    @classmethod
    def _restore_tls_ldif(cls, old: Dict[str, str], changed: List[str]) -> str:
        """LDIF that sets each changed olcTLS* attribute back to ``old``.
        Values are base64 so any path round-trips; a ``replace`` with no
        value removes an attribute that was unset before (and is a no-op
        when it is still unset)."""
        lines = ["dn: cn=config", "changetype: modify"]
        for attr in changed:
            lines.append(f"replace: {attr}")
            if attr in old:
                lines.append(f"{attr}:: {base64.b64encode(old[attr].encode()).decode()}")
            lines.append("-")
        return "\n".join(lines) + "\n"

    @staticmethod
    def _snapshot_files(paths: List[str]) -> Dict[str, Any]:
        """Record each path as it is now: ("link", target) for a symlink,
        ("file", bytes, mode, uid, gid) for a file, None when absent."""
        snap: Dict[str, Any] = {}
        for p in paths:
            if os.path.islink(p):
                snap[p] = ("link", os.readlink(p))
            elif os.path.exists(p):
                st = os.stat(p)
                with open(p, "rb") as f:
                    snap[p] = ("file", f.read(), st.st_mode & 0o777, st.st_uid, st.st_gid)
            else:
                snap[p] = None
        return snap

    @staticmethod
    def _restore_files(snap: Dict[str, Any]) -> None:
        """Put every path back as ``_snapshot_files`` recorded it: content,
        mode and owner, or the symlink, or remove a file that was absent.
        Each one is swapped in atomically. Raises OSError on a failure."""
        for path, old in snap.items():
            tmp = f"{path}.tmp"
            if old is None:
                if os.path.lexists(path):
                    os.unlink(path)
                continue
            if os.path.lexists(tmp):
                os.unlink(tmp)
            if old[0] == "link":
                os.symlink(old[1], tmp)
            else:
                _, data, mode, uid, gid = old
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
                os.chmod(tmp, mode)
                os.chown(tmp, uid, gid)
            os.replace(tmp, path)

    async def _rollback_cert(self, snap: Dict[str, Any], old_attrs: Dict[str, str],
                             changed: List[str], attrs_touched: bool, restarted: bool,
                             msg: str) -> Dict[str, Any]:
        """Undo a failed INSTALL_CERT so slapd runs on the previous certificate.
        An undo step that fails is reported as PARTIAL_ROLLBACK.

        Order matters. A failed restart usually leaves slapd stopped, and the
        cn=config undo goes through slapd's ldapi socket, so slapd is started
        again first, on the restored files. Files this install created stay
        until cn=config no longer names them: removing them earlier would stop
        slapd starting at all. A final restart applies the old TLS paths
        (see _restart_slapd)."""
        undo_errors = []
        existing = {p: v for p, v in snap.items() if v is not None}
        created = {p: None for p, v in snap.items() if v is None}
        # 1. Put back the files that were there before.
        try:
            await asyncio.to_thread(self._restore_files, existing)
        except Exception as e:  # noqa: BLE001
            undo_errors.append(f"restoring the files failed: {str(e)[:150]}")
        # 2. A restart was attempted, so slapd may be down: start it again.
        if restarted:
            try:
                await self._restart_slapd()
            except Exception as e:  # noqa: BLE001
                undo_errors.append(f"restarting slapd failed: {str(e)[:150]}")
        # 3. Point cn=config back at the previous paths, if the modify may have applied.
        config_restored = True
        if attrs_touched:
            try:
                await self._ldapmodify(self._restore_tls_ldif(old_attrs, changed))
            except Exception as e:  # noqa: BLE001
                config_restored = False
                undo_errors.append(f"restoring cn=config failed: {str(e)[:150]}")
        # 4. Remove the files this install created, once nothing names them.
        if created and config_restored:
            try:
                await asyncio.to_thread(self._restore_files, created)
            except Exception as e:  # noqa: BLE001
                undo_errors.append(f"removing the new files failed: {str(e)[:150]}")
        # 5. Restart once more so the old TLS paths take effect.
        if restarted and attrs_touched and config_restored:
            try:
                await self._restart_slapd()
            except Exception as e:  # noqa: BLE001
                undo_errors.append(f"restarting slapd failed: {str(e)[:150]}")
        if undo_errors:
            logger.error("INSTALL_CERT: rollback incomplete: %s", "; ".join(undo_errors))
            return {"status": "ERROR", "error": "PARTIAL_ROLLBACK",
                    "message": f"{msg}; rollback incomplete: {'; '.join(undo_errors)}"}
        logger.warning("INSTALL_CERT failed, previous certificate restored: %s", msg)
        return {"status": "ERROR", "message": f"{msg}; previous certificate restored"}

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

    async def _run_ldapi(self, tool: str, args: List[str], stdin: bytes = b"") -> bytes:
        """Run an OpenLDAP client tool (ldapmodify/ldapsearch) as root over
        ldapi:/// with SASL EXTERNAL (root peer-cred → cn=config access) and
        return its stdout. Raises _CertInstallError on a missing tool, a
        non-zero exit or a 30 s timeout; on timeout or cancellation the process
        is killed and reaped so it can't finish its write after we reported a
        failure."""
        # Start the tool with root's EXTERNAL identity over the local socket.
        try:
            proc = await asyncio.create_subprocess_exec(
                tool, "-Q", "-Y", "EXTERNAL", "-H", "ldapi:///", *args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as e:
            raise _CertInstallError(f"{tool} could not start: {e}") from e
        # Feed stdin, waiting up to 30 seconds; the child is killed and
        # reaped on timeout or cancellation (_communicate).
        try:
            stdout, stderr = await self._communicate(proc, stdin, 30)
        except asyncio.TimeoutError:
            raise _CertInstallError(f"{tool} timed out after 30s") from None
        # Non-zero exit: raise with stderr, stdout or the exit code.
        if proc.returncode != 0:
            err = (stderr.decode(errors="replace").strip() or stdout.decode(errors="replace").strip()
                   or f"{tool} exited {proc.returncode}")
            if tool == "ldapmodify":
                raise _CertInstallRefusalError(f"{tool} failed: {err[:300]}")
            raise _CertInstallError(f"{tool} failed: {err[:300]}")
        return stdout

    async def _ldapmodify(self, ldif: str) -> None:
        """Apply an LDIF to cn=config via SASL EXTERNAL over ldapi:///.
        Raises _CertInstallError on failure. The LDIF is never logged: the
        replication LDIF carries the admin password."""
        await self._run_ldapi("ldapmodify", [], ldif.encode())

    @staticmethod
    async def _communicate(proc, data: Optional[bytes], timeout: float):
        """proc.communicate() with a timeout that kills and reaps the child.
        wait_for alone only cancels the wait: a timed-out ldapmodify left
        running could apply its change after the rollback undid it. A killed
        systemctl's job stays queued in systemd, ahead of any later restart."""
        try:
            return await asyncio.wait_for(proc.communicate(input=data), timeout=timeout)
        except BaseException:
            # Timeout or cancellation: the child must not outlive this call.
            if proc.returncode is None:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                await proc.wait()
            raise

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
        _, stderr = await self._communicate(proc, None, 45)
        # Non-zero exit: raise with stderr or the exit code.
        if proc.returncode != 0:
            err = stderr.decode().strip() or f"systemctl exited {proc.returncode}"
            raise _CertInstallError(f"slapd restart failed: {err[:300]}")

    # ── UPDATE_CONFIG re-apply helpers (Entra .env + mirror-mode) ──────────

    async def _update_config(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply a hub UPDATE_CONFIG push as one transaction.

        The push is MERGED into the current config (a key the hub leaves out
        or sends as None keeps its value, so install-time keys such as
        LDAP_TLS_* survive). Order, each step undone if a later one fails:
        validate → stage the Entra PEMs under new file names → rewrite .env →
        re-apply mirror-mode replication → only then switch the running
        config and manager. On any failure the running config, the manager,
        .env and the PEM files are left as they were, and the reply is ERROR
        naming the failed step; SUCCESS means every step applied. An
        unusable mirror section (no integer server id, malformed peers) skips
        only replication: the rest applies and the reply is PARTIAL. The one
        part not rolled back is the syncprov module and overlay, which are
        additive and harmless without olcSyncrepl. Pushes are serialised."""
        # Log key names only; the payload carries the admin password and Entra key.
        logger.info("Updating LDAP configuration (keys: %s)", sorted(data.keys()))
        async with self.update_config_lock:
            return await self._update_config_locked(data)

    async def _update_config_locked(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Body of ``_update_config``; the caller holds the update lock."""
        incoming = {k: v for k, v in data.items() if v is not None}
        # A blank Entra cert/key means the hub has none; keep the installer's paths.
        for key in ("ENTRA_CLIENT_CERT", "ENTRA_CLIENT_KEY"):
            if key in incoming and not str(incoming[key]).strip():
                del incoming[key]
        merged = {**self.config, **incoming}

        # Step 1: validate, so a bad push changes nothing.
        if not str(merged.get("LDAP_ADMIN_PW") or "").strip():
            return {"status": "ERROR", "message": "LDAP_ADMIN_PW is empty; configuration not applied"}
        # An unusable mirror section only skips replication: the hub derives
        # peers from its other ldap_instances and sends an instance UUID as
        # LDAP_SERVER_ID (lm main.py _ldap_config_for_spoke), and refusing
        # the whole push would also drop the connection settings this spoke
        # gets only from the hub. The reply is PARTIAL, not SUCCESS.
        skipped = ""
        try:
            mirror = self._mirror_settings(incoming)
        except (ValueError, TypeError) as e:
            mirror = None
            skipped = f"replication config invalid, replication not applied: {str(e)[:120]}"

        # Step 2: the ROPC bridge reads the Entra cert/key from file paths;
        # stage any new PEM content as new 0600 files (the live ones stay
        # untouched until the switch).
        try:
            incoming, staged = await asyncio.to_thread(self._store_entra_pems, incoming)
        except OSError as e:
            return {"status": "ERROR",
                    "message": f"could not store the Entra cert/key, configuration not applied: {str(e)[:120]}"}
        merged = {**self.config, **incoming}

        # Step 3: rewrite .env (the pam_exec ROPC bridge reads it per bind;
        # no slapd restart needed), keeping the old bytes for the undo.
        env_before: Optional[str] = None
        env_written = False
        if any(k.startswith("ENTRA_") for k in incoming) or "LDAP_BASE_DN" in incoming:
            try:
                env_before = await asyncio.to_thread(self._read_env)
                await asyncio.to_thread(self._persist_env, incoming)
                env_written = True
            except (OSError, ValueError) as e:
                return await self._undo_update(staged, None, False,
                                               f"env persist failed: {str(e)[:120]}")

        # Step 4: re-apply mirror-mode replication when the push names peers.
        notes = []
        if mirror:
            ok, repl = await self._apply_replication_config(incoming, *mirror)
            if not ok:
                return await self._undo_update(staged, env_before, env_written, repl)
            notes.append(repl)

        # Step 5: every step applied; switch the running config and manager.
        superseded = [self.config.get(k) for k in ("ENTRA_CLIENT_CERT", "ENTRA_CLIENT_KEY")
                      if self.config.get(k) != merged.get(k)]
        self.config = merged
        self.manager = LdapManager(
            admin_dn=merged.get("LDAP_ADMIN_DN", "cn=admin,dc=example,dc=org"),
            admin_pw=merged["LDAP_ADMIN_PW"],
            base_dn=merged.get("LDAP_BASE_DN", "dc=example,dc=org"),
            server_url=merged.get("LDAP_SERVER_URL", "ldap://localhost:389"),
        )
        # A new server/base DN invalidates every cached OU list (and any
        # in-flight read from the old manager).
        self._ou_cache_clear_all()
        await asyncio.to_thread(self._remove_spoke_pems, superseded)
        if env_written:
            notes.insert(0, "entra .env persisted")
        if skipped:
            return {"status": "PARTIAL", "message": f"LDAP configuration updated; {skipped}",
                    "notes": ["configuration applied", *notes, skipped]}
        return {"status": "SUCCESS", "message": "LDAP configuration updated",
                "notes": ["configuration applied", *notes]}

    async def _undo_update(self, staged: List[str], env_before: Optional[str],
                           env_written: bool, failure: str) -> Dict[str, Any]:
        """Undo the file steps of a failed UPDATE_CONFIG and build its ERROR.

        Deletes the PEMs staged for this push and puts .env back byte for
        byte (or removes it if it did not exist). The running config and
        manager were never switched. An undo that itself fails is named in
        the message so the operator knows .env needs a look."""
        # Put .env back first: the ROPC bridge reads it on every bind.
        undo_failed = []
        if env_written:
            try:
                await asyncio.to_thread(self._restore_env, env_before)
            except OSError as e:
                undo_failed.append(f".env not restored: {str(e)[:120]}")
        await asyncio.to_thread(self._remove_spoke_pems, staged)
        message = f"{failure}; configuration not applied"
        if undo_failed:
            message += "; " + "; ".join(undo_failed)
        logger.error("UPDATE_CONFIG failed: %s", message)
        return {"status": "ERROR", "message": message}

    @staticmethod
    def _mirror_settings(data: Dict[str, Any]) -> Optional[Tuple[int, List[str]]]:
        """Return (server id, peer URLs) when ``data`` asks for mirror mode.

        LDAP_MIRROR_PEERS is a JSON list of URLs or of the hub's
        ``{server_id, url}`` dicts, or one bare URL. No peers (the hub sends
        "[]" for a single node) means no mirror: None, and replication is left
        as it is. With peers, LDAP_SERVER_ID must be a positive integer.
        Raises ValueError/TypeError on a malformed value."""
        peers = data.get("LDAP_MIRROR_PEERS")
        if isinstance(peers, str):
            text = peers.strip()
            peers = json.loads(text) if text.startswith("[") else ([text] if text else [])
        urls = replication._clean_peers(peers)
        if not urls:
            return None
        server_id = int(str(data.get("LDAP_SERVER_ID") or "").strip())
        if server_id < 1:
            raise ValueError("LDAP_SERVER_ID must be a positive integer")
        return server_id, urls

    # PEM files this spoke writes are named entra-client.<random>.crt/.key so
    # a push never overwrites the files the ROPC bridge is reading.
    _PEM_NAMES = {"ENTRA_CLIENT_CERT": ("entra-client", ".crt"),
                  "ENTRA_CLIENT_KEY": ("entra-client", ".key")}
    _SPOKE_PEM_RE = re.compile(r"entra-client\.[0-9a-f]{12}\.(?:crt|key)")

    def _store_entra_pems(self, data: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
        """Stage PEM-content ENTRA_CLIENT_CERT / ENTRA_CLIENT_KEY values as new
        0600 files beside .env and return (``data`` with their paths instead,
        the paths written). A value that is already a path is left alone, and
        content equal to the file the running config already points at reuses
        that file. A failure deletes what this call wrote before raising."""
        out, staged = dict(data), []
        try:
            for key, (stem, suffix) in self._PEM_NAMES.items():
                value = out.get(key)
                if not isinstance(value, str) or "-----BEGIN" not in value:
                    continue
                content = value.strip() + "\n"
                # Unchanged content: keep pointing at the current file.
                current = self.config.get(key)
                try:
                    with open(str(current), encoding="utf-8") as fh:
                        if fh.read() == content:
                            out[key] = current
                            continue
                except (OSError, TypeError):
                    pass
                path = str(Path(self._env_path()).parent / f"{stem}.{secrets.token_hex(6)}{suffix}")
                self._write_pem(path, content, 0o600)
                staged.append(path)
                out[key] = path
        except OSError:
            self._remove_spoke_pems(staged)
            raise
        return out, staged

    def _remove_spoke_pems(self, paths: List[Any]) -> None:
        """Delete Entra PEM files this spoke wrote (best effort). Only files
        beside .env with the exact name _store_entra_pems generates
        (entra-client.<12 hex>.crt/.key) are touched, so a path the installer
        or an operator chose, even a similar name, is never deleted."""
        folder = Path(self._env_path()).parent.resolve()
        for p in paths:
            if not isinstance(p, str) or not p:
                continue
            path = Path(p)
            if path.parent.resolve() != folder or not self._SPOKE_PEM_RE.fullmatch(path.name):
                continue
            try:
                path.unlink()
            except OSError as e:
                logger.warning("UPDATE_CONFIG: could not remove %s: %s", path.name, e)

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

    def _read_env(self) -> Optional[str]:
        """Return the current .env text, or None when there is no .env."""
        try:
            with open(self._env_path(), encoding="utf-8") as fh:
                return fh.read()
        except FileNotFoundError:
            return None

    def _restore_env(self, text: Optional[str]) -> None:
        """Put .env back to ``text`` (0600, atomic), or remove it when None."""
        path = self._env_path()
        if text is None:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
            return
        self._write_pem(path, text, 0o600)

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
                v = str(v)
                # One line per key: a newline would inject other .env keys.
                if "\n" in v or "\r" in v or "\0" in v:
                    raise ValueError(f"{k} must be a single line")
                updates[k] = v
        # Nothing to persist.
        if not updates:
            return
        # Read the existing .env lines, if any.
        lines = []
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                lines = fh.read().splitlines()
        # Replace matching keys in place and keep every other line as-is. A
        # multi-line PEM value written by an older spoke is dropped whole (the
        # ROPC bridge can't use it, and it holds a private key).
        seen = set()
        out = []
        in_pem = False
        for line in lines:
            if in_pem:
                in_pem = "-----END" not in line
                continue
            key = line.split("=", 1)[0].strip() if "=" in line else ""
            value = line.split("=", 1)[1] if "=" in line else ""
            if value.strip().startswith("-----BEGIN"):
                in_pem = "-----END" not in value
                if key in updates and key not in seen:
                    out.append(f"{key}={updates[key]}")
                    seen.add(key)
                continue
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
        self._write_pem(path, "\n".join(out) + "\n", 0o600)

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

    async def _read_server_ids(self) -> List[bytes]:
        """Return cn=config's current olcServerID values (raw bytes, as slapd
        stores them; empty when unset). Raises _CertInstallError."""
        out = await self._run_ldapi(
            "ldapsearch", ["-LLL", "-b", "cn=config", "-s", "base", "olcServerID"])
        # Unfold continuation lines (RFC 2849), then read plain ("attr: v")
        # and base64 ("attr:: v") values. Stdlib only: CI can't build
        # python-ldap, and the tests stub only the ldap package.
        text = re.sub(r"\r?\n ", "", out.decode("utf-8", errors="replace"))
        values = []
        for line in text.splitlines():
            m = re.match(r"(?i)olcServerID(::?) ?(.*)$", line)
            if m:
                values.append(base64.b64decode(m.group(2)) if m.group(1) == "::"
                              else m.group(2).encode("utf-8"))
        return values

    @staticmethod
    def _server_id_ldif(values: List[bytes]) -> str:
        """cn=config modify LDIF that sets olcServerID to ``values`` exactly
        (deletes it when empty). A value that is not an LDIF SAFE-STRING
        (RFC 2849: printable ASCII, no leading space/':'/'<', no trailing
        space) is base64-encoded, so any value restores exactly."""
        if not values:
            return "dn: cn=config\nchangetype: modify\ndelete: olcServerID\n-\n"
        lines = ["dn: cn=config", "changetype: modify", "replace: olcServerID"]
        for v in values:
            text = v.decode("ascii", errors="replace")
            safe = (v.isascii() and text.isprintable() and not text.endswith(" ")
                    and not text.startswith((" ", ":", "<")))
            lines.append(f"olcServerID: {text}" if safe
                         else f"olcServerID:: {base64.b64encode(v).decode()}")
        return "\n".join(lines + ["-", ""])

    @staticmethod
    def _redact_credentials(text: str, password: str) -> str:
        """Strip the replication password from an ldapmodify error: slapd can
        echo the rejected olcSyncrepl value, which holds ``credentials=``."""
        # The raw password first: a `"` in it would end the quoted match early.
        if password:
            text = text.replace(password, "***")
        return re.sub(r'credentials=("(?:[^"\\]|\\.)*"|\S+)', "credentials=***", text)

    async def _apply_replication_config(self, data: Dict[str, Any], server_id: int,
                                        peers: List[str]) -> Tuple[bool, str]:
        """Re-apply syncrepl mirror-mode to cn=config (requires co-location on
        the slapd host as root via ldapi EXTERNAL). ``server_id`` and ``peers``
        come from _mirror_settings. Returns (ok, short note).

        All or nothing for the settings that matter: olcServerID is written
        only when it differs and is put back if the next step fails, and
        olcSyncrepl + olcMirrorMode go in ONE modify of the database entry,
        which slapd applies atomically. The syncprov module and overlay are
        added idempotently and are not removed on failure (additive, inert
        without olcSyncrepl). No LDIF or password reaches the log or reply."""
        # Build the LDIF from the merged config's bind identity.
        cfg = {**self.config, **data}
        password = str(cfg.get("LDAP_ADMIN_PW", ""))
        try:
            overlay = replication.build_syncprov_overlay_ldif()
            # One modify record on the DB entry: replace olcSyncrepl, then
            # olcMirrorMode (the mirror-mode record minus its dn/changetype).
            db_modify = replication.build_syncrepl_ldif(
                server_id, peers, cfg.get("LDAP_BASE_DN", ""),
                cfg.get("LDAP_ADMIN_DN", ""), password).rstrip("\n")
            db_modify += "\n-\n" + "\n".join(
                replication.build_mirrormode_ldif(True).splitlines()[2:]) + "\n"
        # Bad input: report it without touching slapd.
        except (ValueError, TypeError) as e:
            return False, f"replication config invalid: {str(e)[:120]}"

        # Step 1: syncprov module + overlay; "exists" means already there.
        err = await self._ldapmodify_tolerant(
            replication.build_syncprov_module_ldif(), tolerate="exists")
        if err:
            return False, f"replication syncprov module load failed: {self._redact_credentials(err, password)[:160]}"
        err = await self._ldapmodify_tolerant(overlay, tolerate="already exists")
        if err:
            return False, f"replication syncprov apply failed: {self._redact_credentials(err, password)[:160]}"

        # Step 2: snapshot olcServerID, then write it only if it changes.
        try:
            before = await self._read_server_ids()
        except _CertInstallError as e:
            return False, f"replication serverID read failed: {str(e)[:160]}"
        wanted = [str(server_id).encode()]
        changed = before != wanted
        if changed:
            err = await self._ldapmodify_tolerant(self._server_id_ldif(wanted))
            if err:
                return False, f"replication serverID apply failed: {self._redact_credentials(err, password)[:160]}"

        # Step 3: syncrepl + mirror mode in one atomic modify; undo step 2 on failure.
        err = await self._ldapmodify_tolerant(db_modify)
        if err:
            note = f"replication mirror apply failed: {self._redact_credentials(err, password)[:160]}"
            if changed:
                undo = await self._ldapmodify_tolerant(self._server_id_ldif(before))
                if undo:
                    note += f"; olcServerID not restored: {self._redact_credentials(undo, password)[:120]}"
            return False, note
        logger.info("UPDATE_CONFIG: mirror-mode replication re-applied (serverID=%s)", server_id)
        return True, "mirror-mode replication re-applied"
